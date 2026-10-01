-- Concurrency is PER ROUTE, PER WORKER (including each graceful-reload worker
-- generation), from access through log. Fleet capacity is the sum of workers'
-- limits. Worker-local ownership has no TTL, shared-memory eviction, or stale
-- count surviving a worker crash. Never release on headers: streams remain live.
-- Native rate-limiting and request-size-limiting own IP rates and body bounds.
local redis = require "resty.redis"
local Handler = { PRIORITY = 800, VERSION = "1.0.0" }
local inflight = {}

-- A single Redis authority supplies the clock and the atomic fixed-minute quota
-- across workers/nodes. It must use noeviction; the runtime ACL needs EVAL,
-- INFO memory, TIME, HGET, HSET, EXPIRE, SELECT, and AUTH when configured.
-- Counter resets on Redis data loss/reinitialization are not durable billing
-- quotas. Protected Redis configuration and persistence remain operational
-- prerequisites; this plugin never repairs or changes that authority.
local QUOTA = [[
local memory = redis.call("INFO", "memory")
if not string.find(memory, "maxmemory_policy:noeviction\r\n", 1, true) then
  return redis.error_reply("resource counter eviction policy is unsafe")
end
local now = tonumber(redis.call("TIME")[1])
local window = math.floor(now / 60)
local previous = redis.call("HGET", KEYS[1], "window")
local count = redis.call("HGET", KEYS[1], "count")
local limit = tonumber(ARGV[1])
local retry = 60 - (now % 60)
if previous or count then
  local old_window, old_count = tonumber(previous), tonumber(count)
  if not old_window or not old_count or old_window < 0
      or old_window % 1 ~= 0 or old_window > window
      or old_count < 0 or old_count % 1 ~= 0 then
    return redis.error_reply("resource counter is corrupt or its clock regressed")
  end
end
if previous and tonumber(previous) == window then
  count = tonumber(count)
else
  count = 0
end
if count >= limit then return {0, retry} end
redis.call("HSET", KEYS[1], "window", window, "count", count + 1)
redis.call("EXPIRE", KEYS[1], 120)
return {1, retry}
]]

local function safe_tenant(value)
  return type(value) == "string" and #value > 0 and #value <= 128
    and value:match("^[A-Za-z0-9][A-Za-z0-9._:@-]*$") ~= nil
end

local function release(ctx)
  local key = ctx.resource_slot
  if not key then return end
  ctx.resource_slot = nil
  local remaining = inflight[key] - 1
  inflight[key] = remaining > 0 and remaining or nil
end

local function deny(ctx, status, code, retry)
  release(ctx)
  local headers = { ["Cache-Control"] = "no-store" }
  if retry then headers["Retry-After"] = tostring(retry) end
  return kong.response.exit(status, { error = code }, headers)
end

local function tenant_quota(conf, tenant)
  local red
  -- Cosocket failures and exceptions both fail closed. Do not log credentials,
  -- identities, or Redis error text. Close on every path, avoiding pooled AUTH
  -- or SELECT state shared with other plugins or a rotated credential.
  local ok, result = pcall(function()
    if type(conf.redis) ~= "table" then return nil end
    red = redis:new()
    red:set_timeout(conf.redis.timeout)
    if not red:connect(conf.redis.host, conf.redis.port) then return nil end
    if conf.redis.password and conf.redis.password ~= ngx.null then
      if not red:auth(conf.redis.password) then return nil end
    end
    if not red:select(conf.redis.database) then return nil end
    -- Length prefixes isolate route/tenant pairs even when IDs contain colons.
    local key = "codestra:resource-quota:v1:" .. #conf.route_key .. ":"
      .. conf.route_key .. ":" .. #tenant .. ":" .. tenant
    return red:eval(QUOTA, 1, key, conf.tenant_quota_per_minute)
  end)
  if red then pcall(red.close, red) end
  if not ok or type(result) ~= "table" or (result[1] ~= 0 and result[1] ~= 1)
    or type(result[2]) ~= "number" or result[2] < 1 or result[2] > 60 then
    return nil
  end
  return result[1] == 1, result[2]
end

function Handler:access(conf)
  local ctx = kong.ctx.plugin
  if ctx.resource_slot then return end
  local active = inflight[conf.route_key] or 0
  if active >= conf.concurrency_limit_per_worker then
    return deny(ctx, 429, "concurrency_limit_exceeded", 1)
  end
  -- No yield occurs between check and acquisition in an OpenResty worker.
  inflight[conf.route_key] = active + 1
  ctx.resource_slot = conf.route_key

  if conf.tenant_quota_per_minute > 0 then
    -- Only codestra-authz's verified request context is authoritative. Never
    -- fall back to caller headers, tenant selectors, or an unverified JWT.
    local tenant = kong.ctx.shared.codestra_authenticated_tenant
    if not safe_tenant(tenant) then
      return deny(ctx, 403, "authenticated_tenant_required")
    end
    local allowed, retry = tenant_quota(conf, tenant)
    if allowed == nil then return deny(ctx, 503, "resource_counter_unavailable", 1) end
    if not allowed then return deny(ctx, 429, "tenant_quota_exceeded", retry) end
  end
end

function Handler:log()
  -- Log also runs for downstream plugin exits, timeouts and client disconnects.
  -- An unacquired/previously released request cannot decrement another slot.
  release(kong.ctx.plugin)
end

function Handler:header_filter()
  -- Kong PDK get_source distinguishes gateway transport errors from upstream
  -- application statuses and explicit plugin exits. Preserve the latter.
  if kong.response.get_source() ~= "error" then return end
  local status = kong.response.get_status()
  local code
  if status == 504 then code = "upstream_timeout"
  elseif status == 502 or status == 503 then code = "upstream_unavailable"
  else return end
  kong.ctx.plugin.resource_error_body = '{"error":"' .. code .. '"}'
  kong.response.clear_header("Content-Length")
  kong.response.clear_header("Content-Encoding")
  kong.response.set_header("Content-Type", "application/json; charset=utf-8")
  kong.response.set_header("Cache-Control", "no-store")
end

function Handler:body_filter()
  local ctx = kong.ctx.plugin
  if not ctx.resource_error_body then return end
  if ctx.resource_error_written then
    ngx.arg[1] = nil
    return
  end
  ctx.resource_error_written = true
  -- PDK sets EOF; discard native error chunks without buffering them.
  kong.response.set_raw_body(ctx.resource_error_body)
end

return Handler
