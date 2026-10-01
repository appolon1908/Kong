local uuid = require("kong.tools.uuid").uuid
local Handler = { PRIORITY = 100002, VERSION = "1.0.0" }
local identity_headers = {
  "X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email",
  "X-Tenant-ID", "X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier",
  "X-Anonymous-Consumer", "X-Codestra-Tenant", "X-Codestra-Scopes",
  "X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes",
  "X-Authenticated-UserID", "X-Authenticated-User", "X-Authenticated-Tenant",
  "X-Authenticated-Campaign", "X-Authenticated-Role", "X-Codestra-Gateway-Secret",
  "X-Internal-Service", "X-Admin", "X-Codestra-Contract-Operation",
  "X-Codestra-Expected-Azp", "X-Codestra-Required-Scope"
}
local function safe_id(value)
  return type(value) == "string" and #value >= 1 and #value <= 128
    and value:match("^[A-Za-z0-9][A-Za-z0-9._:-]*$") ~= nil
end
function Handler:access(conf)
  if conf.not_after and ngx.time() >= conf.not_after then
    return kong.response.exit(403, { error = "legacy_credential_sunset_reached" })
  end
  local tenant = kong.request.get_header("X-Tenant-ID")
  if tenant and not safe_id(tenant) then
    return kong.response.exit(400, { error = "invalid_tenant_selector" })
  end
  kong.ctx.shared.codestra_requested_tenant = tenant
  for _, name in ipairs(identity_headers) do kong.service.request.clear_header(name) end
  local correlation = kong.request.get_header("X-Correlation-ID")
  if not correlation then
    if conf.require_correlation_id and kong.request.get_method() ~= "OPTIONS" then
      return kong.response.exit(400, { error = "correlation_id_required" })
    end
    correlation = uuid()
  end
  if not safe_id(correlation) then
    return kong.response.exit(400, { error = "invalid_correlation_id" })
  end
  kong.ctx.plugin.correlation_id = correlation
  kong.service.request.set_header("X-Correlation-ID", correlation)
  local request_id = kong.request.get_header("X-Request-ID") or correlation
  if not safe_id(request_id) then
    return kong.response.exit(400, { error = "invalid_request_id" })
  end
  kong.ctx.plugin.request_id = request_id
  kong.service.request.set_header("X-Request-ID", request_id)
  local trace = kong.request.get_header("traceparent")
  if trace then
    if type(trace) ~= "string" then
      return kong.response.exit(400, { error = "invalid_traceparent" })
    end
    local version, trace_id, parent_id, flags = trace:match("^(%x%x)%-(%x+)%-(%x+)%-(%x%x)$")
    if version ~= "00" or #trace ~= 55 or #trace_id ~= 32 or #parent_id ~= 16
      or trace_id == string.rep("0", 32) or parent_id == string.rep("0", 16)
      or trace ~= trace:lower() or (flags ~= "00" and flags ~= "01") then
      return kong.response.exit(400, { error = "invalid_traceparent" })
    end
  else
    local trace_id = uuid():gsub("-", "")
    local parent_id = uuid():gsub("-", ""):sub(1, 16)
    kong.service.request.set_header("traceparent", "00-" .. trace_id .. "-" .. parent_id .. "-00")
  end
end
function Handler:header_filter()
  local correlation = kong.ctx.plugin.correlation_id
  if correlation then kong.response.set_header("X-Correlation-ID", correlation) end
  if kong.ctx.plugin.request_id then kong.response.set_header("X-Request-ID", kong.ctx.plugin.request_id) end
  kong.response.set_header("X-Content-Type-Options", "nosniff")
  kong.response.set_header("Referrer-Policy", "no-referrer")
  kong.response.set_header("Strict-Transport-Security", "max-age=31536000")
end
return Handler
