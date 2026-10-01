local Handler = { PRIORITY = 100004, VERSION = "1.0.0" }

local private_roots = {
  "internal", "_internal", "metrics", "admin", "administration", "management",
  "manage", "_management", "worker", "workers", "debug", "_debug", "database",
  "databases", "db", "postgres", "postgresql", "redis", "pgadmin", "phpmyadmin",
  "actuator", "server-status", "server-info", "provider-admin", "provider-administration"
}
local kong_roots = {
  "services", "routes", "plugins", "consumers", "consumer_groups", "upstreams",
  "targets", "certificates", "ca_certificates", "snis", "vaults", "key-auths",
  "jwt", "acls", "clustering", "cache", "config", "schemas", "licenses",
  "workspaces", "admins", "rbac", "vitals", "status", "endpoints"
}
local api_mounts = {
  {}, {"api"}, {"#version"}, {"api", "#version"}, {"platform", "#version"},
  {"#version", "platform"}
}
local mounts = {{"kong"}, {"n8n"}, {"odoo"}, {"keycloak"}}
local provider_mounts = {}
local kong_mounts = {{}, {"kong"}}
for _, prefix in ipairs(api_mounts) do
  mounts[#mounts + 1] = prefix
  for _, kind in ipairs({"provider", "providers", "integrations"}) do
    local provider = {}
    for i, segment in ipairs(prefix) do provider[i] = segment end
    provider[#provider + 1] = kind
    provider[#provider + 1] = "*"
    provider_mounts[#provider_mounts + 1] = provider
    mounts[#mounts + 1] = provider
    kong_mounts[#kong_mounts + 1] = provider
  end
end
local forbidden = {
  {"rest"}, {"n8n", "rest"}, {"n8n", "api"}, {"n8n", "settings"},
  {"web", "database"}, {"odoo", "web", "database"}, {"xmlrpc", "db"},
  {"odoo", "xmlrpc", "db"}
}
for _, prefix in ipairs(provider_mounts) do
  for _, suffix in ipairs({{"rest"}, {"web", "database"}, {"xmlrpc", "db"}}) do
    local segments = {}
    for i, segment in ipairs(prefix) do segments[i] = segment end
    for _, segment in ipairs(suffix) do segments[#segments + 1] = segment end
    forbidden[#forbidden + 1] = segments
  end
end
local function add_roots(prefixes, roots)
  for _, prefix in ipairs(prefixes) do
    for _, root in ipairs(roots) do
      local segments = {}
      for i, segment in ipairs(prefix) do segments[i] = segment end
      segments[#segments + 1] = root
      forbidden[#forbidden + 1] = segments
    end
  end
end
add_roots(mounts, private_roots)
add_roots(kong_mounts, kong_roots)

local function normalized_segments(path)
  if type(path) ~= "string" or #path == 0 or #path > 8192 then return nil end
  -- Bound repeated decoding; remaining '%' after eight rounds is ambiguous
  -- and denied. Decode separators too, since upstream routers may do so.
  for _ = 1, 8 do
    if not path:find("%%") then break end
    if path:gsub("%%%x%x", ""):find("%%") then return nil end
    path = path:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
  end
  if path:find("%%") or path:find("[%z\1-\32\127-\255?#]") then return nil end
  path = path:gsub("\\", "/"):lower()
  if path:sub(1, 1) ~= "/" then return nil end
  local parts = {}
  for segment in path:gmatch("[^/]+") do
    -- Servlet-style path parameters must not disguise a reserved segment or
    -- a dot segment if an upstream framework strips those parameters.
    segment = segment:match("^[^;]*")
    if segment == ".." then
      parts[#parts] = nil
    elseif segment ~= "." and segment ~= "" then
      parts[#parts + 1] = segment
    end
  end
  return parts
end

local function is_private(path)
  local parts = normalized_segments(path)
  if not parts then return true end
  for _, prefix in ipairs(forbidden) do
    if #parts >= #prefix then
      local matches = true
      for i, reserved in ipairs(prefix) do
        if reserved ~= "*" and parts[i] ~= reserved
          and not (reserved == "#version" and parts[i]:match("^v%d+$")) then
          matches = false
          break
        end
      end
      if matches then return true end
    end
  end
  return false
end

function Handler:access(conf)
  -- This flag can be emitted only for a reviewed private route with the
  -- compiler's mandatory ip-restriction plugin. Never infer it from headers.
  if conf.allow_private == true then return end
  if is_private(kong.request.get_path()) or is_private(kong.request.get_raw_path()) then
    return kong.response.exit(404, { error = "private_surface_not_found" })
  end
end
return Handler
