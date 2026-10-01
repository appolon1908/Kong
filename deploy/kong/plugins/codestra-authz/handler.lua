-- Executes after bearer-only openid-connect (priority 1050). Authentication is
-- mandatory; this plugin adds route authorization and never verifies signatures.
local cjson = require "cjson.safe"
local Handler = { PRIORITY = 900, VERSION = "1.0.0" }
local function contains(values, expected)
  if type(values) == "string" then return values == expected end
  if type(values) ~= "table" then return false end
  for _, value in ipairs(values) do if value == expected then return true end end
  return false
end
local function safe(value)
  return type(value) == "string" and #value > 0 and #value <= 128
    and value:match("^[A-Za-z0-9][A-Za-z0-9._:@-]*$") ~= nil
end
local function finite(value)
  return type(value) == "number" and value == value and value ~= math.huge and value ~= -math.huge
end
local function deny(code, reason)
  if code == 401 then
    kong.response.set_header("WWW-Authenticate", 'Bearer realm="codestra", error="invalid_token"')
  elseif reason == "insufficient_scope" then
    kong.response.set_header("WWW-Authenticate", 'Bearer realm="codestra", error="insufficient_scope"')
  end
  return kong.response.exit(code, { error = reason })
end
function Handler:access(conf)
  kong.ctx.shared.codestra_authenticated_tenant = nil
  for _, name in ipairs({"X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email",
                         "X-Tenant-ID", "X-Codestra-Tenant", "X-Codestra-Scopes"}) do
    kong.service.request.clear_header(name)
  end
  local consumer = kong.client.get_consumer()
  if not consumer or not safe(consumer.username) then
    return deny(401, "authentication_required")
  end
  local authorization = kong.request.get_header("authorization")
  if type(authorization) ~= "string" or #authorization > 16384 then
    return deny(401, "invalid_bearer_token")
  end
  local segment = authorization:match("^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+)$")
  local header_segment = segment and segment:match("^([^.]+)%.")
  if not header_segment then return deny(401, "invalid_bearer_token") end
  header_segment = header_segment:gsub("-", "+"):gsub("_", "/")
  local header_raw = ngx.decode_base64(header_segment .. string.rep("=", (4 - #header_segment % 4) % 4))
  local header = header_raw and cjson.decode(header_raw)
  if type(header) ~= "table" or header.alg ~= "RS256"
    or type(header.kid) ~= "string" or #header.kid == 0 or #header.kid > 256 then
    return deny(401, "invalid_bearer_token")
  end
  segment = segment and segment:match("^[^.]+%.([^.]+)%.")
  if not segment then return deny(401, "invalid_bearer_token") end
  segment = segment:gsub("-", "+"):gsub("_", "/")
  local raw = ngx.decode_base64(segment .. string.rep("=", (4 - #segment % 4) % 4))
  local claims = raw and cjson.decode(raw)
  if type(claims) ~= "table" or claims.iss ~= conf.issuer or not contains(claims.aud, conf.audience) then
    return deny(401, "invalid_token_identity")
  end
  local now = ngx.time()
  if not finite(claims.exp) or claims.exp <= now
    or (claims.nbf ~= nil and (not finite(claims.nbf) or claims.nbf > now))
    or not finite(claims.iat) or claims.iat > now
    or claims.exp <= claims.iat or claims.exp - claims.iat > 300 then
    return deny(401, "invalid_token_time")
  end
  local tenant = claims[conf.tenant_claim]
  if not safe(tenant) or not safe(claims.sub) or not contains(conf.authorized_parties, claims.azp)
    or consumer.username ~= claims.azp then
    return deny(403, "unauthorized_identity")
  end
  local selected = kong.ctx.shared.codestra_requested_tenant
  if selected and selected ~= tenant then
    return deny(403, "tenant_mismatch")
  end
  local scopes = {}
  if type(claims.scope) == "string" then
    for scope in claims.scope:gmatch("%S+") do scopes[scope] = true end
  end
  for _, scope in ipairs(conf.scopes) do
    if not scopes[scope] then return deny(403, "insufficient_scope") end
  end
  local roles = type(claims.realm_access) == "table" and claims.realm_access.roles
  for _, role in ipairs(conf.roles) do
    if not contains(roles, role) then return deny(403, "insufficient_role") end
  end
  kong.service.request.set_header("X-Authenticated-Client", claims.azp)
  kong.service.request.set_header("X-Authenticated-Subject", claims.sub)
  kong.service.request.set_header("X-Codestra-Tenant", tenant)
  kong.service.request.set_header("X-Codestra-Scopes", table.concat(conf.scopes, " "))
  -- Only verified, fully authorized context can key shared tenant quotas.
  kong.ctx.shared.codestra_authenticated_tenant = tenant
end
return Handler
