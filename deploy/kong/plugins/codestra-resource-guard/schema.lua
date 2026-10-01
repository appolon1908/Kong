return { name = "codestra-resource-guard", fields = {
  { protocols = { type = "set", default = { "http", "https" },
    elements = { type = "string", one_of = { "http", "https" } } } },
  { config = { type = "record", fields = {
    { route_key = { type = "string", required = true, len_min = 1, len_max = 128,
      match = "^[A-Za-z0-9][A-Za-z0-9._:@-]*$" } },
    { concurrency_limit_per_worker = { type = "integer", required = true, between = {1, 10000} } },
    { tenant_quota_per_minute = { type = "integer", default = 0, between = {0, 1000000} } },
    { redis = { type = "record", fields = {
      -- Kong fills record defaults, so this record always exists; the host is
      -- required only when the tenant quota uses Redis (custom_validator).
      { host = { type = "string", len_min = 1, len_max = 253 } },
      { port = { type = "integer", default = 6379, between = {1, 65535} } },
      { password = { type = "string", referenceable = true, encrypted = true } },
      { timeout = { type = "integer", default = 1000, between = {1, 10000} } },
      { database = { type = "integer", default = 0, between = {0, 15} } }
    } } }
  }, custom_validator = function(conf)
    if (conf.tenant_quota_per_minute or 0) > 0
        and (type(conf.redis) ~= "table" or type(conf.redis.host) ~= "string" or conf.redis.host == "") then
      return nil, "redis is required when tenant_quota_per_minute is enabled"
    end
    return true
  end } }
} }
