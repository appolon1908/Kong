"""Pure, deterministic gateway compilation. No Admin API or runtime side effects."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from scripts.kong_private_surface import private_surface_error, runtime_plugin_config
from scripts.kong_traffic_policy import passive_health, resource_guard, traffic_policy

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "config/integrations"
MAX_BYTES = 1_048_576
OIDC = {"public-oidc-api", "internal-service-jwt", "private-mtls-api", "websocket-api"}
# Issuer per environment: a staging integration must never validate production
# tokens and vice versa. Development binds a local realm chosen at render time.
ENVIRONMENT_ISSUERS = {
    "production": "https://auth.codestra.co/realms/codestra",
    "staging": "https://auth-staging.codestra.co/realms/codestra",
}
POLICY_PLUGINS = {
    "public-oidc-api": ["openid-connect", "codestra-authz"],
    "internal-service-jwt": ["openid-connect", "codestra-authz", "ip-restriction"],
    "private-mtls-api": ["openid-connect", "codestra-authz", "mtls-auth", "ip-restriction"],
    "signed-webhook": ["codestra-webhook-verifier"], "websocket-api": ["openid-connect", "codestra-authz"],
    "public-health": [], "legacy-api-key": ["key-auth"],
}
TRUST_HEADERS = ["X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email",
                 "X-Tenant-ID", "X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier",
                 "X-Anonymous-Consumer", "X-Codestra-Tenant", "X-Codestra-Scopes",
                 "X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes",
                 "X-Authenticated-UserID", "X-Authenticated-User", "X-Authenticated-Tenant",
                 "X-Authenticated-Campaign", "X-Authenticated-Role", "X-Codestra-Gateway-Secret",
                 "X-Internal-Service", "X-Admin", "X-Codestra-Contract-Operation",
                 "X-Codestra-Expected-Azp", "X-Codestra-Required-Scope"]


class ContractError(ValueError):
    """Stable public error; never includes a supplied value or a credential."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_json_key")
        result[key] = value
    return result


def load_json(path):
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ContractError("document_too_large")
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite_json")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("invalid_json_document") from exc


def _require(condition, code):
    if not condition:
        raise ContractError(code)


def hostname(value):
    _require(len(value) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                                     for p in value.split(".")), "invalid_dns_name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise ContractError("literal_address_not_allowed")


def path_segments(path):
    _require(path.startswith("/") and "//" not in path, "invalid_route_path")
    _require(path == "/" or not path.endswith("/"), "trailing_slash_not_supported")
    parts = path.strip("/").split("/") if path != "/" else []
    _require(not any(p in {".", ".."} for p in parts), "invalid_route_path")
    params = []
    for part in parts:
        if "{" in part or "}" in part:
            _require(bool(re.fullmatch(r"\{[a-z][a-z0-9_]*\}", part)), "invalid_path_parameter")
            params.append(part)
    _require(len(params) == len(set(params)), "duplicate_path_parameter")
    return parts


def validate(document, *, today=None):
    schema = load_json(AUTHORITY / "schemas/gateway-integration.schema.json")
    if next(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document), None):
        raise ContractError("integration_schema_invalid")
    meta, spec = document["metadata"], document["spec"]
    auth, upstream, policies = spec["authentication"], spec["upstream"], spec["policies"]
    template = auth["template"]
    policy = load_json(AUTHORITY / "policies" / (template + ".json"))
    policy_schema = load_json(AUTHORITY / "schemas/gateway-policy.schema.json")
    _require(Draft202012Validator(policy_schema).is_valid(policy), "invalid_policy_authority")
    _require(policy["name"] == template, "policy_identity_mismatch")
    _require(policy["plugins"] == POLICY_PLUGINS[template], "policy_plugin_authority_mismatch")
    _require(all(value <= policy["maximumTimeoutMs"] for value in upstream["timeouts"].values()), "policy_timeout_limit")
    _require(meta["environment"] != "production" or policy["newProductionAllowed"], "legacy_production_forbidden")
    if template in OIDC:
        expected_issuer = ENVIRONMENT_ISSUERS.get(meta["environment"])
        _require(expected_issuer is None or auth["issuer"] == expected_issuer, "issuer_environment_mismatch")
    for name in (spec["host"], upstream["dnsName"], policies["redisHost"]):
        hostname(name)
    _require("." in spec["host"], "route_host_must_be_fqdn")
    # The upstream registry is the repository's reviewed boundary; arbitrary provider hosts are rejected.
    upstream_catalog = load_json(AUTHORITY / "upstreams.json")
    _require(upstream["dnsName"] in upstream_catalog["allowedDnsNames"], "upstream_not_registered")
    _require(policies["redisHost"] in upstream_catalog["allowedRedisHosts"], "redis_not_registered")
    if upstream["protocol"] == "https":
        _require(upstream.get("tlsServerName") == upstream["dnsName"], "upstream_sni_mismatch")
    else:
        _require("tlsServerName" not in upstream, "tls_name_on_plaintext_upstream")
        _require(meta["environment"] == "development", "upstream_tls_required")
    for path in (upstream["healthPath"], upstream["readinessPath"]):
        _require("{" not in path, "health_path_must_be_literal")
        path_segments(path)
    for network in policies["sourceAllowlist"]:
        try:
            parsed = ipaddress.ip_network(network, strict=True)
        except ValueError as exc:
            raise ContractError("invalid_source_network") from exc
        _require(parsed.prefixlen > 0, "unbounded_source_network")
    if spec["exposure"] == "private" or template in {"internal-service-jwt", "private-mtls-api"}:
        _require(spec["exposure"] == "private" and bool(policies["sourceAllowlist"]), "private_source_allowlist_required")
    for origin in policies["corsOrigins"]:
        try:
            parsed = urlsplit(origin)
            _require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                     and not parsed.path and not parsed.query and not parsed.fragment
                     and parsed.port in {None, 443}, "invalid_cors_origin")
            hostname(parsed.hostname)
            _require(origin == "https://" + parsed.hostname + (":443" if parsed.port else ""), "invalid_cors_origin")
        except ValueError as exc:
            raise ContractError("invalid_cors_origin") from exc
    fields = {"template"}
    if template in OIDC:
        fields |= {"issuer", "audience", "authorizedParties", "scopes", "roles", "tenantClaim"}
        if template == "private-mtls-api":
            fields.add("caCertificateIds")
    elif template == "signed-webhook":
        fields |= {"secretRef", "keyId"}
    elif template == "legacy-api-key":
        fields.add("legacySunset")
    _require(set(auth) == fields, "authentication_fields_mismatch")
    if template == "signed-webhook":
        _require(auth["secretRef"] == f"{{vault://env/kong-webhook-{meta['id']}}}",
                 "webhook_secret_reference_mismatch")
        _require(upstream["idempotencyAuthority"] == "Middleware", "webhook_replay_authority_required")
        _require(not policies["corsOrigins"], "webhook_cors_forbidden")
    if template == "legacy-api-key":
        _require(date.fromisoformat(auth["legacySunset"]) > (today or date.today()), "legacy_sunset_expired")
    known_scopes = set(load_json(AUTHORITY / "scopes.json")["scopes"])
    _require(set(auth.get("scopes", [])) <= known_scopes, "unknown_scope")
    _require(set(auth.get("roles", [])) <= set(load_json(AUTHORITY / "roles.json")["roles"]), "unknown_role")
    seen_ids, seen_operations = set(), set()
    for route in spec["routes"]:
        path_segments(route["path"])
        boundary_error = private_surface_error(route, exposure=spec["exposure"],
                                               source_allowlist=policies["sourceAllowlist"])
        _require(boundary_error is None, boundary_error)
        traffic = traffic_policy(route, upstream)
        _require(traffic["burstPerSecond"] <= traffic["ratePerMinute"], "burst_exceeds_minute_limit")
        _require(not traffic["tenantQuotaPerMinute"] or template in OIDC,
                 "tenant_quota_requires_verified_identity")
        _require(route["id"] not in seen_ids, "duplicate_route_id")
        seen_ids.add(route["id"])
        _require(len(route["methods"]) == len(route["operationIds"]), "operation_method_count_mismatch")
        _require(not seen_operations.intersection(route["operationIds"]), "duplicate_operation_id")
        seen_operations.update(route["operationIds"])
        _require(set(route["scopes"]) <= known_scopes, "unknown_scope")
        if template in OIDC:
            _require(bool(route["scopes"]) and set(route["scopes"]) <= set(auth["scopes"]), "route_scope_mismatch")
        else:
            _require(not route["scopes"], "scope_requires_oidc")
        if set(route["methods"]) - {"GET", "HEAD", "OPTIONS"}:
            _require(not upstream["retries"] or (upstream["idempotencyAuthority"] == "Middleware"
                     and route.get("retrySafe") is True), "unsafe_write_retry")
        if template == "public-health":
            _require(policies["requireCorrelationId"] is False, "public_health_correlation_must_be_optional")
            _require(set(route["methods"]) <= {"GET", "HEAD"} and route["match"] == "exact"
                     and route["path"] in {"/healthz", "/readyz", "/version"}
                     and meta["dataClassification"] == "public", "public_health_boundary")
        if template == "websocket-api":
            _require(route["methods"] == ["GET"], "websocket_get_required")
        _require(route["maxBodyBytes"] <= policy["maximumBodyBytes"], "policy_body_limit")
    _require((ROOT / spec["operations"]["runbook"]).is_file(), "runbook_missing")
    return document


def _overlaps(a, b):
    left, right = path_segments(a["path"]), path_segments(b["path"])
    for x, y in zip(left, right):
        if x != y and not (x.startswith("{") or y.startswith("{")):
            return False
    if len(left) == len(right):
        return True
    shorter = a if len(left) < len(right) else b
    return shorter["match"] == "prefix"


def validate_set(documents):
    _require(bool(documents) and len(documents) <= 256, "integration_count_invalid")
    ids, operations, services, routes = set(), set(), {}, []
    for document in documents:
        validate(document)
        meta, spec = document["metadata"], document["spec"]
        env = meta["environment"]
        key = (env, meta["id"])
        _require(key not in ids, "duplicate_integration_id")
        ids.add(key)
        service_key = (env, spec["upstream"]["service"])
        binding = canonical(spec["upstream"])
        _require(service_key not in services or services[service_key] == binding, "conflicting_service_binding")
        services[service_key] = binding
        for route in spec["routes"]:
            for operation in route["operationIds"]:
                _require((env, operation) not in operations, "duplicate_operation_id")
                operations.add((env, operation))
            effective = set(route["methods"]) | ({"OPTIONS"} if spec["policies"]["corsOrigins"] else set())
            for old_env, old_host, old_route, old_methods in routes:
                if env == old_env and spec["host"] == old_host and effective & old_methods:
                    _require(not _overlaps(route, old_route), "ambiguous_route_collision")
            routes.append((env, spec["host"], route, effective))
    return documents


def _route_path(route):
    pieces = ["[^/]+" if p.startswith("{") else re.escape(p) for p in path_segments(route["path"])]
    pattern = "/" + "/".join(pieces)
    # Prefix is a segment boundary, never /orders matching /orders-admin.
    return "~" + pattern + ("$" if route["match"] == "exact" else (".*$" if pattern == "/" else "(?:/.*)?$"))


def _plugin(name, config):
    return {"name": name, "config": config}


def compile_integrations(documents, *, environment):
    validate_set(documents)
    selected = sorted((d for d in documents if d["metadata"]["environment"] == environment),
                      key=lambda d: d["metadata"]["id"])
    _require(bool(selected), "environment_has_no_integrations")
    services, upstreams, matrix = {}, {}, []
    for document in selected:
        meta, spec = document["metadata"], document["spec"]
        upstream, auth, policies = spec["upstream"], spec["authentication"], spec["policies"]
        name, template = upstream["service"], auth["template"]
        service_name = environment + "--" + name
        if service_name not in services:
            services[service_name] = {"name": service_name, "protocol": upstream["protocol"],
                "host": service_name, "port": upstream["port"], "retries": upstream["retries"],
                "connect_timeout": upstream["timeouts"]["connectMs"], "read_timeout": upstream["timeouts"]["readMs"],
                "write_timeout": upstream["timeouts"]["writeMs"], "routes": []}
            if upstream["protocol"] == "https":
                services[service_name]["tls_verify"] = True
            upstreams[service_name] = {"name": service_name, "host_header": upstream["dnsName"],
                "targets": [{"target": f'{upstream["dnsName"]}:{upstream["port"]}', "weight": 100}],
                "healthchecks": {"active": {"type": upstream["protocol"], "http_path": upstream["readinessPath"],
                    "healthy": {"interval": 10, "successes": 2},
                    "unhealthy": {"interval": 5, "http_failures": 2, "tcp_failures": 2, "timeouts": 2}},
                    "passive": passive_health()}}
            if upstream["protocol"] == "https":
                upstreams[service_name]["healthchecks"]["active"].update(
                    {"https_sni": upstream["tlsServerName"], "https_verify_certificate": True})
        for route in sorted(spec["routes"], key=lambda r: r["id"]):
            route_name = environment + "--" + meta["id"] + "--" + route["id"]
            traffic = traffic_policy(route, upstream)
            redis = {"host": policies["redisHost"], "port": 6379, "database": 0,
                     "timeout": 2000, "password": policies["redisPasswordRef"]}
            plugins = [_plugin("codestra-request-context", {"require_correlation_id": policies["requireCorrelationId"]}),
                _plugin("request-size-limiting", {"allowed_payload_size": route["maxBodyBytes"], "size_unit": "bytes",
                                                  "require_content_length": False}),
                _plugin("rate-limiting", {"minute": route["ratePerMinute"], "second": traffic["burstPerSecond"],
                    "error_code": 429, "error_message": "rate_limit_exceeded", "policy": "redis", "fault_tolerant": False,
                    "limit_by": "ip", "redis": {"host": policies["redisHost"], "port": 6379, "database": 0,
                    "timeout": 2000, "password": policies["redisPasswordRef"]}})]
            plugins.extend([resource_guard(route_name, traffic, redis),
                _plugin("codestra-private-surface", runtime_plugin_config(
                    exposure=spec["exposure"], source_allowlist=policies["sourceAllowlist"]))])
            if template == "legacy-api-key":
                plugins[0]["config"]["not_after"] = int(datetime.combine(
                    date.fromisoformat(auth["legacySunset"]), datetime.min.time(), tzinfo=timezone.utc).timestamp())
            if template in OIDC:
                plugins.extend([_plugin("openid-connect", {"issuer": auth["issuer"] + "/.well-known/openid-configuration", "auth_methods": ["bearer"],
                    "cache_tokens_salt": "{vault://env/kong-oidc-cache-tokens-salt}",
                    "bearer_token_param_type": ["header"], "audience_required": [auth["audience"]], "consumer_claim": ["azp"],
                    "scopes_required": [" ".join(sorted(route["scopes"]))], "ssl_verify": True,
                    "issuers_allowed": [auth["issuer"]], "verify_signature": True, "verify_claims": True,
                    "consumer_by": ["username"], "consumer_optional": False,
                    "cache_ttl": 300, "cache_ttl_max": 300, "rediscovery_lifetime": 30, "leeway": 0}),
                    _plugin("codestra-authz", {"issuer": auth["issuer"], "audience": auth["audience"],
                        "authorized_parties": sorted(auth["authorizedParties"]), "scopes": sorted(route["scopes"]),
                        "roles": sorted(auth["roles"]), "tenant_claim": auth["tenantClaim"]})])
            if template == "private-mtls-api":
                plugins.append(_plugin("mtls-auth", {"ca_certificates": sorted(auth["caCertificateIds"]),
                                                       "skip_consumer_lookup": True}))
            if template == "signed-webhook":
                plugins.append(_plugin("codestra-webhook-verifier", {"secret": auth["secretRef"],
                    "key_id": auth["keyId"], "maximum_body_bytes": route["maxBodyBytes"], "clock_skew_seconds": 300}))
            if template == "legacy-api-key":
                plugins.append(_plugin("key-auth", {"key_names": ["X-API-Key"], "key_in_header": True,
                    "key_in_query": False, "key_in_body": False, "hide_credentials": True}))
            if policies["sourceAllowlist"]:
                plugins.append(_plugin("ip-restriction", {"allow": sorted(policies["sourceAllowlist"])}))
            if policies["corsOrigins"]:
                plugins.append(_plugin("cors", {"origins": sorted(policies["corsOrigins"]),
                    "methods": sorted(route["methods"]), "credentials": False, "preflight_continue": False,
                    "headers": ["Authorization", "Content-Type", "Idempotency-Key", "X-Correlation-ID", "traceparent"]}))
            services[service_name]["routes"].append({"name": route_name, "hosts": [spec["host"]],
                "paths": [_route_path(route)], "methods": sorted(set(route["methods"]) | ({"OPTIONS"} if policies["corsOrigins"] else set())), "protocols": ["https"],
                "strip_path": False, "preserve_host": False, "regex_priority": 100,
                "plugins": sorted(plugins, key=lambda p: p["name"])})
            matrix.append({"integration_id": meta["id"], "route": route_name, "traffic_policy": traffic,
                "cases": ["positive", "wrong_method", "oversized_body", "rate_exceeded", "redis_unavailable",
                          "upstream_unavailable", "spoofed_identity", "correlation_id", "rollback"] +
                         (["missing_token", "missing_required_claim", "wrong_issuer", "wrong_audience", "wrong_azp", "wrong_role", "wrong_scope", "wrong_tenant"]
                          if template in OIDC else []) +
                         (["invalid_signature", "expired_signature", "wrong_key_id", "durable_replay_denial"]
                          if template == "signed-webhook" else []), "runtime_result": "NOT_RUN"})
    for service in services.values():
        service["routes"].sort(key=lambda r: r["name"])
    declarative = {"_format_version": "3.0", "_transform": True,
                   "plugins": [_plugin("codestra-private-surface", {"allow_private": False}),
                       _plugin("prometheus", {"status_code_metrics": True, "latency_metrics": True,
                       "bandwidth_metrics": True, "upstream_health_metrics": True})],
                   "services": [services[k] for k in sorted(services)],
                   "upstreams": [upstreams[k] for k in sorted(upstreams)],
                   "consumers": [{"username": party} for party in sorted({party for d in selected
                       for party in d["spec"]["authentication"].get("authorizedParties", [])})]}
    return {"schema": "codestra.gateway.compilation.v1", "environment": environment,
        "source_sha256": digest(sorted(selected, key=lambda d: d["metadata"]["id"])),
        "config_sha256": digest(declarative), "runtime_apply_authorized": False,
        "runtime_certified": False, "kong": declarative, "test_matrix": matrix,
        "openapi_stub": openapi_stub(selected)}


def openapi_stub(documents):
    """Draft upstream operation reference; application request/response schemas remain owned upstream."""
    paths = {}
    for document in sorted(documents, key=lambda d: d["metadata"]["id"]):
        spec = document["spec"]
        for route in sorted(spec["routes"], key=lambda r: r["id"]):
            # Different hosts may legitimately expose the same path/method; maintain
            # separate per-host documents instead of silently overwriting operations.
            host_paths = paths.setdefault(spec["host"], {})
            item = host_paths.setdefault(route["path"], {})
            for method, operation in sorted(zip(route["methods"], route["operationIds"])):
                item[method.lower()] = {"operationId": operation,
                    "x-codestra-route-match": route["match"], "x-codestra-required-scopes": sorted(route["scopes"]),
                    "parameters": [{"name": p[1:-1], "in": "path", "required": True, "schema": {"type": "string"}}
                                   for p in path_segments(route["path"]) if p.startswith("{")],
                    "responses": {"default": {"description": "Define the application response schema in the upstream API contract."}}}
    return [{"openapi": "3.1.0", "info": {"title": host, "version": "0.1.0"},
             "servers": [{"url": "https://" + host}], "paths": paths[host],
             "x-codestra-contract-state": "DRAFT_UPSTREAM_SCHEMAS_REQUIRED"} for host in sorted(paths)]
