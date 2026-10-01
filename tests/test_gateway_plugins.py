import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from lupa import LuaRuntime

ROOT = Path(__file__).resolve().parents[1] / "deploy/kong/plugins"
NOW = 1_800_000_000


@pytest.fixture
def gateway():
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.globals().json_decode = lambda value: lua.table_from(json.loads(value), recursive=True)
    lua.globals().decode_base64 = lambda value: base64.b64decode(value)
    lua.globals().hmac_sha256 = lambda key, value: hmac.new(key.encode(), value.encode(), hashlib.sha256).digest()
    lua.execute('''
      package.preload["cjson.safe"] = function() return {decode = json_decode} end
      package.preload["kong.tools.uuid"] = function() return {uuid = function() return "11111111-2222-4333-8444-555555555555" end} end
      package.preload["resty.openssl.mac"] = function()
        return {new = function(key) return {final = function(self, value) return hmac_sha256(key, value) end} end}
      end
      state = {headers = {}, upstream = {}, response = {}, body = "{}", authenticated = true}
      ngx = {time = function() return 1800000000 end, decode_base64 = decode_base64}
      kong = {
        ctx = {plugin = {}, shared = {}},
        request = {
          get_method = function() return state.method or "POST" end,
          get_header = function(name) return state.headers[name] end,
          get_raw_body = function(limit)
            if #state.body > limit then return nil, "too large" end
            return state.body
          end
        },
        client = {
          get_credential = function() return state.authenticated and {} or nil end,
          get_consumer = function() return state.authenticated and {username = "gateway-client"} or nil end
        },
        service = {request = {
          clear_header = function(name) state.upstream[name] = nil end,
          set_header = function(name, value) state.upstream[name] = value end
        }},
        response = {
          exit = function(code, body) state.status = code; state.error = body.error; return code end,
          set_header = function(name, value) state.response[name] = value end
        }
      }
    ''')
    return lua


def handler(lua, name):
    return lua.execute((ROOT / name / "handler.lua").read_text())


def token(claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "fixture-key"}).encode()).decode().rstrip("=")
    return "Bearer " + header + "." + payload + ".c2lnbmF0dXJl"


def claims():
    return {"iss": "https://auth.codestra.co/realms/codestra", "aud": ["gateway-api"],
        "azp": "gateway-client", "sub": "user-1", "tenant_id": "tenant-1", "scope": "gateway.read",
        "realm_access": {"roles": ["service"]},
        "exp": NOW + 60, "nbf": NOW - 60, "iat": NOW - 60}


def auth_config(lua):
    return lua.table_from({"issuer": "https://auth.codestra.co/realms/codestra", "audience": "gateway-api",
        "authorized_parties": ["gateway-client"], "scopes": ["gateway.read"], "roles": ["service"], "tenant_claim": "tenant_id"}, recursive=True)


def test_authz_accepts_only_authenticated_matching_claims(gateway):
    lua = gateway
    plugin = handler(lua, "codestra-authz")
    lua.globals().state.headers["authorization"] = token(claims())
    plugin.access(plugin, auth_config(lua))
    assert lua.globals().state.status is None
    assert lua.globals().state.upstream["X-Codestra-Tenant"] == "tenant-1"
    assert lua.globals().state.upstream["X-Authenticated-Subject"] == "user-1"


@pytest.mark.parametrize("field,value,code", [("iss", "https://attacker.example", 401),
    ("aud", "other", 401), ("azp", "other", 403), ("scope", "gateway.write", 403),
    ("tenant_id", "bad\r\nheader", 403), ("exp", NOW, 401), ("nbf", NOW + 60, 401), ("iat", NOW + 60, 401)])
def test_authz_rejects_claim_mismatch(gateway, field, value, code):
    data = claims()
    data[field] = value
    plugin = handler(gateway, "codestra-authz")
    gateway.globals().state.headers["authorization"] = token(data)
    gateway.globals().state.upstream["X-Authenticated-Subject"] = "spoofed"
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == code
    assert gateway.globals().state.upstream["X-Authenticated-Subject"] is None


def test_role_mismatch_is_denied(gateway):
    data = claims()
    data["realm_access"] = {"roles": ["unrelated-role"]}
    plugin = handler(gateway, "codestra-authz")
    gateway.globals().state.headers["authorization"] = token(data)
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 403


def test_context_allows_cors_preflight_without_caller_correlation(gateway):
    plugin = handler(gateway, "codestra-request-context")
    gateway.globals().state.method = "OPTIONS"
    plugin.access(plugin, gateway.table_from({"require_correlation_id": True}))
    assert gateway.globals().state.status is None
    assert len(gateway.globals().state.upstream["traceparent"]) == 55


def test_authentication_and_tenant_selection_are_mandatory_boundaries(gateway):
    plugin = handler(gateway, "codestra-authz")
    gateway.globals().state.headers["authorization"] = token(claims())
    gateway.globals().state.authenticated = False
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401
    gateway.globals().state.authenticated = True
    gateway.globals().kong.ctx.shared.codestra_requested_tenant = "other-tenant"
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 403


def test_context_removes_spoofed_headers_and_preserves_trace(gateway):
    plugin = handler(gateway, "codestra-request-context")
    state = gateway.globals().state
    state.upstream["X-Authenticated-Subject"] = "spoofed"
    state.headers["X-Correlation-ID"] = "request-1"
    state.headers["traceparent"] = "00-" + "1" * 32 + "-" + "2" * 16 + "-01"
    plugin.access(plugin, gateway.table_from({"require_correlation_id": True}))
    plugin.header_filter(plugin)
    assert state.status is None
    assert state.upstream["X-Authenticated-Subject"] is None
    assert state.response["X-Correlation-ID"] == "request-1"
    assert state.response["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("trace", ["invalid", "00-" + "0" * 32 + "-" + "1" * 16 + "-01",
    "00-" + "a" * 32 + "-" + "0" * 16 + "-01", "00-" + "a" * 32 + "-" + "1" * 16 + "-ff", ["a", "b"]])
def test_malformed_trace_rejected(gateway, trace):
    plugin = handler(gateway, "codestra-request-context")
    gateway.globals().state.headers["traceparent"] = gateway.table_from(trace) if isinstance(trace, list) else trace
    plugin.access(plugin, gateway.table_from({"require_correlation_id": False}))
    assert gateway.globals().state.status == 400


def webhook(gateway):
    state = gateway.globals().state
    secret = "test-only-key-material-for-local-fixtures"
    values = {"X-Webhook-Key-ID": "key-v1", "X-Webhook-Event-ID": "event-1", "X-Webhook-Timestamp": str(NOW)}
    signed = f"v1\nkey-v1\n{NOW}\nevent-1\n{{}}".encode()
    values["X-Webhook-Signature"] = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    for name, value in values.items():
        state.headers[name] = value
    return gateway.table_from({"secret": secret, "key_id": "key-v1", "clock_skew_seconds": 300, "maximum_body_bytes": 1024})


def test_webhook_verifies_hmac_without_rewriting_signed_bytes(gateway):
    plugin = handler(gateway, "codestra-webhook-verifier")
    conf = webhook(gateway)
    before = dict(gateway.globals().state.headers)
    plugin.access(plugin, conf)
    assert gateway.globals().state.status is None
    assert dict(gateway.globals().state.headers) == before
    assert gateway.globals().state.body == "{}"


@pytest.mark.parametrize("header,value", [("X-Webhook-Key-ID", "other-key"), ("X-Webhook-Event-ID", "other-event"),
    ("X-Webhook-Timestamp", str(NOW - 301)), ("X-Webhook-Signature", "v1=" + "0" * 64)])
def test_webhook_rejects_tampered_metadata(gateway, header, value):
    plugin = handler(gateway, "codestra-webhook-verifier")
    conf = webhook(gateway)
    gateway.globals().state.headers[header] = value
    plugin.access(plugin, conf)
    assert gateway.globals().state.status == 401


def test_webhook_rejects_tampered_and_oversized_body(gateway):
    plugin = handler(gateway, "codestra-webhook-verifier")
    conf = webhook(gateway)
    gateway.globals().state.body = '{"changed":true}'
    plugin.access(plugin, conf)
    assert gateway.globals().state.status == 401
    gateway.globals().state.body = "x" * 1025
    plugin.access(plugin, conf)
    assert gateway.globals().state.status == 413


def test_plugin_schemas_load_and_priorities_preserve_authentication(gateway):
    for name in ("codestra-request-context", "codestra-authz", "codestra-webhook-verifier"):
        schema = gateway.execute((ROOT / name / "schema.lua").read_text())
        assert schema.name == name
    assert handler(gateway, "codestra-request-context").PRIORITY > 1050
    assert handler(gateway, "codestra-authz").PRIORITY < 1050


def test_legacy_sunset_denies_existing_compiled_configuration(gateway):
    plugin = handler(gateway, "codestra-request-context")
    plugin.access(plugin, gateway.table_from({"require_correlation_id": False, "not_after": NOW}))
    assert gateway.globals().state.status == 403


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_token_time_is_rejected(gateway, value):
    data = claims()
    data["exp"] = value
    plugin = handler(gateway, "codestra-authz")
    gateway.globals().state.headers["authorization"] = token(data)
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401

@pytest.mark.parametrize("name", ["X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes",
    "X-Authenticated-UserID", "X-Authenticated-User", "X-Authenticated-Tenant",
    "X-Authenticated-Campaign", "X-Authenticated-Role", "X-Codestra-Gateway-Secret",
    "X-Internal-Service", "X-Admin", "X-Codestra-Contract-Operation",
    "X-Codestra-Expected-Azp", "X-Codestra-Required-Scope"])
def test_context_strips_all_identity_authority_headers(gateway, name):
    plugin = handler(gateway, "codestra-request-context")
    gateway.globals().state.upstream[name] = "forged"
    plugin.access(plugin, gateway.table_from({"require_correlation_id": False}))
    assert gateway.globals().state.upstream[name] is None


def test_optional_nbf_does_not_reject_valid_keycloak_token(gateway):
    data = claims()
    del data["nbf"]
    gateway.globals().state.headers["authorization"] = token(data)
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status is None


@pytest.mark.parametrize("iat,exp", [(NOW - 301, NOW + 1), (NOW - 60, NOW - 60)])
def test_invalid_or_overlong_token_lifetime_denied(gateway, iat, exp):
    data = claims()
    data.update(iat=iat, exp=exp)
    gateway.globals().state.headers["authorization"] = token(data)
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401


def test_bearer_failure_has_standard_challenge(gateway):
    gateway.globals().state.authenticated = False
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401
    assert gateway.globals().state.response["WWW-Authenticate"] == 'Bearer realm="codestra", error="invalid_token"'


@pytest.mark.parametrize("scope", [None, [], {}, 42, "*", "gateway.reading"])
def test_missing_or_invalid_scope_never_authorizes(gateway, scope):
    data = claims()
    data["scope"] = scope
    gateway.globals().state.headers["authorization"] = token(data)
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 403


@pytest.mark.parametrize("secret", ["short", "{vault://env/kong-webhook-unresolved}"])
def test_webhook_key_failure_is_closed(gateway, secret):
    plugin = handler(gateway, "codestra-webhook-verifier")
    conf = webhook(gateway)
    conf.secret = secret
    plugin.access(plugin, conf)
    assert gateway.globals().state.status == 503

def test_other_authentication_credential_cannot_substitute_for_oidc_consumer(gateway):
    gateway.globals().state.headers["authorization"] = token(claims())
    gateway.execute("kong.client.get_consumer = function() return nil end")
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401


def test_consumer_must_match_verified_token_azp(gateway):
    gateway.globals().state.headers["authorization"] = token(claims())
    gateway.execute('kong.client.get_consumer = function() return {username="another-client"} end')
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 403


def test_tenant_quota_identity_is_minted_only_after_authorization(gateway):
    plugin = handler(gateway, "codestra-authz")
    gateway.globals().state.headers["authorization"] = token(claims())
    gateway.globals().state.headers["X-Codestra-Tenant"] = "forged"
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().kong.ctx.shared.codestra_authenticated_tenant == "tenant-1"
    gateway.globals().state.authenticated = False
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401
    assert gateway.globals().kong.ctx.shared.codestra_authenticated_tenant is None


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS512", None])
def test_only_contracted_rs256_tokens_allowed(gateway, algorithm):
    header = {"kid": "fixture-key"}
    if algorithm:
        header["alg"] = algorithm
    encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    auth = token(claims()).split(".")
    auth[0] = "Bearer " + encoded
    gateway.globals().state.headers["authorization"] = ".".join(auth)
    plugin = handler(gateway, "codestra-authz")
    plugin.access(plugin, auth_config(gateway))
    assert gateway.globals().state.status == 401
