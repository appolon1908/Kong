from __future__ import annotations

import json
from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "kong" / "plugins" / "oidc" / "keycloak.yml"
N8N = ROOT / "config" / "kong-n8n-control-plane-routes.json"
CONTROL_PLANE = ROOT / "deploy" / "kong" / "control-plane.yml"


def test_canonical_keycloak_oidc_contract_exists_and_is_secret_free():
    config = yaml.safe_load(PLUGIN.read_text())
    plugin = config["plugins"][0]
    assert plugin["name"] == "openid-connect"
    assert plugin["enabled"] is True
    assert plugin["config"]["issuer"] == (
        "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
    )
    assert plugin["config"]["auth_methods"] == ["bearer"]
    assert plugin["config"]["audience"] == ["middleware-api"]
    assert plugin["config"]["consumer_claim"] == ["azp"]
    assert plugin["config"]["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"
    serialized = PLUGIN.read_text().lower()
    assert "client_secret" not in serialized
    assert "access_token" not in serialized


def test_existing_control_plane_already_uses_keycloak_oidc():
    config = yaml.safe_load(CONTROL_PLANE.read_text())
    service = next(item for item in config["services"] if item["name"] == "codestra-control-plane")
    plugins = {item["name"]: item for item in service["plugins"]}
    oidc = plugins["openid-connect"]["config"]
    assert oidc["issuer"] == (
        "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration"
    )
    assert oidc["auth_methods"] == ["bearer"]
    assert oidc["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"


def test_n8n_authority_is_bound_to_same_keycloak_realm():
    spec = json.loads(N8N.read_text())
    assert spec["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert spec["oidc_discovery"] == spec["issuer"] + "/.well-known/openid-configuration"
    assert spec["jwks_uri"] == spec["issuer"] + "/protocol/openid-connect/certs"
    assert spec["audience"] == "middleware-api"
    assert spec["client_id"] == "n8n-automation"
    assert spec["safety"]["oidc_required"] is True
    assert spec["safety"]["oidc_enforcement"] == "jwt-rs256-plus-claim-guard"
    # The /v1/integrations/n8n aliases are retired deny-only routes: no legacy
    # JWT validation path survives for them and the service is disabled.
    assert spec["status"] == "RETIRED_DENY_ONLY"
    assert spec["service"]["enabled"] is False
    assert spec["safety"]["legacy_jwt_validation_retained"] is False
    assert spec["preserve_authorization_header"] is True
    assert spec["token_exchange"] is False


def test_only_health_is_allowed_as_an_auth_exception_in_this_contract():
    config = yaml.safe_load(CONTROL_PLANE.read_text())
    service = next(item for item in config["services"] if item["name"] == "codestra-control-plane")
    protected = [route for route in service["routes"] if route["name"] != "control-plane-health"]
    assert protected
    assert all(route["paths"] != ["/api/v1/health"] for route in protected)


def test_canonical_generator_enforces_token_audience_and_verification():
    from scripts.generate_middleware_routes import route_plugins
    row = {"audience": "middleware-api", "scope": "gateway.read",
           "operation_id": "test", "calling_client": "n8n-automation"}
    oidc = next(p for p in route_plugins(row, "https://auth.codestra.co/realms/codestra") if p["name"] == "openid-connect")["config"]
    assert oidc["audience_required"] == ["middleware-api"]
    assert oidc["issuers_allowed"] == ["https://auth.codestra.co/realms/codestra"]
    assert oidc["bearer_token_param_type"] == ["header"]
    assert oidc["verify_signature"] is True and oidc["verify_claims"] is True
    assert oidc["ssl_verify"] is True
    assert oidc["consumer_optional"] is False and oidc["consumer_by"] == ["username"]
    assert oidc["cache_ttl"] == 300 and oidc["cache_ttl_max"] == 300
    assert oidc["rediscovery_lifetime"] == 30 and oidc["leeway"] == 0


@pytest.mark.parametrize("field,value,reason", [
    ("verify_signature", False, "signature"),
    ("verify_claims", False, "claim"),
    ("ssl_verify", False, "TLS"),
    ("audience_required", ["wrong-audience"], "audience"),
    ("issuers_allowed", ["https://attacker.example"], "issuer"),
    ("consumer_optional", True, "consumer"),
    ("consumer_by", ["custom_id"], "consumer"),
    ("bearer_token_param_type", ["query"], "header-only"),
    ("cache_ttl", 3600, "bounded"),
    ("cache_ttl_max", 3600, "bounded"),
    ("rediscovery_lifetime", 3600, "rediscovery"),
    ("leeway", 60, "bounded"),
    ("extra_jwks_uris", ["https://attacker.example/jwks"], "authority"),
    ("ignore_signature", ["client_credentials"], "authority"),
])
def test_canonical_token_validation_rejects_security_downgrade(tmp_path, field, value, reason):
    from types import SimpleNamespace
    from scripts.validate_kong_foundation import validate_token_settings, FoundationError
    from scripts.generate_middleware_routes import route_plugins
    row = {"audience": "middleware-api", "scope": "gateway.read",
           "operation_id": "test", "calling_client": "n8n-automation"}
    plugins = route_plugins(row, "https://auth.codestra.co/realms/codestra")
    next(p for p in plugins if p["name"] == "openid-connect")["config"][field] = value
    path = "config/kong-middleware-routes.production.yml"
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump({"plugins": plugins}))
    profiles = {"rules": {"maximumLeewaySeconds": 60, "maximumCacheTtlSeconds": 3600}}
    with pytest.raises(FoundationError, match=reason):
        validate_token_settings({path: SimpleNamespace(format="kong-declarative")}, profiles, tmp_path)

def test_concrete_canonical_caller_has_native_azp_guard():
    from scripts.generate_middleware_routes import route_plugins
    row = {"audience": "middleware-api", "scope": "n8n.results.read",
           "operation_id": "read-n8n-result", "calling_client": "n8n-automation"}
    oidc = next(p for p in route_plugins(row, "https://auth.codestra.co/realms/codestra") if p["name"] == "openid-connect")["config"]
    assert oidc["roles_claim"] == ["azp"]
    assert oidc["roles_required"] == ["n8n-automation"]


def test_canonical_post_function_enforces_concrete_caller_and_fails_closed_on_family():
    from lupa import LuaRuntime
    from scripts.generate_middleware_routes import post_function
    base = {"operation_id": "read-n8n-result", "scope": "n8n.results.read"}
    for caller, consumer, expected in [
        ("n8n-automation", "n8n-automation", None),
        ("n8n-automation", "unreviewed-client", 403),
        ("authorized-provisioning-client", "n8n-automation", 403),
        ("never-registered", "n8n-automation", 403),
    ]:
        lua = LuaRuntime(unpack_returned_tuples=True)
        lua.execute("""state={upstream={},status=nil}
          kong={
            client={get_consumer=function() return {username=caller} end},
            service={request={
              clear_header=function(name) state.upstream[name]=nil end,
              set_header=function(name,value) state.upstream[name]=value end
            }},
            response={exit=function(code,body) state.status=code return code end}
          }""")
        lua.globals().caller = consumer
        lua.globals().state.upstream["X-Codestra-Contract-Operation"] = "forged"
        lua.execute(post_function({**base, "calling_client": caller}))
        assert lua.globals().state.status == expected
        if expected:
            assert lua.globals().state.upstream["X-Codestra-Contract-Operation"] is None
        else:
            assert lua.globals().state.upstream["X-Codestra-Contract-Operation"] == "read-n8n-result"

def test_canonical_actor_evidence_is_required_by_native_oidc():
    from scripts.generate_middleware_routes import route_plugins
    issuer = "https://auth.codestra.co/realms/codestra"
    service = {"audience": "middleware-api", "scope": "n8n.results.read",
               "operation_id": "read-n8n-result", "calling_client": "n8n-automation"}
    human = {"audience": "middleware-api", "scope": "email.production.write",
             "operation_id": "grant-email-production", "calling_client": "production-operator"}
    replay = {"audience": "middleware-api", "scope": "platform.command.replay",
              "operation_id": "replay-operation", "calling_client": "platform-command-client"}
    service_oidc = next(p for p in route_plugins(service, issuer) if p["name"] == "openid-connect")["config"]
    assert service_oidc["groups_claim"] == ["amr"]
    assert service_oidc["groups_required"] == ["client_credentials"]
    human_oidc = next(p for p in route_plugins(human, issuer) if p["name"] == "openid-connect")["config"]
    assert human_oidc["groups_claim"] == ["amr"]
    assert human_oidc["groups_required"] == ["mfa"]
    replay_oidc = next(p for p in route_plugins(replay, issuer) if p["name"] == "openid-connect")["config"]
    assert replay_oidc["groups_claim"] == ["amr"]
    assert replay_oidc["groups_required"] == ["mfa"]
    assert replay_oidc["roles_claim"] == ["realm_access", "roles"]
    assert replay_oidc["roles_required"] == ["platform-operator"]


def test_canonical_pre_auth_strips_forged_consumer_headers_before_oidc():
    from lupa import LuaRuntime
    from scripts.generate_middleware_routes import route_plugins
    row = {"audience": "middleware-api", "scope": "n8n.results.read",
           "operation_id": "read-n8n-result", "calling_client": "n8n-automation"}
    plugins = route_plugins(row, "https://auth.codestra.co/realms/codestra")
    source = next(p for p in plugins if p["name"] == "pre-function")["config"]["access"][0]
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute("""state={upstream={}}
        kong={service={request={clear_header=function(name) state.upstream[name]=nil end}}}""")
    state = lua.globals().state
    for name in ("X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier",
                 "X-Anonymous-Consumer", "X-Authenticated-Tenant", "X-Codestra-Tenant"):
        state.upstream[name] = "forged"
    state.upstream["X-Tenant-ID"] = "requested-tenant"
    state.upstream["X-Correlation-ID"] = "request-1"
    lua.execute(source)
    assert all(state.upstream[name] is None for name in (
        "X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier",
        "X-Anonymous-Consumer", "X-Authenticated-Tenant", "X-Codestra-Tenant"))
    assert state.upstream["X-Tenant-ID"] == "requested-tenant"
    assert state.upstream["X-Correlation-ID"] == "request-1"


def test_canonical_sanitizer_never_authorizes_before_oidc():
    from scripts.generate_middleware_routes import pre_auth_function
    source = pre_auth_function()
    for forbidden in ("get_consumer", "get_credential", "get_header", "decode", "response.exit", "set_header"):
        assert forbidden not in source
    foundation = json.loads((ROOT / "config/kong-gateway-foundation.v1.json").read_text())
    priorities = {plugin["plugin"]: plugin["priority"] for plugin in foundation["plugins"]}
    assert priorities["pre-function"] > priorities["openid-connect"] > priorities["post-function"]
