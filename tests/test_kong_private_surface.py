"""Private paths are denied by contract and by the actual Lua access handler."""
from pathlib import Path
import sys

import pytest
from lupa import LuaRuntime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
PLUGIN = ROOT / "deploy/kong/plugins/codestra-private-surface"


@pytest.fixture
def policy():
    import kong_private_surface
    return kong_private_surface


PRIVATE_PATHS = [
    "/internal/jobs", "/metrics", "/admin", "/management/reload", "/debug/vars",
    "/workers/run", "/database/query", "/db", "/actuator/env", "/server-status",
    "/services", "/routes/route-id", "/consumers", "/plugins", "/config",
    "/kong/status", "/v1/admin/system", "/api/v1/internal/tasks",
    "/provider/twilio/admin", "/providers/odoo/database", "/n8n/rest/settings",
    "/n8n/api/v1/workflows", "/odoo/web/database/manager", "/web/database/selector",
    "/v1/platform/debug", "/platform/v1/management",
    "/api/v1/providers/twilio/admin", "/v2/provider/odoo/database",
    "/api/v1/integrations/n8n/admin", "/api/v1/integrations/odoo/web/database/manager",
]

BYPASS_PATHS = [
    "/INTERNAL/jobs", "/%69nternal/jobs", "/%2569nternal/jobs", "/%252569nternal/jobs",
    "/internal%2Fjobs", "/%2finternal/jobs", "//internal///jobs", "/a/../internal/jobs",
    "/a/%2e%2e/internal/jobs", "/a/%252e%252e/internal/jobs", "/a\\..\\internal\\jobs",
    "/internal%5cjobs", "/internal;ignored/jobs", "/internal%3bignored/jobs",
    "/a/..;/metrics", "/%6detric%73", "/metrics%00ignored", "/metrics%3fignored",
    "/%c0%afinternal/jobs", "/%zz/internal/jobs", "/%25252525252525252569nternal/jobs",
]

BUSINESS_PATHS = [
    "/healthz", "/readyz", "/version", "/v1/platform/commands",
    "/v1/platform/accounts/admin/preferences", "/platform/v1/queues/queue-1/metrics",
    "/api/v1/integrations/odoo/campaigns/campaign-1/desired-state",
    "/v1/platform/contacts/database/notes", "/metrics-report", "/internalized/orders",
]


@pytest.mark.parametrize("path", PRIVATE_PATHS)
@pytest.mark.parametrize("method", ["GET", "POST", "HEAD", "OPTIONS", "DELETE"])
def test_public_contract_rejects_private_surface_independently_of_method(policy, path, method):
    assert policy.private_surface_error({"path": path, "match": "exact", "methods": [method]},
        exposure="public", source_allowlist=[]) == "public_private_surface_forbidden"


@pytest.mark.parametrize("path,match", [
    ("/", "prefix"), ("/{resource}", "exact"), ("/{resource}/jobs", "exact"),
    ("/api", "prefix"), ("/api/{version}", "prefix"), ("/v1/{resource}", "exact"),
    ("/providers/{provider}", "prefix"), ("/v1/platform/{resource}", "prefix"),
    ("/n8n", "prefix"),
])
def test_public_pattern_cannot_match_a_forbidden_surface(policy, path, match):
    assert policy.private_surface_error({"path": path, "match": match}, exposure="public",
        source_allowlist=[]) == "public_private_surface_forbidden"


@pytest.mark.parametrize("path", BUSINESS_PATHS + ["/v1/platform/queues/{queue_id}/metrics"])
def test_contract_preserves_business_resources_with_management_words(policy, path):
    assert policy.private_surface_error({"path": path, "match": "exact"}, exposure="public",
        source_allowlist=[]) is None


@pytest.mark.parametrize("path", BYPASS_PATHS + ["~^/internal", "/{bad", "/a/./b", "/a//b"])
def test_contract_rejects_noncanonical_and_encoded_route_declarations(policy, path):
    assert policy.private_surface_error({"path": path, "match": "exact"}, exposure="public",
        source_allowlist=[]) is not None


@pytest.mark.parametrize("allowlist", [[], ["0.0.0.0/0"], ["::/0"], ["invalid"], ["10.1.0.3/24"],
    ["0.0.0.0/1", "128.0.0.0/1"], ["::/1", "8000::/1"]])
def test_private_classification_cannot_bypass_bounded_source_policy(policy, allowlist):
    assert policy.private_surface_error({"path": "/internal/jobs", "match": "prefix"},
        exposure="private", source_allowlist=allowlist) == "private_source_allowlist_required"
    with pytest.raises(ValueError, match="private_source_allowlist_required"):
        policy.runtime_plugin_config(exposure="private", source_allowlist=allowlist)


def test_only_explicit_private_configuration_can_allow_private_routes(policy):
    assert policy.private_surface_error({"path": "/internal/jobs", "match": "prefix"},
        exposure="private", source_allowlist=["10.5.0.0/24"]) is None
    assert policy.runtime_plugin_config(exposure="private", source_allowlist=["10.5.0.0/24"]) == {
        "allow_private": True}
    assert policy.runtime_plugin_config(exposure="public", source_allowlist=["10.5.0.0/24"]) == {
        "allow_private": False}
    with pytest.raises(ValueError, match="route_exposure_required"):
        policy.runtime_plugin_config(exposure=None, source_allowlist=[])


@pytest.fixture
def gateway():
    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute('''
      state = {path = "/", method = "GET", headers = {}, authenticated = false}
      kong = {
        request = {
          get_path = function() return state.normalized_path or state.path end,
          get_raw_path = function() return state.path end,
          get_method = function() return state.method end,
          get_header = function(name) return state.headers[name] end
        },
        response = {exit = function(status, body) state.status = status; state.error = body.error; return status end}
      }
    ''')
    return lua


def run_plugin(lua, path, conf=None):
    lua.globals().state.path = path
    handler = lua.execute((PLUGIN / "handler.lua").read_text())
    handler.access(handler, lua.table_from(conf or {}, recursive=True))
    return lua.globals().state


@pytest.mark.parametrize("path", PRIVATE_PATHS + BYPASS_PATHS)
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"])
def test_lua_blocks_management_paths_and_bypass_variants_before_authentication(gateway, path, method):
    gateway.globals().state.method = method
    state = run_plugin(gateway, path)
    assert state.status == 404
    assert state.error == "private_surface_not_found"


@pytest.mark.parametrize("path", BUSINESS_PATHS)
def test_lua_preserves_public_business_resources(gateway, path):
    assert run_plugin(gateway, path).status is None


def test_lua_does_not_trust_client_headers_to_change_private_scope(gateway):
    state = gateway.globals().state
    for name in ("X-Codestra-Private", "X-Forwarded-For", "X-Private-Route", "X-Authenticated-Client"):
        state.headers[name] = "true"
    assert run_plugin(gateway, "/metrics").status == 404


def test_lua_private_override_is_boolean_and_route_configuration_only(gateway):
    assert run_plugin(gateway, "/internal/jobs", {"allow_private": True}).status is None
    assert run_plugin(gateway, "/internal/jobs", {"allow_private": "true"}).status == 404


def test_lua_checks_raw_path_when_normalized_view_hides_an_encoded_bypass(gateway):
    gateway.globals().state.normalized_path = "/v1/platform/commands"
    assert run_plugin(gateway, "/%2569nternal/jobs").status == 404


def test_lua_checks_normalized_path_if_rewrite_targets_private_surface(gateway):
    gateway.globals().state.normalized_path = "/internal/jobs"
    assert run_plugin(gateway, "/v1/platform/commands").status == 404


def test_lua_default_schema_denies_private_and_runs_before_identity(gateway):
    schema = gateway.execute((PLUGIN / "schema.lua").read_text())
    defaults = {key: value.default for field in schema.fields[1].config.fields.values()
                for key, value in field.items()}
    assert run_plugin(gateway, "/metrics", defaults).status == 404
    handler = gateway.execute((PLUGIN / "handler.lua").read_text())
    # Request context runs at 100002; authentication and CORS run later.
    assert handler.PRIORITY > 100002
