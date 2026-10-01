import importlib.util
import copy
import sys
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pas244_planner", ROOT / "scripts" / "plan_kong_route_reconciliation.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


def manifest():
    return json.loads((ROOT / "config" / "kong-route-reconciliation.pas236.json").read_text())


def inventory():
    return json.loads((ROOT / "config" / "kong-production-route-inventory.v2.json").read_text())


def authority_inputs():
    value = inventory()
    routes = {
        row["name"]: row
        for row in value["routes"]
        if isinstance(row.get("name"), str)
    }
    blocked = {
        row["route"]
        for row in value["activationBlockedRoutes"]
        if row.get("activationAuthorized") is False
    }
    return routes, blocked


def live_rows():
    authority, _ = authority_inputs()
    services = []
    routes = []
    plugins = []
    for idx, spec in enumerate(manifest()["routes"], start=1):
        sid = f"00000000-0000-0000-0000-{idx:012d}"
        rid = f"route-{idx}"
        decision = spec["decision"]
        upstream = (
            spec["target"] if decision == "REPOINT"
            else spec["expected"] if decision == "EXCEPTION"
            else {"host": "legacy-upstream", "port": 8080}
        )
        governed = authority.get(spec["name"], {})
        service = copy.deepcopy(governed.get("service", {"name": f"service-{idx}", "protocol": "http"}))
        existing = next((row for row in services if row["name"] == service["name"]), None)
        if existing is None:
            service.update(id=sid, host=upstream["host"], port=upstream["port"])
            services.append(service)
        else:
            sid = existing["id"]
        route = {key: copy.deepcopy(value) for key, value in governed.items() if key not in {"service", "plugins"}}
        route.update(id=rid, name=spec["name"], service={"id": sid})
        routes.append(route)
        for plugin_name in (authority.get(spec["name"], {}).get("plugins") or []):
            plugins.append({
                "id": f"{rid}-{plugin_name}",
                "name": plugin_name,
                "enabled": True,
                "route": {"id": rid},
            })
    return routes, services, plugins


def build(value=None, *, blocked=None, authority=None):
    routes, services, plugins = live_rows()
    default_authority, default_blocked = authority_inputs()
    return MOD.build_plan(
        value or manifest(),
        routes,
        services,
        plugins,
        default_authority if authority is None else authority,
        default_blocked if blocked is None else blocked,
    )


def test_manifest_is_bounded_and_apply_disabled():
    value = manifest()
    MOD.validate_manifest(value)
    assert value["runtime_apply_authorized"] is False
    assert value["canonical_public_upstream"] == {
        "host": "middleware-integration-api",
        "port": 8095,
    }
    assert len(value["routes"]) == 24
    assert sum(r["decision"] == "REPOINT" for r in value["routes"]) == 15
    assert sum(r["decision"] == "RETIRE" for r in value["routes"]) == 4
    assert sum(r["decision"] == "EXCEPTION" for r in value["routes"]) == 5


def test_plan_is_deterministic_and_never_applies():
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    first = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    second = MOD.build_plan(
        manifest(),
        list(reversed(routes)),
        list(reversed(services)),
        list(reversed(plugins)),
        authority,
        blocked,
    )
    assert first == second
    assert first["runtime_apply_performed"] is False
    assert first["runtime_apply_authorized"] is False
    assert first["required_release_gates"] == [
        "SNAPSHOT",
        "ROLLBACK_PACKAGE",
        "GATED_APPLY",
        "POST_APPLY_VERIFY",
    ]
    assert first["summary"] == {"DELETE": 4, "KEEP": 20}


def test_repoint_drift_becomes_update():
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    target = next(r for r in routes if r["name"] == "breero-production-api-route")
    sid = target["service"]["id"]
    service = next(s for s in services if s["id"] == sid)
    service["host"] = "scraper.internal.codestra.agency"
    service["port"] = 8443
    plan = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    row = next(r for r in plan["plan"] if r["route"] == "breero-production-api-route")
    assert row["action"] == "UPDATE"


def test_exception_drift_is_error_not_update():
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    target = next(r for r in routes if r["name"] == "codestra-email-standby-route")
    sid = target["service"]["id"]
    service = next(s for s in services if s["id"] == sid)
    service["host"] = "unexpected"
    plan = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    row = next(r for r in plan["plan"] if r["route"] == "codestra-email-standby-route")
    assert row["action"] == "ERROR"


def test_retire_with_missing_required_successor_fails_closed():
    value = manifest()
    row = next(r for r in value["routes"] if r["name"] == "cod-web-out-email-production")
    row["successor"] = "required-successor-route"
    plan = build(value)
    result = next(r for r in plan["plan"] if r["route"] == row["name"])
    assert result["action"] == "ERROR"
    assert result["reason"] == "required_successor_missing"


def test_retire_without_successor_or_deny_authority_is_rejected():
    value = manifest()
    row = next(r for r in value["routes"] if r["name"] == "gateway-test-route")
    row.pop("deny_authority")
    with pytest.raises(RuntimeError, match="retirement requires successor"):
        MOD.validate_manifest(value)


def test_activation_blocked_retirement_requires_source_deny_authority():
    plan = build(blocked=set())
    row = next(r for r in plan["plan"] if r["route"] == "gateway-test-route")
    assert row["action"] == "ERROR"
    assert row["reason"] == "required_deny_authority_missing"


def test_plugin_auth_security_drift_fails_closed():
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    target = next(r for r in routes if r["name"] == "sms-route")
    rid = target["id"]
    plugins[:] = [
        p for p in plugins
        if not (p.get("route") or {}).get("id") == rid or p.get("name") != "key-auth"
    ]
    plan = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    row = next(r for r in plan["plan"] if r["route"] == "sms-route")
    assert row["action"] == "ERROR"
    assert row["reason"] == "plugin_security_drift"


@pytest.mark.parametrize("field,value", [("hosts", ["attacker.invalid"]), ("paths", ["/"]),
    ("methods", None), ("protocols", ["http"]), ("strip_path", True), ("preserve_host", True)])
def test_governed_route_shape_drift_cannot_be_kept_or_repointed(field, value):
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    route = next(row for row in routes if row["name"] == "breero-production-api-route")
    route[field] = value
    plan = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    result = next(row for row in plan["plan"] if row["route"] == route["name"])
    assert result["action"] == "ERROR"
    assert result["reason"] == "route_shape_drift"


@pytest.mark.parametrize("field,value", [("protocol", "https"), ("connect_timeout", 60000),
    ("read_timeout", 120000), ("write_timeout", 120000), ("name", "unreviewed-service")])
def test_governed_service_transport_drift_prevents_mutation(field, value):
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    route = next(row for row in routes if row["name"] == "breero-production-api-route")
    service = next(row for row in services if row["id"] == route["service"]["id"])
    service[field] = value
    plan = MOD.build_plan(manifest(), routes, services, plugins, authority, blocked)
    result = next(row for row in plan["plan"] if row["route"] == route["name"])
    assert result["action"] == "ERROR"
    assert result["reason"] == "service_transport_drift"


def test_manifest_rejects_noncanonical_middleware_host():
    value = manifest()
    value["canonical_public_upstream"]["host"] = "codestra-middleware-integration-api-1"
    with pytest.raises(RuntimeError, match="canonical_public_upstream"):
        MOD.validate_manifest(value)


def test_planner_has_no_arbitrary_admin_url_override():
    source = (ROOT / "scripts" / "plan_kong_route_reconciliation.py").read_text()
    assert "--admin-url" not in source
    assert "http_admin_request" not in source


def test_planner_cli_propagates_private_control_plane_selection(monkeypatch, capsys):
    routes, services, plugins = live_rows()
    selected = []
    def request(method, path, **kwargs):
        selected.append(kwargs)
        return {"data": {"/routes": routes, "/services": services, "/plugins": plugins}[path.split("?")[0]]}
    monkeypatch.setattr(MOD, "admin_request", request)
    monkeypatch.setattr(sys, "argv", ["planner", "--container", "selected-kong-cp"])
    monkeypatch.chdir(ROOT)
    assert MOD.main() == 0
    assert all(kwargs["container"] == "selected-kong-cp" for kwargs in selected)
    assert all(kwargs["traditional_approval"] is None for kwargs in selected)
    assert json.loads(capsys.readouterr().out)["runtime_apply_authorized"] is False

def test_already_retired_routes_are_converged_when_prerequisites_hold():
    routes, services, plugins = live_rows()
    authority, blocked = authority_inputs()
    retired={row["name"] for row in manifest()["routes"] if row["decision"]=="RETIRE"}
    routes=[row for row in routes if row["name"] not in retired]
    plan=MOD.build_plan(manifest(),routes,services,plugins,authority,blocked)
    rows=[row for row in plan["plan"] if row["route"] in retired]
    assert len(rows)==4
    assert all(row["action"]=="KEEP" and row["reason"]=="already_retired" for row in rows)
    assert not any(row["action"]=="ERROR" for row in plan["plan"])
