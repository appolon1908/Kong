"""Kong source for the Keycloak -> Caddy -> Kong -> Middleware edge certification.

Pins the Middleware public API route contract, declares the four canonical
campaign routes with exact methods and scopes, and prepares staging identities
for campaign TEST_SYN without authorizing any runtime apply.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "config/kong-canonical-middleware-routes.json"
PRODUCTION = ROOT / "config/kong-campaign-automation-routes.json"
STAGING = ROOT / "config/staging/kong-campaign-automation-routes.json"
VENDORED = ROOT / "config/middleware-public-api-route-contract.v1.json"
EDGE_CONTRACT_SHA256 = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"

CANONICAL_ROUTES = {
    ("POST", "/api/v1/integrations/n8n/results"): ("codestra-campaign-result-submit", "n8n.results.submit"),
    ("GET", "/api/v1/integrations/n8n/results/{event_id}"): ("codestra-campaign-result-read", "n8n.results.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}"): ("codestra-odoo-campaign-read", "odoo.campaigns.read"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state"): (
        "codestra-odoo-campaign-desired-state-read",
        "odoo.campaigns.read",
    ),
}
STAGING_IDENTITIES = {
    "test-syn-n8n-submit": {"n8n.results.submit"},
    "test-syn-n8n-read": {"n8n.results.read"},
    "test-syn-odoo-reader": {"odoo.campaigns.read"},
    "test-syn-wrong-tenant": {"n8n.results.read", "odoo.campaigns.read"},
    "test-syn-wrong-audience": set(),
}
SAMPLES = {"{campaign_id}": "TEST_SYN", "{event_id}": "EVT-TEST-SYN-0001"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def module(name: str):
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def concrete(template: str) -> str:
    for placeholder, value in SAMPLES.items():
        template = template.replace(placeholder, value)
    return template


# --- contract pin ---------------------------------------------------------------


def test_vendored_middleware_contract_hashes_to_the_pin():
    canonical = load(CANONICAL)
    pin = canonical["middlewareEdgeContract"]
    assert pin["sha256"] == EDGE_CONTRACT_SHA256
    assert pin["vendoredCopy"] == "config/middleware-public-api-route-contract.v1.json"
    contract = load(VENDORED)
    digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert digest == pin["sha256"]
    assert contract["schema"] == pin["schema"] == "codestra.middleware.public-api-route-contract.v2"
    assert contract["service"] == "middleware-integration-api"
    assert contract["listener_port"] == 8095


def test_every_scoped_contract_route_is_declared_with_the_same_method_and_scope():
    contract = load(VENDORED)
    scoped = {
        (r["method"], r["path"]): r["scope"]
        for r in contract["routes"]
        if r["classification"] == "shared_edge" and (r["method"], r["path"]) in CANONICAL_ROUTES
    }
    assert scoped == {key: value[1] for key, value in CANONICAL_ROUTES.items()}
    canonical = {
        (r["methods"][0], r["pathTemplate"]): r for r in load(CANONICAL)["contractRoutes"]
    }
    authority = {
        (r["method"], r.get("path_template", r["path"])): r for r in load(PRODUCTION)["routes"]
    }
    for (method, template), (name, scope) in CANONICAL_ROUTES.items():
        route = canonical[(method, template)]
        assert route["methods"] == [method]
        assert route["pathTemplate"] == template
        assert route["securityAuthority"] == "config/kong-middleware-authority.v2.json"
        assert route["serviceHost"] == "middleware-integration-api"
        assert route["servicePort"] == 8095
        assert route["stripPath"] is False
        assert {"pre-function", "openid-connect", "post-function", "correlation-id", "rate-limiting", "request-size-limiting",
                "codestra-private-surface", "codestra-resource-guard", "codestra-request-context"} == set(
            route["requiredPlugins"]
        )
        row = authority[(method, template)]
        assert row["name"] == name
        assert row["method"] == method
        assert row["scope"] == scope
        generated = re.compile(route["paths"][0][1:])
        assert generated.fullmatch(concrete(template))
        legacy = row["path"]
        if legacy.startswith("~"):
            assert re.compile(legacy[1:]).fullmatch(concrete(template))
        else:
            assert legacy == concrete(template)


# --- exact paths ----------------------------------------------------------------


@pytest.mark.parametrize("method,template", sorted(CANONICAL_ROUTES))
def test_kong_paths_admit_the_template_sample_and_nothing_else(method, template):
    row = next(r for r in load(PRODUCTION)["routes"] if r.get("path_template", r["path"]) == template)
    sample = concrete(template)
    if row["path"].startswith("~"):
        pattern = re.compile(row["path"][1:])
        assert pattern.fullmatch(sample)
        assert pattern.fullmatch(sample.replace("TEST_SYN", "MOY-SHIPPER-OUT").replace("EVT-TEST-SYN-0001", "evt.1:a"))
        for rejected in (sample + "/other", sample + "/", sample.rsplit("/", 1)[0] + "/", sample + "/desired-state/x"):
            assert pattern.fullmatch(rejected) is None, rejected
    else:
        assert row["path"] == template == sample


def test_read_and_desired_state_regexes_do_not_overlap():
    rows = {r["name"]: r for r in load(PRODUCTION)["routes"]}
    campaign = re.compile(rows["codestra-odoo-campaign-read"]["path"][1:])
    desired = re.compile(rows["codestra-odoo-campaign-desired-state-read"]["path"][1:])
    assert campaign.fullmatch("/api/v1/integrations/odoo/campaigns/TEST_SYN/desired-state") is None
    assert desired.fullmatch("/api/v1/integrations/odoo/campaigns/TEST_SYN") is None
    results = re.compile(rows["codestra-campaign-result-read"]["path"][1:])
    assert results.fullmatch("/api/v1/integrations/n8n/results") is None


def test_retired_campaign_surfaces_are_absent_everywhere():
    for path in (PRODUCTION, STAGING):
        text = path.read_text(encoding="utf-8")
        assert "campaign-actions" not in text and "campaign-commands" not in text, path
    contract = load(VENDORED)
    assert all(
        row["classification"] == "denied"
        for row in contract["routes"]
        if "campaign-actions" in row["path"] or "campaign-commands" in row["path"]
    )
    canonical = load(CANONICAL)
    active = json.dumps(canonical["contractRoutes"])
    denied = json.dumps(canonical["deniedRoutes"])
    assert "campaign-actions" not in active and "campaign-commands" not in active
    assert "campaign-actions" in denied and "campaign-commands" in denied


# --- identities and scope guard ---------------------------------------------------


def test_production_consumers_separate_n8n_and_odoo_reader_identities():
    production = load(PRODUCTION)
    consumers = {c["custom_id"]: set(c["scopes"]) for c in production["consumers"]}
    assert consumers == {
        "codestra-n8n-campaign-crm-production": {"n8n.policy.check", "n8n.results.submit", "n8n.results.read"},
        "codestra-odoo-campaign-reader-production": {"odoo.campaigns.read"},
    }
    assert production["forbidden_scopes"] == ["odoo.campaign.control.write"]
    assert production["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert production["audience"] == "middleware-api"
    assert production["environment"] == "production"


def test_staging_manifest_is_test_syn_only_and_not_apply_authorized():
    staging = load(STAGING)
    assert staging["environment"] == "staging"
    assert staging["status"] == "PREPARED_STAGING_NO_RUNTIME_APPLY"
    assert staging["production_authority"] == "config/kong-campaign-automation-routes.json"
    assert staging["issuer"] == "https://auth-staging.codestra.co/realms/codestra"
    assert staging["oidc_discovery"] == staging["issuer"] + "/.well-known/openid-configuration"
    assert staging["jwks_uri"] == staging["issuer"] + "/protocol/openid-connect/certs"
    assert staging["audience"] == "middleware-api"
    assert staging["campaign_scope"] == ["TEST_SYN"]
    assert "auth.codestra.co/" not in STAGING.read_text(encoding="utf-8")
    assert staging["safety"]["reconciliation_apply"] is False
    assert staging["safety"]["production_identity_allowed"] is False
    assert staging["safety"]["provider_effects_authorized"] is False
    assert staging["safety"]["odoo_writes_authorized"] is False
    assert staging["safety"]["credentials_in_repository"] is False
    assert {c["custom_id"]: set(c["scopes"]) for c in staging["consumers"]} == STAGING_IDENTITIES
    assert all(c["username"] == c["custom_id"] for c in staging["consumers"])
    assert not any("odoo.campaign.control.write" in c["scopes"] for c in staging["consumers"])


def test_staging_routes_mirror_production_for_the_certified_routes():
    production = {r["name"]: r for r in load(PRODUCTION)["routes"]}
    staging = {r["name"]: r for r in load(STAGING)["routes"]}
    assert set(staging) == {name for name, _scope in CANONICAL_ROUTES.values()}
    for name, row in staging.items():
        assert row == production[name], name
    assert "codestra-campaign-policy-check" not in staging


@pytest.mark.parametrize("manifest_path", [PRODUCTION, STAGING])
def test_claim_guard_binds_issuer_audience_environment_azp_and_scope(manifest_path):
    campaign = module("reconcile_kong_campaign_automation")
    manifest = load(manifest_path)
    campaign.validate_manifest_routes(manifest)
    for route in manifest["routes"]:
        guard = campaign.claim_guard(manifest, route["scope"])
        parties = campaign.authorized_parties(manifest, route["scope"])
        assert f"if c.iss~={json.dumps(manifest['issuer'])}" in guard
        assert f"v=={json.dumps(manifest['audience'])}" in guard
        assert "exit(401,{error='invalid_issuer'})" in guard
        assert "exit(401,{error='invalid_audience'})" in guard
        assert f"c.environment~={json.dumps(manifest['environment'])}" in guard
        assert all(f"[{json.dumps(party)}]=true" in guard for party in parties)
        assert "exit(403,{error='service_identity_denied'})" in guard
        assert f"if not s[{json.dumps(route['scope'])}]" in guard
        assert "exit(403,{error='insufficient_scope'})" in guard
        # The audience check precedes identity and scope so a wrong-audience token is a 401.
        assert guard.index("invalid_audience") < guard.index("service_identity_denied") < guard.index("insufficient_scope")
        assert "require('cjson.safe')" in guard


def test_staging_guard_admits_exactly_one_scope_per_test_identity():
    campaign = module("reconcile_kong_campaign_automation")
    staging = load(STAGING)
    assert campaign.authorized_parties(staging, "n8n.results.submit") == ["test-syn-n8n-submit"]
    assert campaign.authorized_parties(staging, "n8n.results.read") == ["test-syn-n8n-read", "test-syn-wrong-tenant"]
    assert campaign.authorized_parties(staging, "odoo.campaigns.read") == ["test-syn-odoo-reader", "test-syn-wrong-tenant"]
    with pytest.raises(RuntimeError, match="no campaign consumer holds scope"):
        campaign.authorized_parties(staging, "n8n.policy.check")


def test_manifest_validation_fails_closed_on_drift():
    campaign = module("reconcile_kong_campaign_automation")
    base = load(STAGING)

    duplicate = json.loads(json.dumps(base))
    duplicate["routes"].append(dict(duplicate["routes"][0]))
    with pytest.raises(RuntimeError, match="duplicate campaign route"):
        campaign.validate_manifest_routes(duplicate)

    retired = json.loads(json.dumps(base))
    retired["routes"][0]["path"] = "/api/v1/integrations/odoo/campaign-actions"
    with pytest.raises(RuntimeError, match="retired campaign surface"):
        campaign.validate_manifest_routes(retired)

    loose = json.loads(json.dumps(base))
    loose["routes"][1]["path"] = "~/api/v1/integrations/n8n/results/.*"
    with pytest.raises(RuntimeError, match="regex is not exact"):
        campaign.validate_manifest_routes(loose)

    untemplated = json.loads(json.dumps(base))
    del untemplated["routes"][1]["path_template"]
    with pytest.raises(RuntimeError, match="must declare path_template"):
        campaign.validate_manifest_routes(untemplated)

    write = json.loads(json.dumps(base))
    write["consumers"][2]["scopes"].append("odoo.campaign.control.write")
    with pytest.raises(RuntimeError, match="forbidden scope"):
        campaign.validate_manifest_routes(write)

    method = json.loads(json.dumps(base))
    method["routes"][0]["method"] = "DELETE"
    with pytest.raises(RuntimeError, match="unsupported campaign route method"):
        campaign.validate_manifest_routes(method)


def test_reconciler_refuses_apply_for_a_staging_manifest_and_keeps_dry_run_default():
    source = (ROOT / "scripts/reconcile_kong_campaign_automation.py").read_text(encoding="utf-8")
    assert 'parser.add_argument("--apply", action="store_true")' in source
    assert "runtime apply is not authorized by this manifest" in source
    assert '"methods[]": [method]' in source
    assert '"methods[]": ["POST"]' not in source
    assert "consumer_entity(spec)" in source


# --- renderer and validator -----------------------------------------------------


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_renderer_emits_exact_routes_plugins_and_consumers(environment):
    renderer = module("render_kong_campaign_automation_routes")
    document = renderer.render(environment)
    manifest = load(PRODUCTION if environment == "production" else STAGING)
    assert document["_format_version"] == "3.0"
    assert yaml.safe_load(yaml.safe_dump(document)) == document
    service = document["services"][0]
    assert (service["name"], service["host"], service["port"]) == (
        "codestra-campaign-automation-api",
        "middleware-integration-api",
        8095,
    )
    # Explicit transport policy: Kong would otherwise default to 60s timeouts and
    # five retries on a service that carries command submissions.
    assert (service["connect_timeout"], service["read_timeout"], service["write_timeout"], service["retries"]) == (
        3000,
        30000,
        30000,
        0,
    )
    routes = {r["name"]: r for r in service["routes"]}
    assert set(routes) == {r["name"] for r in manifest["routes"]}
    for row in manifest["routes"]:
        route = routes[row["name"]]
        assert route["methods"] == [row["method"]]
        assert route["paths"] == [row["path"]]
        assert route["strip_path"] is False
        assert [p["name"] for p in route["plugins"]] == [
            "jwt",
            "post-function",
            "request-size-limiting",
            "rate-limiting",
            "correlation-id",
        ]
        rate = next(p for p in route["plugins"] if p["name"] == "rate-limiting")["config"]
        assert rate["policy"] == "redis" and rate["fault_tolerant"] is False and rate["limit_by"] == "consumer"
    assert [c["username"] for c in document["consumers"]] == [c["username"] for c in manifest["consumers"]]
    assert all(set(c) == {"username", "custom_id"} for c in document["consumers"])
    assert "jwt_secrets" not in json.dumps(document)


def test_edge_contract_validator_passes_and_fails_closed(tmp_path, monkeypatch):
    validator = module("validate_middleware_edge_contract")
    rows = validator.validate()
    assert rows[0] == f"MIDDLEWARE_EDGE_CONTRACT_SHA256={EDGE_CONTRACT_SHA256}"
    assert rows[1].startswith("MIDDLEWARE_EDGE_CONTRACT=PASS ROUTES=4 STAGING_IDENTITIES=5")
    assert len([row for row in rows if row.startswith("ROUTE=")]) == 4

    tampered = tmp_path / "contract.json"
    contract = load(VENDORED)
    contract["routes"].append({"method": "DELETE", "path": "/api/v1/integrations/odoo/campaigns/{campaign_id}", "auth": "odoo-service-jwt", "scope": "odoo.campaigns.read"})
    tampered.write_text(json.dumps(contract), encoding="utf-8")
    monkeypatch.setattr(validator, "load", lambda path, _load=validator.load: _load(tampered) if path == VENDORED else _load(path))
    with pytest.raises(SystemExit, match="sha256 .* != pinned"):
        validator.validate()
