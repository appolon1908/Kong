"""Read-only MCR-J acceptance checks; never invoke the PAS-9 generator."""

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pytest
import yaml

from scripts import validate_kong_v3_identity_security as security


ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads((ROOT / path).read_text())


@pytest.fixture(scope="module")
def acceptance():
    return read_json("contracts/mcr-j-post-pas-9.v1.json")


@pytest.fixture
def documents():
    return {
        "source": read_json("config/middleware-public-api-route-contract.v1.json"),
        "canonical": read_json("config/kong-canonical-middleware-routes.json"),
        "authority": read_json("config/kong-middleware-authority.v2.json"),
        "profiles": read_json("config/kong-authentication-profiles.v1.json"),
        "policy": read_json("config/kong-access-policy.v1.json"),
        "production": yaml.safe_load((ROOT / "config/kong-middleware-routes.production.yml").read_text()),
        "staging": yaml.safe_load((ROOT / "config/staging/kong-middleware-routes.staging.yml").read_text()),
    }


def plugin(route, name):
    matches = [item for item in route["plugins"] if item["name"] == name]
    assert len(matches) == 1, f"expected exactly one {name} plugin"
    return matches[0]


def unique(rows, key):
    indexed = {key(row): row for row in rows}
    assert len(indexed) == len(rows), "duplicate inventory binding"
    return indexed


def route_name(row):
    return "middleware-" + re.sub(r"[^a-z0-9-]+", "-", row["operation_id"].lower().replace("_", "-")).strip("-")


def exact_path(template):
    # Independently bind the reviewed parameter grammar, without importing the generator.
    return "~" + "".join(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}" if part.startswith("{") else re.escape(part)
        for part in re.split(r"(\{[^{}]+\})", template)
    ) + "$"


def check_inventory(docs, contract):
    source = docs["source"]
    digest = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert digest == contract["sourceSha256"], "frozen source drift"
    assert (ROOT / "config/middleware-public-api-route-contract.sha256").read_text().strip() == digest
    rows = unique(source["routes"], lambda r: r["operation_id"])
    unique(source["routes"], lambda r: (r["method"], r["path"]))
    assert Counter(r["classification"] for r in rows.values()) == contract["classificationCounts"]
    shared = {route_name(r): r for r in rows.values() if r["classification"] == "shared_edge"}
    assert len(shared) == 105
    canonical = docs["canonical"]
    assert canonical["middlewareEdgeContract"]["sha256"] == digest
    assert canonical["runtimeApplyAuthorized"] is False
    assert canonical["providerEffectsEnabled"] is False
    projected = unique(canonical["contractRoutes"], lambda r: r["name"])
    assert projected.keys() == shared.keys(), "canonical inventory drift"
    authority = docs["authority"]
    assert authority["contract"]["sha256"] == digest
    assert authority["runtime_apply_authorized"] is False
    assert authority["provider_effects_enabled"] is False
    assert authority["upstream"] == contract["upstream"]
    bindings = unique(authority["routes"], lambda r: r["operation_id"])
    assert bindings.keys() == {r["operation_id"] for r in shared.values()}
    for name, row in shared.items():
        actual = projected[name]
        assert actual["pathTemplate"] == row["path"]
        assert actual["paths"] == [exact_path(row["path"])], "canonical path drift"
        assert actual["methods"] == [row["method"]]
        assert (actual["serviceHost"], actual["servicePort"]) == ("middleware-integration-api", 8095)
        assert row["upstream"] == "middleware-integration-api:8095"
        bound = bindings[row["operation_id"]]
        for target, source_key in (("method", "method"), ("path", "path"), ("audience", "audience"),
                                   ("scope", "scope"), ("azp", "calling_client"), ("authentication", "auth")):
            assert bound[target] == row[source_key], f"authority {target} drift"
        assert bound["issuer"] == contract["issuers"]["production"]
    denied = {route_name(r): r for r in rows.values() if r["classification"] == "denied"}
    denials = unique(canonical["deniedRoutes"], lambda r: r["name"])
    assert denials.keys() == denied.keys()
    for name, row in denied.items():
        assert denials[name]["pathTemplate"] == row["path"]
        assert denials[name]["method"] == row["method"]
        assert denials[name]["statusCode"] == 404
        assert "serviceHost" not in denials[name]


def check_idempotency(docs, contract):
    groups = {}
    for row in docs["source"]["routes"]:
        idem = row["idempotency"]
        key = (idem["required"], idem["carrier"], idem["replay"])
        groups.setdefault(key, []).append(row["operation_id"])
    expected = {(g["required"], g["carrier"], g["replay"]): g for g in contract["idempotencyClasses"]}
    assert groups.keys() == expected.keys(), "idempotency classification drift"
    for key, operations in groups.items():
        assert sorted(operations) == expected[key]["operations"], "idempotency carrier binding drift"


def check_security(docs, contract):
    security.validate(profiles=docs["profiles"], policy=docs["policy"])
    rows = unique(docs["policy"]["v3MiddlewareSecurityAuthority"]["routeSecurity"], lambda r: r["operationId"])
    assert rows.keys() == {r["operation_id"] for r in docs["source"]["routes"]}
    for source in docs["source"]["routes"]:
        row = rows[source["operation_id"]]
        for field in ("method", "path", "classification", "auth", "audience"):
            assert row[field] == source[field], f"security {field} binding drift"
        caller = source["calling_client"]
        assert row["callerSelector"] == (caller[0] if isinstance(caller, list) else caller), "security AZP binding drift"
        assert row["requiredScope"] == (None if source["classification"] == "denied" else source["scope"]), "security scope binding drift"
        if source["classification"] != "denied":
            assert row["tenantAuthority"] == contract["tenantAuthority"], "exact tenant rule drift"
    propagation = docs["profiles"]["identityPropagationProfiles"]["V3_MIDDLEWARE_STRIP_AND_PROPAGATE"]
    assert set(contract["identityHeaders"]) <= set(propagation["strip"])


def check_manifest(manifest, environment, docs, contract):
    assert len(manifest["services"]) == 1, "unexpected public service"
    service = manifest["services"][0]
    assert (service["host"], service["port"]) == ("middleware-integration-api", 8095), "upstream drift"
    assert service["retries"] == 0, "gateway must not replay writes"
    assert "codestra.runtime-apply-authorized.false" in service["tags"]
    assert "codestra.provider-effects-enabled.false" in service["tags"]
    shared = {route_name(r): r for r in docs["source"]["routes"] if r["classification"] == "shared_edge"}
    routes = unique(service["routes"], lambda r: r["name"])
    assert routes.keys() == shared.keys(), "public inventory drift"
    for name, row in shared.items():
        route = routes[name]
        assert route["paths"] == [exact_path(row["path"])], "public path drift"
        assert route["methods"] == [row["method"]], "public method drift"
        assert route["hosts"] == ["api.codestra.co"]
        assert route["strip_path"] is False
        plugins = unique(route["plugins"], lambda p: p["name"])
        oidc = plugins["openid-connect"]["config"]
        assert oidc["issuer"] == contract["issuers"][environment] + "/.well-known/openid-configuration", "issuer drift"
        assert oidc["auth_methods"] == ["bearer"]
        assert oidc["audience"] == [row["audience"]], "audience drift"
        assert oidc["scopes_required"] == [row["scope"]], "scope drift"
        assert oidc["consumer_claim"] == ["azp"], "AZP claim drift"
        assert not oidc.get("anonymous"), "anonymous fallback"
        guard = "\n".join(plugins["post-function"]["config"]["access"])
        caller = row["calling_client"]
        if not isinstance(caller, str):
            caller = json.dumps(caller, sort_keys=True, separators=(",", ":"))
        for variable, value in (("operation_id", row["operation_id"]), ("expected_azp", caller), ("required_scope", row["scope"])):
            assert f"local {variable} = {json.dumps(value)}" in guard, "trusted metadata drift"
        strip = re.search(r"for _, name in ipairs\(\{(.*?)\}\) do\s+kong.service.request.clear_header\(name\)\s+end", guard, re.S)
        assert strip, "identity sanitization missing"
        assert set(contract["generatedGuardClears"]) <= set(re.findall(r'"([^"]+)"', strip[1])), "identity sanitization incomplete"
        for header, variable in contract["generatedGuardOverwrites"].items():
            mint = f"kong.service.request.set_header('{header}', {variable})"
            assert mint in guard and strip.end() < guard.index(mint), "identity propagation order drift"
        for path in contract["forbiddenPublicProbes"]:
            assert re.match(route["paths"][0][1:], path) is None, f"private surface exposed: {path}"
    denied = {route_name(r): r for r in docs["source"]["routes"] if r["classification"] == "denied"}
    denials = unique(manifest["routes"], lambda r: r["name"])
    assert denials.keys() == denied.keys(), "denied inventory drift"
    for name, row in denied.items():
        route = denials[name]
        assert route["paths"] == [exact_path(row["path"])]
        assert route["methods"] == [row["method"]]
        assert not route.get("service"), "denied route has upstream"
        assert route["plugins"] == [{"name": "request-termination", "config": {"status_code": 404, "message": "not found"}}], "denial drift"


def test_mcr_j_frozen_inventory_and_carriers(documents, acceptance):
    assert acceptance["runtimeApplyAuthorized"] is False
    assert acceptance["providerEffectsEnabled"] is False
    check_inventory(documents, acceptance)
    check_idempotency(documents, acceptance)
    check_security(documents, acceptance)


@pytest.mark.parametrize("field", ["runtimeApplyAuthorized", "providerEffectsEnabled"])
def test_mcr_j_rejects_activation_flag_drift(documents, acceptance, field):
    drifted = deepcopy(acceptance)
    drifted[field] = True
    with pytest.raises(AssertionError):
        assert drifted["runtimeApplyAuthorized"] is False
        assert drifted["providerEffectsEnabled"] is False


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_mcr_j_generated_edge_binding(documents, acceptance, environment):
    check_manifest(documents[environment], environment, documents, acceptance)


@pytest.mark.parametrize("field,value,message", [
    ("issuer", "https://wrong.invalid/realms/codestra", "issuer drift"),
    ("audience", ["*"], "audience drift"),
    ("audience", ["codestra-odoo"], "audience drift"),
    ("scopes_required", ["platform.command"], "scope drift"),
    ("scopes_required", [], "scope drift"),
    ("consumer_claim", ["sub"], "AZP claim drift"),
    ("anonymous", "public", "anonymous fallback"),
])
@pytest.mark.parametrize("environment", ["production", "staging"])
def test_mcr_j_rejects_oidc_drift(documents, acceptance, environment, field, value, message):
    manifest = documents[environment]
    plugin(manifest["services"][0]["routes"][0], "openid-connect")["config"][field] = value
    with pytest.raises(AssertionError, match=message):
        check_manifest(manifest, environment, documents, acceptance)


@pytest.mark.parametrize("mutation,message", [
    ("missing", "public inventory drift"), ("duplicate", "duplicate inventory"),
    ("private", "public inventory drift"), ("metrics", "public path drift"),
    ("internal", "public path drift"), ("provider", "public path drift"),
    ("broad", "public path drift"), ("upstream", "upstream drift"),
    ("sanitize", "identity sanitization missing"), ("azp", "trusted metadata drift"),
    ("deny", "denial drift"),
])
def test_mcr_j_rejects_edge_mutations(documents, acceptance, mutation, message):
    manifest = documents["production"]
    service = manifest["services"][0]
    route = service["routes"][0]
    if mutation == "missing":
        service["routes"].pop()
    elif mutation == "duplicate":
        service["routes"].append(deepcopy(route))
    elif mutation == "private":
        extra = deepcopy(route)
        extra["name"] = "private-route"
        extra["paths"] = ["~^/api/v1/integration/automation-results$"]
        service["routes"].append(extra)
    elif mutation in {"metrics", "internal", "provider", "broad"}:
        route["paths"] = ["~^/" + (".*" if mutation == "broad" else mutation) + "$"]
    elif mutation == "upstream":
        service["port"] = 8080
    elif mutation in {"sanitize", "azp"}:
        guard = plugin(route, "post-function")["config"]["access"]
        guard[0] = guard[0].replace("clear_header", "get_header") if mutation == "sanitize" else guard[0].replace("local expected_azp =", "local untrusted_azp =")
    elif mutation == "deny":
        manifest["routes"][0]["plugins"][0]["config"]["status_code"] = 200
    with pytest.raises(AssertionError, match=message):
        check_manifest(manifest, "production", documents, acceptance)


@pytest.mark.parametrize("field,value,message", [
    ("callerSelector", "platform-operator", "AZP binding drift"),
    ("requiredScope", "platform.command", "scope binding drift"),
    ("tenantAuthority", "token-claim OR X-Tenant-ID", "exact tenant rule drift"),
])
def test_mcr_j_rejects_plausible_security_substitution(documents, acceptance, field, value, message):
    row = next(r for r in documents["policy"]["v3MiddlewareSecurityAuthority"]["routeSecurity"] if r["classification"] == "shared_edge")
    row[field] = value
    if field == "callerSelector":
        row["callerClass"] = documents["profiles"]["v3CallerAuthority"]["callers"][value]["class"]
    with pytest.raises(AssertionError, match=message):
        check_security(documents, acceptance)


def test_mcr_j_rejects_carrier_swap_even_when_counts_match(documents, acceptance):
    rows = documents["source"]["routes"]
    header = next(r for r in rows if r["idempotency"]["carrier"] == "Idempotency-Key")
    body = next(r for r in rows if r["idempotency"]["carrier"] == "body.idempotency_key")
    header["idempotency"], body["idempotency"] = body["idempotency"], header["idempotency"]
    with pytest.raises(AssertionError, match="carrier binding drift"):
        check_idempotency(documents, acceptance)
