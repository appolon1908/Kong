"""Executable enforcement for the Kong API Gateway Control Plane V1 foundation.

The positive test proves the committed registry, every reviewed source, the node
configuration and the generated documentation agree. The mutation tests prove
the validator fails closed on each class of gateway-architecture debt the
mission forbids: undocumented routes, wildcards, missing methods, silent loss of
authentication, provider or IP upstreams, implicit retries, undeclared runtime
drift, ambiguous precedence, unsafe node settings, missing runtime variables,
environment mixing and ungoverned or misplaced plugins. Every mutation runs on
an isolated copy of the repository; nothing here touches a Kong node.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_kong_foundation.py"
SPEC = importlib.util.spec_from_file_location("kong_foundation_validator", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator  # dataclasses resolve postponed annotations through sys.modules
SPEC.loader.exec_module(validator)

FOUNDATION = "config/kong-gateway-foundation.v1.json"
CONTROL_PLANE = "deploy/kong/control-plane.yml"
INVENTORY = "config/kong-production-route-inventory.v2.json"
COMPOSE = "deploy/kong/compose.kong.yaml"
RUNTIME_ENV = "deploy/kong/runtime.env.example"
COPIED = ("config", "deploy", "kong", "docs", "scripts")


def _validate(root: Path) -> dict:
    return validator.validate_foundation(root=root)


BASE: dict[str, Path] = {}


@pytest.fixture(scope="module")
def base_copy(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("kong-base")
    for name in COPIED:
        shutil.copytree(ROOT / name, base / name, ignore=shutil.ignore_patterns("__pycache__"))
    BASE["root"] = base
    return base


@pytest.fixture
def repo(base_copy, tmp_path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(base_copy, root)
    return root


def restore(root: Path, path: str) -> None:
    """Undo a mutation between steps of a multi-step test."""
    shutil.copy(BASE["root"] / path, root / path)


def read_json(root: Path, path: str) -> dict:
    return json.loads((root / path).read_text(encoding="utf-8"))


def write_json(root: Path, path: str, document: dict) -> None:
    (root / path).write_text(json.dumps(document, indent=2), encoding="utf-8")


def read_yaml(root: Path, path: str) -> dict:
    return yaml.safe_load((root / path).read_text(encoding="utf-8"))


def write_yaml(root: Path, path: str, document: dict) -> None:
    (root / path).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def expect_failure(root: Path, match: str) -> None:
    with pytest.raises(validator.FoundationError, match=match):
        _validate(root)


# --------------------------------------------------------------------------- positive


def test_foundation_registry_validates_every_reviewed_source():
    result = _validate(ROOT)
    foundation = result["foundation"]
    assert foundation["runtimeApplyAuthorized"] is False
    assert foundation["status"] == "SOURCE_CANDIDATE_NO_RUNTIME_APPLY"
    assert len(result["documents"]) == len(foundation["sources"])
    assert set(result["routes"]) == {entry["routeId"] for entry in foundation["routes"]}
    # every route has an explicit classification on every axis
    for entry in foundation["routes"]:
        assert entry["authentication"] in foundation["authenticationClasses"]
        assert entry["mechanism"] in foundation["enums"]["mechanisms"]
        assert entry["lifecycle"] in foundation["enums"]["lifecycles"]
        assert entry["activation"] in foundation["enums"]["activations"]
        assert entry["disposition"] in foundation["enums"]["dispositions"]
    # canonical routes carry no forbidden debt
    forbidden = set(foundation["debtRules"]["forbiddenOnCanonical"])
    for entry in foundation["routes"]:
        if entry["lifecycle"] == "CANONICAL":
            assert not (set(entry["acceptedFindings"]) & forbidden), entry["routeId"]


def test_generated_registry_tables_are_current():
    result = _validate(ROOT)
    assert validator.sync_docs(result, root=ROOT, write=False) == []


def test_precedence_is_declared_for_every_overlap_and_nothing_else():
    result = _validate(ROOT)
    declared = {(c["left"], c["right"]): c["winner"] for c in result["foundation"]["precedence"]["knownConflicts"]}
    observed = {(o.left, o.right): o.winner for o in result["overlaps"]}
    assert observed == declared
    # the legacy key-auth message routes are the only ambiguity and they are
    # explicitly retired by the successor apply
    ambiguous = [key for key, winner in observed.items() if winner == "AMBIGUOUS"]
    assert ambiguous == [("codestra-communication-canonical-read", "communication-message-read")]


def test_every_plugin_in_every_source_is_governed_and_auth_is_never_global():
    result = _validate(ROOT)
    registry = {p["plugin"]: p for p in result["foundation"]["plugins"]}
    for document in result["documents"].values():
        for route in document.routes.values():
            for plugin in route.plugins or ():
                assert plugin in registry
        for plugin in document.global_plugins:
            if document.format != "oidc-plugin-template":
                assert plugin in result["foundation"]["pluginGovernance"]["globalPluginsAllowed"]
    for name, entry in registry.items():
        if entry["authentication"]:
            assert "GLOBAL" not in entry["allowedScopes"], name


def test_unauthenticated_routes_are_only_public_read_only_or_blocked():
    result = _validate(ROOT)
    for route_id, entry in result["routes"].items():
        if "NO_GATEWAY_AUTHENTICATION" not in entry["acceptedFindings"]:
            continue
        route = result["materialized"][route_id]
        if entry["authentication"] == "PUBLIC":
            assert entry["publicReason"]
            assert not (set(route.methods or ()) & validator.MUTATION_METHODS) or entry["lifecycle"] in ("LEGACY", "RETIRE_CANDIDATE")
        else:
            assert entry["activation"] == "BLOCKED" or entry.get("authenticationGap"), route_id


def test_runtime_env_template_declares_every_vault_reference():
    declared = {line.split("=", 1)[0] for line in (ROOT / RUNTIME_ENV).read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#") and "=" in line}
    for reference in validator.VAULT_ENV.findall((ROOT / CONTROL_PLANE).read_text(encoding="utf-8")):
        assert reference.upper().replace("-", "_") in declared, reference


# --------------------------------------------------------------------------- precedence engine


def _route(name, hosts=None, paths=None, methods=None, regex_priority=0):
    return validator.SourceRoute(source="synthetic", name=name, hosts=hosts, paths=paths, methods=methods,
                                 regex_priority=regex_priority)


@pytest.mark.parametrize(("specific", "generic", "reason"), [
    (_route("a", ("api.example",), ("/v1/x",), ("GET",)), _route("b", None, ("/v1/x",), ("GET",)), "specific host beats generic host"),
    (_route("a", ("api.example",), ("/v1/x/y",), ("GET",)), _route("b", ("api.example",), ("/v1/x",), ("GET",)), "specific path beats broad path"),
    (_route("a", ("api.example",), ("/v1/x",), ("GET",)), _route("b", ("api.example",), ("/v1/x",), None), "specific method beats methodless"),
    (_route("a", ("api.example",), ("~^/v1/x/[0-9]+$",), ("GET",)), _route("b", ("api.example",), ("/v1/x",), ("GET",)), "regex beats prefix"),
    (_route("a", ("api.example",), ("~^/v1/x/[0-9]+$",), ("GET",), 5), _route("b", ("api.example",), ("~^/v1/x/[0-9a-z]+$",), ("GET",), 1), "higher regex_priority wins"),
    (_route("a", ("api.example",), ("/v1/x",), ("GET",)), _route("b", ("*.example",), ("/v1/x",), ("GET",)), "plain host beats wildcard host"),
])
def test_router_precedence_is_deterministic(specific, generic, reason):
    overlaps = validator.analyze_precedence({"a": specific, "b": generic})
    assert overlaps and overlaps[0].winner == "a", reason


def test_identical_matches_are_ambiguous_and_disjoint_regexes_do_not_overlap():
    same = validator.analyze_precedence({
        "a": _route("a", ("api.example",), ("/v1/x",), ("GET",)),
        "b": _route("b", ("api.example",), ("/v1/x",), ("GET",)),
    })
    assert same[0].winner == "AMBIGUOUS"
    assert validator.analyze_precedence({
        "a": _route("a", ("h",), ("~/api/v1/c/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",), ("GET",)),
        "b": _route("b", ("h",), ("~/api/v1/c/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$",), ("GET",)),
    }) == []
    assert validator.analyze_precedence({
        "a": _route("a", ("h",), ("/v1/x",), ("GET",)),
        "b": _route("b", ("other",), ("/v1/x",), ("GET",)),
    }) == []
    assert validator.analyze_precedence({
        "a": _route("a", ("h",), ("/v1/x",), ("GET",)),
        "b": _route("b", ("h",), ("/v1/x",), ("POST",)),
    }) == []


# --------------------------------------------------------------------------- mutations: routes and sources


def test_route_added_to_a_source_without_registration_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["routes"].append({
        "name": "shadow-route", "protocols": ["http"], "hosts": ["api.codestra.co"], "paths": ["/api/v1/shadow"],
        "methods": ["GET"], "strip_path": False, "preserve_host": False,
    })
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "undocumented routes")


def test_new_contract_file_must_be_registered_before_it_can_exist(repo):
    # A contract dropped into config/ without a registry entry is refused, so a
    # merge cannot introduce routes the foundation has not classified.
    (repo / "config/kong-something-new-routes.v1.json").write_text('{"routes": []}', encoding="utf-8")
    expect_failure(repo, "unregistered Kong source files")


def test_registry_entry_whose_source_route_vanished_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["routes"] = [r for r in document["services"][0]["routes"] if r["name"] != "control-plane-health"]
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "does not declare route control-plane-health")


@pytest.mark.parametrize(("field", "value", "match"), [
    ("hosts", ["*"], "wildcard hosts are forbidden"),
    ("hosts", ["*.codestra.co"], "WILDCARD_HOST"),
    ("hosts", [], "HOST_UNSPECIFIED"),
    ("methods", [], "METHODS_UNSPECIFIED"),
    ("methods", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], "ALL_METHODS"),
    ("paths", ["/"], "CATCH_ALL_PATH"),
    ("paths", ["/api/v1"], "CATCH_ALL_PREFIX"),
])
def test_wildcard_or_broad_match_on_a_canonical_route_fails(repo, field, value, match):
    document = read_yaml(repo, CONTROL_PLANE)
    route = next(r for r in document["services"][0]["routes"] if r["name"] == "control-plane-health")
    route[field] = value
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, match)


def test_removing_authentication_from_a_canonical_service_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["plugins"] = [p for p in document["services"][0]["plugins"] if p["name"] != "openid-connect"]
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "NO_GATEWAY_AUTHENTICATION|CLAIM_GUARD_WITHOUT_TOKEN_AUTHENTICATION")


def test_claim_guard_moved_to_pre_function_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    for plugin in document["services"][0]["plugins"]:
        if plugin["name"] == "post-function":
            plugin["name"] = "pre-function"
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "pre-function")


@pytest.mark.parametrize("url", ["http://10.40.0.3:8443", "http://twilio-adapter:8080", "http://codestra-control-plane:9999"])
def test_canonical_service_cannot_point_at_ip_provider_or_unknown_listener(repo, url):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["url"] = url
    write_yaml(repo, CONTROL_PLANE, document)
    # the source no longer agrees with the registered upstream: binding drift
    expect_failure(repo, "declares host=|declares port=")
    # and even if the registry were edited to follow, the alias declaration blocks it
    foundation = read_json(repo, FOUNDATION)
    entry = next(s for s in foundation["services"] if s["serviceId"] == "codestra-control-plane")
    scheme, host, port = validator._url_parts(url)
    entry["upstream"] = {"protocol": scheme, "host": host, "port": port}
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "undeclared Middleware alias")


def test_provider_and_ip_upstreams_are_detected_on_the_route():
    foundation = validator.load_json(ROOT / FOUNDATION)
    application = {"upstreamClass": "APPLICATION_DIRECT"}
    for host, code in (("10.40.0.3", "HARD_CODED_UPSTREAM_IP"), ("scraper.internal.codestra.agency", "DIRECT_PROVIDER_UPSTREAM"),
                       ("twilio-adapter", "DIRECT_PROVIDER_UPSTREAM"), ("kong-test-upstream", "TEST_UPSTREAM"),
                       ("codestra-kong-service-auth-adapter-1", "LEGACY_UPSTREAM")):
        route = validator.SourceRoute(source="synthetic", name="r", hosts=("api.codestra.co",), paths=("/v1/x",),
                                      methods=("GET",), plugins=("jwt",), upstream_host=host, upstream_port=8080)
        assert code in validator.detect_route_findings({}, route, application, foundation), host


def test_implicit_retries_or_kong_default_timeouts_on_a_canonical_service_fail(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    del document["services"][0]["retries"]
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "IMPLICIT_RETRIES|retry profile must be the Kong default")
    restore(repo, CONTROL_PLANE)
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0].update(connect_timeout=60000, read_timeout=60000, write_timeout=60000)
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "do not match profile")


def test_mutation_route_without_body_limit_on_a_canonical_route_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    route = next(r for r in document["services"][0]["routes"] if r["name"] == "control-plane-reconciliation")
    route.pop("plugins")
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "UNBOUNDED_REQUEST_BODY")


def test_unknown_or_misplaced_plugins_fail(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["plugins"].append({"name": "openid-connect", "config": {}})
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "not allowed globally|must never be global")
    restore(repo, CONTROL_PLANE)
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["plugins"].append({"name": "made-up-plugin", "config": {}})
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "made-up-plugin")


# --------------------------------------------------------------------------- mutations: drift, precedence, registry


def test_undeclared_runtime_drift_fails(repo):
    inventory = read_json(repo, INVENTORY)
    # the n8n readback drift (8080 -> 8095) is declared since PR #105; use a route
    # whose upstream port carries no declared drift
    route = next(r for r in inventory["routes"] if r["name"] == "codestra-callback-read")
    route["service"]["port"] = 8096
    write_json(repo, INVENTORY, inventory)
    expect_failure(repo, "undeclared runtime drift on (upstream_)?port")


def test_stale_drift_declaration_fails(repo):
    inventory = read_json(repo, INVENTORY)
    for route in inventory["routes"]:
        if route["name"] == "codestra-campaign-policy-check":
            route["protocols"] = ["http"]
    write_json(repo, INVENTORY, inventory)
    expect_failure(repo, "stale route knownDrift")


def test_undeclared_or_misdeclared_overlap_fails(repo):
    foundation = read_json(repo, FOUNDATION)
    foundation["precedence"]["knownConflicts"] = [c for c in foundation["precedence"]["knownConflicts"] if c["left"] != "sms-dlr-telnexa-route"]
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "undeclared route overlap")
    restore(repo, FOUNDATION)
    foundation = read_json(repo, FOUNDATION)
    for conflict in foundation["precedence"]["knownConflicts"]:
        if conflict["left"] == "sms-dlr-telnexa-route":
            conflict["winner"] = "sms-route"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "registry expects winner")


def test_new_ambiguous_overlap_with_a_canonical_runtime_route_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["routes"].append({
        "name": "control-plane-callbacks-shadow", "protocols": ["http"], "hosts": ["api.codestra.co"],
        "paths": ["/api/v1/callbacks"], "methods": ["GET"], "strip_path": False, "preserve_host": False,
    })
    write_yaml(repo, CONTROL_PLANE, document)
    foundation = read_json(repo, FOUNDATION)
    foundation["routes"].append({
        "routeId": "control-plane-callbacks-shadow", "serviceId": "codestra-control-plane", "environment": "production",
        "bindings": [{"source": CONTROL_PLANE, "route": "control-plane-callbacks-shadow", "role": "DESIRED"}],
        "trafficClass": "READ_API", "authentication": "SERVICE_AUTHENTICATED", "mechanism": "OIDC_BEARER_CLAIM_GUARD",
        "audience": "codestra-control-plane", "requiredScopes": [], "rateLimitProfile": "AUTHENTICATED_STANDARD_120",
        "requestSizeProfile": "NONE_READ_ONLY", "lifecycle": "CANONICAL", "activation": "SOURCE_CANDIDATE",
        "disposition": "KEEP", "acceptedFindings": [],
    })
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "undeclared route overlap.*AMBIGUOUS")


def test_route_cannot_lose_its_classification_or_become_public_by_omission(repo):
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-mail-api")
    entry["activation"] = "RUNTIME_OBSERVED"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "neither PUBLIC, BLOCKED")
    restore(repo, FOUNDATION)
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-mail-api")
    entry["activation"] = "RUNTIME_OBSERVED"
    entry["authentication"] = "PUBLIC"
    entry["publicReason"] = "not acceptable"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "public mutation route .* must be legacy, blocked or gateway-terminated|does not list it")
    restore(repo, FOUNDATION)
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "control-plane-health")
    del entry["authentication"]
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "lacks authentication")


def test_legacy_shared_key_cannot_be_promoted_to_canonical(repo):
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "crm-route")
    entry["lifecycle"] = "CANONICAL"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "shared-key route crm-route must be legacy|forbidden findings")


def test_inventory_activation_gate_and_registry_must_agree(repo):
    inventory = read_json(repo, INVENTORY)
    inventory["activationBlockedRoutes"] = [i for i in inventory["activationBlockedRoutes"] if i["route"] != "codestra-mail-api"]
    write_json(repo, INVENTORY, inventory)
    expect_failure(repo, "does not list it in activationBlockedRoutes")


def test_registry_must_remain_source_only(repo):
    foundation = read_json(repo, FOUNDATION)
    foundation["runtimeApplyAuthorized"] = True
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "source-only")
    restore(repo, FOUNDATION)
    foundation = read_json(repo, FOUNDATION)
    foundation["boundaryRules"]["directProviderRoutesAllowed"] = True
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "directProviderRoutesAllowed")


# --------------------------------------------------------------------------- mutations: environments


def test_staging_overlay_cannot_bind_the_production_issuer_or_drift_from_base(repo):
    path = "config/staging/kong-campaign-automation-routes.json"
    overlay = read_json(repo, path)
    overlay["issuer"] = "https://auth.codestra.co/realms/codestra"
    write_json(repo, path, overlay)
    expect_failure(repo, "staging requires")
    restore(repo, path)
    overlay = read_json(repo, path)
    overlay["routes"][0]["rate_per_minute"] = 999
    write_json(repo, path, overlay)
    expect_failure(repo, "drifts from base|does not match profile")


def test_staging_and_production_must_not_share_an_issuer(repo):
    foundation = read_json(repo, FOUNDATION)
    foundation["environments"]["staging"]["issuer"] = foundation["environments"]["production"]["issuer"]
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "must not share an issuer|staging requires")


# --------------------------------------------------------------------------- mutations: node boundary


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda g: g["ports"].append("0.0.0.0:8001:8001"), "Admin, Manager and Status must not be published|host loopback"),
    (lambda g: g["ports"].append("127.0.0.1:8100:8100"), "must not be published"),
    (lambda g: g["environment"].update(KONG_ADMIN_LISTEN="0.0.0.0:8001"), "disabled on data planes"),
    (lambda g: g["environment"].update(KONG_ADMIN_GUI_LISTEN="0.0.0.0:8002"), "Manager must remain off"),
    (lambda g: g["environment"].update(KONG_PG_SSL_VERIFY="off"), "data plane database settings"),
    (lambda g: g["environment"].update(KONG_TRUSTED_IPS="0.0.0.0/0"), "trusted_ips must be required"),
    (lambda g: g["environment"].update(KONG_UNTRUSTED_LUA="on"), "sandboxed"),
    (lambda g: g["environment"].update(KONG_HEADERS="server_tokens"), "server headers"),
    (lambda g: g.update(read_only=False), "read-only"),
    (lambda g: g.update(cap_drop=[]), "capabilities"),
    (lambda g: g.update(image="kong/kong-gateway:3.14.0.1"), "immutable digest"),
    (lambda g: g.setdefault("volumes", []).append("/var/run/docker.sock:/var/run/docker.sock"), "Docker socket"),
])
def test_unsafe_node_settings_fail(repo, mutate, match):
    compose = read_yaml(repo, COMPOSE)
    mutate(compose["services"]["kong-gateway"])
    write_yaml(repo, COMPOSE, compose)
    expect_failure(repo, match)


def test_missing_runtime_variable_for_a_vault_reference_fails(repo):
    path = repo / RUNTIME_ENV
    text = "\n".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("KONG_OIDC_CACHE_TOKENS_SALT="))
    path.write_text(text + "\n", encoding="utf-8")
    expect_failure(repo, "does not declare KONG_OIDC_CACHE_TOKENS_SALT")


def test_conf_example_must_match_load_bearing_settings(repo):
    path = repo / "deploy/kong/kong.conf.example"
    path.write_text(path.read_text(encoding="utf-8").replace("untrusted_lua = sandbox", "untrusted_lua = on"), encoding="utf-8")
    expect_failure(repo, "kong.conf.example untrusted_lua")


# --------------------------------------------------------------------------- docs


def test_generated_documentation_drift_is_detected(repo):
    path = repo / "docs/route-registry-v1.md"
    text = path.read_text(encoding="utf-8")
    start = text.index("<!-- BEGIN GENERATED: routes -->")
    end = text.index("<!-- END GENERATED: routes -->")
    path.write_text(text[:start] + "<!-- BEGIN GENERATED: routes -->\nstale\n" + text[end:], encoding="utf-8")
    result = _validate(repo)
    assert validator.sync_docs(result, root=repo, write=False) == ["docs/route-registry-v1.md"]
    validator.sync_docs(result, root=repo, write=True)
    assert validator.sync_docs(result, root=repo, write=False) == []


def test_cli_reports_pass_and_source_only(capsys):
    assert validator.main([]) == 0
    out = capsys.readouterr().out
    assert "KONG_GATEWAY_FOUNDATION=PASS" in out
    assert "RUNTIME_APPLY_AUTHORIZED=NO" in out


def test_lane_d_parallel_mode_accepts_an_integrated_candidate_without_downgrade():
    result = validator.validate_foundation()
    status = validator.validate_v3_certification(result, "parallel")
    assert status["phase"] == "INTEGRATED"
    assert status["middlewareContractSha256"] == validator.FINAL_MIDDLEWARE_CONTRACT_SHA256
    assert status["classificationCounts"] == validator.FINAL_MIDDLEWARE_ROUTE_COUNTS
    assert status["missingMiddlewareRoutes"] == 0
    assert status["staleMiddlewareRoutes"] == 0
    assert status["active8080Aliases"] == 0
    assert status["directProviderRoutes"] == 0
    assert status["directN8nExecutionRoutes"] == 0
    assert status["directOdooRoutes"] == 0
    assert status["publicPostgresRedisRoutes"] == 0
    assert status["undeclaredOverlaps"] == 0
    assert status["staleKnownDrift"] == 0
    assert status["secretHits"] == 0
    assert status["laneCArtifactsIntegrated"] is True
    assert status["finalAuthorityRendered"] is True
    assert status["provisionalIndependentAuthority"] is False


def test_lane_d_integrated_gate_refuses_a_mocked_preintegration_status(monkeypatch):
    result = validator.validate_foundation()
    preintegration = copy.deepcopy(validator.v3_certification_status(result))
    preintegration["phase"] = "PARALLEL"
    preintegration["laneCArtifactsIntegrated"] = False
    preintegration["finalAuthorityRendered"] = False
    monkeypatch.setattr(
        validator,
        "v3_certification_status",
        lambda _result, root=validator.ROOT: copy.deepcopy(preintegration),
    )
    with pytest.raises(validator.FoundationError, match="A/B/C are not fully integrated"):
        validator.validate_v3_certification(result, "integrated")


def test_lane_d_gate_rejects_active_8080_or_direct_provider_routes():
    result = validator.validate_foundation()
    route = next(
        entry for entry in result["routes"].values()
        if validator._candidate_route_is_active(entry, result["foundation"])
        and entry.get("serviceId") is not None
    )
    service_id = route["serviceId"]

    changed = copy.deepcopy(result)
    changed["services"][service_id]["upstream"] = {
        "protocol": "http",
        "host": "middleware-integration-api",
        "port": 8080,
    }
    with pytest.raises(validator.FoundationError, match="active 8080 aliases remain"):
        validator.validate_v3_certification(changed, "parallel")

    changed = copy.deepcopy(result)
    changed["services"][service_id]["upstream"] = {
        "protocol": "http",
        "host": "odoo",
        "port": 8069,
    }
    with pytest.raises(validator.FoundationError, match="direct provider routes remain"):
        validator.validate_v3_certification(changed, "parallel")


def test_lane_d_auto_phase_reports_integrated_after_abc_land():
    result = validator.validate_foundation()
    status = validator.validate_v3_certification(result, "auto")
    assert status["phase"] == "INTEGRATED"
    assert status["missingMiddlewareRoutes"] == 0
    assert status["staleMiddlewareRoutes"] == 0
    assert status["laneCArtifactsIntegrated"] is True
    assert status["finalAuthorityRendered"] is True
    assert status["provisionalIndependentAuthority"] is False
