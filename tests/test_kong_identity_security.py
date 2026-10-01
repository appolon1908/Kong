"""Mission 2 — identity, authentication and API access security enforcement.

Positive tests prove the committed access policy, authentication profiles and
foundation agree and that every route carries an explicit access class,
issuer, audience, scope, party and identity-propagation posture. Negative
tests mutate isolated copies of the repository and prove the canonical
validator fails closed on: an unclassified route, a protected route without
authentication, a public route that is not allowlisted, a wrong or wildcard
issuer, a missing/wrong/wildcard audience, a missing required scope, identity
headers treated as authority, arbitrary tenant-header trust, a committed
client secret, a global authentication plugin and an authentication downgrade.

The Mission 1 reconciliation (PR #105) is merged: the canonical Middleware edge
is the 99-operation v2 authority (openid-connect per route on
middleware-integration-api:8095), its 10 retired aliases are gateway-terminated
404s, the retired appolon-middleware-integration-api:8080 alias has no
activatable route, and every superseded jwt / PR #104 route points at its v2
successor. Nothing here contacts a Kong node.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_kong_foundation.py"
SPEC = importlib.util.spec_from_file_location("kong_foundation_validator_m2", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

FOUNDATION = "config/kong-gateway-foundation.v1.json"
POLICY = "config/kong-access-policy.v1.json"
PROFILES = "config/kong-authentication-profiles.v1.json"
CONTROL_PLANE = "deploy/kong/control-plane.yml"
COPIED = ("config", "deploy", "kong", "docs", "scripts", "tests", "tools", "operations", "orbit", "contracts", ".github")
BASE: dict[str, Path] = {}

AUTHORITY = "config/kong-middleware-authority.v2.json"
CANONICAL = "config/kong-canonical-middleware-routes.json"
PROD_YML = "config/kong-middleware-routes.production.yml"
STG_YML = "config/staging/kong-middleware-routes.staging.yml"
PLATFORM_READ = "config/kong-platform-api-read-routes.v1.json"
PROD_ISSUER = "https://auth.codestra.co/realms/codestra"
STG_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
V2_PLUGINS = {"openid-connect", "post-function", "correlation-id", "rate-limiting", "request-size-limiting"}
DENIED_TEMPLATES = {
    "/api/v1/integration/campaign-actions", "/api/v1/integrations/odoo/campaign-actions",
    "/api/v1/integrations/odoo/campaign-commands", "/v1/integrations/n8n/commands", "/v1/integrations/n8n/operations",
}
KONG_SET_CONSUMER_HEADERS = {"X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier", "X-Anonymous-Consumer"}


@pytest.fixture(scope="module")
def base_copy(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("kong-m2-base")
    for name in COPIED:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, base / name, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    BASE["root"] = base
    return base


@pytest.fixture
def repo(base_copy, tmp_path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(base_copy, root)
    return root


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
        validator.validate_foundation(root=root)


def policy_entry(document: dict, route_id: str) -> dict:
    return next(r for r in document["routes"] if r["routeId"] == route_id)


# --------------------------------------------------------------------------- positive


def test_access_policy_validates_and_every_route_is_classified():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    assert policy["runtimeApplyAuthorized"] is False and profiles["runtimeApplyAuthorized"] is False
    assert {r["routeId"] for r in policy["routes"]} == set(result["routes"])
    for item in policy["routes"]:
        assert item["accessClass"] in validator.ACCESS_CLASSES
        assert item["authenticationProfile"] in profiles["profiles"]
        assert item["issuerProfile"] in profiles["issuerProfiles"]
        assert item["audienceProfile"] in profiles["audienceProfiles"]
        assert item["identityPropagation"] in profiles["identityPropagationProfiles"]
        assert item["tenantPolicy"] in profiles["tenantPolicies"]
        assert isinstance(item["requiredScopes"], list)
    assert result["secret_scan"] == 0


def test_intentional_public_routes_are_allowlisted_read_only_or_legacy():
    result = validator.validate_foundation(root=ROOT)
    policy = result["policy"]
    allow = {i["routeId"] for i in policy["publicAllowlist"]}
    public = {i["routeId"] for i in policy["routes"] if i["accessClass"] == "PUBLIC"}
    assert allow == public
    for route_id in public:
        route = result["materialized"][route_id]
        entry = result["routes"][route_id]
        mutating = set(route.methods or ()) & validator.MUTATION_METHODS
        terminated = "GATEWAY_TERMINATED" in entry["acceptedFindings"]
        assert not mutating or terminated or entry["lifecycle"] in ("LEGACY", "RETIRE_CANDIDATE"), route_id
        if terminated:
            assert entry["serviceId"] is None and route.upstream_host is None
            # Materialized canonical routes include the inherited global guard.
            assert set(route.plugins) == {"codestra-private-surface", "request-termination"}
    # the Mission 1 critical finding stays visible: blocked, not public, not resolved
    mail = policy_entry(policy, "codestra-mail-api")
    assert mail["accessClass"] == "ADMIN_INTERNAL" and mail["authenticationProfile"] == "BLOCKED_NONE_V1"
    assert result["routes"]["codestra-mail-api"]["activation"] == "BLOCKED"
    assert "codestra-mail-api" not in allow


def test_protected_routes_bind_issuer_audience_scopes_and_parties():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    for item in policy["routes"]:
        entry = result["routes"][item["routeId"]]
        profile = profiles["profiles"][item["authenticationProfile"]]
        if item["accessClass"] == "PUBLIC" or profile["strength"] == 0:
            continue
        if profile["issuerProfile"] == "environment":
            issuer = profiles["issuerProfiles"][item["issuerProfile"]]
            assert issuer["environment"] == entry["environment"]
            assert issuer["algorithms"] == ["RS256"] and issuer["clockSkewSeconds"] == 0
        if entry["mechanism"] in validator.load_json(ROOT / FOUNDATION)["debtRules"]["tokenMechanisms"]:
            assert profiles["audienceProfiles"][item["audienceProfile"]]["audience"] not in (None, "*")
        assert item["requiredScopes"] == entry.get("requiredScopes", [])
        assert all("*" not in scope for scope in item["requiredScopes"])
        if profile["authorizedParties"] == "explicit":
            assert item["authorizedParties"]


def test_client_id_equals_audience_only_where_contractually_defined():
    result = validator.validate_foundation(root=ROOT)
    audiences = result["profiles"]["audienceProfiles"]
    for name, aud in audiences.items():
        if aud["clientIdIsAudience"]:
            assert aud["contractuallyDefinedBy"], name
    for item in result["policy"]["routes"]:
        if audiences[item["audienceProfile"]]["clientIdIsAudience"]:
            assert "AUDIENCE_IS_CLIENT_ID" in result["routes"][item["routeId"]]["acceptedFindings"]


def test_human_service_admin_and_internal_identities_are_separated():
    result = validator.validate_foundation(root=ROOT)
    for item in result["policy"]["routes"]:
        entry = result["routes"][item["routeId"]]
        if entry["activation"] == "BLOCKED":
            continue
        if item["accessClass"] == "ADMIN_INTERNAL":
            assert item["principalClasses"] == ["ADMIN"]
            assert "platform.admin" in item["requiredScopes"]
        if item["accessClass"] in ("SERVICE_AUTHENTICATED", "INTERNAL") and entry["lifecycle"] != "DESIGN_ONLY":
            assert "HUMAN" not in item["principalClasses"], item["routeId"]
        if "HUMAN" in item["principalClasses"] and entry["lifecycle"] != "DESIGN_ONLY":
            assert item["accessClass"] == "AUTHENTICATED", item["routeId"]


def test_identity_headers_are_never_authority_and_unstripped_routes_are_explicit():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    assert policy["identityHeaders"]["headerAuthorityAllowed"] is False
    never = set(policy["identityHeaders"]["neverTrustedFromClients"])
    for header in ("X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes", "X-Consumer-ID", "X-Authenticated-UserID"):
        assert header in never
    for item in policy["routes"]:
        prop = profiles["identityPropagationProfiles"][item["identityPropagation"]]
        assert prop["stripsClientIdentity"] or "IDENTITY_HEADERS_NOT_STRIPPED" in item["acceptedFindings"]
        assert "HEADER_AUTHORITY" not in item["tenantPolicy"] or "CLAIM_AUTHORITY" in item["tenantPolicy"]


def test_guards_strip_before_minting_and_never_log_or_echo_tokens():
    for lua in ("deploy/kong/scope-policy.lua", "deploy/kong/calling-policy.lua", "deploy/kong/moneybee-identity-policy.lua"):
        text = (ROOT / lua).read_text(encoding="utf-8")
        assert text.index("clear_header") < text.index("set_header"), lua
        assert "kong.log" not in text and "ngx.log" not in text, lua
        # every exit body is a constant table: no token, claim or header value is echoed
        for body in re.findall(r"kong\.response\.exit\(\d+,\s*(\{.*?\})\)", text):
            assert "token" not in body and "claims." not in body and "header" not in body, (lua, body)
    for handler in ("codestra-authz", "codestra-request-context", "codestra-webhook-verifier"):
        text = (ROOT / f"deploy/kong/plugins/{handler}/handler.lua").read_text(encoding="utf-8")
        assert "kong.log" not in text and "ngx.log" not in text, handler


def test_token_and_cache_settings_are_bounded_and_vault_backed():
    result = validator.validate_foundation(root=ROOT)
    cache = result["profiles"]["tokenCachePolicies"]["OIDC_CACHE_V1"]
    assert cache["cacheTokensSalt"].startswith("{vault://env/") and cache["saltInGit"] is False
    assert 0 < cache["cacheTtlSeconds"] <= result["profiles"]["rules"]["maximumCacheTtlSeconds"]
    control_plane = read_yaml(ROOT, CONTROL_PLANE)
    oidc = next(p for p in control_plane["services"][0]["plugins"] if p["name"] == "openid-connect")["config"]
    assert oidc["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"
    assert oidc.get("leeway", 0) == 0 and "anonymous" not in oidc
    assert oidc["audience"] == ["codestra-control-plane"] and oidc["auth_methods"] == ["bearer"]


def test_evidence_and_templates_contain_no_credential_values():
    markers = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ|BEGIN (?:RSA |EC |)PRIVATE KEY|client_secret\"?\s*[:=]\s*\"[A-Za-z0-9]{16,}")
    for path in ("docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json", "docs/evidence/PRODUCTION_HEAD_CANARY_20260906.json",
                 "deploy/kong/runtime.env.example", "deploy/kong/kong.conf.example", "kong/plugins/oidc/keycloak.yml"):
        assert not markers.search((ROOT / path).read_text(encoding="utf-8")), path
    evidence = read_json(ROOT, "docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json")
    assert evidence["secretsCaptured"] is False
    assert validator.scan_secrets(ROOT) == []


def test_logging_policy_and_admin_isolation_are_preserved():
    result = validator.validate_foundation(root=ROOT)
    logging = result["policy"]["logging"]
    for header in ("Authorization", "Cookie", "Set-Cookie", "access_token", "refresh_token", "id_token", "client_secret"):
        assert header in logging["neverPersisted"]
    assert logging["logPluginsRegistered"] == []
    assert not {p["plugin"] for p in result["foundation"]["plugins"]} & {"file-log", "http-log", "tcp-log", "udp-log", "syslog"}
    compose = read_yaml(ROOT, "deploy/kong/compose.kong.yaml")["services"]["kong-gateway"]
    assert compose["environment"]["KONG_ADMIN_LISTEN"] == "off"
    assert compose["environment"]["KONG_ADMIN_GUI_LISTEN"] == "off"
    assert all(str(p).startswith("127.0.0.1:8000:") for p in compose["ports"])


# --------------------------------------------------------------------------- Mission 1 dependency (reported, never falsified)


def test_mission1_reconciliation_is_merged_and_recorded():
    result = validator.validate_foundation(root=ROOT)
    status = validator.m1_dependency_status(result["foundation"], ROOT)
    assert status["state"] == "MERGED" and status["reconciled"] and status["transitional8080Aliases"] == []
    assert status["retiredAliases"] == ["appolon-middleware-integration-api:8080"]
    reconciliation = result["policy"]["m1Reconciliation"]
    assert reconciliation["pullRequest"] == 105 and reconciliation["state"] == "MERGED"
    assert reconciliation["mergeCommit"] == result["foundation"]["reconciledMain"]["commit"]
    assert "m1Dependency" not in result["policy"]
    assert not [i for i in result["policy"]["routes"] if "m1Dependency" in i]
    assert (ROOT / AUTHORITY).is_file()


def test_retired_middleware_8080_alias_has_no_activatable_route():
    # Formerly the strict M1_DEPENDENCY_PENDING guard; PR #105 is merged so this is a plain invariant.
    result = validator.validate_foundation(root=ROOT)
    foundation = result["foundation"]
    rules = foundation["debtRules"]
    aliases = foundation["boundaryRules"]["middlewareUpstreamAliases"]
    assert [a for a in aliases if a["role"] == "CANONICAL_PUBLIC_API"] == [
        a for a in aliases if a["host"] == "middleware-integration-api" and a["port"] == 8095]
    for alias in aliases:
        if alias["port"] == 8080:
            assert alias["role"].startswith("RETIRED"), alias
    retired = validator.retired_middleware_aliases(foundation)
    assert ("appolon-middleware-integration-api", 8080) in retired
    for service in foundation["services"]:
        if service["upstreamClass"] in rules["middlewareUpstreamClasses"]:
            if (service["upstream"]["host"], service["upstream"]["port"]) in retired:
                assert "RETIRED_UPSTREAM_ALIAS" in service["acceptedFindings"] and service["lifecycle"] in rules["retiredAliasLifecycles"], service["serviceId"]
            else:
                assert service["upstream"]["port"] != 8080, service["serviceId"]
            if service["lifecycle"] == "CANONICAL":
                assert service["upstream"]["port"] in (8095, 8096, 443), service["serviceId"]
    drift = {(d["subject"], d["field"]): d for d in foundation["knownDrift"]}
    for entry in foundation["routes"]:
        route = result["materialized"][entry["routeId"]]
        if "RETIRED_UPSTREAM_ALIAS" in entry["acceptedFindings"]:
            assert entry["lifecycle"] in rules["retiredAliasLifecycles"], entry["routeId"]
            if entry["activation"] == "RUNTIME_OBSERVED":
                # live residue: the readback still shows the retired alias, the contract does not
                assert entry["lifecycle"] == "RETIRE_CANDIDATE" and entry["retiredBy"] in result["routes"]
                assert drift[(entry["routeId"], "upstream_port")]["observed"] == 8080
                assert drift[(entry["routeId"], "upstream_port")]["desired"] == 8095
        elif entry["lifecycle"] == "CANONICAL" and route.upstream_host is not None:
            assert (route.upstream_host, route.upstream_port) not in retired, entry["routeId"]
            assert route.upstream_port != 8080, entry["routeId"]


def test_v2_shared_edge_routes_are_governed_from_the_authority():
    result = validator.validate_foundation(root=ROOT)
    policy = {i["routeId"]: i for i in result["policy"]["routes"]}
    authority = validator.load_json(ROOT / AUTHORITY)
    canonical = validator.load_json(ROOT / CANONICAL)
    assert authority["runtime_apply_authorized"] is False and authority["provider_effects_enabled"] is False
    assert canonical["middlewareEdgeContract"]["sha256"] == authority["contract"]["sha256"]
    operations = {validator.authority_route_name(o["operation_id"]): o for o in authority["routes"]}
    assert len(operations) == validator.FINAL_MIDDLEWARE_ROUTE_COUNTS["shared_edge"]
    for name, operation in operations.items():
        for suffix, environment, issuer, sources in (
            ("", "production", PROD_ISSUER, {CANONICAL, PROD_YML, AUTHORITY}),
            ("@staging", "staging", STG_ISSUER, {STG_YML}),
        ):
            entry = result["routes"][name + suffix]
            route = result["materialized"][name + suffix]
            item = policy[name + suffix]
            assert entry["serviceId"] == "middleware-integration-api" + suffix and entry["environment"] == environment
            assert {b["source"] for b in entry["bindings"]} == sources and all(b["role"] == "DESIRED" for b in entry["bindings"])
            assert entry["lifecycle"] == "CANONICAL" and entry["activation"] == "SOURCE_CANDIDATE" and entry["mechanism"] == "OIDC_BEARER"
            assert (route.upstream_host, route.upstream_port) == ("middleware-integration-api", 8095)
            assert route.hosts == ("api.codestra.co",) and route.paths[0].startswith("~/") and route.paths[0].endswith("$")
            assert V2_PLUGINS <= set(route.plugins) and route.issuer == issuer
            assert route.audience == operation["audience"] and route.required_scope == operation["scope"]
            assert route.expected_azp == validator.canonical_azp(operation["azp"])
            human_or_service = operation["authentication"] == "service-or-user-jwt"
            assert entry["authentication"] == ("AUTHENTICATED" if human_or_service else "SERVICE_AUTHENTICATED")
            assert item["authenticationProfile"] == ("HUMAN_OR_SERVICE_OIDC_V1" if human_or_service else "SERVICE_OIDC_V1")
            assert item["principalClasses"] == (["HUMAN", "SERVICE"] if human_or_service else ["SERVICE"])
            assert item["issuerProfile"] == ("KEYCLOAK_CODESTRA_PRODUCTION" if environment == "production" else "KEYCLOAK_CODESTRA_STAGING")
            assert result["profiles"]["audienceProfiles"][item["audienceProfile"]]["audience"] == operation["audience"]
            assert item["requiredScopes"] == [operation["scope"]] and item["contractExpectedAzp"] == operation["azp"]
            assert item["authorizedParties"] == "consumer-mapped" and item["failurePolicy"] == "FAIL_CLOSED_V1"
            assert item["tokenCache"] == "OIDC_CACHE_V1" and item["identityPropagation"] == "OIDC_STRIP_AND_CONTRACT_METADATA"
            assert item["acceptedFindings"] == ["EXPECTED_AZP_ENFORCED_UPSTREAM"]
    for path, issuer in ((PROD_YML, PROD_ISSUER), (STG_YML, STG_ISSUER)):
        manifest = read_yaml(ROOT, path)
        service = manifest["services"][0]
        assert (service["host"], service["port"], service["retries"]) == ("middleware-integration-api", 8095, 0)
        assert "8080" not in (ROOT / path).read_text(encoding="utf-8")
        for route in service["routes"]:
            plugins = {p["name"]: p["config"] for p in route["plugins"]}
            oidc = plugins["openid-connect"]
            assert oidc["issuer"] == issuer + "/.well-known/openid-configuration"
            assert oidc["cache_tokens_salt"].startswith("{vault://env/") and oidc["auth_methods"] == ["bearer"]
            assert oidc["audience"] and "*" not in oidc["audience"] and oidc["scopes_required"] and oidc["consumer_claim"] == ["azp"]
            assert plugins["correlation-id"]["header_name"] == "X-Correlation-ID"
            assert plugins["rate-limiting"]["minute"] == 120 and plugins["request-size-limiting"]["allowed_payload_size"] == 2
            assert isinstance(route["regex_priority"], int) and route["regex_priority"] > 0


def test_denied_aliases_are_fail_closed_404_terminations():
    result = validator.validate_foundation(root=ROOT)
    policy = {i["routeId"]: i for i in result["policy"]["routes"]}
    allow = {a["routeId"] for a in result["policy"]["publicAllowlist"]}
    denied = [r for r in result["foundation"]["routes"] if r["trafficClass"] == "DENIED_ALIAS"]
    assert len(denied) == 20 and len({r["environment"] for r in denied}) == 2
    templates = set()
    for entry in denied:
        route = result["materialized"][entry["routeId"]]
        assert entry["serviceId"] is None and entry["acceptedFindings"] == ["GATEWAY_TERMINATED"]
        assert entry["authentication"] == "PUBLIC" and entry["mechanism"] == "NONE" and entry["deniedStatus"] == 404
        assert entry["lifecycle"] == "CANONICAL" and entry["routeId"] in allow
        assert route.upstream_host is None and route.upstream_port is None
        assert set(route.plugins) == {"codestra-private-surface", "request-termination"}
        assert route.hosts == ("api.codestra.co",) and route.paths[0].startswith("~/") and "*" not in route.paths[0]
        assert policy[entry["routeId"]]["authenticationProfile"] == "DENIED_TERMINATION_V1"
        assert policy[entry["routeId"]]["identityPropagation"] == "NONE_TERMINATED"
        templates.add(entry["deniedTemplate"].split("{")[0].rstrip("/"))
    assert DENIED_TEMPLATES <= templates
    for name in ("codestra-n8n-command-submit", "codestra-n8n-command-read"):
        entry = result["routes"][name]
        assert entry["lifecycle"] == "RETIRE_CANDIDATE" and entry["retiredBy"] in result["routes"]
        assert result["routes"][entry["retiredBy"]]["trafficClass"] == "DENIED_ALIAS"
        assert result["routes"][name + "@staging"]["activation"] == "BLOCKED"
    for path in (PROD_YML, STG_YML):
        for route in read_yaml(ROOT, path)["routes"]:
            assert [p["name"] for p in route["plugins"]] == ["request-termination"]
            assert route["plugins"][0]["config"]["status_code"] == 404 and "service" not in route


def test_superseded_routes_point_at_their_v2_successor_and_no_stale_canonical_remains():
    result = validator.validate_foundation(root=ROOT)
    routes = result["routes"]
    canonical_names = {r["name"] for r in validator.load_json(ROOT / CANONICAL)["contractRoutes"]}
    denied_names = {r["name"] for r in validator.load_json(ROOT / CANONICAL)["deniedRoutes"]}
    for entry in routes.values():
        bound = {b["route"] for b in entry["bindings"] if b["source"] == CANONICAL}
        if bound and entry["lifecycle"] == "CANONICAL":
            assert bound <= canonical_names | denied_names, entry["routeId"]
    for name in ("codestra-callback-control", "codestra-callback-read", "codestra-campaign-policy-check", "codestra-campaign-result-submit",
                 "codestra-campaign-result-read", "codestra-odoo-campaign-read", "codestra-odoo-campaign-desired-state-read"):
        entry = routes[name]
        assert entry["lifecycle"] == "TRANSITIONAL" and entry["disposition"] == "DEPRECATE"
        successor = routes[entry["supersededBy"]]
        assert successor["lifecycle"] == "CANONICAL" and successor["routeId"].startswith("middleware-")
        assert result["materialized"][name].methods == result["materialized"][successor["routeId"]].methods
        assert CANONICAL not in {b["source"] for b in entry["bindings"]}
    platform = validator.load_json(ROOT / PLATFORM_READ)
    for route in platform["routes"]:
        entry = routes[route["name"]]
        assert entry["lifecycle"] == "TRANSITIONAL" and routes[entry["supersededBy"]]["lifecycle"] == "CANONICAL"
        assert entry["serviceId"] == "codestra-platform-api" and result["services"]["codestra-platform-api"]["supersededBy"] == "middleware-integration-api"
    conflicts = result["foundation"]["precedence"]["knownConflicts"]
    ambiguous = [c for c in conflicts if c["winner"] == "AMBIGUOUS"]
    assert {(c["left"], c["right"]) for c in ambiguous} == {("codestra-communication-canonical-read", "communication-message-read")}
    for conflict in conflicts:
        v2 = [r for r in (conflict["left"], conflict["right"]) if r.startswith("middleware-")]
        other = [r for r in (conflict["left"], conflict["right"]) if not r.startswith("middleware-")]
        if v2 and other:
            assert conflict["winner"] == v2[0] and conflict["resolution"] in ("SUCCESSOR_REPLACES_LEGACY_ON_APPLY", "DETERMINISTIC_SPECIFICITY"), conflict
        if len(v2) == 2:
            assert conflict["winner"] != "AMBIGUOUS", conflict
    for name in ("codestra-intake-leads", "codestra-intake-survey-responses"):
        assert routes[name]["lifecycle"] == "CANONICAL" and routes[name]["contractCoverage"]


def test_generated_guard_strips_identity_before_minting_and_never_logs():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    never = set(policy["identityHeaders"]["neverTrustedFromClients"])
    minted = set(policy["identityHeaders"]["mintedOnlyByGateway"])
    strip = set(profiles["identityPropagationProfiles"]["OIDC_STRIP_AND_CONTRACT_METADATA"]["strip"])
    metadata = {"X-Codestra-Contract-Operation", "X-Codestra-Expected-Azp", "X-Codestra-Required-Scope"}
    assert metadata <= never and metadata <= minted
    assert strip == never - KONG_SET_CONSUMER_HEADERS - metadata
    for path in (PROD_YML, STG_YML):
        for route in read_yaml(ROOT, path)["services"][0]["routes"]:
            source = "\n".join(next(p for p in route["plugins"] if p["name"] == "post-function")["config"]["access"])
            assert source.index("clear_header") < source.index("set_header"), route["name"]
            assert "kong.log" not in source and "ngx.log" not in source and "get_header" not in source
            for header in strip:
                assert f'"{header}"' in source, (route["name"], header)
            for header in metadata:
                assert f"set_header('{header}'" in source, (route["name"], header)


def test_environments_are_not_collapsed():
    result = validator.validate_foundation(root=ROOT)
    environments = result["foundation"]["environments"]
    assert environments["production"]["issuer"] == PROD_ISSUER and environments["staging"]["issuer"] == STG_ISSUER
    overlay = next(o for o in environments["staging"]["overlays"] if o["base"] == PROD_YML)
    assert overlay["overlay"] == STG_YML and overlay["excludedRoutes"] == []
    for entry in result["foundation"]["routes"]:
        for binding in entry["bindings"]:
            source = next(s for s in result["foundation"]["sources"] if s["path"] == binding["source"])
            assert source["environment"] == entry["environment"], entry["routeId"]


def test_mission1_security_invariants_are_not_regressed():
    result = validator.validate_foundation(root=ROOT)
    foundation = result["foundation"]
    rules = foundation["boundaryRules"]
    assert rules["directProviderRoutesAllowed"] is False and rules["fallbackRoutesAllowed"] is False
    assert rules["adminPubliclyReachable"] is False and rules["clientSuppliedIdentityHeadersTrusted"] is False
    assert rules["middlewareListenerSplit"]["canonicalPublicApiListener"] == 8095
    for entry in foundation["routes"]:
        if entry["lifecycle"] == "CANONICAL":
            route = result["materialized"][entry["routeId"]]
            assert route.methods and route.hosts and route.paths
            assert not {"DIRECT_PROVIDER_UPSTREAM", "HARD_CODED_UPSTREAM_IP", "NO_GATEWAY_AUTHENTICATION"} & set(entry["acceptedFindings"])
    assert set(foundation["pluginGovernance"]["globalPluginsAllowed"]) == {"prometheus", "codestra-private-surface"}


# --------------------------------------------------------------------------- negative mutations


def test_unclassified_route_fails(repo):
    policy = read_json(repo, POLICY)
    policy["routes"] = [r for r in policy["routes"] if r["routeId"] != "control-plane-health"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "disagree on the route set")
    policy = read_json(BASE["root"], POLICY)
    del policy_entry(policy, "control-plane-health")["accessClass"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "lacks accessClass")


def test_protected_route_without_authentication_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["plugins"] = [p for p in document["services"][0]["plugins"] if p["name"] != "openid-connect"]
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "NO_GATEWAY_AUTHENTICATION|CLAIM_GUARD_WITHOUT_TOKEN_AUTHENTICATION")


def test_public_route_not_allowlisted_fails(repo):
    policy = read_json(repo, POLICY)
    policy["publicAllowlist"] = [i for i in policy["publicAllowlist"] if i["routeId"] != "codestra-token-validation-certification"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "public route codestra-token-validation-certification is not on the public allowlist")


def test_route_cannot_be_reclassified_public_by_policy_alone(repo):
    policy = read_json(repo, POLICY)
    entry = policy_entry(policy, "codestra-callback-read")
    entry["accessClass"] = "PUBLIC"
    entry["authenticationProfile"] = "PUBLIC_V1"
    policy["publicAllowlist"].append({"routeId": "codestra-callback-read", "reason": "not acceptable"})
    write_json(repo, POLICY, policy)
    expect_failure(repo, "class PUBLIC != foundation SERVICE_AUTHENTICATED")


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(issuer="https://auth-staging.codestra.co/realms/codestra"), "does not match the environment issuer"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(issuer="https://*.codestra.co/realms/codestra"), "does not match the environment issuer|wildcards are forbidden"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(algorithms=["RS256", "HS256"]), "RS256 only"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(clockSkewSeconds=600), "clock skew is unbounded"),
    (lambda p: p["audienceProfiles"]["MIDDLEWARE_API"].update(audience="*"), "must not be a wildcard"),
    (lambda p: p["audienceProfiles"]["CALLBACK_API"].update(audience="codestra-callback-api-other"), "!= foundation audience"),
    (lambda p: p["audienceProfiles"]["MONEYBEE_API"].update(clientIdIsAudience=True), "without a contract"),
    (lambda p: p["tokenCachePolicies"]["OIDC_CACHE_V1"].update(cacheTokensSalt="deadbeefcafefeed"), "through the vault"),
    (lambda p: p["tokenCachePolicies"]["OIDC_CACHE_V1"].update(cacheTtlSeconds=86400), "ttl is unbounded"),
    (lambda p: p["rules"].update(wildcardAudienceAllowed=True), "must remain forbidden"),
    (lambda p: p["rules"].update(identityHeaderAuthorityAllowed=True), "must remain forbidden"),
    (lambda p: p["failurePolicies"]["FAIL_CLOSED_V1"].update(downgradeToPublic=True), "allows downgrade to public"),
])
def test_profile_catalogue_mutations_fail(repo, mutate, match):
    profiles = read_json(repo, PROFILES)
    mutate(profiles)
    write_json(repo, PROFILES, profiles)
    expect_failure(repo, match)


@pytest.mark.parametrize(("route_id", "mutate", "match"), [
    ("codestra-n8n-command-submit", lambda e: e.update(issuerProfile="KEYCLOAK_CODESTRA_STAGING"), "is not the production realm"),
    ("codestra-n8n-command-submit", lambda e: e.update(issuerProfile="NONE"), "unknown issuer profile|is not the production realm"),
    ("codestra-n8n-command-submit", lambda e: e.update(audienceProfile="NONE"), "!= foundation audience"),
    ("codestra-n8n-command-submit", lambda e: e.update(audienceProfile="CALLBACK_API"), "!= foundation audience"),
    ("codestra-n8n-command-submit", lambda e: e.update(requiredScopes=[]), "required scopes drift"),
    ("codestra-n8n-command-submit", lambda e: e.update(requiredScopes=["middleware.*"]), "required scopes drift|wildcard scope"),
    ("codestra-n8n-command-submit", lambda e: e.update(authorizedParties=[]), "must not be empty"),
    ("codestra-n8n-command-submit", lambda e: e.update(authorizedParties=["someone-else"]), "is not an authorized party"),
    ("codestra-n8n-command-submit", lambda e: e.update(principalClasses=["HUMAN"]), "principal classes outside the profile"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="HUMAN_OIDC_V1"), "does not serve class SERVICE_AUTHENTICATED"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="LEGACY_SHARED_KEY_V1"), "does not serve class|is not part of profile|not allowed for lifecycle"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="BLOCKED_NONE_V1"), "is not part of profile|not allowed for activation"),
    ("codestra-n8n-command-submit", lambda e: e.update(tenantPolicy="HEADER_AUTHORITY"), "unknown tenant policy"),
    ("codestra-n8n-command-submit", lambda e: e.update(identityPropagation="GATEWAY_MINTED_TENANT_ROLE"), "finding claims unstripped headers but the profile strips them"),
    ("codestra-n8n-command-submit", lambda e: e.update(acceptedFindings=[]), "forwards client identity headers without accepting the finding"),
    ("control-plane-system-admin", lambda e: e.update(principalClasses=["SERVICE"]), "principal classes outside the profile"),
    ("control-plane-system-admin", lambda e: e.update(authenticationProfile="SERVICE_OIDC_V1"), "does not serve class ADMIN_INTERNAL"),
    ("moneybee-account-bootstrap", lambda e: e.update(accessClass="SERVICE_AUTHENTICATED"), "class SERVICE_AUTHENTICATED != foundation AUTHENTICATED"),
    ("codestra-calling-command-submit", lambda e: e.update(principalClasses=["HUMAN"]), "principal classes outside the profile"),
])
def test_route_policy_mutations_fail(repo, route_id, mutate, match):
    policy = read_json(repo, POLICY)
    mutate(policy_entry(policy, route_id))
    write_json(repo, POLICY, policy)
    expect_failure(repo, match)


def test_authentication_downgrade_in_the_foundation_is_caught(repo):
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-n8n-command-read")
    entry["authentication"] = "AUTHENTICATED"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "class SERVICE_AUTHENTICATED != foundation AUTHENTICATED")
    foundation = read_json(BASE["root"], FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-n8n-command-read")
    entry["audience"] = None
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "requires an audience|source audience")


def test_wrong_issuer_in_a_source_fails(repo):
    path = "config/kong-n8n-control-plane-routes.json"
    contract = read_json(repo, path)
    contract["issuer"] = "https://auth.evil.example/realms/codestra"
    write_json(repo, path, contract)
    expect_failure(repo, "binds issuer https://auth.evil.example")


def test_global_authentication_plugin_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["plugins"].append({"name": "jwt", "config": {"claims_to_verify": ["exp"]}})
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "not allowed globally|must never be global")


def test_plaintext_secret_in_any_authority_file_fails(repo):
    # Values are assembled at runtime so this test file never contains them.
    planted = "".join(chr(65 + i % 26) for i in range(40))
    key_name = "client_" + "secret"
    (repo / "operations/kong-database/notes.env").write_text(key_name + ": " + planted + "\n", encoding="utf-8")
    expect_failure(repo, "committed secret material detected.*client_secret_literal")
    (repo / "operations/kong-database/notes.env").unlink()
    pem = "-----BEGIN " + "PRIVATE KEY-----" + "\nMIIE\n" + "-----END " + "PRIVATE KEY-----" + "\n"
    (repo / "deploy/kong/leak.pem").write_text(pem, encoding="utf-8")
    expect_failure(repo, "private_key_block")


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda c: c.update(cache_tokens_salt="synthetic-salt-value"), "cache_tokens_salt through the vault"),
    (lambda c: c.update(leeway=900), "leeway exceeds the bound"),
    (lambda c: c.update(cache_ttl=86400), "cache_ttl exceeds the bound"),
    (lambda c: c.update(anonymous="00000000-0000-0000-0000-000000000000"), "anonymous consumer"),
    (lambda c: c.update(audience=["*"]), "non-wildcard audience|source audience"),
    (lambda c: c.update(auth_methods=["bearer", "password"]), "only bearer authentication"),
])
def test_unsafe_openid_connect_settings_fail(repo, mutate, match):
    document = read_yaml(repo, CONTROL_PLANE)
    oidc = next(p for p in document["services"][0]["plugins"] if p["name"] == "openid-connect")
    mutate(oidc["config"])
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, match)


def test_ungoverned_log_plugin_requires_redaction(repo):
    foundation = read_json(repo, FOUNDATION)
    foundation["plugins"].append({
        "plugin": "http-log", "kind": "bundled", "authentication": False, "priority": 12, "allowedScopes": ["ROUTE"],
        "owner": "x", "purpose": "x", "securityImpact": "HIGH", "orderingDependency": "x", "environments": ["production"],
        "configurationSources": ["deploy/kong/control-plane.yml"],
    })
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "governed without credential redaction")


# --------------------------------------------------------------------------- post-#105 negative matrix


def _first_v2_route(document: dict) -> dict:
    return document["services"][0]["routes"][0]


def _oidc(route: dict) -> dict:
    return next(p for p in route["plugins"] if p["name"] == "openid-connect")["config"]


def test_reintroducing_an_8080_shared_edge_upstream_fails(repo):
    document = read_yaml(repo, PROD_YML)
    document["services"][0]["port"] = 8080
    write_yaml(repo, PROD_YML, document)
    expect_failure(repo, "declares port=8080 but registry says 8095")


def test_reintroducing_the_retired_appolon_alias_fails(repo):
    document = read_yaml(repo, PROD_YML)
    document["services"][0].update(host="appolon-middleware-integration-api", port=8080)
    write_yaml(repo, PROD_YML, document)
    foundation = read_json(repo, FOUNDATION)
    service = next(s for s in foundation["services"] if s["serviceId"] == "middleware-integration-api")
    service["upstream"].update(host="appolon-middleware-integration-api", port=8080)
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "retired Middleware alias")
    # and the alias may not be quietly re-labelled as transitional
    foundation = read_json(BASE["root"], FOUNDATION)
    alias = next(a for a in foundation["boundaryRules"]["middlewareUpstreamAliases"] if a["host"] == "appolon-middleware-integration-api")
    alias["role"] = "TRANSITIONAL_N8N_AND_PROVIDER_CONTROL"
    assert validator.m1_dependency_status(foundation, repo)["state"] == "M1_DEPENDENCY_PENDING"


def test_v2_route_without_access_class_or_profile_fails(repo):
    policy = read_json(repo, POLICY)
    policy["routes"] = [r for r in policy["routes"] if r["routeId"] != "middleware-check-automation-policy"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "disagree on the route set")
    policy = read_json(BASE["root"], POLICY)
    del policy_entry(policy, "middleware-check-automation-policy")["authenticationProfile"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "lacks authenticationProfile")


@pytest.mark.parametrize(("path", "issuer", "match"), [
    (PROD_YML, STG_ISSUER, "production requires"),
    (STG_YML, PROD_ISSUER, "staging requires"),
    (PROD_YML, "https://auth.evil.example/realms/codestra", "production requires"),
])
def test_wrong_issuer_in_a_generated_manifest_fails(repo, path, issuer, match):
    document = read_yaml(repo, path)
    for route in document["services"][0]["routes"]:
        _oidc(route)["issuer"] = issuer + "/.well-known/openid-configuration"
    write_yaml(repo, path, document)
    expect_failure(repo, match)


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda c: c.update(audience=["wrong-api"]), "desired sources disagree|source audience"),
    (lambda c: c.update(audience=["*"]), "non-wildcard audience|desired sources disagree"),
    (lambda c: c.pop("scopes_required"), "at least one explicit scope|desired sources disagree"),
    (lambda c: c.update(scopes_required=["*"]), "at least one explicit scope|desired sources disagree"),
    (lambda c: c.pop("cache_tokens_salt"), "cache_tokens_salt through the vault"),
    (lambda c: c.update(cache_tokens_salt="synthetic-literal-salt"), "cache_tokens_salt through the vault"),
    (lambda c: c.update(anonymous="00000000-0000-0000-0000-000000000000"), "anonymous consumer"),
    (lambda c: c.update(leeway=3600), "bounded identity cache and rediscovery required"),
])
def test_v2_openid_connect_downgrades_fail(repo, mutate, match):
    document = read_yaml(repo, PROD_YML)
    mutate(_oidc(_first_v2_route(document)))
    write_yaml(repo, PROD_YML, document)
    expect_failure(repo, match)


def test_wrong_calling_client_in_the_generated_guard_or_the_policy_fails(repo):
    document = read_yaml(repo, PROD_YML)
    route = _first_v2_route(document)
    guard = next(p for p in route["plugins"] if p["name"] == "post-function")["config"]
    guard["access"] = [guard["access"][0].replace('local expected_azp = "n8n-automation"', 'local expected_azp = "someone-else"')]
    write_yaml(repo, PROD_YML, document)
    expect_failure(repo, "desired sources disagree.*expected_azp|contractExpectedAzp")
    write_yaml(repo, PROD_YML, read_yaml(BASE["root"], PROD_YML))
    policy = read_json(BASE["root"], POLICY)
    policy_entry(policy, "middleware-check-automation-policy")["contractExpectedAzp"] = "someone-else"
    write_json(repo, POLICY, policy)
    expect_failure(repo, "contractExpectedAzp 'someone-else' != contracted/forwarded azp")


def test_wildcard_route_in_the_canonical_contract_fails(repo):
    canonical = read_json(repo, CANONICAL)
    canonical["contractRoutes"][0]["paths"] = ["/*"]
    write_json(repo, CANONICAL, canonical)
    document = read_yaml(repo, PROD_YML)
    _first_v2_route(document)["paths"] = ["/*"]
    write_yaml(repo, PROD_YML, document)
    expect_failure(repo, "wildcard paths are forbidden|CATCH_ALL_PATH")


def test_denied_alias_given_an_upstream_fails(repo):
    document = read_yaml(repo, PROD_YML)
    moved = document["routes"].pop(0)
    document["services"][0]["routes"].append(moved)
    write_yaml(repo, PROD_YML, document)
    expect_failure(repo, "binds a service but the registry declares none|GATEWAY_TERMINATED|must be gateway-terminated")
    canonical = read_json(BASE["root"], CANONICAL)
    canonical["deniedRoutes"][0]["serviceHost"] = "middleware-integration-api"
    write_json(repo, CANONICAL, canonical)
    write_yaml(repo, PROD_YML, read_yaml(BASE["root"], PROD_YML))
    expect_failure(repo, "must be a 404 with no upstream")


@pytest.mark.parametrize(("mutate_yaml", "mutate_canonical", "match"), [
    (lambda d: d["routes"][0]["plugins"][0]["config"].update(status_code=200), None, "must terminate with 404"),
    (lambda d: d["routes"][0]["plugins"].append({"name": "request-transformer", "config": {}}), None, "request-termination only|desired sources disagree"),
    (None, lambda c: c["deniedRoutes"][0].update(statusCode=302), "must be a 404 with no upstream"),
])
def test_denied_alias_that_stops_being_a_404_fails(repo, mutate_yaml, mutate_canonical, match):
    if mutate_yaml:
        document = read_yaml(repo, PROD_YML)
        mutate_yaml(document)
        write_yaml(repo, PROD_YML, document)
    if mutate_canonical:
        canonical = read_json(repo, CANONICAL)
        mutate_canonical(canonical)
        write_json(repo, CANONICAL, canonical)
    expect_failure(repo, match)


def test_unknown_source_and_unknown_route_fail(repo):
    (repo / "config/kong-surprise-routes.v1.json").write_text("{}\n", encoding="utf-8")
    expect_failure(repo, "unregistered Kong source files.*kong-surprise-routes")
    (repo / "config/kong-surprise-routes.v1.json").unlink()
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "middleware-list-callbacks")
    entry["bindings"][0]["route"] = "middleware-list-callbacks-v3"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "does not declare route middleware-list-callbacks-v3|undocumented routes in config/kong-canonical-middleware-routes.json")


def test_duplicate_canonical_authority_and_undeclared_overlap_fail(repo):
    foundation = read_json(repo, FOUNDATION)
    original = next(r for r in foundation["routes"] if r["routeId"] == "middleware-list-callbacks")
    duplicate = json.loads(json.dumps(original))
    duplicate["routeId"] = "middleware-list-callbacks-duplicate"
    foundation["routes"].append(duplicate)
    write_json(repo, FOUNDATION, foundation)
    policy = read_json(repo, POLICY)
    item = json.loads(json.dumps(policy_entry(policy, "middleware-list-callbacks")))
    item["routeId"] = "middleware-list-callbacks-duplicate"
    policy["routes"].append(item)
    write_json(repo, POLICY, policy)
    expect_failure(repo, "undeclared route overlap.*middleware-list-callbacks")
    foundation = read_json(BASE["root"], FOUNDATION)
    foundation["precedence"]["knownConflicts"] = [
        c for c in foundation["precedence"]["knownConflicts"] if c["right"] != "middleware-create-callback"]
    write_json(repo, FOUNDATION, foundation)
    write_json(repo, POLICY, read_json(BASE["root"], POLICY))
    expect_failure(repo, "undeclared route overlap.*codestra-callback-control vs middleware-create-callback")


def test_mixing_production_and_staging_sources_fails(repo):
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "middleware-list-callbacks@staging")
    entry["bindings"] = [{"source": PROD_YML, "route": "middleware-list-callbacks", "role": "DESIRED"}]
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "is a production source but the route is staging|undocumented routes in config/staging/kong-middleware-routes.staging.yml")


@pytest.mark.parametrize(("path", "mutate", "match"), [
    (FOUNDATION, lambda d: d.update(runtimeApplyAuthorized=True), "must remain source-only"),
    (POLICY, lambda d: d.update(runtimeApplyAuthorized=True), "source-only v1 policy"),
    (PROFILES, lambda d: d.update(runtimeApplyAuthorized=True), "source-only v1 catalogue"),
    (AUTHORITY, lambda d: d.update(runtime_apply_authorized=True), "runtime_apply_authorized"),
    (AUTHORITY, lambda d: d.update(provider_effects_enabled=True), "provider_effects_enabled"),
])
def test_runtime_apply_or_provider_effects_cannot_be_authorized(repo, path, mutate, match):
    document = read_json(repo, path)
    mutate(document)
    write_json(repo, path, document)
    expect_failure(repo, match)
