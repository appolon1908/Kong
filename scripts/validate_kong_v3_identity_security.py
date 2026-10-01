#!/usr/bin/env python3
"""Validate PAS-148 Kong V3 identity, caller and API-security authority.

This validator is source-only. It never contacts Kong, Keycloak, Middleware,
Redis, Caddy, or a provider and cannot authorize a runtime apply.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROFILES_PATH = ROOT / "config" / "kong-authentication-profiles.v1.json"
POLICY_PATH = ROOT / "config" / "kong-access-policy.v1.json"

EXPECTED_MIDDLEWARE_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
EXPECTED_MIDDLEWARE_COMMIT = "bd406a6508c8095a3f23b35149a2eebcb94c94c6"
EXPECTED_IDENTITY_SOURCE_COMMIT = "45a487d71a516ae3039b00c250752897469ffe7a"
EXPECTED_PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
EXPECTED_STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
EXPECTED_MIDDLEWARE_AUDIENCE = "middleware-api"
EXPECTED_COUNTS = {"shared_edge": 105, "denied": 10, "private_only": 2}
EXPECTED_CALLERS = {
    "none",
    "all_declared_clients",
    "approval_job_family_client_only",
    "authorized-provisioning-client",
    "browser-session",
    "callback-ui",
    "command_family_client_only",
    "command_prefix_client_only",
    "github-app",
    "job_family_client_only",
    "middleware-worker",
    "n8n-automation",
    "n8n-operations-automation",
    "observability-collector",
    "odoo-integration",
    "platform-command-client",
    "platform-operator",
    "production-operator",
}
EXPECTED_PRIVILEGED_SCOPES = {
    "platform.command",
    "platform.command.read",
    "platform.command.replay",
}
EXPECTED_CALLER_CLASSES = {
    "CONCRETE_SERVICE_CLIENT",
    "CONCRETE_HUMAN_CLIENT",
    "CLIENT_FAMILY",
    "SYMBOLIC_RUNTIME_SELECTOR",
}
EXPECTED_NEGATIVE_DIMENSIONS = {
    "issuer",
    "audience",
    "azp",
    "scope",
    "role",
    "tenant",
    "mfa",
    "grant",
    "expiry",
    "replay",
    "identity-header-spoofing",
}
REQUIRED_STRIP_HEADERS = {
    "X-User-ID",
    "X-Username",
    "X-Email",
    "X-Roles",
    "X-Scopes",
    "X-Consumer-ID",
    "X-Consumer-Username",
    "X-Credential-Identifier",
    "X-Anonymous-Consumer",
    "X-Authenticated-UserID",
    "X-Authenticated-User",
    "X-Authenticated-Client",
    "X-Authenticated-Subject",
    "X-Authenticated-Tenant",
    "X-Authenticated-Campaign",
    "X-Authenticated-Role",
    "X-Authenticated-Email",
    "X-Codestra-Tenant",
    "X-Codestra-Scopes",
    "X-Codestra-Gateway-Secret",
    "X-Internal-Service",
    "X-Admin",
    "X-Codestra-Contract-Operation",
    "X-Codestra-Expected-Azp",
    "X-Codestra-Required-Scope",
}
REPLAY_OPERATION = "replay_operation_platform_v1_operations__operation_id__replay_post"
REPLAY_PATH = "/platform/v1/operations/{operation_id}/replay"


class IdentitySecurityError(ValueError):
    """The V3 identity/security contract is incomplete or unsafe."""


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise IdentitySecurityError(f"{path} must contain a JSON object")
    return value


def canonical_digest(document: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_caller(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], str):
        return value[0]
    raise IdentitySecurityError(f"unreviewed caller selector shape: {value!r}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentitySecurityError(message)


def validate_profiles(profiles: dict[str, Any]) -> dict[str, Any]:
    require(profiles.get("schema") == "codestra.kong.authentication-profiles.v1", "wrong authentication-profile schema")
    require(profiles.get("runtimeApplyAuthorized") is False, "authentication profiles must remain source-only")
    authority = profiles.get("v3CallerAuthority")
    require(isinstance(authority, dict), "missing v3CallerAuthority")
    require(authority.get("runtimeApplyAuthorized") is False, "V3 caller authority must not authorize runtime apply")

    middleware = authority.get("middleware", {})
    require(middleware.get("commit") == EXPECTED_MIDDLEWARE_COMMIT, "Middleware commit pin drift")
    require(middleware.get("routeContractSha256") == EXPECTED_MIDDLEWARE_DIGEST, "Middleware route digest drift")
    require(middleware.get("routeCount") == 117, "Middleware route count drift")

    keycloak = authority.get("keycloak", {})
    require(keycloak.get("commit") == EXPECTED_IDENTITY_SOURCE_COMMIT, "Keycloak identity commit pin drift")

    token = authority.get("tokenPolicy", {})
    require(token.get("productionIssuer") == EXPECTED_PRODUCTION_ISSUER, "production issuer drift")
    require(token.get("stagingIssuer") == EXPECTED_STAGING_ISSUER, "staging issuer drift")
    require(token.get("maximumAccessTokenLifetimeSeconds") == 300, "access tokens must be <=300s")
    require(token.get("serviceGrantType") == "client_credentials", "service grant must be client_credentials")
    require(token.get("humanGrantType") == "authorization_code", "human grant must be authorization_code")
    require(token.get("humanPkceRequired") is True, "human PKCE must be required")
    require(token.get("privilegedHumanMfaRequired") is True, "privileged human MFA must be required")
    require(token.get("wildcardCallerSelectorsAllowed") is False, "wildcard callers must be forbidden")
    require(token.get("wildcardScopesAllowed") is False, "wildcard scopes must be forbidden")
    require(set(token.get("privilegedScopes", [])) == EXPECTED_PRIVILEGED_SCOPES, "privileged scope set drift")
    require(set(token.get("privilegedRoles", [])) == {"platform-operator"}, "privileged role set drift")

    callers = authority.get("callers", {})
    require(set(callers) == EXPECTED_CALLERS, "caller catalogue is not the exact 18-selector authority")
    require(authority.get("callerSelectorCount") == 18, "callerSelectorCount must be 18")
    require(authority.get("unknownCallerIdentities") == 0, "UNKNOWN_CALLER_IDENTITIES must be 0")
    require(authority.get("aliases", {}).get("platform-command-family") == "platform-command-client", "platform command alias drift")

    for name, caller in callers.items():
        require(caller.get("class") in EXPECTED_CALLER_CLASSES, f"{name}: invalid caller class")
        require(caller.get("wildcardsAllowed") is False, f"{name}: wildcard caller authority is forbidden")
        require("*" not in name, f"{name}: wildcard selector is forbidden")
        for audience in caller.get("audiences", []):
            require(audience != "*" and "*" not in audience, f"{name}: wildcard audience is forbidden")
        grants = set(caller.get("grantTypes", []))
        actors = set(caller.get("actorKinds", []))
        if caller["class"] == "CONCRETE_SERVICE_CLIENT":
            require(actors == {"service"}, f"{name}: concrete service must be service-only")
            require(grants == {"client_credentials"}, f"{name}: concrete service must use client_credentials")
        if caller["class"] == "CONCRETE_HUMAN_CLIENT":
            require(actors == {"user"}, f"{name}: concrete human must be user-only")
            require(grants == {"authorization_code"}, f"{name}: concrete human must use authorization_code")
            require(caller.get("humanPkceRequired") is True, f"{name}: human PKCE must be required")
        if "service" in actors:
            require("client_credentials" in grants, f"{name}: service actor lacks client_credentials")
        if "user" in actors:
            require("authorization_code" in grants, f"{name}: user actor lacks authorization_code")
            require(caller.get("humanPkceRequired") is True, f"{name}: user actor lacks PKCE")
        if name != "none":
            require(caller.get("maxAccessTokenLifetimeSeconds") == 300, f"{name}: token lifetime must be 300s")

    replay = callers["platform-command-client"].get("replayRequirements", {})
    require(
        replay
        == {
            "scope": "platform.command.replay",
            "role": "platform-operator",
            "mfaRequired": True,
            "actorKind": "user",
            "grantType": "authorization_code",
            "pkceRequired": True,
        },
        "platform command replay boundary drift",
    )

    prod_issuer = profiles.get("issuerProfiles", {}).get("KEYCLOAK_CODESTRA_PRODUCTION", {})
    stg_issuer = profiles.get("issuerProfiles", {}).get("KEYCLOAK_CODESTRA_STAGING", {})
    require(prod_issuer.get("issuer") == EXPECTED_PRODUCTION_ISSUER, "Kong production issuer profile drift")
    require(stg_issuer.get("issuer") == EXPECTED_STAGING_ISSUER, "Kong staging issuer profile drift")
    require(prod_issuer.get("algorithms") == ["RS256"], "production issuer must be RS256 only")
    require(stg_issuer.get("algorithms") == ["RS256"], "staging issuer must be RS256 only")

    middleware_aud = profiles.get("audienceProfiles", {}).get("MIDDLEWARE_API", {})
    require(middleware_aud.get("audience") == EXPECTED_MIDDLEWARE_AUDIENCE, "middleware-api audience drift")
    require("*" not in str(middleware_aud.get("audience")), "wildcard middleware audience forbidden")

    mixed = profiles.get("profiles", {}).get("HUMAN_OR_SERVICE_OIDC_V1", {})
    require(mixed.get("authModes") == ["service-or-user-jwt"], "service-or-user-jwt profile marker missing")
    grants = mixed.get("actorGrantPolicy", {})
    require(grants.get("service", {}).get("grantType") == "client_credentials", "mixed service grant drift")
    require(grants.get("user", {}).get("grantType") == "authorization_code", "mixed user grant drift")
    require(grants.get("user", {}).get("pkceRequired") is True, "mixed user PKCE missing")
    require(mixed.get("privilegedHumanMfaRequired") is True, "mixed privileged MFA missing")
    require(mixed.get("wildcardAzpAllowed") is False, "mixed wildcard azp must be false")
    require(mixed.get("wildcardScopesAllowed") is False, "mixed wildcard scopes must be false")

    propagation = profiles.get("identityPropagationProfiles", {}).get("V3_MIDDLEWARE_STRIP_AND_PROPAGATE", {})
    require(propagation.get("stripsClientIdentity") is True, "V3 propagation must strip client identity")
    require(propagation.get("clientSuppliedIdentityHeadersTrusted") is False, "client identity headers must never be trusted")
    require(REQUIRED_STRIP_HEADERS <= set(propagation.get("strip", [])), "V3 propagation strip list incomplete")
    require(propagation.get("selectorHeadersAreAuthority") is False, "selector headers must not become authority")

    rules = profiles.get("rules", {})
    for key in (
        "wildcardCallerSelectorAllowed",
        "privilegedDefaultGrantAllowed",
        "clientSuppliedIdentityHeadersTrusted",
    ):
        require(rules.get(key) is False, f"{key} must remain false")
    require(rules.get("serviceOrUserJwtRequiresTypedActor") is True, "typed service/user actor policy missing")
    require(rules.get("humanAuthorizationCodePkceRequired") is True, "human PKCE rule missing")
    require(rules.get("privilegedHumanMfaRequired") is True, "privileged MFA rule missing")
    require(rules.get("replayRequiresPlatformOperatorAndMfa") is True, "replay role/MFA rule missing")
    require(rules.get("maximumAccessTokenLifetimeSeconds") == 300, "global V3 token lifetime bound drift")

    fail = profiles.get("failurePolicies", {}).get("FAIL_CLOSED_V1", {})
    require(fail.get("wrongIssuer") == 401, "wrong issuer must fail 401")
    require(fail.get("wrongAudience") == 401, "wrong audience must fail 401")
    require(fail.get("missingRequiredScope") == 403, "missing scope must fail 403")
    require(fail.get("unauthorizedClient") == 403, "unauthorized azp must fail 403")
    require(fail.get("missingRequiredRole") == 403, "missing role must fail 403")
    require(fail.get("missingMfaEvidence") == 403, "missing MFA must fail 403")
    require(fail.get("unauthorizedGrantType") == 403, "wrong grant must fail 403")
    require(fail.get("downgradeToPublic") is False, "auth failures must never downgrade to public")
    return authority


def validate_policy(policy: dict[str, Any], profiles: dict[str, Any]) -> dict[str, Any]:
    require(policy.get("schema") == "codestra.kong.access-policy.v1", "wrong access-policy schema")
    require(policy.get("runtimeApplyAuthorized") is False, "access policy must remain source-only")
    authority = policy.get("v3MiddlewareSecurityAuthority")
    require(isinstance(authority, dict), "missing v3MiddlewareSecurityAuthority")
    require(authority.get("runtimeApplyAuthorized") is False, "V3 security authority must not authorize runtime apply")
    require(authority.get("routeAuthorityOwnedByLaneA") is True, "Lane B must not become route authority")

    source = authority.get("source", {})
    require(source.get("middlewareCommit") == EXPECTED_MIDDLEWARE_COMMIT, "V3 policy Middleware commit drift")
    require(source.get("routeContractSha256") == EXPECTED_MIDDLEWARE_DIGEST, "V3 policy route digest drift")
    require(source.get("routeCount") == 117, "V3 policy route count drift")
    require(source.get("classificationCounts") == EXPECTED_COUNTS, "V3 policy classification counts drift")
    require(source.get("identitySourceCommit") == EXPECTED_IDENTITY_SOURCE_COMMIT, "V3 policy Keycloak commit drift")

    require(authority.get("canonicalMiddlewareAudience") == EXPECTED_MIDDLEWARE_AUDIENCE, "canonical middleware audience drift")
    require(authority.get("callerSelectorCount") == 18, "policy caller selector count must be 18")
    require(set(authority.get("callerSelectors", [])) == EXPECTED_CALLERS, "policy caller selector set drift")
    require(authority.get("unknownCallerIdentities") == 0, "UNKNOWN_CALLER_IDENTITIES must be 0")
    require(set(authority.get("privilegedScopes", [])) == EXPECTED_PRIVILEGED_SCOPES, "policy privileged scopes drift")
    require(authority.get("privilegedDefaultGrantsAllowed") is False, "privileged scopes must never be default grants")

    mixed = authority.get("serviceOrUserJwt", {})
    require(mixed.get("service", {}).get("grantType") == "client_credentials", "service-or-user service grant drift")
    require(mixed.get("user", {}).get("grantType") == "authorization_code", "service-or-user human grant drift")
    require(mixed.get("user", {}).get("pkceRequired") is True, "service-or-user human PKCE missing")
    require(mixed.get("privilegedHumanMfaRequired") is True, "service-or-user privileged MFA missing")
    require(mixed.get("wildcardCallerAllowed") is False, "service-or-user wildcard caller forbidden")
    require(mixed.get("wildcardScopeAllowed") is False, "service-or-user wildcard scope forbidden")

    rows = authority.get("routeSecurity", [])
    require(len(rows) == 117, "routeSecurity must represent all 117 Middleware routes")
    require(len({row.get("operationId") for row in rows}) == 117, "duplicate/missing operationId in routeSecurity")
    require(len({(row.get("method"), row.get("path")) for row in rows}) == 117, "duplicate/missing method+path in routeSecurity")
    counts = {name: sum(row.get("classification") == name for row in rows) for name in EXPECTED_COUNTS}
    require(counts == EXPECTED_COUNTS, "routeSecurity classification counts drift")
    selectors = {row.get("callerSelector") for row in rows}
    require(selectors == EXPECTED_CALLERS, "routeSecurity does not cover exact 18 caller selectors")

    profile_callers = profiles["v3CallerAuthority"]["callers"]
    service_or_user_count = 0
    for row in rows:
        op = row.get("operationId")
        classification = row.get("classification")
        caller = row.get("callerSelector")
        require(caller in profile_callers, f"{op}: unknown caller {caller!r}")
        require(row.get("callerClass") == profile_callers[caller]["class"], f"{op}: caller class drift")

        if classification == "denied":
            require(row.get("auth") == "deny", f"{op}: denied route auth drift")
            require(row.get("requiredScope") is None, f"{op}: denied route cannot require scope")
            require(row.get("kongPublicEdgeEnforcement") is False, f"{op}: denied route cannot proxy through public edge")
            continue

        require(row.get("maximumAccessTokenLifetimeSeconds") == 300, f"{op}: token lifetime must be 300s")
        require(row.get("requiredScope") not in (None, "", "*"), f"{op}: active route scope missing/wildcard")
        require("*" not in str(row.get("audience")), f"{op}: wildcard audience forbidden")
        require(row.get("tenantAuthority", "").startswith("token-claim"), f"{op}: tenant claim must remain authority")

        if classification == "private_only":
            require(row.get("kongPublicEdgeEnforcement") is False, f"{op}: private-only route must stay off public Kong edge")
            continue

        require(row.get("kongPublicEdgeEnforcement") is True, f"{op}: shared edge route missing Kong enforcement")
        required_dims = {"issuer", "audience", "azp", "scope", "tenant", "expiry"}
        require(required_dims <= set(row.get("failClosedDimensions", [])), f"{op}: fail-closed auth matrix incomplete")
        require(row.get("identityPropagationProfile") == "V3_MIDDLEWARE_STRIP_AND_PROPAGATE", f"{op}: spoofing-safe propagation missing")

        if op == REPLAY_OPERATION:
            require(row.get("actorKindsAllowed") == ["user"], "service replay must be denied")
            require(row.get("grantTypesAllowed") == ["authorization_code"], "replay must use authorization_code")

        if row.get("auth") == "service-or-user-jwt":
            service_or_user_count += 1
            actors = set(row.get("actorKindsAllowed", []))
            grants = set(row.get("grantTypesAllowed", []))
            if "service" in actors:
                require("client_credentials" in grants, f"{op}: service actor lacks client_credentials")
            if "user" in actors:
                require("authorization_code" in grants, f"{op}: user actor lacks authorization_code")
                require(row.get("humanPkceRequired") is True, f"{op}: user actor lacks PKCE")
                if row.get("requiredScope") in EXPECTED_PRIVILEGED_SCOPES:
                    require(row.get("humanMfaRequired") is True, f"{op}: privileged human path lacks MFA")

    require(service_or_user_count == 84, f"SERVICE_OR_USER_ROUTES drift: {service_or_user_count}")

    replay = next((row for row in rows if row.get("operationId") == REPLAY_OPERATION), None)
    require(replay is not None, "replay route missing")
    require(replay.get("path") == REPLAY_PATH, "replay path drift")
    require(replay.get("callerSelector") == "platform-command-client", "replay caller drift")
    require(replay.get("actorKindsAllowed") == ["user"], "service replay must be denied")
    require(replay.get("grantTypesAllowed") == ["authorization_code"], "replay must use authorization_code")
    require(replay.get("requiredScope") == "platform.command.replay", "replay scope drift")
    require(replay.get("requiredRealmRole") == "platform-operator", "replay role drift")
    require(replay.get("humanPkceRequired") is True, "replay PKCE missing")
    require(replay.get("humanMfaRequired") is True, "replay MFA missing")
    boundary = replay.get("replayBoundary", {})
    require(boundary.get("serviceReplayAllowed") is False, "service replay must remain false")
    require(boundary.get("requiredRealmRole") == "platform-operator", "replay boundary role drift")
    require(boundary.get("mfaRequired") is True, "replay boundary MFA drift")

    neg = authority.get("negativeAuthMatrix", [])
    dimensions = {row.get("dimension") for row in neg}
    require(dimensions == EXPECTED_NEGATIVE_DIMENSIONS, "negative auth matrix dimensions incomplete")
    for row in neg:
        if row["dimension"] == "identity-header-spoofing":
            require(row.get("expectedAction") == "strip-and-ignore", "spoofed identity headers must be stripped")
        else:
            require(row.get("expectedStatus") in {401, 403}, f"{row['dimension']}: negative case must fail closed")

    spoof = authority.get("headerSpoofingPolicy", {})
    require(spoof.get("clientSuppliedIdentityHeadersTrusted") is False, "spoofed identity headers must not be trusted")
    require(REQUIRED_STRIP_HEADERS <= set(spoof.get("stripBeforeTrustedPropagation", [])), "spoofing strip list incomplete")
    require(spoof.get("tenantHeaderIsSelectorOnly") is True, "tenant header must remain selector-only")
    require(set(policy.get("identityHeaders", {}).get("neverTrustedFromClients", [])) >= REQUIRED_STRIP_HEADERS, "access-policy never-trusted header list incomplete")
    require(policy.get("identityHeaders", {}).get("headerAuthorityAllowed") is False, "header authority must remain false")

    return authority


def validate_external_sources(
    policy_authority: dict[str, Any],
    *,
    middleware_contract: Path | None,
    keycloak_callers: Path | None,
    keycloak_access: Path | None,
) -> None:
    rows = {row["operationId"]: row for row in policy_authority["routeSecurity"]}

    if middleware_contract is not None:
        middleware = load_json(middleware_contract)
        require(canonical_digest(middleware) == EXPECTED_MIDDLEWARE_DIGEST, "external Middleware digest mismatch")
        require(len(middleware.get("routes", [])) == 117, "external Middleware route count mismatch")
        for source in middleware["routes"]:
            op = source["operation_id"]
            require(op in rows, f"external Middleware operation absent from security projection: {op}")
            row = rows[op]
            require(row["method"] == source["method"], f"{op}: method drift vs Middleware")
            require(row["path"] == source["path"], f"{op}: path drift vs Middleware")
            require(row["classification"] == source["classification"], f"{op}: classification drift vs Middleware")
            require(row["auth"] == source["auth"], f"{op}: auth mode drift vs Middleware")
            require(row["audience"] == source["audience"], f"{op}: audience drift vs Middleware")
            require(row["callerSelector"] == normalize_caller(source["calling_client"]), f"{op}: caller drift vs Middleware")
            source_scope = None if source["classification"] == "denied" else source["scope"]
            require(row["requiredScope"] == source_scope, f"{op}: scope drift vs Middleware")

    if keycloak_callers is not None:
        callers = load_json(keycloak_callers)
        require(callers.get("middleware", {}).get("targetRouteContractSha256") == EXPECTED_MIDDLEWARE_DIGEST, "Keycloak caller authority route digest drift")
        require(set(callers.get("callers", {})) == EXPECTED_CALLERS, "Keycloak caller set drift")
        # The Kong catalogue intentionally copies the richer caller definitions; compare exact caller records.
        profiles = load_json(PROFILES_PATH)
        require(callers.get("callers") == profiles["v3CallerAuthority"]["callers"], "Kong caller catalogue differs from pinned Keycloak caller authority")
        require(callers.get("tokenPolicy") == profiles["v3CallerAuthority"]["tokenPolicy"], "Kong token policy differs from pinned Keycloak authority")

    if keycloak_access is not None:
        access = load_json(keycloak_access)
        require(access.get("source", {}).get("sha256") == EXPECTED_MIDDLEWARE_DIGEST, "Keycloak API access digest drift")
        access_rows = {row["operationId"]: row for row in access.get("routes", [])}
        require(set(access_rows) == set(rows), "Keycloak/Kong operation set drift")
        for op, expected in access_rows.items():
            row = rows[op]
            require(row["requiredScope"] == expected.get("requiredScope"), f"{op}: scope drift vs Keycloak")
            require(row["requiredRealmRole"] == expected.get("requiredRealmRole"), f"{op}: role drift vs Keycloak")


def validate(
    profiles: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    *,
    middleware_contract: Path | None = None,
    keycloak_callers: Path | None = None,
    keycloak_access: Path | None = None,
) -> dict[str, Any]:
    profiles = profiles or load_json(PROFILES_PATH)
    policy = policy or load_json(POLICY_PATH)
    caller_authority = validate_profiles(profiles)
    security_authority = validate_policy(policy, profiles)
    validate_external_sources(
        security_authority,
        middleware_contract=middleware_contract,
        keycloak_callers=keycloak_callers,
        keycloak_access=keycloak_access,
    )
    return {
        "callerAuthority": caller_authority,
        "securityAuthority": security_authority,
    }


def validate_generated_manifests(root: Path = ROOT) -> None:
    """Bind deployable identity gates to the pinned Middleware route contract."""
    spec = importlib.util.spec_from_file_location(
        "kong_middleware_route_generator", ROOT / "scripts/generate_middleware_routes.py"
    )
    require(spec is not None and spec.loader is not None, "route generator unavailable")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    route_plugins, safe_name = generator.route_plugins, generator.safe_name

    contract = load_json(root / "config/middleware-public-api-route-contract.v1.json")
    require(canonical_digest(contract) == EXPECTED_MIDDLEWARE_DIGEST, "Middleware route contract digest drift")
    shared = [row for row in contract["routes"] if row["classification"] == "shared_edge"]
    for relative, issuer in (
        ("config/kong-middleware-routes.production.yml", EXPECTED_PRODUCTION_ISSUER),
        ("config/staging/kong-middleware-routes.staging.yml", EXPECTED_STAGING_ISSUER),
    ):
        try:
            manifest = yaml.safe_load((root / relative).read_text())
            routes = manifest["services"][0]["routes"]
        except (OSError, KeyError, IndexError, TypeError, yaml.YAMLError) as exc:
            raise IdentitySecurityError(f"{relative}: invalid generated manifest") from exc
        actual = {route.get("name"): route for route in routes}
        require(len(actual) == len(routes) == len(shared), f"{relative}: shared route set drift")
        require(set(actual) == {safe_name(row["operation_id"]) for row in shared},
                f"{relative}: shared route set drift")
        for row in shared:
            name = safe_name(row["operation_id"])
            plugins = actual[name].get("plugins", [])
            require(isinstance(plugins, list), f"{relative}: {name} missing identity plugins")
            identity_names = {"pre-function", "openid-connect", "post-function"}
            for expected in route_plugins(row, issuer):
                if expected["name"] not in identity_names:
                    continue
                matching = [plugin for plugin in plugins if plugin.get("name") == expected["name"]]
                require(matching == [expected], f"{relative}: {name} {expected['name']} identity gate drift")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--middleware-contract", type=Path)
    parser.add_argument("--keycloak-callers", type=Path)
    parser.add_argument("--keycloak-access", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = validate(
        middleware_contract=args.middleware_contract,
        keycloak_callers=args.keycloak_callers,
        keycloak_access=args.keycloak_access,
    )
    validate_generated_manifests()
    authority = result["securityAuthority"]
    rows = authority["routeSecurity"]
    print("KONG_V3_IDENTITY_SECURITY=PASS")
    print(f"MIDDLEWARE_ROUTE_DIGEST={EXPECTED_MIDDLEWARE_DIGEST}")
    print(f"ROUTES={len(rows)}")
    print(f"SHARED_EDGE={sum(r['classification']=='shared_edge' for r in rows)}")
    print(f"DENIED={sum(r['classification']=='denied' for r in rows)}")
    print(f"PRIVATE_ONLY={sum(r['classification']=='private_only' for r in rows)}")
    print(f"CALLER_SELECTORS={authority['callerSelectorCount']}")
    print(f"UNKNOWN_CALLER_IDENTITIES={authority['unknownCallerIdentities']}")
    print(f"SERVICE_OR_USER_ROUTES={sum(r['auth']=='service-or-user-jwt' for r in rows)}")
    print("ISSUER_AUDIENCE_AZP_SCOPE_NEGATIVE_MATRIX=PASS")
    print("SERVICE_OR_USER_JWT_MATRIX=PASS")
    print("REPLAY_NEGATIVE_PATH=PASS")
    print("HEADER_SPOOFING_PREVENTION=PASS")
    print("PRIVILEGED_DEFAULT_GRANTS=0")
    print("RUNTIME_APPLY_AUTHORIZED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
