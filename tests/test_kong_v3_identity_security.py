from __future__ import annotations

import copy
import importlib.util
import sys
import shutil

import yaml
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_kong_v3_identity_security.py"
SPEC = importlib.util.spec_from_file_location("kong_v3_identity_security", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


@pytest.fixture
def documents() -> tuple[dict, dict]:
    return (
        validator.load_json(validator.PROFILES_PATH),
        validator.load_json(validator.POLICY_PATH),
    )


def expect_failure(profiles: dict, policy: dict, match: str) -> None:
    with pytest.raises(validator.IdentitySecurityError, match=match):
        validator.validate(profiles=profiles, policy=policy)


def replay_row(policy: dict) -> dict:
    rows = policy["v3MiddlewareSecurityAuthority"]["routeSecurity"]
    return next(row for row in rows if row["operationId"] == validator.REPLAY_OPERATION)


def test_final_identity_security_authority_passes_and_covers_all_117_routes(documents):
    profiles, policy = documents
    result = validator.validate(profiles=profiles, policy=policy)
    authority = result["securityAuthority"]
    rows = authority["routeSecurity"]

    assert len(rows) == 117
    assert authority["source"]["classificationCounts"] == {
        "shared_edge": 105,
        "denied": 10,
        "private_only": 2,
    }
    assert authority["callerSelectorCount"] == 18
    assert authority["unknownCallerIdentities"] == 0
    assert sum(row["auth"] == "service-or-user-jwt" for row in rows) == 84
    assert set(authority["callerSelectors"]) == validator.EXPECTED_CALLERS
    assert authority["privilegedDefaultGrantsAllowed"] is False


def test_exact_issuer_and_middleware_audience_are_fail_closed(documents):
    profiles, policy = documents

    wrong_issuer = copy.deepcopy(profiles)
    wrong_issuer["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"]["issuer"] = (
        "https://auth-staging.codestra.co/realms/codestra"
    )
    expect_failure(wrong_issuer, policy, "production issuer profile drift")

    wrong_audience = copy.deepcopy(profiles)
    wrong_audience["audienceProfiles"]["MIDDLEWARE_API"]["audience"] = "wrong-api"
    expect_failure(wrong_audience, policy, "middleware-api audience drift")

    wildcard_audience = copy.deepcopy(profiles)
    wildcard_audience["audienceProfiles"]["MIDDLEWARE_API"]["audience"] = "*"
    expect_failure(wildcard_audience, policy, "middleware-api audience drift|wildcard")


def test_unknown_or_wildcard_caller_authority_fails(documents):
    profiles, policy = documents

    unknown = copy.deepcopy(profiles)
    unknown["v3CallerAuthority"]["callers"]["unreviewed-client"] = {
        "class": "CONCRETE_SERVICE_CLIENT",
        "actorKinds": ["service"],
        "grantTypes": ["client_credentials"],
        "authModes": ["service-or-user-jwt"],
        "audiences": ["middleware-api"],
        "wildcardsAllowed": False,
        "maxAccessTokenLifetimeSeconds": 300,
    }
    expect_failure(unknown, policy, "exact 18-selector authority")

    wildcard = copy.deepcopy(profiles)
    wildcard["v3CallerAuthority"]["callers"]["n8n-automation"]["wildcardsAllowed"] = True
    expect_failure(wildcard, policy, "wildcard caller authority")


def test_service_or_user_jwt_human_and_service_boundaries_fail_closed(documents):
    profiles, policy = documents

    service_grant = copy.deepcopy(profiles)
    service_grant["profiles"]["HUMAN_OR_SERVICE_OIDC_V1"]["actorGrantPolicy"]["service"][
        "grantType"
    ] = "authorization_code"
    expect_failure(service_grant, policy, "mixed service grant drift")

    human_grant = copy.deepcopy(profiles)
    human_grant["profiles"]["HUMAN_OR_SERVICE_OIDC_V1"]["actorGrantPolicy"]["user"][
        "grantType"
    ] = "client_credentials"
    expect_failure(human_grant, policy, "mixed user grant drift")

    no_pkce = copy.deepcopy(policy)
    target = next(
        row
        for row in no_pkce["v3MiddlewareSecurityAuthority"]["routeSecurity"]
        if row["auth"] == "service-or-user-jwt"
        and "user" in row["actorKindsAllowed"]
    )
    target["humanPkceRequired"] = False
    expect_failure(profiles, no_pkce, "user actor lacks PKCE")


def test_scope_and_privileged_default_grant_downgrades_fail(documents):
    profiles, policy = documents

    wildcard_scope = copy.deepcopy(policy)
    target = next(
        row
        for row in wildcard_scope["v3MiddlewareSecurityAuthority"]["routeSecurity"]
        if row["classification"] == "shared_edge"
    )
    target["requiredScope"] = "*"
    expect_failure(profiles, wildcard_scope, "scope missing/wildcard")

    defaults = copy.deepcopy(policy)
    defaults["v3MiddlewareSecurityAuthority"]["privilegedDefaultGrantsAllowed"] = True
    expect_failure(profiles, defaults, "never be default grants")


def test_replay_requires_user_authorization_code_pkce_role_and_mfa(documents):
    profiles, policy = documents
    replay = replay_row(policy)
    assert replay["actorKindsAllowed"] == ["user"]
    assert replay["grantTypesAllowed"] == ["authorization_code"]
    assert replay["requiredScope"] == "platform.command.replay"
    assert replay["requiredRealmRole"] == "platform-operator"
    assert replay["humanPkceRequired"] is True
    assert replay["humanMfaRequired"] is True
    assert replay["replayBoundary"]["serviceReplayAllowed"] is False

    service_replay = copy.deepcopy(policy)
    replay_row(service_replay)["actorKindsAllowed"] = ["service"]
    expect_failure(profiles, service_replay, "service replay must be denied")

    no_role = copy.deepcopy(policy)
    replay_row(no_role)["requiredRealmRole"] = None
    expect_failure(profiles, no_role, "replay role drift")

    no_mfa = copy.deepcopy(policy)
    replay_row(no_mfa)["humanMfaRequired"] = False
    expect_failure(profiles, no_mfa, "privileged human path lacks MFA|replay MFA missing")


def test_wrong_tenant_policy_and_missing_fail_closed_dimension_fail(documents):
    profiles, policy = documents

    wrong_tenant = copy.deepcopy(policy)
    target = next(
        row
        for row in wrong_tenant["v3MiddlewareSecurityAuthority"]["routeSecurity"]
        if row["classification"] == "shared_edge"
    )
    target["tenantAuthority"] = "X-Tenant-ID"
    expect_failure(profiles, wrong_tenant, "tenant claim must remain authority")

    missing_azp = copy.deepcopy(policy)
    target = next(
        row
        for row in missing_azp["v3MiddlewareSecurityAuthority"]["routeSecurity"]
        if row["classification"] == "shared_edge"
    )
    target["failClosedDimensions"].remove("azp")
    expect_failure(profiles, missing_azp, "fail-closed auth matrix incomplete")


def test_spoofable_identity_headers_must_be_stripped_before_propagation(documents):
    profiles, policy = documents
    strip = set(
        profiles["identityPropagationProfiles"]["V3_MIDDLEWARE_STRIP_AND_PROPAGATE"][
            "strip"
        ]
    )
    assert validator.REQUIRED_STRIP_HEADERS <= strip
    assert (
        profiles["identityPropagationProfiles"]["V3_MIDDLEWARE_STRIP_AND_PROPAGATE"][
            "clientSuppliedIdentityHeadersTrusted"
        ]
        is False
    )

    profile_spoof = copy.deepcopy(profiles)
    profile_spoof["identityPropagationProfiles"]["V3_MIDDLEWARE_STRIP_AND_PROPAGATE"][
        "strip"
    ].remove("X-Authenticated-Client")
    expect_failure(profile_spoof, policy, "strip list incomplete")

    policy_spoof = copy.deepcopy(policy)
    policy_spoof["identityHeaders"]["headerAuthorityAllowed"] = True
    expect_failure(profiles, policy_spoof, "header authority must remain false")


def test_negative_auth_matrix_covers_every_required_dimension(documents):
    profiles, policy = documents
    matrix = policy["v3MiddlewareSecurityAuthority"]["negativeAuthMatrix"]
    assert {case["dimension"] for case in matrix} == validator.EXPECTED_NEGATIVE_DIMENSIONS

    missing = copy.deepcopy(policy)
    missing["v3MiddlewareSecurityAuthority"]["negativeAuthMatrix"] = [
        case
        for case in missing["v3MiddlewareSecurityAuthority"]["negativeAuthMatrix"]
        if case["dimension"] != "role"
    ]
    expect_failure(profiles, missing, "negative auth matrix dimensions incomplete")


def test_runtime_apply_cannot_be_enabled(documents):
    profiles, policy = documents

    bad_profiles = copy.deepcopy(profiles)
    bad_profiles["v3CallerAuthority"]["runtimeApplyAuthorized"] = True
    expect_failure(bad_profiles, policy, "must not authorize runtime apply")

    bad_policy = copy.deepcopy(policy)
    bad_policy["v3MiddlewareSecurityAuthority"]["runtimeApplyAuthorized"] = True
    expect_failure(profiles, bad_policy, "must not authorize runtime apply")


@pytest.mark.parametrize("environment,plugin_name,field", [
    ("production", "openid-connect", "roles_required"),
    ("production", "openid-connect", "groups_required"),
    ("staging", "post-function", "access"),
])
def test_generated_identity_gate_drift_fails(tmp_path, environment, plugin_name, field):
    contract = Path("config/middleware-public-api-route-contract.v1.json")
    target = tmp_path / contract
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / contract, target)
    for env, relative in (
        ("production", "config/kong-middleware-routes.production.yml"),
        ("staging", "config/staging/kong-middleware-routes.staging.yml"),
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
        if env == environment:
            data = yaml.safe_load(target.read_text())
            route = next(route for route in data["services"][0]["routes"]
                         if any(plugin["name"] == plugin_name and field in plugin["config"]
                                for plugin in route["plugins"]))
            plugin = next(plugin for plugin in route["plugins"] if plugin["name"] == plugin_name)
            plugin["config"].pop(field)
            target.write_text(yaml.safe_dump(data, sort_keys=False))
    with pytest.raises(validator.IdentitySecurityError, match="identity gate drift"):
        validator.validate_generated_manifests(tmp_path)


def test_generated_identity_gates_match_contract():
    validator.validate_generated_manifests()
