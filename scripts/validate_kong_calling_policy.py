#!/usr/bin/env python3
"""Validate Kong calling policy and contract lock without applying runtime state."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / ".codestra/calling-contract.lock.json"
POLICY_PATH = ROOT / "config/kong-calling-routes.v1.json"
LUA_PATH = ROOT / "deploy/kong/calling-policy.lua"
RENDERER_PATH = ROOT / "scripts/render_kong_calling_routes.py"

DIGEST = "b39cdffe56a8185c91174228f0423df68b1137f34875f6ee52f9914f904bf724"
AUTHORITY = "appolon1908-hue/codestra-production-platform#257"

EXPECTED_LOCK = {
    "version": "1.0.0",
    "sha256": DIGEST,
    "authority": AUTHORITY,
    "role": "api_policy",
    "external_effects_enabled": False,
}

EXPECTED_ROUTES = {
    "codestra-calling-command-submit": {
        "path": "/v1/telephony/commands",
        "methods": ["POST"],
        "requiredScope": "telephony:command",
        "idempotencyRequired": True,
        "ratePerMinute": 60,
    },
    "codestra-calling-operation-read": {
        "path": "~/v1/telephony/operations/[0-9a-fA-F-]{36}$",
        "methods": ["GET"],
        "requiredScope": "telephony:status",
        "idempotencyRequired": False,
        "ratePerMinute": 240,
    },
    "codestra-calling-operation-cancel": {
        "path": "~/v1/telephony/operations/[0-9a-fA-F-]{36}/cancel$",
        "methods": ["POST"],
        "requiredScope": "telephony:command",
        "idempotencyRequired": True,
        "ratePerMinute": 60,
    },
    "codestra-calling-operation-reconcile": {
        "path": "~/v1/telephony/operations/[0-9a-fA-F-]{36}/reconcile$",
        "methods": ["POST"],
        "requiredScope": "telephony:status",
        "idempotencyRequired": True,
        "ratePerMinute": 30,
    },
    "codestra-realtime-session-create": {
        "path": "/api/v1/realtime/sessions",
        "methods": ["POST"],
        "requiredScope": "realtime:session:create",
        "idempotencyRequired": True,
        "ratePerMinute": 30,
    },
}


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs)


def require_exact_mapping(document: object, expected: dict[str, Any], label: str) -> dict[str, Any]:
    if type(document) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    if set(document) != set(expected):
        raise ValueError(f"{label} fields do not match the canonical schema")
    for key, value in expected.items():
        if type(document[key]) is not type(value) or document[key] != value:
            raise ValueError(f"{label}.{key} mismatch")
    return document


def validate_lock(document: object) -> None:
    lock = require_exact_mapping(document, EXPECTED_LOCK, "calling contract lock")
    if not re.fullmatch(r"[0-9a-f]{64}", lock["sha256"]):
        raise ValueError("calling contract digest is malformed")
    if type(lock["external_effects_enabled"]) is not bool:
        raise ValueError("external_effects_enabled must be a JSON boolean")


def validate_policy(document: object, lua_source: str) -> None:
    if type(document) is not dict:
        raise ValueError("calling policy must be a JSON object")
    policy = document

    required_top = {
        "schema",
        "authority",
        "contractVersion",
        "contractDigest",
        "status",
        "runtimeApplyAuthorized",
        "host",
        "service",
        "identity",
        "commonPolicy",
        "routes",
        "websocket",
        "privateBoundary",
        "failClosed",
    }
    if set(policy) != required_top:
        raise ValueError("calling policy top-level fields do not match the canonical schema")
    if policy["schema"] != "codestra.kong.calling-routes.v1":
        raise ValueError("calling policy schema mismatch")
    if policy["authority"] != AUTHORITY or policy["contractDigest"] != DIGEST:
        raise ValueError("calling policy authority or digest mismatch")
    if policy["contractVersion"] != "1.0.0":
        raise ValueError("calling policy version mismatch")
    if policy["status"] != "SOURCE_CANDIDATE_NO_RUNTIME_APPLY":
        raise ValueError("calling policy status mismatch")
    if type(policy["runtimeApplyAuthorized"]) is not bool or policy["runtimeApplyAuthorized"] is not False:
        raise ValueError("runtime application must remain explicitly unauthorized")
    if policy["host"] != "telephony.internal.invalid":
        raise ValueError("private telephony host mismatch")

    service = policy["service"]
    expected_service = {
        "name": "codestra-calling-api",
        "protocol": "http",
        "host": "codestra-middleware-integration-api-1",
        "port": 8095,
        "connectTimeoutMs": 3000,
        "readTimeoutMs": 30000,
        "writeTimeoutMs": 30000,
    }
    require_exact_mapping(service, expected_service, "calling service")

    identity = policy["identity"]
    if identity["issuer"] != "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration":
        raise ValueError("OIDC issuer mismatch")
    if identity["audience"] != "middleware-api":
        raise ValueError("OIDC audience mismatch")
    if identity["authMethods"] != ["bearer"] or identity["consumerClaim"] != "azp":
        raise ValueError("OIDC authentication profile mismatch")
    if identity["tenantClaim"] != "tenant_id" or identity["campaignMembershipClaim"] != "campaign_ids":
        raise ValueError("tenant or campaign claim mismatch")
    stripped = set(identity["stripInboundHeaders"])
    required_stripped = {
        "X-Authenticated-Client",
        "X-Authenticated-Subject",
        "X-Authenticated-Tenant",
        "X-Authenticated-Campaign",
        "X-Authenticated-Role",
    }
    if stripped != required_stripped:
        raise ValueError("identity-header stripping policy mismatch")
    minted = identity["mintedHeaders"]
    if set(minted) != required_stripped - {"X-Authenticated-Role"}:
        raise ValueError("minted identity-header policy mismatch")

    common = policy["commonPolicy"]
    if common["protocols"] != ["http"] or common["httpsRedirectStatusCode"] != 426:
        raise ValueError("HTTPS edge policy mismatch")
    if common["stripPath"] is not False or common["preserveHost"] is not True:
        raise ValueError("route path/host policy mismatch")
    if common["requestBuffering"] is not True or common["responseBuffering"] is not True:
        raise ValueError("request/response buffering policy mismatch")
    if common["correlationHeader"] != "X-Correlation-ID" or common["correlationRequired"] is not True:
        raise ValueError("correlation policy mismatch")
    if common["idempotencyHeader"] != "Idempotency-Key":
        raise ValueError("idempotency header mismatch")
    if common["identityGuardSource"] != "deploy/kong/calling-policy.lua":
        raise ValueError("identity guard source mismatch")
    if common["correlationGuardSource"] != "deploy/kong/correlation-required.lua":
        raise ValueError("correlation guard source mismatch")
    if set(common["requiredPlugins"]) != {
        "openid-connect",
        "pre-function",
        "post-function",
        "correlation-id",
        "rate-limiting",
        "request-size-limiting",
    }:
        raise ValueError("required plugin set mismatch")
    if common["rateLimitPolicy"] != "redis" or common["rateLimitFaultTolerant"] is not False:
        raise ValueError("rate limiting must be shared and fail closed")
    if common["requestBodyLimitMb"] != 1:
        raise ValueError("request body limit mismatch")

    routes = policy["routes"]
    if type(routes) is not list:
        raise ValueError("routes must be a list")
    indexed: dict[str, dict[str, Any]] = {}
    for route in routes:
        if type(route) is not dict or type(route.get("name")) is not str:
            raise ValueError("invalid calling route entry")
        if route["name"] in indexed:
            raise ValueError(f"duplicate calling route: {route['name']}")
        indexed[route["name"]] = route
    if set(indexed) != set(EXPECTED_ROUTES):
        raise ValueError("calling route inventory mismatch")
    for name, expected in EXPECTED_ROUTES.items():
        route = indexed[name]
        for key, value in expected.items():
            if type(route.get(key)) is not type(value) or route.get(key) != value:
                raise ValueError(f"{name}.{key} mismatch")
        if any(method not in {"GET", "POST"} for method in route["methods"]):
            raise ValueError(f"{name} has an unsupported method")
        if route["ratePerMinute"] <= 0:
            raise ValueError(f"{name} rate limit must be positive")
    command = indexed["codestra-calling-command-submit"]
    if command.get("tenantBodyField") != "tenant_id" or command.get("campaignBodyField") != "campaign_id":
        raise ValueError("command tenant/campaign binding mismatch")
    realtime = indexed["codestra-realtime-session-create"]
    if realtime.get("campaignBodyField") != "campaign_id":
        raise ValueError("realtime campaign binding mismatch")

    websocket = policy["websocket"]
    if websocket != {
        "path": "/ws/agent",
        "decision": "BYPASS_KONG_DIRECT_CADDY_TO_WEBSOCKET_GATEWAY",
        "kongRouteForbidden": True,
    }:
        raise ValueError("WebSocket authority decision mismatch")
    private = policy["privateBoundary"]
    if private != {
        "prefixes": ["/internal", "/internal/"],
        "publicKongRouteForbidden": True,
    }:
        raise ValueError("private route boundary mismatch")

    fail_closed = policy["failClosed"]
    expected_statuses = {
        "missingOrInvalidCredentialStatus": 401,
        "missingScopeStatus": 403,
        "missingTenantClaimStatus": 403,
        "crossTenantStatus": 403,
        "unauthorizedCampaignStatus": 403,
        "missingCorrelationStatus": 400,
        "missingIdempotencyStatus": 400,
        "identityGuardIndeterminateStatus": 503,
    }
    require_exact_mapping(fail_closed, expected_statuses, "fail-closed status policy")

    required_lua_markers = {
        "kong.client.get_credential()",
        "kong.client.get_consumer()",
        "telephony:command",
        "telephony:status",
        "realtime:session:create",
        "X-Correlation-ID",
        "Idempotency-Key",
        "X-Authenticated-Tenant",
        "X-Authenticated-Campaign",
        "campaign_ids",
        "cross_tenant_denied",
        "campaign_membership_required",
        "verified_identity_unavailable",
        "/ws/agent",
        "^/internal/?",
    }
    missing_markers = sorted(marker for marker in required_lua_markers if marker not in lua_source)
    if missing_markers:
        raise ValueError(f"calling Lua guard is incomplete: {missing_markers}")
    for name in required_stripped:
        if name not in lua_source:
            raise ValueError(f"calling Lua guard does not strip/mint {name}")
    if "runtimeApplyAuthorized" in lua_source or "LIVE_PSTN_DIALING=true" in lua_source:
        raise ValueError("calling Lua guard must not authorize runtime activation")


def validate_files() -> None:
    validate_lock(parse_json(LOCK_PATH))
    policy = parse_json(POLICY_PATH)
    validate_policy(policy, LUA_PATH.read_text(encoding="utf-8"))
    cells = parse_json(ROOT / "config/codestra-kong-cells.v1.json")
    registry = parse_json(ROOT / "config/codestra-kong-route-registry.v1.json")
    assert isinstance(policy, dict) and isinstance(cells, dict) and isinstance(registry, dict)
    telephony = next(item for item in cells["cells"] if item["id"] == "telephony-private")
    telephony_route = next(item for item in registry["routes"] if item["id"] == "telephony-private")
    if telephony["public_routes"] is not False or telephony["proxy_visibility"] != "PRIVATE_VLAN_ONLY":
        raise ValueError("telephony cell exposure boundary mismatch")
    if policy["host"] != telephony_route["host"]:
        raise ValueError("calling policy conflicts with telephony cell host")
    if not RENDERER_PATH.is_file():
        raise ValueError("executable calling configuration renderer is missing")
    renderer = RENDERER_PATH.read_text(encoding="utf-8")
    for marker in ("def render()", '"openid-connect"', '"post-function"', '"rate-limiting"'):
        if marker not in renderer:
            raise ValueError(f"calling configuration renderer is incomplete: {marker}")


def self_test() -> None:
    validate_files()
    base = parse_json(POLICY_PATH)
    assert type(base) is dict
    mutations = []
    for path, value in (
        (("runtimeApplyAuthorized",), True),
        (("contractDigest",), "0" * 64),
        (("identity", "audience"), "wrong-audience"),
        (("websocket", "kongRouteForbidden"), False),
        (("privateBoundary", "publicKongRouteForbidden"), False),
        (("commonPolicy", "rateLimitFaultTolerant"), True),
        (("routes", 0, "requiredScope"), "wrong.scope"),
        (("routes", 0, "idempotencyRequired"), False),
    ):
        document = copy.deepcopy(base)
        target: Any = document
        for element in path[:-1]:
            target = target[element]
        target[path[-1]] = value
        mutations.append(document)
    lua = LUA_PATH.read_text(encoding="utf-8")
    for number, document in enumerate(mutations, 1):
        try:
            validate_policy(document, lua)
        except ValueError:
            continue
        raise AssertionError(f"negative calling policy fixture {number} was accepted")

    duplicate_samples = [
        '{"runtimeApplyAuthorized":true,"runtimeApplyAuthorized":false}',
        '{"contractDigest":"0","contractDigest":"' + DIGEST + '"}',
        '{"external_effects_enabled":true,"external_effects_enabled":false}',
    ]
    for number, sample in enumerate(duplicate_samples, 1):
        try:
            json.loads(sample, object_pairs_hook=reject_duplicate_pairs)
        except ValueError:
            continue
        raise AssertionError(f"duplicate-key fixture {number} was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        validate_files()
    print("KONG_CALLING_POLICY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
