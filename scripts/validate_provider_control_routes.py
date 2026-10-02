#!/usr/bin/env python3
"""Validate the disabled-by-default Kong provider-control route authority."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "kong-provider-control-routes.v1.json"

EXPECTED_ROUTES = {
    ("POST", "/api/v1/control/ai/inference-requests"): ("codestra-ai-inference-request", "codestra-ai", "ai.inference.request", True),
    ("POST", "/api/v1/control/communications/email"): ("codestra-communication-email-request", "codestra-communication", "communication.email.request", True),
    ("POST", "/api/v1/control/communications/sms"): ("codestra-communication-sms-request", "codestra-communication", "communication.sms.request", True),
    ("POST", "/api/v1/control/marketing/campaigns"): ("codestra-marketing-campaign-request", "codestra-marketing", "marketing.campaign.request", True),
    ("POST", "/api/v1/odoo/events"): ("codestra-odoo-event-publish", "odoo-integration", "odoo.events.publish", False),
    ("POST", "/api/v1/control/social/publications"): ("codestra-social-publication-request", "codestra-social", "social.publish.request", True),
}
EXPECTED_LEGACY = {"/v1/crm", "/v1/email", "/v1/sms", "/v1/webhooks", "/v1/sms/dlr/telnexa"}
EXPECTED_DEPENDENCIES = {
    "middlewareRepository": "appolon1908/Middleware-",
    "middlewarePullRequest": 82,
    "keycloakRepository": "appolon1908/Keycloak",
    "keycloakPullRequest": 60,
}
EXPECTED_SERVICE = {
    "host": "appolon-middleware-integration-api",
    "port": 8080,
    "protocol": "http",
}
EXPECTED_RETIREMENT_ACCEPTANCE = "zero runtime consumers and reviewed replacement ownership"


def validate(contract: dict) -> None:
    if contract.get("schema") != "codestra.kong.provider-control-routes.v1":
        raise ValueError("schema drift")
    if contract.get("status") != "PREPARED_DISABLED" or contract.get("runtimeApplyAuthorized") is not False:
        raise ValueError("source contract must remain disabled")
    if contract.get("issuer") != "https://auth.codestra.co/realms/codestra":
        raise ValueError("issuer drift")
    if contract.get("audience") != "middleware-api":
        raise ValueError("audience drift")
    if contract.get("dependencies") != EXPECTED_DEPENDENCIES:
        raise ValueError("reviewed dependency identity drift")
    if contract.get("service") != EXPECTED_SERVICE:
        raise ValueError("middleware upstream service drift")
    security = contract.get("security", {})
    expected_security = {
        "grantType": "client_credentials",
        "oidcEnforcement": "jwt-rs256-plus-claim-guard",
        "preserveAuthorizationHeader": True,
        "middlewareRevalidatesIdentity": True,
        "fullScopeAllowed": False,
        "wildcardScopesAllowed": False,
        "sharedKeysAllowed": False,
        "directProviderRoutesAllowed": False,
        "maximumTokenLifetimeSeconds": 300,
        "requiredClaims": ["iss", "sub", "aud", "azp", "iat", "exp", "jti", "scope"],
    }
    if security != expected_security:
        raise ValueError("security authority drift")
    actual = {}
    names = set()
    for route in contract.get("routes", []):
        key = (route.get("method"), route.get("path"))
        if key in actual:
            raise ValueError(f"duplicate route: {key}")
        name = route.get("name")
        if name in names:
            raise ValueError(f"duplicate route name: {name}")
        names.add(name)
        actual[key] = (name, route.get("clientId"), route.get("scope"), route.get("externalEffect"))
    if actual != EXPECTED_ROUTES:
        raise ValueError("exact route/client/scope matrix drift")
    if set(contract.get("legacySharedKeyRoutes", [])) != EXPECTED_LEGACY:
        raise ValueError("legacy shared-key inventory drift")
    retirement = contract.get("legacyRetirement", {})
    if retirement.get("state") != "BLOCKED_PENDING_CONSUMER_MIGRATION":
        raise ValueError("legacy retirement state drift")
    if retirement.get("runtimeDeletionAuthorized") is not False:
        raise ValueError("legacy route deletion must not be authorized")
    if retirement.get("acceptance") != EXPECTED_RETIREMENT_ACCEPTANCE:
        raise ValueError("legacy retirement acceptance drift")


def main() -> int:
    validate(json.loads(CONTRACT.read_text(encoding="utf-8")))
    print("KONG_PROVIDER_CONTROL_SOURCE=PASS")
    print("KONG_PROVIDER_CONTROL_RUNTIME_APPLY=DISABLED")
    print("DIRECT_PROVIDER_ROUTES_ALLOWED=NO")
    print(f"LEGACY_SHARED_KEY_ROUTES={len(EXPECTED_LEGACY)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
