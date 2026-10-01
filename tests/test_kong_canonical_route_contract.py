import json
from pathlib import Path


MANIFEST = json.loads(
    Path("config/kong-canonical-middleware-routes.json").read_text()
)
SOURCE = Path("scripts/reconcile_kong_canonical_routes.py").read_text()
N8N_AUTHORITY = json.loads(
    Path("config/kong-n8n-control-plane-routes.json").read_text()
)
PLATFORM_CONTRACT = json.loads(
    Path("contracts/platform-control-plane.v1.json").read_text()
)
INTAKE_AUTHORITY = json.loads(Path("config/kong-intake-routes.json").read_text())
PUBLIC_CONTRACT = json.loads(
    Path("config/middleware-public-api-route-contract.v1.json").read_text()
)
MIDDLEWARE_AUTHORITY = json.loads(
    Path("config/kong-middleware-authority.v2.json").read_text()
)


def test_only_proven_middleware_routes_are_managed_public_routes():
    assert MANIFEST["runtimeApplyAuthorized"] is False
    assert "runtime apply is not authorized by the reviewed manifest" in SOURCE
    assert {route["path"] for route in MANIFEST["routes"]} == {
        "/v1/crm",
        "/v1/email",
        "/v1/sms",
        "/v1/webhooks",
        "/v1/sms/dlr/telnexa",
    }
    assert MANIFEST["legacyHostEnabled"] is False


def test_authenticated_middleware_contract_routes_are_canonical():
    expected = {
        (row["method"], row["path"])
        for row in PUBLIC_CONTRACT["routes"]
        if row["classification"] == "shared_edge"
    }
    routes = {
        (route["methods"][0], route["pathTemplate"]): route
        for route in MANIFEST["contractRoutes"]
    }
    assert set(routes) == expected
    for route in routes.values():
        assert route["hosts"] == ["api.codestra.co"]
        assert route["serviceHost"] == "middleware-integration-api"
        assert route["servicePort"] == 8095
        assert route["securityAuthority"] == "config/kong-middleware-authority.v2.json"
        assert {
            "openid-connect",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(route["requiredPlugins"])
        assert "post-function" in route["requiredPlugins"]
        # Pre-auth is limited to header stripping; claim guards remain post-auth.
        assert "pre-function" in route["requiredPlugins"]

    assert MANIFEST["runtimeApplyAuthorized"] is False
    assert MANIFEST["providerEffectsEnabled"] is False


def test_intake_authority_is_service_only_and_fail_closed():
    routes = {route["name"]: route for route in INTAKE_AUTHORITY["routes"]}
    assert INTAKE_AUTHORITY["host"] == "api.codestra.co"
    assert INTAKE_AUTHORITY["service"]["host"] == "codestra-middleware-integration-api-1"
    assert INTAKE_AUTHORITY["service"]["port"] == 8095
    # Explicit transport policy: intake writes carry Idempotency-Key but the gateway
    # still must not re-send them, and Kong must not fall back to 60s defaults.
    assert (INTAKE_AUTHORITY["service"]["connect_timeout"], INTAKE_AUTHORITY["service"]["read_timeout"],
            INTAKE_AUTHORITY["service"]["write_timeout"], INTAKE_AUTHORITY["service"]["retries"]) == (3000, 30000, 30000, 0)
    assert routes["codestra-intake-leads"]["requiredClientId"] == "sdk-intake"
    assert routes["codestra-intake-leads"]["requiredScope"] == "leads.write"
    assert routes["codestra-intake-survey-responses"]["requiredScope"] == "surveys.write"
    for route in routes.values():
        assert set(route["requiredHeaders"]) == {
            "Authorization",
            "X-Tenant-ID",
            "X-Correlation-ID",
            "Idempotency-Key",
        }
        assert route["maxBodyMb"] == 1
        assert route["ratePerMinute"] > 0
    assert INTAKE_AUTHORITY["security"]["browserTokensForbidden"] is True
    assert INTAKE_AUTHORITY["security"]["sameOriginBffRequired"] is True
    assert INTAKE_AUTHORITY["security"]["directOdooRoutingForbidden"] is True
    assert INTAKE_AUTHORITY["activation"]["runtimeApplyAuthorized"] is False


def test_n8n_control_plane_preserves_identity_for_middleware_revalidation():
    assert N8N_AUTHORITY["status"] == "RETIRED_DENY_ONLY"
    assert N8N_AUTHORITY["runtime_apply_authorized"] is False
    assert N8N_AUTHORITY["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert N8N_AUTHORITY["audience"] == "middleware-api"
    assert N8N_AUTHORITY["client_id"] == "n8n-automation"
    assert N8N_AUTHORITY["preserve_authorization_header"] is True
    assert N8N_AUTHORITY["token_exchange"] is False
    assert N8N_AUTHORITY["service"]["host"] == "middleware-integration-api"
    assert N8N_AUTHORITY["service"]["port"] == 8095
    assert N8N_AUTHORITY["service"]["enabled"] is False
    routes = {route["name"]: route for route in N8N_AUTHORITY["routes"]}
    assert routes["codestra-n8n-command-submit"]["scope"] == "middleware.request.forward"
    assert routes["codestra-n8n-command-read"]["scope"] == "middleware.status.read"
    assert N8N_AUTHORITY["safety"]["direct_provider_routes"] is False
    assert {route["classification"] for route in routes.values()} == {"denied"}
    assert N8N_AUTHORITY["safety"]["reconciliation_apply"] is False
    assert PLATFORM_CONTRACT["status"] == "APPROVED_PRODUCTION"
    assert PLATFORM_CONTRACT["safety"]["deployment_permitted_by_contract"] is True
    canonical_paths = {
        route["pathTemplate"] for route in MANIFEST["contractRoutes"]
    }
    assert not {
        "/v1/integrations/n8n/commands",
        "/v1/integrations/n8n/operations",
    } & canonical_paths
    denied_paths = {route["pathTemplate"] for route in MANIFEST["deniedRoutes"]}
    assert {
        "/v1/integrations/n8n/commands",
        "/v1/integrations/n8n/operations",
    } <= denied_paths
    assert len(
        [
            row
            for row in MIDDLEWARE_AUTHORITY["routes"]
            if row["path"].startswith("/v2/automation/")
        ]
    ) == 13


def test_every_managed_route_has_explicit_security_controls():
    for route in MANIFEST["routes"]:
        assert route["methods"]
        assert route["auth"] == "key-auth"
        assert route["maxBodyMb"] > 0
        assert route["ratePerMinute"] > 0


def test_unverified_existing_routes_are_not_approval_authority():
    assert MANIFEST["unverifiedExistingRouteNames"]
    assert "allowedExistingRouteNames" not in MANIFEST
    assert "name-only public routes require exact source contracts" in SOURCE


def test_reconciler_is_dry_run_by_default_and_fail_closed():
    assert 'parser.add_argument("--apply", action="store_true")' in SOURCE
    assert "expected exactly one managed route" in SOURCE
    assert "required auth plugin absent" in SOURCE
    assert "unsafe Kong pagination URL" in SOURCE
    assert "unexpected_public" in SOURCE
    assert "legacy public host remains enabled" in SOURCE
