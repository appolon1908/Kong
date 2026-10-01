import copy
import importlib.util
import json
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config/kong-canonical-middleware-routes.json"
RECONCILER_PATH = ROOT / "scripts/reconcile_kong_canonical_routes.py"
EXPORTER_PATH = ROOT / "scripts/export_kong_public_route_contracts.py"
CONTROL_PLANE_PATH = ROOT / "deploy/kong/control-plane.yml"
SCOPE_POLICY_PATH = ROOT / "deploy/kong/scope-policy.lua"
STANDBY_APPLIER_PATH = ROOT / "scripts/apply_kong_standby.py"
CAMPAIGN_RECONCILER_PATH = ROOT / "scripts/reconcile_kong_campaign_automation.py"
PROVIDER_CONTROL_VALIDATOR_PATH = ROOT / "scripts/validate_provider_control_routes.py"
CONTRACT_PATH = ROOT / "config/middleware-public-api-route-contract.v1.json"
MIDDLEWARE_AUTHORITY_PATH = ROOT / "config/kong-middleware-authority.v2.json"
GENERATOR_PATH = ROOT / "scripts/generate_middleware_routes.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module():
    return _load(RECONCILER_PATH, "reconcile_kong_canonical_routes")


def _exporter():
    return _load(EXPORTER_PATH, "export_kong_public_route_contracts")


def test_provider_control_authority_is_fail_closed_and_mutation_covered():
    module = _load(PROVIDER_CONTROL_VALIDATOR_PATH, "validate_provider_control_routes")
    contract = json.loads(module.CONTRACT.read_text())
    module.validate(copy.deepcopy(contract))

    mutations = []
    enabled = copy.deepcopy(contract)
    enabled["runtimeApplyAuthorized"] = True
    mutations.append(enabled)
    shared_key = copy.deepcopy(contract)
    shared_key["security"]["sharedKeysAllowed"] = True
    mutations.append(shared_key)
    direct_provider = copy.deepcopy(contract)
    direct_provider["security"]["directProviderRoutesAllowed"] = True
    mutations.append(direct_provider)
    wrong_client = copy.deepcopy(contract)
    wrong_client["routes"][0]["clientId"] = "codestra-marketing"
    mutations.append(wrong_client)
    wrong_scope = copy.deepcopy(contract)
    wrong_scope["routes"][0]["scope"] = "marketing.campaign.request"
    mutations.append(wrong_scope)
    wrong_name = copy.deepcopy(contract)
    wrong_name["routes"][0]["name"] = "unreviewed-route-name"
    mutations.append(wrong_name)
    duplicate_name = copy.deepcopy(contract)
    duplicate_name["routes"][1]["name"] = duplicate_name["routes"][0]["name"]
    mutations.append(duplicate_name)
    wrong_audience = copy.deepcopy(contract)
    wrong_audience["audience"] = "ai-provider-adapter"
    mutations.append(wrong_audience)
    wrong_dependency = copy.deepcopy(contract)
    wrong_dependency["dependencies"]["middlewarePullRequest"] = 999
    mutations.append(wrong_dependency)
    wrong_upstream = copy.deepcopy(contract)
    wrong_upstream["service"]["host"] = "unreviewed-middleware"
    mutations.append(wrong_upstream)
    delete_legacy = copy.deepcopy(contract)
    delete_legacy["legacyRetirement"]["runtimeDeletionAuthorized"] = True
    mutations.append(delete_legacy)
    weaken_retirement = copy.deepcopy(contract)
    weaken_retirement["legacyRetirement"]["acceptance"] = "review later"
    mutations.append(weaken_retirement)

    for mutation in mutations:
        with pytest.raises(ValueError):
            module.validate(mutation)


def test_standby_apply_refuses_unowned_name_collisions(monkeypatch):
    module = _load(STANDBY_APPLIER_PATH, "apply_kong_standby")
    calls = []

    def fake_request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"data": [{"id": "existing", "name": "standby-service", "tags": ["production"]}]}

    monkeypatch.setattr(module, "request", fake_request)
    with pytest.raises(RuntimeError, match="refusing to adopt unowned"):
        module.upsert("services", "standby-service", {"tags": [module.TAG]})
    assert [method for method, _, _ in calls] == ["GET"]


def test_standby_apply_updates_only_resources_it_already_owns(monkeypatch):
    module = _load(STANDBY_APPLIER_PATH, "apply_kong_standby_owned")
    owned_id = "00000000-0000-0000-0000-000000000001"

    def fake_request(method, path, payload=None):
        if method == "GET":
            return {"data": [{"id": owned_id, "tags": [module.TAG]}]}
        return {"id": owned_id, **payload}

    monkeypatch.setattr(module, "request", fake_request)
    result = module.upsert("services", "standby-service", {"tags": [module.TAG]})
    assert result["id"] == owned_id


def test_standby_apply_rejects_untrusted_owned_resource_identity(monkeypatch):
    module = _load(STANDBY_APPLIER_PATH, "apply_kong_standby_invalid_identity")
    monkeypatch.setattr(
        module,
        "request",
        lambda method, path, payload=None: {
            "data": [{"id": "../routes/production", "tags": [module.TAG]}]
        },
    )
    with pytest.raises(RuntimeError, match="invalid Kong service identity"):
        module.upsert("services", "standby-service", {"tags": [module.TAG]})


def test_campaign_reconciler_validates_manifest_consumer_identity():
    source = CAMPAIGN_RECONCILER_PATH.read_text()
    assert 'f"/consumers/{consumer[\'id\']}"' in source
    # Every manifest consumer is read back and compared field by field, and the
    # scope grant never travels to Kong as consumer state.
    assert "for spec in manifest_consumers(manifest):" in source
    assert "identity = consumer_entity(spec)" in source
    assert 'require_exact_fields(consumer, identity, "campaign service consumer")' in source
    assert 'require_exact_fields(credential, jwt_payload, "campaign JWT credential")' in source


def _inline_scope_policy() -> str:
    document = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    plugins = document["services"][0]["plugins"]
    post_function = next(plugin for plugin in plugins if plugin["name"] == "post-function")
    return post_function["config"]["access"][0].strip()


def test_control_plane_scope_policy_runs_after_authentication():
    """pre-function has priority 1000000 and executes before every auth plugin.

    The policy reads verified claims, so attaching it there would leave it with
    no credential and no claims on every request. post-function (priority -1000)
    is the only serverless phase that observes the result of openid-connect.
    """
    document = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    names = {plugin["name"] for plugin in document["services"][0]["plugins"]}
    assert "post-function" in names
    assert "pre-function" not in names


def test_control_plane_scope_policy_uses_sandbox_safe_primitives():
    """os.getenv is absent from Kong's Lua sandbox (only clock/date/difftime/time).

    Reading the gateway secret through the env vault keeps untrusted_lua on
    `sandbox`; os.getenv would force `untrusted_lua = on`, disabling the sandbox
    for every serverless function on the node.
    """
    policy = SCOPE_POLICY_PATH.read_text()
    code = "\n".join(
        line for line in policy.splitlines() if not line.lstrip().startswith("--")
    )
    assert "os.getenv" not in code
    assert 'kong.vault.get("{vault://env/kong-control-plane-gateway-secret}")' in code


def test_control_plane_scope_policy_requires_a_verified_credential():
    """The policy decodes the bearer token itself, so it must first prove that an
    authentication plugin accepted the request."""
    policy = SCOPE_POLICY_PATH.read_text()
    guard = policy.index("kong.client.get_credential()")
    claims = policy.index("local function verified_claims()")
    assert guard < claims
    assert 'error="unauthenticated"' in policy


def test_control_plane_never_inherits_client_supplied_identity_headers():
    policy = SCOPE_POLICY_PATH.read_text()
    for header in (
        "X-Authenticated-Client",
        "X-Authenticated-Tenant",
        "X-Authenticated-Role",
        "X-Codestra-Gateway-Secret",
    ):
        assert header in policy
    assert "kong.service.request.clear_header(name)" in policy
    assert policy.index("clear_header(name)") < policy.index(
        'kong.service.request.set_header("X-Authenticated-Client"'
    )


def test_control_plane_rate_limit_counts_across_every_node():
    document = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    plugins = {p["name"]: p for p in document["services"][0]["plugins"]}
    config = plugins["rate-limiting"]["config"]
    assert config["policy"] == "redis"
    assert config["fault_tolerant"] is False
    assert config["redis"]["port"] == 6379
    assert config["redis"]["password"].startswith("{vault://env/")


def test_public_route_manifest_disables_legacy_and_name_only_trust():
    manifest = json.loads(MANIFEST_PATH.read_text())
    assert manifest["schema"] == "codestra.kong.canonical-routes.v2"
    assert manifest["legacyHost"] == "api.codestra.agency"
    assert manifest["legacyHostEnabled"] is False
    assert "allowedExistingRouteNames" not in manifest
    assert manifest["unverifiedExistingRouteNames"]
    approved = {
        item["name"] for item in manifest["routes"] + manifest["contractRoutes"]
    }
    assert approved.isdisjoint(manifest["unverifiedExistingRouteNames"])


def test_contract_routes_bind_exact_dedicated_security_authority():
    manifest = json.loads(MANIFEST_PATH.read_text())
    for route in manifest["contractRoutes"]:
        authority = ROOT / route["securityAuthority"]
        assert authority.is_file()
        assert route["hosts"] == ["api.codestra.co"]
        assert route["securityAuthority"] == "config/kong-middleware-authority.v2.json"
        assert route["serviceHost"] == "middleware-integration-api"
        assert route["servicePort"] == 8095
        assert {
            "openid-connect",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(route["requiredPlugins"])
        assert "post-function" in route["requiredPlugins"]
        # Pre-auth is limited to header stripping; claim guards remain post-auth.
        assert "pre-function" in route["requiredPlugins"]


def test_callback_contract_rejects_security_plugin_config_drift():
    generator = _load(GENERATOR_PATH, "generate_middleware_callback_drift")
    contract = json.loads(CONTRACT_PATH.read_text())
    authority = json.loads(MIDDLEWARE_AUTHORITY_PATH.read_text())
    source = next(
        row for row in contract["routes"] if row["path"] == "/api/v1/callbacks"
    )
    committed = next(
        row for row in authority["routes"] if row["operation_id"] == source["operation_id"]
    )
    assert generator.authority_route(source, committed["issuer"]) == committed

    drifted = copy.deepcopy(source)
    drifted["audience"] = "wrong-api"
    assert generator.authority_route(drifted, committed["issuer"]) != committed


def _intake_plugins(route: dict) -> dict[str, dict]:
    access = (
        f"require {route['requiredClientId']} {route['requiredScope']} "
        "X-Tenant-ID Idempotency-Key"
    )
    return {
        "jwt": {
            "config": {
                "header_names": ["authorization"],
                "claims_to_verify": ["exp"],
                "key_claim_name": "azp",
            }
        },
        "openid-connect": {
            "config": {
                "auth_methods": ["bearer"],
                "consumer_claim": ["azp"],
                "issuer": "https://auth.codestra.co/realms/codestra/.well-known/openid-configuration",
                "audience": [route["requiredClientId"]],
                "scopes_required": [route["requiredScope"]],
            }
        },
        "post-function": {"config": {"access": [access]}},
        "request-size-limiting": {
            "config": {"allowed_payload_size": route["maxBodyMb"]}
        },
        "rate-limiting": {
            "config": {"minute": route["ratePerMinute"], "policy": "redis", "fault_tolerant": False,
                       "redis": {"host": "codestra-redis", "port": 6379}}
        },
        "correlation-id": {
            "config": {
                "header_name": "X-Correlation-ID",
                "generator": "uuid",
                "echo_downstream": True,
            }
        },
        "request-termination": {"config": {"status_code": 403}},
    }


def test_event_intake_contract_and_authority_are_generated_exactly():
    generator = _load(GENERATOR_PATH, "generate_middleware_intake_exact")
    contract = json.loads(CONTRACT_PATH.read_text())
    canonical = json.loads(MANIFEST_PATH.read_text())
    authority = json.loads(MIDDLEWARE_AUTHORITY_PATH.read_text())
    source = next(
        row for row in contract["routes"] if row["path"] == "/api/v1/odoo/events"
    )
    expected_route = generator.canonical_route(source)
    assert expected_route in canonical["contractRoutes"]
    committed = next(
        row for row in authority["routes"] if row["operation_id"] == source["operation_id"]
    )
    assert generator.authority_route(source, committed["issuer"]) == committed


def test_event_intake_contract_rejects_identity_scope_and_client_drift():
    generator = _load(GENERATOR_PATH, "generate_middleware_intake_drift")
    contract = json.loads(CONTRACT_PATH.read_text())
    authority = json.loads(MIDDLEWARE_AUTHORITY_PATH.read_text())
    source = next(
        row for row in contract["routes"] if row["path"] == "/api/v1/odoo/events"
    )
    committed = next(
        row for row in authority["routes"] if row["operation_id"] == source["operation_id"]
    )
    for key, value in (
        ("audience", "wrong-api"),
        ("scope", "wrong.scope"),
        ("calling_client", "wrong-client"),
    ):
        drifted = copy.deepcopy(source)
        drifted[key] = value
        assert generator.authority_route(drifted, committed["issuer"]) != committed


def test_intake_contract_cannot_authorize_runtime_apply():
    canonical = json.loads(MANIFEST_PATH.read_text())
    authority = json.loads(MIDDLEWARE_AUTHORITY_PATH.read_text())
    assert canonical["runtimeApplyAuthorized"] is False
    assert canonical["providerEffectsEnabled"] is False
    assert authority["runtime_apply_authorized"] is False
    assert authority["provider_effects_enabled"] is False


def test_campaign_contract_rejects_scope_guard_drift():
    generator = _load(GENERATOR_PATH, "generate_middleware_campaign_drift")
    contract = json.loads(CONTRACT_PATH.read_text())
    authority = json.loads(MIDDLEWARE_AUTHORITY_PATH.read_text())
    source = next(
        row
        for row in contract["routes"]
        if row["path"] == "/api/v1/automation/policy-check"
    )
    committed = next(
        row for row in authority["routes"] if row["operation_id"] == source["operation_id"]
    )
    assert generator.authority_route(source, committed["issuer"]) == committed
    drifted = copy.deepcopy(source)
    drifted["scope"] = "wrong.scope"
    assert generator.authority_route(drifted, committed["issuer"]) != committed


def test_reconciler_pagination_cannot_leave_the_selected_admin_origin():
    module = _module()
    assert module.safe_next("http://127.0.0.1:8001", "/routes?offset=next") == (
        "http://127.0.0.1:8001/routes?offset=next"
    )
    assert module.safe_next(
        "http://127.0.0.1:8001", "http://127.0.0.1:8001/routes?offset=next"
    ) == "http://127.0.0.1:8001/routes?offset=next"
    with pytest.raises(RuntimeError, match="unsafe Kong pagination URL"):
        module.safe_next(
            "http://127.0.0.1:8001", "https://attacker.invalid/routes?offset=next"
        )


def test_reconciler_is_exact_and_never_unions_legacy_hosts():
    source = RECONCILER_PATH.read_text()
    assert "name-only public route allowlists are forbidden" in source
    assert "name-only public routes require exact source contracts" in source
    assert "unsafe Kong pagination URL" in source
    assert 'desired_hosts = [manifest["canonicalHost"]]' in source
    assert "original_hosts +" not in source
    assert "LEGACY_PUBLIC_ROUTE_NAMES" in source
    assert "duplicate enabled route plugins" in source
    assert "securityAuthority" in source
    assert "verify_security_plugins" in source
    assert "correlation-id" in source
    assert 'return "true" if value else "false"' in source


def test_read_only_route_exporter_redacts_secret_values_without_exporting_credentials():
    module = _exporter()
    source = EXPORTER_PATH.read_text()
    value = {
        "client_secret": "do-not-export",
        "nested": {"password": "do-not-export", "secret_is_base64": True},
        "key_claim_name": "azp",
        "allowed_payload_size": 2,
        "headers": [
            "Authorization: Bearer do-not-export-token",
            "X-API-Key: do-not-export-key",
            "X-Safe-Header: safe-value",
        ],
        "upstream_url": "https://user:do-not-export@example.invalid/path",
    }
    sanitized = module.sanitize(value)
    assert sanitized["client_secret"]["redacted"] is True
    assert sanitized["nested"]["password"]["redacted"] is True
    assert sanitized["nested"]["secret_is_base64"] is True
    assert sanitized["key_claim_name"] == "azp"
    assert sanitized["headers"][0]["redacted"] is True
    assert sanitized["headers"][1]["redacted"] is True
    assert sanitized["headers"][2] == "X-Safe-Header: safe-value"
    assert sanitized["upstream_url"]["redacted"] is True
    rendered = json.dumps(sanitized)
    assert "do-not-export" not in rendered
    assert "method=\"GET\"" in source
    assert "credentials_exported" in source
    assert "consumers" not in source.lower()
    assert "unsafe Kong pagination URL" in source


def test_exporter_pagination_cannot_leave_the_selected_admin_origin():
    module = _exporter()
    with pytest.raises(RuntimeError, match="unsafe Kong pagination URL"):
        module.safe_next(
            "http://127.0.0.1:8001", "http://attacker.invalid/routes?offset=next"
        )


def test_inline_and_standalone_control_plane_scope_policies_are_identical():
    assert _inline_scope_policy() == SCOPE_POLICY_PATH.read_text().strip()


def test_control_plane_scope_policy_covers_exact_admin_and_message_roots():
    policy = SCOPE_POLICY_PATH.read_text()
    assert 'path == "/v1/admin/system" or path:find("^/v1/admin/system/")' in policy
    assert 'required = "platform.admin"' in policy
    assert 'path == "/api/v1/messages" or path:find("^/api/v1/messages/")' in policy
    assert 'required = "communications.message.read"' in policy
    assert 'error="route_scope_undefined"' in policy
    assert 'path == "/api/v1/health"' in policy
    assert 'path:find("^/api/v1/events/")' in policy
    assert 'X-Authenticated-Role", "platform_admin"' in policy


def _control_plane_live_objects():
    declared = yaml.safe_load(CONTROL_PLANE_PATH.read_text())
    expected_service = declared["services"][0]
    service = {
        "id": "service-1",
        "name": expected_service["name"],
        "protocol": "http",
        "host": "codestra-control-plane",
        "port": 8096,
        "path": None,
        "enabled": expected_service["enabled"],
        "connect_timeout": 3000,
        "read_timeout": 30000,
        "write_timeout": 30000,
        "retries": 0,
    }
    routes = [
        {
            "id": f"route-{index}",
            "name": route["name"],
            "hosts": route["hosts"],
            "paths": route["paths"],
            "methods": route["methods"],
            "protocols": route["protocols"],
            "strip_path": route["strip_path"],
            "preserve_host": route["preserve_host"],
            "path_handling": route["path_handling"],
            "https_redirect_status_code": route["https_redirect_status_code"],
            "request_buffering": route["request_buffering"],
            "response_buffering": route["response_buffering"],
            "regex_priority": route["regex_priority"],
            "headers": route.get("headers"),
            "snis": route.get("snis"),
            "sources": route.get("sources"),
            "destinations": route.get("destinations"),
            "service": {"id": service["id"]},
        }
        for index, route in enumerate(expected_service["routes"])
    ]
    service_plugins = [
        {"name": plugin["name"], "enabled": True, "config": plugin.get("config", {})}
        for plugin in expected_service["plugins"]
    ]
    route_plugins = {
        route["name"]: [
            {"name": plugin["name"], "enabled": True, "config": plugin.get("config", {})}
            for plugin in route.get("plugins", [])
        ]
        for route in expected_service["routes"]
    }
    return declared, service, routes, service_plugins, route_plugins


def _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes):
    route_names = {route["id"]: route["name"] for route in routes}

    def fake_all_rows(_base, path):
        if path.startswith("/services/"):
            return service_plugins
        route_id = path.split("/")[2]
        return route_plugins[route_names[route_id]]

    monkeypatch.setattr(module, "all_rows", fake_all_rows)


def test_control_plane_verifier_accepts_exact_declarative_authority(monkeypatch):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    assert module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service}) == {
        route["name"] for route in declared["services"][0]["routes"]
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda service, routes, plugins: service.update(protocol="https"), "service.protocol"),
        (lambda service, routes, plugins: service.update(path="/wrong"), "service.path"),
        (lambda service, routes, plugins: service.update(enabled=False), "service.enabled"),
        (lambda service, routes, plugins: service.update(read_timeout=60000), "service.read_timeout"),
        (lambda service, routes, plugins: service.update(retries=5), "service.retries"),
        (lambda service, routes, plugins: routes[0].update(protocols=["https"]), "protocols"),
        (lambda service, routes, plugins: routes[0].update(strip_path=True), "strip_path"),
        (lambda service, routes, plugins: routes[0].update(preserve_host=True), "preserve_host"),
        (lambda service, routes, plugins: routes[0].update(path_handling="v1"), "path_handling"),
        (lambda service, routes, plugins: routes[0].update(https_redirect_status_code=308), "https_redirect"),
        (lambda service, routes, plugins: routes[0].update(request_buffering=False), "request_buffering"),
        (lambda service, routes, plugins: routes[0].update(response_buffering=False), "response_buffering"),
        (lambda service, routes, plugins: routes[0].update(regex_priority=10), "regex_priority"),
        (lambda service, routes, plugins: routes[0].update(headers={"x-drift": ["1"]}), "headers"),
        (
            lambda service, routes, plugins: plugins.append(
                {"name": "cors", "enabled": True, "config": {}}
            ),
            "service_plugins",
        ),
    ],
)
def test_control_plane_verifier_rejects_declarative_drift(monkeypatch, mutation, message):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    mutation(service, routes, service_plugins)
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    with pytest.raises(RuntimeError, match=message):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})


def test_control_plane_verifier_rejects_duplicate_and_undeclared_route_plugins(monkeypatch):
    module = _module()
    declared, service, routes, service_plugins, route_plugins = _control_plane_live_objects()
    protected = next(name for name, plugins in route_plugins.items() if plugins)
    route_plugins[protected].append(route_plugins[protected][0].copy())
    _stub_control_plane_plugins(monkeypatch, module, service_plugins, route_plugins, routes)
    with pytest.raises(RuntimeError, match="duplicate enabled route plugins"):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})

    route_plugins[protected] = route_plugins[protected][:1]
    unprotected = next(name for name, plugins in route_plugins.items() if not plugins)
    route_plugins[unprotected].append({"name": "cors", "enabled": True, "config": {}})
    with pytest.raises(RuntimeError, match="route_plugins"):
        module.verify_control_plane("http://admin.invalid", declared, routes, {service["id"]: service})


def test_undefined_control_plane_paths_are_denied_before_proxy_identity_headers():
    policy = SCOPE_POLICY_PATH.read_text()
    deny = policy.index('return kong.response.exit(403,{error="route_scope_undefined"})')
    identity = policy.index('kong.service.request.set_header("X-Authenticated-Client"')
    assert deny < identity
