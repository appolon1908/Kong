from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
# Kong Gateway tag charset (conservative): letters, digits, "_", "-", ".", "~".
TAG_CHARSET = re.compile(r"[A-Za-z0-9_.~-]+")


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_middleware_routes", ROOT / "scripts/generate_middleware_routes.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load_generator()
CONTRACT = ROOT / "config/middleware-public-api-route-contract.v1.json"
PINNED = ROOT / "config/middleware-public-api-route-contract.sha256"
CANONICAL = ROOT / "config/kong-canonical-middleware-routes.json"
AUTHORITY = ROOT / "config/kong-middleware-authority.v2.json"
PRODUCTION = ROOT / "config/kong-middleware-routes.production.yml"
STAGING = ROOT / "config/staging/kong-middleware-routes.staging.yml"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vendored_contract_hash_and_complete_route_generation():
    contract = load_json(CONTRACT)
    digest = hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert PINNED.read_text(encoding="utf-8").strip() == digest
    canonical = load_json(CANONICAL)
    assert canonical["middlewareEdgeContract"]["sha256"] == digest
    assert canonical["middlewareEdgeContract"]["schema"] == contract["schema"]

    expected = {
        (row["method"], row["path"]): row
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    declared = {
        (row["methods"][0], row["pathTemplate"]): row
        for row in canonical["contractRoutes"]
    }
    assert set(declared) == set(expected)
    for key, row in declared.items():
        assert row["serviceHost"] == "middleware-integration-api", key
        assert row["servicePort"] == 8095, key
        assert row["methods"] == [expected[key]["method"]], key
        assert row["paths"][0].startswith("~/") and row["paths"][0].endswith("$"), key
        assert {
            "openid-connect",
            "post-function",
            "correlation-id",
            "rate-limiting",
            "request-size-limiting",
        } <= set(row["requiredPlugins"]), key


def test_denied_routes_are_explicit_404s_and_never_have_an_upstream():
    contract = load_json(CONTRACT)
    expected = {
        (row["method"], row["path"])
        for row in contract["routes"]
        if row["classification"] == "denied"
    }
    canonical = load_json(CANONICAL)
    denied = {(row["method"], row["pathTemplate"]): row for row in canonical["deniedRoutes"]}
    assert set(denied) == expected
    assert all(row["statusCode"] == 404 and "serviceHost" not in row for row in denied.values())


def test_staging_and_production_declarative_manifests_are_separate_and_safe():
    contract = load_json(CONTRACT)
    expected = {
        (row["method"], row["path"])
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    for path, issuer, environment in (
        (PRODUCTION, "https://auth.codestra.co/realms/codestra", "production"),
        (STAGING, "https://auth-staging.codestra.co/realms/codestra", "staging"),
    ):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert manifest["_format_version"] == "3.0"
        # decK rejects unknown top-level keys; generation metadata lives in tags.
        assert set(manifest) == {"_format_version", "_transform", "services", "routes", "plugins", "upstreams"}
        assert manifest["plugins"] == [{"name": "codestra-private-surface", "config": {"allow_private": False}}]
        assert len(manifest["upstreams"]) == 1
        assert manifest["upstreams"][0]["name"] == "middleware-integration-api"
        assert manifest["upstreams"][0]["targets"] == [{"target": "middleware-integration-api:8095", "weight": 100}]
        service = manifest["services"][0]
        assert (service["host"], service["port"]) == ("middleware-integration-api", 8095)
        assert f"codestra.environment.{environment}" in service["tags"]
        assert "codestra.runtime-apply-authorized.false" in service["tags"]
        assert "codestra.provider-effects-enabled.false" in service["tags"]
        by_operation = {
            generator.safe_name(row["operation_id"]): (row["method"], row["path"])
            for row in contract["routes"]
        }
        routes = {}
        for route in service["routes"]:
            assert all(TAG_CHARSET.fullmatch(tag) for tag in route["tags"]), route["tags"]
            assert "codestra.classification.shared_edge" in route["tags"]
            operation = next(
                tag.removeprefix("codestra.operation.")
                for tag in route["tags"]
                if tag.startswith("codestra.operation.")
            )
            routes[(route["methods"][0], by_operation[operation][1])] = route
            for plugin in route["plugins"]:
                if plugin["name"] == "openid-connect":
                    assert plugin["config"]["issuer"].startswith(issuer)
        assert set(routes) == expected
        for route in manifest["routes"]:
            assert all(TAG_CHARSET.fullmatch(tag) for tag in route["tags"]), route["tags"]
            assert "codestra.classification.denied" in route["tags"]
        assert "8080" not in path.read_text(encoding="utf-8")


def test_authority_preserves_audience_scope_and_azp_expectations():
    contract = load_json(CONTRACT)
    expected = {
        row["operation_id"]: row
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    authority = load_json(AUTHORITY)
    assert authority["runtime_apply_authorized"] is False
    assert authority["provider_effects_enabled"] is False
    actual = {row["operation_id"]: row for row in authority["routes"]}
    assert set(actual) == set(expected)
    for operation_id, row in actual.items():
        contract_row = expected[operation_id]
        assert row["audience"] == contract_row["audience"]
        assert row["scope"] == contract_row["scope"]
        assert row["azp"] == contract_row["calling_client"]


def test_generated_post_function_uses_valid_scalar_lua_metadata():
    for path in (PRODUCTION, STAGING):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        for route in manifest["services"][0]["routes"]:
            for plugin in route.get("plugins", []):
                if plugin["name"] != "post-function":
                    continue
                source = "\n".join(plugin["config"]["access"])
                assert "local expected_azp = [" not in source
                assert "local expected_azp = \"" in source
