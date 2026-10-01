from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/middleware-public-api-route-contract.v1.json"
PIN = ROOT / "config/middleware-public-api-route-contract.sha256"
AUTHORITY = ROOT / "config/kong-middleware-authority.v2.json"
CANONICAL = ROOT / "config/kong-canonical-middleware-routes.json"
PRODUCTION = ROOT / "config/kong-middleware-routes.production.yml"
STAGING = ROOT / "config/staging/kong-middleware-routes.staging.yml"
PROVISIONAL = ROOT / "config/kong-middleware-v3-command-routes.v1.json"
GENERATOR = ROOT / "scripts/generate_middleware_routes.py"

EXPECTED_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
EXPECTED_COUNTS = {"shared_edge": 105, "denied": 10, "private_only": 2}
EXPECTED_UPSTREAM = "middleware-integration-api:8095"
KERNEL_ROUTES = {
    ("POST", "/platform/v1/commands"): "platform.command",
    ("GET", "/platform/v1/kernel/describe"): "platform.command.read",
    ("GET", "/platform/v1/operations/{operation_id}"): "platform.command.read",
    ("POST", "/platform/v1/operations/{operation_id}/cancel"): "platform.command",
    ("POST", "/platform/v1/operations/{operation_id}/replay"): "platform.command.replay",
    ("GET", "/platform/v1/operations/{operation_id}/timeline"): "platform.command.read",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def route_key(row: dict) -> tuple[str, str]:
    return row["method"], row["path"]


def test_final_middleware_contract_is_exact_117_route_authority() -> None:
    contract = load_json(CONTRACT)
    assert contract["schema"] == "codestra.middleware.public-api-route-contract.v2"
    assert canonical_digest(contract) == EXPECTED_DIGEST
    assert PIN.read_text(encoding="utf-8").strip() == EXPECTED_DIGEST
    assert len(contract["routes"]) == 117
    assert Counter(row["classification"] for row in contract["routes"]) == Counter(
        EXPECTED_COUNTS
    )

    shared = [row for row in contract["routes"] if row["classification"] == "shared_edge"]
    assert all(row["upstream"] == EXPECTED_UPSTREAM for row in shared)

    by_key = {route_key(row): row for row in shared}
    for key, scope in KERNEL_ROUTES.items():
        row = by_key[key]
        assert row["audience"] == "middleware-api"
        assert row["calling_client"] == "platform-command-client"
        assert row["auth"] == "service-or-user-jwt"
        assert row["scope"] == scope


def test_provisional_v3_authority_is_removed_and_folded_into_main_authority() -> None:
    assert not PROVISIONAL.exists()

    authority = load_json(AUTHORITY)
    assert authority["schema"] == "codestra.kong.middleware-authority.v2"
    assert authority["runtime_apply_authorized"] is False
    assert authority["provider_effects_enabled"] is False
    assert authority["contract"]["sha256"] == EXPECTED_DIGEST
    assert authority["upstream"] == {"host": "middleware-integration-api", "port": 8095}
    assert len(authority["routes"]) == 105

    contract = load_json(CONTRACT)
    expected_shared = {
        route_key(row)
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    authority_keys = {route_key(row) for row in authority["routes"]}
    assert authority_keys == expected_shared

    by_key = {route_key(row): row for row in authority["routes"]}
    for key, scope in KERNEL_ROUTES.items():
        row = by_key[key]
        assert row["issuer"] == "https://auth.codestra.co/realms/codestra"
        assert row["audience"] == "middleware-api"
        assert row["azp"] == "platform-command-client"
        assert row["authentication"] == "service-or-user-jwt"
        assert row["scope"] == scope


def test_canonical_and_generated_manifests_are_8095_and_complete() -> None:
    canonical = load_json(CANONICAL)
    edge = canonical["middlewareEdgeContract"]
    assert edge["source"] == "ingtrader21-spec/Middleware-:deploy/public-api-route-contract.json"
    assert edge["sha256"] == EXPECTED_DIGEST
    assert canonical["runtimeApplyAuthorized"] is False
    assert canonical["providerEffectsEnabled"] is False
    assert len(canonical["contractRoutes"]) == 105
    assert len(canonical["deniedRoutes"]) == 10

    contract = load_json(CONTRACT)
    expected_shared = {
        route_key(row)
        for row in contract["routes"]
        if row["classification"] == "shared_edge"
    }
    expected_denied = {
        route_key(row)
        for row in contract["routes"]
        if row["classification"] == "denied"
    }
    canonical_shared = {
        (row["methods"][0], row["pathTemplate"]) for row in canonical["contractRoutes"]
    }
    canonical_denied = {
        (row["method"], row["pathTemplate"]) for row in canonical["deniedRoutes"]
    }
    assert canonical_shared == expected_shared
    assert canonical_denied == expected_denied

    assert all(row["serviceHost"] == "middleware-integration-api" for row in canonical["contractRoutes"])
    assert all(row["servicePort"] == 8095 for row in canonical["contractRoutes"])

    for path, issuer in (
        (PRODUCTION, "https://auth.codestra.co/realms/codestra"),
        (STAGING, "https://auth-staging.codestra.co/realms/codestra"),
    ):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert len(manifest["services"]) == 1
        service = manifest["services"][0]
        assert service["host"] == "middleware-integration-api"
        assert service["port"] == 8095
        assert service["retries"] == 0
        assert len(service["routes"]) == 105
        assert len(manifest["routes"]) == 10

        for route in service["routes"]:
            oidc = next(plugin for plugin in route["plugins"] if plugin["name"] == "openid-connect")
            assert oidc["config"]["issuer"] == issuer + "/.well-known/openid-configuration"

        for route in [*service["routes"], *manifest["routes"]]:
            assert all(value.startswith("~/") for value in route["paths"])
            assert all(not value.startswith("~^/") for value in route["paths"])

        rendered = path.read_text(encoding="utf-8")
        assert "appolon-middleware-integration-api" not in rendered
        assert "port: 8080" not in rendered
        assert "~^/" not in rendered


def test_generator_is_deterministic_at_final_contract() -> None:
    outputs = [CANONICAL, AUTHORITY, PRODUCTION, STAGING]
    before = {path: path.read_bytes() for path in outputs}
    completed = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "generated 105 shared routes and 10 denied routes" in completed.stdout
    after = {path: path.read_bytes() for path in outputs}
    assert after == before
