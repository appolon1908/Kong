from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "render_middleware_jwt_fallback.py"


def load_renderer():
    spec = importlib.util.spec_from_file_location("render_middleware_jwt_fallback", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def plugins(route):
    return {item["name"]: item for item in route.get("plugins", [])}


def test_pas151_jwt_fallback_replaces_all_oidc_and_adds_rs256_consumer():
    renderer = load_renderer()
    source = yaml.safe_load(
        (ROOT / "config" / "staging" / "kong-middleware-routes.staging.yml").read_text(
            encoding="utf-8"
        )
    )
    public_key = "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"
    rendered = renderer.transform_manifest(source, public_key)

    routes = rendered["services"][0]["routes"]
    assert len(routes) == 105
    assert all("openid-connect" not in plugins(route) for route in routes)
    assert all("jwt" in plugins(route) for route in routes)

    for route in routes:
        jwt = plugins(route)["jwt"]["config"]
        assert jwt["key_claim_name"] == "iss"
        assert jwt["claims_to_verify"] == ["exp", "nbf"]
        assert jwt["header_names"] == ["authorization"]
        assert jwt["run_on_preflight"] is True

    assert rendered["consumers"] == [
        {
            "username": "codestra-keycloak-staging-jwks",
            "custom_id": "codestra-keycloak-staging-jwks",
            "jwt_secrets": [
                {
                    "key": renderer.STAGING_ISSUER,
                    "algorithm": "RS256",
                    "secret": renderer.DUMMY_RS256_SECRET,
                    "rsa_public_key": public_key,
                }
            ],
        }
    ]


def test_pas151_jwt_fallback_keeps_fail_closed_caller_semantics():
    renderer = load_renderer()
    source = yaml.safe_load(
        (ROOT / "config" / "staging" / "kong-middleware-routes.staging.yml").read_text(
            encoding="utf-8"
        )
    )
    rendered = renderer.transform_manifest(
        source, "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"
    )

    scripts = {
        route["name"]: plugins(route)["post-function"]["config"]["access"][0]
        for route in rendered["services"][0]["routes"]
    }
    all_scripts = "\n".join(scripts.values())
    for marker in (
        "invalid_issuer",
        "invalid_audience",
        "expired_token",
        "invalid_token_lifetime",
        "insufficient_scope",
        "missing_azp",
        "unauthorized_azp",
        "symbolic_selector_not_concrete_identity",
    ):
        assert marker in all_scripts

    concrete = next(
        code
        for code in scripts.values()
        if 'local expected_azp = "n8n-automation"' in code
    )
    assert "local concrete_caller = true" in concrete

    symbolic = next(
        code
        for code in scripts.values()
        if 'local expected_azp = "platform-command-client"' in code
    )
    assert "local concrete_caller = false" in symbolic
    assert "Family/symbolic membership is re-authorized by Middleware" in symbolic


def test_pas151_jwt_fallback_preserves_denied_routes():
    renderer = load_renderer()
    source = yaml.safe_load(
        (ROOT / "config" / "staging" / "kong-middleware-routes.staging.yml").read_text(
            encoding="utf-8"
        )
    )
    rendered = renderer.transform_manifest(
        source, "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"
    )
    assert rendered.get("routes") == source.get("routes")
