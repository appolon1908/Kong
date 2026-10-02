"""Invariants for the n8n editor browser-flow contract.

The editor is a human administrative surface behind a Community Edition n8n that
cannot authenticate against Keycloak itself. These assertions pin the properties
that make gateway enforcement meaningful, so a later edit cannot quietly turn the
editor into a bearer-authenticated or publicly routable surface.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "config" / "kong-n8n-editor-routes.json"
SERVICE_SPEC_PATH = ROOT / "config" / "kong-n8n-control-plane-routes.json"
SPEC = json.loads(SPEC_PATH.read_text(encoding="utf-8"))

APPLYABLE_STATUSES = {"APPROVED_STAGING", "APPROVED_PRODUCTION"}


def test_the_editor_contract_is_not_applyable_until_a_human_promotes_it():
    # The reconcilers refuse any status outside this set, so an unverified
    # editor route cannot reach a live gateway by being merged.
    assert SPEC["status"] not in APPLYABLE_STATUSES
    assert SPEC["safety"]["reconciliation_apply"] is False
    assert SPEC["service"]["enabled"] is False


def test_the_editor_uses_a_browser_flow_and_never_bearer_only():
    flow = SPEC["browser_flow"]
    assert flow["auth_methods"] == ["authorization_code", "session"]
    assert "bearer" not in flow["auth_methods"]
    assert "bearer" in flow["rejected_auth_methods"]
    assert SPEC["safety"]["oidc_enforcement"] == "authorization-code-plus-session"
    assert SPEC["safety"]["bearer_only_methods_rejected"] is True
    assert flow["required_realm_role"] == "codestra-n8n-editor"


def test_promotion_requires_negative_role_authorization_evidence():
    requirements = SPEC["activation_requirements"]
    assert any(
        "without the codestra-n8n-editor realm role" in requirement
        and "HTTP 403" in requirement
        for requirement in requirements
    )


def test_the_editor_does_not_reuse_the_service_identity():
    service_spec = json.loads(SERVICE_SPEC_PATH.read_text(encoding="utf-8"))
    # A bearer service client must never be able to open an editor session.
    assert SPEC["client_id"] != service_spec["client_id"]
    assert SPEC["host"] != service_spec["host"]
    assert SPEC["preserve_authorization_header"] is False


def test_session_cookies_are_not_readable_or_sendable_in_the_clear():
    flow = SPEC["browser_flow"]
    assert flow["session_cookie_secure"] is True
    assert flow["session_cookie_httponly"] is True
    assert flow["session_cookie_samesite"] in {"Lax", "Strict"}
    assert 0 < flow["session_idle_timeout_seconds"] <= 3600
    assert 0 < flow["session_absolute_timeout_seconds"] <= 86400
    assert flow["session_idle_timeout_seconds"] < flow["session_absolute_timeout_seconds"]


def test_defence_in_depth_beneath_the_gateway_is_required():
    safety = SPEC["safety"]
    assert safety["oidc_required"] is True
    assert safety["editor_publicly_routable"] is False
    assert safety["edge_admin_cidr_gate_required"] is True
    # Gateway OIDC alone is not the whole control: n8n's own login stays on, so
    # a gateway bypass does not yield editor access.
    assert safety["native_n8n_auth_required_behind_gateway"] is True
    assert SPEC["edge_boundary"]["n8n_native_auth_remains_enabled"] is True


def test_the_terminating_edge_authenticates_nothing():
    boundary = SPEC["edge_boundary"]
    assert boundary["edge_authenticates"] is False
    assert boundary["gateway_authenticates"] is True
    assert boundary["terminating_edge"] == "appolon1908/Caddy"


def test_no_credential_material_is_present_in_the_contract():
    assert SPEC["safety"]["credentials_in_repository"] is False
    raw = SPEC_PATH.read_text(encoding="utf-8")
    assert not re.search(r'(?i)"client_secret"\s*:', raw)
    assert "BEGIN" not in raw
    assert not re.search(r'(?i)"authorization"\s*:\s*"bearer\s+[^\"]+"', raw)
    # No *value* may look like credential material. Prose that says a secret is
    # held outside Git is fine; a long opaque token is not. Keys are skipped
    # because reviewed field names are legitimately long.
    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                assert key.casefold() not in {"client_secret", "authorization"}, key
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            assert not re.match(r"(?i)^bearer\s+\S+", node), node
            assert not re.fullmatch(r"[A-Za-z0-9+/=]{32,}", node), node

    walk(SPEC)


def test_credential_patterns_reject_short_and_punctuated_json_values():
    fixtures = (
        '{"client_secret": "short-secret"}',
        '{"Authorization": "Bearer short-secret"}',
    )
    assert re.search(r'(?i)"client_secret"\s*:', fixtures[0])
    assert re.search(r'(?i)"authorization"\s*:\s*"bearer\s+[^\"]+"', fixtures[1])


def test_parsed_scan_rejects_json_escaped_credential_fields_and_values():
    fixtures = (
        '{"client\\u005fsecret": "short-secret"}',
        '{"Authorization": "Bearer\\u0020short-secret"}',
    )
    for fixture in fixtures:
        parsed = json.loads(fixture)
        with __import__("pytest").raises(AssertionError):
            def walk(node):
                if isinstance(node, dict):
                    for key, item in node.items():
                        assert key.casefold() not in {"client_secret", "authorization"}
                        walk(item)
                elif isinstance(node, str):
                    assert not re.match(r"(?i)^bearer\s+\S+", node)

            walk(parsed)


def test_activation_requirements_are_recorded():
    requirements = SPEC["activation_requirements"]
    assert isinstance(requirements, list) and len(requirements) >= 5
    assert all(isinstance(item, str) and item.strip() for item in requirements)
