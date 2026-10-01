from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_kong_postman.py"
SPEC = importlib.util.spec_from_file_location("kong_postman_generator", MODULE_PATH)
assert SPEC and SPEC.loader
postman = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = postman
SPEC.loader.exec_module(postman)

CASES = postman.load_json(postman.CASES_PATH)
COLLECTION = postman.load_json(postman.COLLECTION_PATH)
ENVIRONMENT = postman.load_json(postman.ENVIRONMENT_PATH)
MCR = postman.load_json(postman.MCR_CONTRACT_PATH)


def all_items(folders: list[dict]) -> list[dict]:
    items: list[dict] = []
    for node in folders:
        items.extend(all_items(node["item"]) if "item" in node else [node])
    return items


def script(item: dict, listen: str) -> str:
    return "\n".join(next(e for e in item["event"] if e["listen"] == listen)["script"]["exec"])


def folder(name: str) -> dict:
    return next(f for f in COLLECTION["item"] if f["name"] == name)


def test_checked_in_collection_and_environment_are_deterministic() -> None:
    assert COLLECTION == postman.render_collection(CASES, MCR)
    assert ENVIRONMENT == postman.render_environment()


def test_collection_is_bound_to_final_middleware_digest() -> None:
    assert CASES["source_contract_sha256"] == postman.FINAL_DIGEST
    assert COLLECTION["variable"] == [
        {"key": "source_contract_sha256", "value": postman.FINAL_DIGEST},
        {"key": "mcr_contract_sha256", "value": postman.canonical_digest(MCR)},
    ]


def test_collection_covers_required_crm_automation_and_webhook_families() -> None:
    assert CASES["route_family_counts"] == {
        "Automation V2": 13,
        "CRM Contacts": 9,
        "CRM Opportunities": 4,
        "CRM Tasks": 2,
        "CRM Tickets": 4,
        "Webhook & Event Ingress": 3,
    }
    assert len(CASES["routes"]) == 35
    paths = {(row["method"], row["path"]) for row in CASES["routes"]}
    assert ("POST", "/platform/v1/integrations/github/events") in paths
    assert ("POST", "/api/v1/odoo/events") in paths
    assert ("POST", "/api/v1/integrations/n8n/results") in paths
    assert sum(1 for row in CASES["routes"] if row["path"].startswith("/v2/automation/")) == 13


def test_negative_matrix_contains_auth_edge_idempotency_size_and_pending_denials() -> None:
    negative = next(folder for folder in COLLECTION["item"] if folder["name"] == "Negative Security & Edge")
    names = {item["name"] for item in negative["item"]}
    assert names == {
        "missing-token",
        "wrong-issuer",
        "wrong-audience",
        "wrong-azp",
        "missing-scope",
        "missing-idempotency",
        "wrong-method",
        "oversize-body",
        "private-metrics",
        "private-internal",
        "pending-telnexa",
        "pending-vicidial",
        "pending-n8n-ack",
        "pending-observability",
        "pending-sms-inbound",
    }


def test_environment_is_safe_by_default_and_contains_no_credentials() -> None:
    values = {row["key"]: row["value"] for row in ENVIRONMENT["values"]}
    assert values["base_url"] == "http://127.0.0.1:8000"
    assert values["RUN_KONG_V3_PARITY"] == "false"
    assert values["delivery_event_signature"] == ""
    for key in (
        "bearer_token",
        "wrong_issuer_token",
        "wrong_audience_token",
        "wrong_azp_token",
        "missing_scope_token",
    ):
        assert values[key] == ""


def test_collection_has_explicit_live_run_guard() -> None:
    prerequest = next(event for event in COLLECTION["event"] if event["listen"] == "prerequest")
    rendered = "\n".join(prerequest["script"]["exec"])
    assert "RUN_KONG_V3_PARITY" in rendered
    assert "disabled" in rendered
def test_live_run_guard_skips_disabled_runs_and_fails_misdirected_runs() -> None:
    prerequest = next(event for event in COLLECTION["event"] if event["listen"] == "prerequest")
    rendered = "\n".join(prerequest["script"]["exec"])
    disabled, rest = rendered.split("} else if (!loopback && !staging) {")
    refused = rest.split("} else {")[0]
    # A default (disabled) run must skip cleanly, never fail the Newman run.
    assert "RUN_KONG_V3_PARITY" in disabled and "pm.execution.skipRequest()" in disabled
    assert "throw" not in disabled
    # Newman sends a request whose pre-request script only throws and drops a
    # throw after skipRequest(), so the refusal must be a failed assertion first.
    assert refused.index("pm.test(") < refused.index("pm.execution.skipRequest()")
    assert "throw new Error(refusal)" in refused[refused.index("pm.test("):refused.index("pm.execution.skipRequest()")]
    assert "throw" not in refused[refused.index("pm.execution.skipRequest()"):]
    assert "127\\.0\\.0\\.1|localhost" in rendered
    assert "staging" in rendered


def test_every_request_asserts_and_skips_when_inputs_are_unset() -> None:
    items = all_items(COLLECTION["item"])
    assert len(items) == 35 + 8 + 15 + 9
    for item in items:
        test = script(item, "test")
        assert test.startswith("const spec = ")
        for assertion in ("no internal leakage", "no 5xx", "spec.expect", "spec.echoCorrelation", "spec.error"):
            assert assertion in test, (item["name"], assertion)
        assert "pm.execution.skipRequest()" in script(item, "prerequest")
        headers = {h["key"] for h in item["request"]["header"]}
        assert "Accept" in headers
        if "Authorization" in headers:
            token = next(h["value"] for h in item["request"]["header"] if h["key"] == "Authorization")
            token_var = token.removeprefix("Bearer {{").removesuffix("}}")
            assert f'"{token_var}"' in script(item, "prerequest")


def test_every_negative_declares_an_exact_status_expectation() -> None:
    for name in ("Negative Security & Edge", "MCR Negative Security & Edge"):
        for item in folder(name)["item"]:
            assert '"expect": [' in script(item, "test"), item["name"]


def test_mcr_folder_covers_every_contract_route_with_normalized_headers() -> None:
    items = {item["name"]: item for item in folder("MCR Platform")["item"]}
    assert set(items) == {f"{r['method']} {r['pathTemplate']}" for r in MCR["routes"]}
    for route in MCR["routes"]:
        item = items[f"{route['method']} {route['pathTemplate']}"]
        headers = {h["key"] for h in item["request"]["header"]}
        assert set(route["requiredHeaders"]) | {"Authorization"} <= headers
        assert item["request"]["url"]["raw"].startswith("{{base_url}}/platform/v1/")
        mode = '"mode": "hard_denied"' if route["effects"] == "hard_denied_by_middleware" else '"mode": "routed"'
        assert mode in script(item, "test")
    delivery = items["POST /platform/v1/delivery-events"]
    assert "delivery_event_signature" in script(delivery, "prerequest")


def test_mcr_negatives_assert_normalized_gateway_errors_and_private_denials() -> None:
    items = {item["name"]: item for item in folder("MCR Negative Security & Edge")["item"]}
    codes = MCR["headerPolicy"]["gatewayErrors"]["missingHeaderCodes"]
    expected_errors = {
        "mcr-missing-tenant": ("X-Tenant-ID", codes["X-Tenant-ID"]),
        "mcr-missing-correlation": ("X-Correlation-ID", codes["X-Correlation-ID"]),
        "mcr-execute-missing-idempotency": ("Idempotency-Key", codes["Idempotency-Key"]),
        "mcr-delivery-missing-signature": ("X-Codestra-Signature", codes["X-Codestra-Signature"]),
    }
    for name, (header, code) in expected_errors.items():
        assert header not in {h["key"] for h in items[name]["request"]["header"]}
        assert f'"error": "{code}"' in script(items[name], "test")
    for name in ("mcr-private-campaign-namespace", "mcr-internal-prefix", "mcr-private-odoo-actual-state"):
        assert '"expect": [404]' in script(items[name], "test")


def test_positive_probes_reject_gateway_auth_and_routing_failures() -> None:
    routed = [item for item in all_items(COLLECTION["item"]) if '"mode": "routed"' in script(item, "test")]
    assert len(routed) == 35 + sum(1 for r in MCR["routes"] if r["effects"] != "hard_denied_by_middleware")
    for item in routed:
        test = script(item, "test")
        assert "positive probe passed gateway authentication and routing" in test, item["name"]
        assert "pm.expect([401, 403]).to.not.include(pm.response.code);" in test
        assert "private_surface_not_found" in test
        assert "no Route matched" in test
