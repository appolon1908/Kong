from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_kong_cross_repo_parity.py"
SPEC = importlib.util.spec_from_file_location("kong_cross_repo_parity", MODULE_PATH)
assert SPEC and SPEC.loader
parity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = parity
SPEC.loader.exec_module(parity)

CONFIG = parity.load_json(ROOT / "config" / "kong-cross-repo-parity.v1.json")


def test_parallel_lane_pins_final_external_authorities_and_stays_source_only() -> None:
    parity.validate_config(CONFIG)
    sources = CONFIG["sources"]
    assert sources["kong"]["frozen_base_sha"] == "ee86cdf870aebaac550a78a9617321ee48324589"
    assert sources["middleware"]["source_sha"] == "bd406a6508c8095a3f23b35149a2eebcb94c94c6"
    assert sources["middleware"]["contract_sha256"] == "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
    assert sources["caddy"]["source_sha"] == "22c6d51ed2f5340139177131fb810e787f0f7550"
    assert sources["keycloak"]["source_sha"] == "45a487d71a516ae3039b00c250752897469ffe7a"
    assert CONFIG["runtime_apply_authorized"] is False
    assert CONFIG["provider_effects_enabled"] is False
    assert CONFIG["live_staging_probe_authorized"] is False


def test_integrated_lane_a_contract_is_final_and_not_pending() -> None:
    report = parity.validate_kong(CONFIG, ROOT, allow_pending_lane_a=False)
    assert report["pending_lane_a"] is False
    assert report["observed_contract_sha256"] == CONFIG["sources"]["kong"]["final_contract_sha256"]
    assert report["observed_contract_sha256"] == CONFIG["sources"]["middleware"]["contract_sha256"]
    assert report["final_contract_sha256"] == CONFIG["sources"]["kong"]["final_contract_sha256"]
    assert report["upstream"] == "middleware-integration-api:8095"
    assert report["side_effecting_gateway_retries"] == 0


def test_required_route_family_contract_is_complete() -> None:
    families = CONFIG["required_route_families"]
    assert families["contacts"]["minimum_routes"] == 9
    assert families["tasks"]["minimum_routes"] == 4
    assert families["tickets"]["minimum_routes"] == 4
    assert families["opportunities"]["minimum_routes"] == 4
    assert families["automation_v2"]["exact_routes"] == 13


def test_transport_invariants_forbid_bypass_and_gateway_retries() -> None:
    transport = CONFIG["transport_invariants"]
    assert transport["canonical_public_chain"] == "Caddy -> Kong -> middleware-integration-api:8095"
    assert transport["side_effecting_gateway_retries"] == 0
    assert transport["direct_provider_routing_allowed"] is False
    assert transport["direct_odoo_routing_allowed"] is False
    assert transport["direct_n8n_execution_routing_allowed"] is False
    assert {
        "Authorization",
        "X-Correlation-ID",
        "Idempotency-Key",
        "traceparent",
        "tracestate",
    } <= set(transport["preserve_headers"])


def test_postman_route_cases_are_bound_to_final_middleware_digest() -> None:
    cases = json.loads(
        (ROOT / "postman" / "kong-v3-parity-route-cases.v1.json").read_text(encoding="utf-8")
    )
    assert cases["source_contract_sha256"] == CONFIG["sources"]["middleware"]["contract_sha256"]
    assert cases["generated_test_data_only"] is True
    assert cases["route_family_counts"] == {
        "Automation V2": 13,
        "CRM Contacts": 9,
        "CRM Opportunities": 4,
        "CRM Tasks": 2,
        "CRM Tickets": 4,
        "Webhook & Event Ingress": 3,
    }
    assert len(cases["routes"]) == 35
