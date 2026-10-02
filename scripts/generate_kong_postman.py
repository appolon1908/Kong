#!/usr/bin/env python3
"""Generate PAS-149 Kong V3 contract-probe Postman artifacts.

The route-case file is a derived test snapshot, not gateway authority. It is
regenerated only from the exact Middleware public route contract and carries
that contract's canonical SHA-256. The Postman collection is then generated
only from that snapshot, so repository-only --check is deterministic.

The default environment is loopback and live execution is disabled unless the
operator explicitly sets RUN_KONG_V3_PARITY=true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "postman" / "kong-v3-parity-route-cases.v1.json"
COLLECTION_PATH = ROOT / "postman" / "Kong-V3-Integration-Parity.postman_collection.json"
ENVIRONMENT_PATH = ROOT / "postman" / "Kong-V3-Integration-Parity.postman_environment.json"
FINAL_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"


class PostmanError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PostmanError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PostmanError(f"{path} must contain a JSON object")
    return value


def dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def family(path: str) -> str | None:
    if path.startswith("/v2/automation/"):
        return "Automation V2"
    if "/contacts" in path:
        return "CRM Contacts"
    if path.startswith("/platform/v1/tasks"):
        return "CRM Tasks"
    if "/tickets" in path:
        return "CRM Tickets"
    if "/opportunities" in path:
        return "CRM Opportunities"
    if path in {
        "/api/v1/odoo/events",
        "/api/v1/integrations/n8n/results",
        "/platform/v1/integrations/github/events",
    }:
        return "Webhook & Event Ingress"
    return None


def route_case(row: dict[str, Any]) -> dict[str, Any]:
    caller = row.get("calling_client")
    callers = caller if isinstance(caller, list) else [caller]
    idem = row.get("idempotency") or {}
    return {
        "operation_id": row.get("operation_id"),
        "family": family(str(row.get("path"))),
        "method": row.get("method"),
        "path": row.get("path"),
        "classification": row.get("classification"),
        "calling_clients": [str(v) for v in callers if v is not None],
        "audience": row.get("audience"),
        "scope": row.get("scope"),
        "auth": row.get("auth"),
        "idempotency": {
            "required": bool(idem.get("required")),
            "carrier": idem.get("carrier", "none"),
        },
    }


def derive_cases(contract_path: Path) -> dict[str, Any]:
    contract = load_json(contract_path)
    digest = canonical_digest(contract)
    if digest != FINAL_DIGEST:
        raise PostmanError(f"Middleware contract digest is not final: {digest}")
    routes = [
        route_case(row)
        for row in contract.get("routes", [])
        if row.get("classification") == "shared_edge" and family(str(row.get("path", "")))
    ]
    if not routes:
        raise PostmanError("no PAS-149 route cases derived")
    routes.sort(key=lambda r: (r["family"], r["path"], r["method"]))

    counts: dict[str, int] = {}
    for row in routes:
        counts[row["family"]] = counts.get(row["family"], 0) + 1

    expected = {
        "Automation V2": 13,
        "CRM Contacts": 9,
        "CRM Tasks": 2,
        "CRM Tickets": 4,
        "CRM Opportunities": 4,
        "Webhook & Event Ingress": 3,
    }
    if counts != expected:
        raise PostmanError(f"derived route family counts mismatch: {counts}")

    return {
        "schema_version": 1,
        "kind": "codestra.kong.postman-route-cases.v1",
        "source_repository": "appolon1908/Middleware-",
        "source_sha": "2862af0aa97367b18cb360af69212abe4243a1ac",
        "source_contract_path": "deploy/public-api-route-contract.json",
        "source_contract_sha256": digest,
        "generated_test_data_only": True,
        "route_family_counts": counts,
        "routes": routes,
    }


def postman_path(path: str) -> str:
    return re.sub(r"\{([a-zA-Z0-9_]+)\}", r"{{\1}}", path)


def body_for(case: dict[str, Any]) -> str:
    carrier = case["idempotency"]["carrier"]
    if carrier == "body.idempotency_key":
        return json.dumps({"idempotency_key": "{{idempotency_key}}"}, indent=2)
    if carrier == "body.event_id":
        return json.dumps({"event_id": "{{event_id}}"}, indent=2)
    return "{}"


def headers_for(case: dict[str, Any], token_var: str = "bearer_token") -> list[dict[str, str]]:
    headers = [
        {"key": "Authorization", "value": f"Bearer {{{{{token_var}}}}}", "type": "text"},
        {"key": "X-Correlation-ID", "value": "{{correlation_id}}", "type": "text"},
        {"key": "Content-Type", "value": "application/json", "type": "text"},
    ]
    idem = case["idempotency"]
    if idem["required"] and idem["carrier"] == "Idempotency-Key":
        headers.append({"key": "Idempotency-Key", "value": "{{idempotency_key}}", "type": "text"})
    return headers


def request_item(case: dict[str, Any]) -> dict[str, Any]:
    method = str(case["method"])
    request: dict[str, Any] = {
        "method": method,
        "header": headers_for(case),
        "url": {
            "raw": "{{base_url}}" + postman_path(str(case["path"])),
            "host": ["{{base_url}}"],
            "path": [segment for segment in postman_path(str(case["path"])).strip("/").split("/") if segment],
        },
        "description": (
            f"Contract probe only. Source operation={case['operation_id']}; "
            f"caller={','.join(case['calling_clients'])}; audience={case['audience']}; "
            f"scope={case['scope']}; auth={case['auth']}. "
            "Business payload validity/effects remain Middleware-owned."
        ),
    }
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        request["body"] = {"mode": "raw", "raw": body_for(case), "options": {"raw": {"language": "json"}}}
    return {"name": f"{method} {case['path']}", "request": request}


def negative_item(
    name: str,
    method: str,
    path: str,
    *,
    token_var: str | None = "bearer_token",
    idempotency: bool = False,
    body: str | None = None,
    expectation: str,
) -> dict[str, Any]:
    headers = [
        {"key": "X-Correlation-ID", "value": "{{correlation_id}}", "type": "text"},
        {"key": "Content-Type", "value": "application/json", "type": "text"},
    ]
    if token_var:
        headers.insert(0, {"key": "Authorization", "value": f"Bearer {{{{{token_var}}}}}", "type": "text"})
    if idempotency:
        headers.append({"key": "Idempotency-Key", "value": "{{idempotency_key}}", "type": "text"})
    req: dict[str, Any] = {
        "method": method,
        "header": headers,
        "url": {
            "raw": "{{base_url}}" + path,
            "host": ["{{base_url}}"],
            "path": [segment for segment in path.strip("/").split("/") if segment],
        },
        "description": expectation,
    }
    if body is not None:
        req["body"] = {"mode": "raw", "raw": body, "options": {"raw": {"language": "json"}}}
    return {"name": name, "request": req}


def render_collection(cases: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases["routes"]:
        grouped.setdefault(case["family"], []).append(request_item(case))

    positive_folders = [
        {"name": name, "item": grouped[name]}
        for name in sorted(grouped)
    ]

    negatives = [
        negative_item("missing-token", "GET", "/platform/v1/contacts", token_var=None, expectation="Expect 401; no anonymous fallback."),
        negative_item("wrong-issuer", "GET", "/platform/v1/contacts", token_var="wrong_issuer_token", expectation="Expect 401 for issuer mismatch."),
        negative_item("wrong-audience", "GET", "/platform/v1/contacts", token_var="wrong_audience_token", expectation="Expect 401 for audience mismatch."),
        negative_item("wrong-azp", "GET", "/platform/v1/contacts", token_var="wrong_azp_token", expectation="Expect 403/401 for unauthorized caller."),
        negative_item("missing-scope", "GET", "/platform/v1/contacts", token_var="missing_scope_token", expectation="Expect 403 for missing required scope."),
        negative_item(
            "missing-idempotency",
            "POST",
            "/platform/v1/commands",
            body="{}",
            expectation="Expect fail-closed response because Idempotency-Key is absent.",
        ),
        negative_item("wrong-method", "PUT", "/platform/v1/contacts", expectation="Expect 404/405; no legacy fallback."),
        negative_item(
            "oversize-body",
            "POST",
            "/platform/v1/contacts",
            idempotency=True,
            body="{{oversize_payload}}",
            expectation="Expect gateway request-size rejection before Middleware.",
        ),
        negative_item("private-metrics", "GET", "/metrics", token_var=None, expectation="Expect public 404 before any upstream."),
        negative_item("private-internal", "GET", "/internal/health", token_var=None, expectation="Expect public 404 before any upstream."),
        negative_item("pending-telnexa", "POST", "/api/v1/events/telnexa", token_var=None, body="{}", expectation="Expect public 404; contract pending."),
        negative_item("pending-vicidial", "POST", "/webhooks/vicidial/call-result/test", token_var=None, body="{}", expectation="Expect public 404; contract pending."),
        negative_item("pending-n8n-ack", "POST", "/api/v1/n8n/acknowledgements", token_var=None, body="{}", expectation="Expect public 404; contract pending."),
        negative_item("pending-observability", "POST", "/v1/observability/incidents", token_var=None, body="{}", expectation="Expect public 404; contract pending."),
        negative_item("pending-sms-inbound", "POST", "/webhooks/sms/inbound/test", token_var=None, body="{}", expectation="Expect public 404; contract pending."),
    ]

    guard = {
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": [
                "if (pm.environment.get('RUN_KONG_V3_PARITY') !== 'true') {",
                "  throw new Error('Live parity execution is disabled. Use an isolated local/staging gateway and set RUN_KONG_V3_PARITY=true explicitly.');",
                "}",
            ],
        },
    }
    return {
        "info": {
            "_postman_id": "f0e2db5d-1490-4d4d-bb3d-kongv3parity",
            "name": "Kong V3 Integration Parity",
            "description": (
                "Generated source-only contract probes for PAS-149. "
                "Default target is loopback; no production activation or provider effect is authorized."
            ),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "event": [guard],
        "variable": [
            {"key": "source_contract_sha256", "value": cases["source_contract_sha256"]},
        ],
        "item": positive_folders + [{"name": "Negative Security & Edge", "item": negatives}],
    }


def render_environment() -> dict[str, Any]:
    values = [
        ("base_url", "http://127.0.0.1:8000"),
        ("RUN_KONG_V3_PARITY", "false"),
        ("bearer_token", ""),
        ("wrong_issuer_token", ""),
        ("wrong_audience_token", ""),
        ("wrong_azp_token", ""),
        ("missing_scope_token", ""),
        ("correlation_id", "TEST_SYN-kong-v3-parity"),
        ("idempotency_key", ""),
        ("event_id", "EVT-TEST-SYN-0001"),
        ("contact_id", "CONTACT-TEST-SYN"),
        ("note_id", "NOTE-TEST-SYN"),
        ("task_id", "TASK-TEST-SYN"),
        ("ticket_id", "TICKET-TEST-SYN"),
        ("opportunity_id", "OPP-TEST-SYN"),
        ("approval_id", "APPROVAL-TEST-SYN"),
        ("capability", "test-syn"),
        ("command_id", "CMD-TEST-SYN"),
        ("dead_letter_id", "DLQ-TEST-SYN"),
        ("job_id", "JOB-TEST-SYN"),
        ("oversize_payload", ""),
    ]
    return {
        "id": "4c9cce36-2091-4f42-kong-v3-parity-env",
        "name": "Kong V3 Integration Parity - Safe Local",
        "values": [
            {"key": key, "value": value, "enabled": True}
            for key, value in values
        ],
        "_postman_variable_scope": "environment",
        "_postman_exported_using": "Codestra PAS-149 deterministic generator",
    }


def check_artifact(path: Path, expected: Any) -> None:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    rendered = dump(expected)
    if current.replace("\r\n", "\n") != rendered:
        raise PostmanError(f"generated artifact is stale: {path.relative_to(ROOT)}")


def write_artifact(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump(value), encoding="utf-8", newline="\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--middleware-contract", type=Path)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.middleware_contract:
            cases = derive_cases(args.middleware_contract.resolve())
        else:
            cases = load_json(CASES_PATH)
            if cases.get("source_contract_sha256") != FINAL_DIGEST:
                raise PostmanError("checked-in route cases do not pin the final Middleware digest")

        collection = render_collection(cases)
        environment = render_environment()

        if args.write:
            write_artifact(CASES_PATH, cases)
            write_artifact(COLLECTION_PATH, collection)
            write_artifact(ENVIRONMENT_PATH, environment)

        if args.check:
            check_artifact(CASES_PATH, cases)
            check_artifact(COLLECTION_PATH, collection)
            check_artifact(ENVIRONMENT_PATH, environment)

    except PostmanError as exc:
        print("KONG_POSTMAN_GENERATION=FAIL")
        print(f"ERROR={exc}")
        return 1

    print("KONG_POSTMAN_GENERATION=PASS")
    print(f"SOURCE_CONTRACT_SHA256={cases['source_contract_sha256']}")
    print(f"ROUTE_CASES={len(cases['routes'])}")
    print("LIVE_RUN_DEFAULT=FALSE")
    print("DEFAULT_BASE_URL=http://127.0.0.1:8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
