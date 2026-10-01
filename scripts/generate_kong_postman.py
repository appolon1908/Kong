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
MCR_CONTRACT_PATH = ROOT / "config" / "kong-mcr-routes.v1.json"
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
        "source_repository": "ingtrader21-spec/Middleware-",
        "source_sha": "bd406a6508c8095a3f23b35149a2eebcb94c94c6",
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
        {"key": "Accept", "value": "application/json", "type": "text"},
    ]
    idem = case["idempotency"]
    if idem["required"] and idem["carrier"] == "Idempotency-Key":
        headers.append({"key": "Idempotency-Key", "value": "{{idempotency_key}}", "type": "text"})
    return headers


# Per-request assertions. Every item carries its own test script so a single
# request run from the Postman UI asserts exactly what a collection run does.
TEST_LOGIC = [
    "const body = pm.response.text();",
    "pm.test('no internal leakage in response', function () {",
    "  pm.expect(body).to.not.match(/Traceback|stack traceback|\\.lua:\\d+|psycopg|postgres(ql)?:\\/\\/|redis:\\/\\/|odoo:8069|middleware-integration-api|codestra-redis/i);",
    "});",
    "pm.test('no 5xx from gateway or upstream', function () {",
    "  pm.expect(pm.response.code).to.be.below(500);",
    "});",
    "if (spec.expect) {",
    "  pm.test('status is one of ' + spec.expect.join('/'), function () {",
    "    pm.expect(spec.expect).to.include(pm.response.code);",
    "  });",
    "}",
    "if (spec.mode === 'routed' || spec.mode === 'hard_denied') {",
    "  pm.test('request reached Middleware (no Kong route miss)', function () {",
    "    pm.expect(pm.response.code).to.not.equal(405);",
    "    pm.expect(body).to.not.include('no Route matched');",
    "  });",
    "}",
    "if (spec.mode === 'routed') {",
    "  pm.test('positive probe passed gateway authentication and routing', function () {",
    "    pm.expect([401, 403]).to.not.include(pm.response.code);",
    "    pm.expect(body).to.not.include('private_surface_not_found');",
    "  });",
    "}",
    "if (spec.mode === 'hard_denied') {",
    "  pm.test('execute stays hard-denied (no 2xx)', function () {",
    "    pm.expect(pm.response.code).to.not.be.within(200, 299);",
    "  });",
    "}",
    "if (spec.error) {",
    "  pm.test('normalized gateway error ' + spec.error, function () {",
    "    pm.expect(pm.response.headers.get('Content-Type') || '').to.include('application/json');",
    "    pm.expect(pm.response.json().error).to.equal(spec.error);",
    "  });",
    "}",
    "if (spec.echoCorrelation) {",
    "  pm.test('X-Correlation-ID echoed unchanged', function () {",
    "    pm.expect(pm.response.headers.get('X-Correlation-ID')).to.equal(pm.variables.get('correlation_id'));",
    "  });",
    "}",
]

MCR_PATH_VARIABLES = {"lead_id": "lead_id", "campaign_id": "mcr_campaign_id"}
MCR_HEADER_VALUES = {
    "X-Tenant-ID": "{{tenant_id}}",
    "X-Correlation-ID": "{{correlation_id}}",
    "Idempotency-Key": "{{idempotency_key}}",
    "X-Codestra-Event-ID": "{{event_id}}",
    "X-Codestra-Timestamp": "{{delivery_event_timestamp}}",
    "X-Codestra-Signature": "{{delivery_event_signature}}",
}
MCR_HEADER_VARIABLES = {"X-Codestra-Signature": "delivery_event_signature"}


def case_events(spec: dict[str, Any], required_vars: list[str]) -> list[dict[str, Any]]:
    """Item pre-request skips (never sends) a probe whose operator-supplied
    inputs are unset, so an empty token cannot produce a vacuous pass."""
    return [
        {
            "listen": "prerequest",
            "script": {
                "type": "text/javascript",
                "exec": [
                    f"const needs = {json.dumps(required_vars)};",
                    "const missing = needs.filter(function (k) { return !pm.variables.get(k); });",
                    "if (missing.length) {",
                    "  console.log('SKIPPED ' + pm.info.requestName + ': unset ' + missing.join(','));",
                    "  pm.execution.skipRequest();",
                    "}",
                ],
            },
        },
        {
            "listen": "test",
            "script": {
                "type": "text/javascript",
                "exec": [f"const spec = {json.dumps(spec, sort_keys=True)};", *TEST_LOGIC],
            },
        },
    ]


def url_for(path: str) -> dict[str, Any]:
    return {
        "raw": "{{base_url}}" + path,
        "host": ["{{base_url}}"],
        "path": [segment for segment in path.strip("/").split("/") if segment],
    }


def request_item(case: dict[str, Any]) -> dict[str, Any]:
    method = str(case["method"])
    request: dict[str, Any] = {
        "method": method,
        "header": headers_for(case),
        "url": url_for(postman_path(str(case["path"]))),
        "description": (
            f"Contract probe only. Source operation={case['operation_id']}; "
            f"caller={','.join(case['calling_clients'])}; audience={case['audience']}; "
            f"scope={case['scope']}; auth={case['auth']}. "
            "Business payload validity/effects remain Middleware-owned."
        ),
    }
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        request["body"] = {"mode": "raw", "raw": body_for(case), "options": {"raw": {"language": "json"}}}
    spec = {"mode": "routed", "expect": None, "error": None, "echoCorrelation": True}
    return {"name": f"{method} {case['path']}", "event": case_events(spec, ["bearer_token"]), "request": request}


def mcr_path(template: str) -> str:
    return re.sub(r"\{([a-zA-Z0-9_]+)\}", lambda m: "{{" + MCR_PATH_VARIABLES[m.group(1)] + "}}", template)


def mcr_headers(route: dict[str, Any], omit: str | None = None, token_var: str | None = "bearer_token") -> list[dict[str, str]]:
    headers = []
    if token_var:
        headers.append({"key": "Authorization", "value": f"Bearer {{{{{token_var}}}}}", "type": "text"})
    headers += [
        {"key": name, "value": MCR_HEADER_VALUES[name], "type": "text"}
        for name in route["requiredHeaders"]
        if name != omit
    ]
    headers += [
        {"key": "Content-Type", "value": "application/json", "type": "text"},
        {"key": "Accept", "value": "application/json", "type": "text"},
    ]
    return headers


def mcr_item(route: dict[str, Any]) -> dict[str, Any]:
    method = route["method"]
    request: dict[str, Any] = {
        "method": method,
        "header": mcr_headers(route),
        "url": url_for(mcr_path(route["pathTemplate"])),
        "description": (
            f"MCR contract probe only. route={route['name']}; scope={route['requiredScope']}; "
            f"upstream={route['serviceHost']}:{route['servicePort']}; effects={route['effects']}."
        ),
    }
    if method == "POST":
        request["body"] = {"mode": "raw", "raw": "{}", "options": {"raw": {"language": "json"}}}
    hard_denied = route["effects"] == "hard_denied_by_middleware"
    spec = {"mode": "hard_denied" if hard_denied else "routed", "expect": None, "error": None, "echoCorrelation": True}
    needs = ["bearer_token"] + [MCR_HEADER_VARIABLES[h] for h in route["requiredHeaders"] if h in MCR_HEADER_VARIABLES]
    return {"name": f"{method} {route['pathTemplate']}", "event": case_events(spec, needs), "request": request}


def negative_item(
    name: str,
    method: str,
    path: str,
    *,
    expect: list[int],
    token_var: str | None = "bearer_token",
    idempotency: bool = False,
    body: str | None = None,
    headers: list[dict[str, str]] | None = None,
    error: str | None = None,
    echo: bool = False,
    expectation: str,
) -> dict[str, Any]:
    if headers is None:
        headers = [
            {"key": "X-Correlation-ID", "value": "{{correlation_id}}", "type": "text"},
            {"key": "Content-Type", "value": "application/json", "type": "text"},
            {"key": "Accept", "value": "application/json", "type": "text"},
        ]
        if token_var:
            headers.insert(0, {"key": "Authorization", "value": f"Bearer {{{{{token_var}}}}}", "type": "text"})
        if idempotency:
            headers.append({"key": "Idempotency-Key", "value": "{{idempotency_key}}", "type": "text"})
    req: dict[str, Any] = {
        "method": method,
        "header": headers,
        "url": url_for(path),
        "description": expectation,
    }
    if body is not None:
        req["body"] = {"mode": "raw", "raw": body, "options": {"raw": {"language": "json"}}}
    spec = {"mode": "denied", "expect": expect, "error": error, "echoCorrelation": echo}
    return {"name": name, "event": case_events(spec, [token_var] if token_var else []), "request": req}


def mcr_negatives(mcr: dict[str, Any]) -> list[dict[str, Any]]:
    routes = {route["name"]: route for route in mcr["routes"]}
    codes = mcr["headerPolicy"]["gatewayErrors"]["missingHeaderCodes"]
    status = mcr["headerPolicy"]["gatewayErrors"]["missingHeaderStatus"]

    def missing(name: str, route_name: str, header: str) -> dict[str, Any]:
        route = routes[route_name]
        return negative_item(
            name,
            route["method"],
            mcr_path(route["pathTemplate"]),
            expect=[status],
            headers=mcr_headers(route, omit=header),
            body="{}" if route["method"] == "POST" else None,
            error=codes[header],
            expectation=f"Expect {status} {codes[header]} from the gateway header guard before Middleware.",
        )

    status_route = routes["mcr-status"]
    return [
        missing("mcr-missing-tenant", "mcr-plan", "X-Tenant-ID"),
        missing("mcr-missing-correlation", "mcr-status", "X-Correlation-ID"),
        missing("mcr-execute-missing-idempotency", "mcr-execute", "Idempotency-Key"),
        missing("mcr-delivery-missing-signature", "mcr-delivery-events", "X-Codestra-Signature"),
        negative_item(
            "mcr-missing-token",
            status_route["method"],
            mcr_path(status_route["pathTemplate"]),
            expect=[401],
            token_var=None,
            headers=mcr_headers(status_route, token_var=None),
            echo=True,
            expectation="Expect 401; no anonymous MCR access.",
        ),
        negative_item("mcr-wrong-method", "DELETE", "/platform/v1/suppressions", expect=[404, 405], expectation="Expect 404/405; no MCR route for DELETE."),
        negative_item(
            "mcr-private-campaign-namespace",
            "GET",
            "/platform/v1/campaigns/odoo:CAMP-TEST-SYN/eligible-leads",
            expect=[404],
            expectation="Expect 404; only klyrow:/whatsapp: campaign namespaces route.",
        ),
        negative_item("mcr-internal-prefix", "GET", "/internal/platform/v1/campaign-engine/status", token_var=None, expect=[404], expectation="Expect public 404 before any upstream."),
        negative_item(
            "mcr-private-odoo-actual-state",
            "POST",
            "/api/v1/integration/campaigns/actual-state",
            token_var=None,
            body="{}",
            expect=[404],
            expectation="Expect public 404; private_only Odoo/DB surface is never gateway-routed.",
        ),
    ]


def render_collection(cases: dict[str, Any], mcr: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases["routes"]:
        grouped.setdefault(case["family"], []).append(request_item(case))

    positive_folders = [
        {"name": name, "item": grouped[name]}
        for name in sorted(grouped)
    ]
    mcr_folder = {"name": "MCR Platform", "item": [mcr_item(route) for route in mcr["routes"]]}

    negatives = [
        negative_item("missing-token", "GET", "/platform/v1/contacts", token_var=None, expect=[401], echo=True, expectation="Expect 401; no anonymous fallback."),
        negative_item("wrong-issuer", "GET", "/platform/v1/contacts", token_var="wrong_issuer_token", expect=[401], echo=True, expectation="Expect 401 for issuer mismatch."),
        negative_item("wrong-audience", "GET", "/platform/v1/contacts", token_var="wrong_audience_token", expect=[401], echo=True, expectation="Expect 401 for audience mismatch."),
        negative_item("wrong-azp", "GET", "/platform/v1/contacts", token_var="wrong_azp_token", expect=[401, 403], echo=True, expectation="Expect 403/401 for unauthorized caller."),
        negative_item("missing-scope", "GET", "/platform/v1/contacts", token_var="missing_scope_token", expect=[403], echo=True, expectation="Expect 403 for missing required scope."),
        negative_item(
            "missing-idempotency",
            "POST",
            "/platform/v1/commands",
            body="{}",
            expect=[400, 409, 422, 428],
            echo=True,
            expectation="Expect fail-closed response because Idempotency-Key is absent.",
        ),
        negative_item("wrong-method", "PUT", "/platform/v1/contacts", expect=[404, 405], expectation="Expect 404/405; no legacy fallback."),
        negative_item(
            "oversize-body",
            "POST",
            "/platform/v1/contacts",
            idempotency=True,
            body="{{oversize_payload}}",
            expect=[413],
            expectation="Expect gateway request-size rejection before Middleware.",
        ),
        negative_item("private-metrics", "GET", "/metrics", token_var=None, expect=[404], expectation="Expect public 404 before any upstream."),
        negative_item("private-internal", "GET", "/internal/health", token_var=None, expect=[404], expectation="Expect public 404 before any upstream."),
        negative_item("pending-telnexa", "POST", "/api/v1/events/telnexa", token_var=None, body="{}", expect=[404], expectation="Expect public 404; contract pending."),
        negative_item("pending-vicidial", "POST", "/webhooks/vicidial/call-result/test", token_var=None, body="{}", expect=[404], expectation="Expect public 404; contract pending."),
        negative_item("pending-n8n-ack", "POST", "/api/v1/n8n/acknowledgements", token_var=None, body="{}", expect=[404], expectation="Expect public 404; contract pending."),
        negative_item("pending-observability", "POST", "/v1/observability/incidents", token_var=None, body="{}", expect=[404], expectation="Expect public 404; contract pending."),
        negative_item("pending-sms-inbound", "POST", "/webhooks/sms/inbound/test", token_var=None, body="{}", expect=[404], expectation="Expect public 404; contract pending."),
    ]

    guard = {
        "listen": "prerequest",
        "script": {
            "type": "text/javascript",
            "exec": [
                "const base = String(pm.variables.get('base_url') || '');",
                "const loopback = /^https?:\\/\\/(127\\.0\\.0\\.1|localhost|\\[::1\\])(:\\d+)?$/.test(base);",
                "const staging = /^https:\\/\\/[a-z0-9.-]*staging[a-z0-9.-]*(:\\d+)?$/.test(base);",
                "if (pm.environment.get('RUN_KONG_V3_PARITY') !== 'true') {",
                "  // Live parity execution is disabled unless explicitly enabled.",
                "  pm.execution.skipRequest();",
                "} else if (!loopback && !staging) {",
                "  // An enabled run aimed outside loopback/staging is operator error. A bare",
                "  // throw does not stop Newman from sending the request, and Newman drops a",
                "  // throw after skipRequest(); a failed assertion fails the run instead.",
                "  const refusal = 'Refusing base_url outside loopback/staging: ' + base;",
                "  console.error('KONG_V3_PARITY_GUARD=REFUSED ' + refusal);",
                "  pm.test('live parity target is loopback or staging', function () { throw new Error(refusal); });",
                "  pm.execution.skipRequest();",
                "} else {",
                "  pm.variables.set('correlation_id', 'TEST_SYN-' + pm.variables.replaceIn('{{$guid}}'));",
                "  if (!pm.environment.get('idempotency_key')) {",
                "    pm.variables.set('idempotency_key', 'TEST_SYN-' + pm.variables.replaceIn('{{$guid}}'));",
                "  }",
                "  if (!pm.environment.get('delivery_event_timestamp')) {",
                "    pm.variables.set('delivery_event_timestamp', new Date().toISOString());",
                "  }",
                "  if (!pm.environment.get('oversize_payload')) {",
                "    pm.variables.set('oversize_payload', JSON.stringify({ pad: 'x'.repeat(2 * 1024 * 1024 + 1) }));",
                "  }",
                "}",
            ],
        },
    }
    return {
        "info": {
            "_postman_id": "f0e2db5d-1490-4d4d-bb3d-kongv3parity",
            "name": "Kong V3 Integration Parity",
            "description": (
                "Generated source-only contract probes for PAS-149 and MCR-J. "
                "Default target is loopback; no production activation or provider effect is authorized."
            ),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "event": [guard],
        "variable": [
            {"key": "source_contract_sha256", "value": cases["source_contract_sha256"]},
            {"key": "mcr_contract_sha256", "value": canonical_digest(mcr)},
        ],
        "item": positive_folders
        + [mcr_folder, {"name": "Negative Security & Edge", "item": negatives}, {"name": "MCR Negative Security & Edge", "item": mcr_negatives(mcr)}],
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
        ("tenant_id", "TENANT-TEST-SYN"),
        ("lead_id", "LEAD-TEST-SYN"),
        ("mcr_campaign_id", "klyrow:CAMP-TEST-SYN"),
        ("delivery_event_timestamp", ""),
        ("delivery_event_signature", ""),
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

        collection = render_collection(cases, load_json(MCR_CONTRACT_PATH))
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
