#!/usr/bin/env python3
"""Validate the PAS-149 Kong webhook/event-ingress registry.

The registry is transport metadata only. It must agree with the exact
Middleware public contract and Caddy edge declarations, while leaving
signature semantics, replay state, durable event ledgers and business effects
outside Kong.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config" / "kong-webhook-registry.v1.json"
# Caddy rows name the gateway by this repository's current full name; the
# release registry contract is the single authority for that identity.
KONG_REPOSITORY = json.loads(
    (ROOT / "config" / "kong-release-registry-contract.v1.json").read_text(encoding="utf-8")
)["repository"]["fullName"]


class WebhookError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WebhookError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WebhookError(f"{path} must contain a JSON object")
    return value


def path_matches(pattern: str, concrete: str) -> bool:
    if pattern.endswith("*"):
        return concrete.startswith(pattern[:-1])
    if "|" in pattern:
        return concrete in pattern.split("|")
    return concrete == pattern


def validate_registry_shape(registry: dict[str, Any]) -> None:
    if registry.get("schema_version") != 1 or registry.get("kind") != "codestra.kong.webhook-registry.v1":
        raise WebhookError("invalid webhook registry schema")
    if registry.get("runtime_apply_authorized") is not False:
        raise WebhookError("webhook registry may not authorize runtime apply")
    if registry.get("provider_effects_enabled") is not False:
        raise WebhookError("webhook registry may not enable provider effects")
    invariants = registry.get("invariants") or {}
    if invariants.get("direct_provider_routes") != 0:
        raise WebhookError("direct provider routes must be zero")
    if invariants.get("direct_odoo_routes") != 0:
        raise WebhookError("direct Odoo routes must be zero")
    if invariants.get("direct_n8n_execution_routes") != 0:
        raise WebhookError("direct n8n execution routes must be zero")


def validate_against_middleware(registry: dict[str, Any], middleware_repo: Path) -> dict[str, Any]:
    contract = load_json(middleware_repo / "deploy" / "public-api-route-contract.json")
    routes = {
        (str(row.get("method")), str(row.get("path"))): row
        for row in contract.get("routes", [])
    }
    for entry in registry["canonical_entries"]:
        key = (entry["method"], entry["path"])
        row = routes.get(key)
        if row is None:
            raise WebhookError(f"canonical webhook route missing from Middleware: {key}")
        if row.get("classification") != "shared_edge":
            raise WebhookError(f"canonical webhook is not shared_edge: {key}")
        for field, source_field in (
            ("audience", "audience"),
            ("scope", "scope"),
            ("auth", "auth"),
        ):
            if entry[field] != row.get(source_field):
                raise WebhookError(f"{entry['id']} {field} drift")
        caller = row.get("calling_client")
        callers = caller if isinstance(caller, list) else [caller]
        if entry["calling_client"] not in callers:
            raise WebhookError(f"{entry['id']} caller drift")
        idem = row.get("idempotency") or {}
        if entry["idempotency"] != {
            "required": idem.get("required"),
            "carrier": idem.get("carrier"),
        }:
            raise WebhookError(f"{entry['id']} idempotency drift")
        if entry["gateway"] != "Kong" or entry["upstream"] != "middleware-integration-api:8095":
            raise WebhookError(f"{entry['id']} bypasses canonical upstream")
        if entry["event_ledger_owner"] != "Middleware":
            raise WebhookError(f"{entry['id']} duplicates provider event ledger ownership")
        if entry["gateway_retries"] != 0:
            raise WebhookError(f"{entry['id']} gateway retries must be zero")

    concrete_paths = [str(row.get("path")) for row in contract.get("routes", [])]
    for entry in registry["pending_denied_entries"]:
        if any(path_matches(entry["path_pattern"], path) for path in concrete_paths):
            raise WebhookError(
                f"pending-denied webhook unexpectedly exists in Middleware: {entry['path_pattern']}"
            )
        if entry.get("classification") != "DENIED_PENDING_CONTRACT":
            raise WebhookError(f"{entry['id']} must remain DENIED_PENDING_CONTRACT")
        if entry.get("expected_public_status") != 404:
            raise WebhookError(f"{entry['id']} must fail public ingress with 404")

    return {
        "canonical": len(registry["canonical_entries"]),
        "pending_denied": len(registry["pending_denied_entries"]),
    }


def validate_against_caddy(registry: dict[str, Any], caddy_repo: Path) -> dict[str, Any]:
    caddy_webhooks = load_json(caddy_repo / "config" / "webhook-edge-registry.v1.json")
    public_edge = load_json(caddy_repo / "config" / "public-edge-registry.v1.json")
    caddy_webhook_by_path = {
        str(row.get("path")): row
        for row in caddy_webhooks.get("entries", [])
    }
    edge_entries = public_edge.get("entries", [])

    # Odoo/n8n have explicit Caddy webhook rows. GitHub is covered by /platform/v1/*.
    for entry in registry["canonical_entries"]:
        if entry["id"] in {"odoo-events", "n8n-results"}:
            row = caddy_webhook_by_path.get(entry["path"])
            if not row or row.get("classification") != "CANONICAL":
                raise WebhookError(f"Caddy canonical webhook missing: {entry['path']}")
            if row.get("gateway") != KONG_REPOSITORY:
                raise WebhookError(f"Caddy webhook does not hand off to Kong: {entry['path']}")
        elif entry["id"] == "github-events":
            row = next(
                (
                    item
                    for item in edge_entries
                    if item.get("path") == "/platform/v1/*"
                    and item.get("classification") == "CANONICAL"
                    and item.get("gateway") == KONG_REPOSITORY
                ),
                None,
            )
            if row is None:
                raise WebhookError("Caddy /platform/v1/* canonical edge missing for GitHub events")

    for entry in registry["pending_denied_entries"]:
        matched = [
            row
            for row in edge_entries
            if row.get("classification") == "DENIED_PENDING_CONTRACT"
            and (
                path_matches(str(row.get("path", "")), entry["path_pattern"])
                or path_matches(entry["path_pattern"], str(row.get("path", "")))
            )
        ]
        if not matched:
            raise WebhookError(f"Caddy pending denial missing: {entry['path_pattern']}")
        if not all(row.get("expected_public_status") == 404 for row in matched):
            raise WebhookError(f"Caddy pending denial is not 404: {entry['path_pattern']}")

    return {
        "canonical_handoffs": 3,
        "pending_denials": len(registry["pending_denied_entries"]),
    }


def certify(middleware_repo: Path, caddy_repo: Path) -> dict[str, Any]:
    registry = load_json(REGISTRY_PATH)
    validate_registry_shape(registry)
    middleware = validate_against_middleware(registry, middleware_repo)
    caddy = validate_against_caddy(registry, caddy_repo)
    return {
        "verdict": "PASS",
        "middleware": middleware,
        "caddy": caddy,
        "direct_provider_routes": 0,
        "direct_odoo_routes": 0,
        "direct_n8n_execution_routes": 0,
        "runtime_apply_authorized": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--middleware-repo", type=Path, required=True)
    parser.add_argument("--caddy-repo", type=Path, required=True)
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = certify(args.middleware_repo.resolve(), args.caddy_repo.resolve())
    except WebhookError as exc:
        print("KONG_WEBHOOK_REGISTRY=FAIL")
        print(f"ERROR={exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("KONG_WEBHOOK_REGISTRY=PASS")
        print(f"CANONICAL_WEBHOOK_INGRESS={report['middleware']['canonical']}")
        print(f"PENDING_WEBHOOK_DENIALS={report['middleware']['pending_denied']}")
        print("DIRECT_PROVIDER_ROUTES=0")
        print("DIRECT_ODOO_ROUTES=0")
        print("DIRECT_N8N_EXECUTION_ROUTES=0")
        print("PROVIDER_EVENT_LEDGER_OWNER=MIDDLEWARE")
        print("RUNTIME_APPLY_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
