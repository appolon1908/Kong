#!/usr/bin/env python3
"""Read-only PAS-236 Kong route reconciliation planner.

This tool never mutates Kong. It reads the bounded private Admin API, compares
live route/service/plugin bindings with governed source authorities, and emits a
fail-closed plan for later independently gated snapshot/apply/rollback work.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import (
    DEFAULT_CONTAINER,
    PRIVATE_ADMIN_URL,
    admin_request,
    collect_admin_rows,
    normalize_admin_reference,
)

ALLOWED_DECISIONS = {"REPOINT", "RETIRE", "EXCEPTION"}
CANONICAL_UPSTREAM = {"host": "middleware-integration-api", "port": 8095}
REQUIRED_RELEASE_GATES = (
    "SNAPSHOT",
    "ROLLBACK_PACKAGE",
    "GATED_APPLY",
    "POST_APPLY_VERIFY",
)
ROUTE_SHAPE_FIELDS = ("hosts", "paths", "methods", "protocols", "strip_path", "preserve_host")


def _matching_value(value):
    # These route arrays are matching sets; plugin config arrays are not.
    if isinstance(value, list):
        return sorted(value, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def request(path: str, *, container=DEFAULT_CONTAINER, traditional_approval=None) -> dict:
    return admin_request("GET", normalize_admin_reference(path), container=container,
                         traditional_approval=traditional_approval) or {}


def all_rows(path: str, *, container=DEFAULT_CONTAINER, traditional_approval=None) -> list[dict]:
    return collect_admin_rows(lambda ref: request(ref, container=container,
        traditional_approval=traditional_approval), path, normalize_admin_reference)


def upstream_for(route: dict, services: dict[str, dict]) -> dict:
    service_id = (route.get("service") or {}).get("id")
    service = services.get(service_id, {})
    return {
        "service": service.get("name"),
        "host": service.get("host"),
        "port": service.get("port"),
        "protocol": service.get("protocol"),
    }


def plugin_names_for(route: dict, plugins: list[dict]) -> list[str]:
    route_id = route.get("id")
    names = {
        str(plugin.get("name"))
        for plugin in plugins
        if plugin.get("enabled", True)
        and (plugin.get("route") or {}).get("id") == route_id
        and plugin.get("name")
    }
    return sorted(names)


def validate_manifest(manifest: dict) -> None:
    if manifest.get("runtime_apply_authorized") is not False:
        raise RuntimeError("planner manifest must keep runtime_apply_authorized=false")
    if manifest.get("canonical_public_upstream") != CANONICAL_UPSTREAM:
        raise RuntimeError(
            "canonical_public_upstream must match config/kong-middleware-authority.v2.json"
        )
    rows = manifest.get("routes")
    if not isinstance(rows, list) or len(rows) != 24:
        raise RuntimeError("PAS-236 manifest must contain exactly 24 route dispositions")
    names = [row.get("name") for row in rows]
    if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
        raise RuntimeError("route disposition names must be unique non-empty strings")
    for row in rows:
        decision = row.get("decision")
        if decision not in ALLOWED_DECISIONS:
            raise RuntimeError(f"unsupported route disposition: {row.get("name")}")
        if decision == "REPOINT":
            if row.get("target") != CANONICAL_UPSTREAM:
                raise RuntimeError(f"invalid canonical target: {row.get("name")}")
        elif decision == "RETIRE":
            successor = row.get("successor")
            deny_authority = row.get("deny_authority")
            if not successor and deny_authority != "activationBlockedRoutes":
                raise RuntimeError(
                    f"retirement requires successor or activationBlockedRoutes deny authority: "
                    f"{row.get("name")}"
                )
        elif decision == "EXCEPTION":
            expected = row.get("expected")
            if not isinstance(expected, dict) or not expected.get("host") or not expected.get("port"):
                raise RuntimeError(f"invalid exception target: {row.get("name")}")


def build_plan(
    manifest: dict,
    routes: list[dict],
    services: list[dict],
    plugins: list[dict],
    authority_routes: dict[str, dict],
    activation_blocked_routes: set[str],
) -> dict:
    validate_manifest(manifest)
    by_route: dict[str, list[dict]] = {}
    for route in routes:
        if route.get("name"):
            by_route.setdefault(route["name"], []).append(route)
    service_by_id = {row["id"]: row for row in services if isinstance(row.get("id"), str)}

    plan = []
    for spec in sorted(manifest["routes"], key=lambda item: item["name"]):
        matches = by_route.get(spec["name"], [])
        if not matches and spec["decision"] == "RETIRE":
            item={"route":spec["name"],"decision":"RETIRE","action":"KEEP","reason":"already_retired"}
            if spec.get("successor"):
                item["successor"]=spec["successor"]
                item["successor_present"]=len(by_route.get(spec["successor"], []))==1
                if not item["successor_present"]:
                    item.update(action="ERROR",reason="required_successor_missing")
            else:
                item["deny_authority"]=spec.get("deny_authority")
                item["deny_authority_present"]=spec["name"] in activation_blocked_routes
                if not item["deny_authority_present"]:
                    item.update(action="ERROR",reason="required_deny_authority_missing")
            plan.append(item)
            continue
        if len(matches) != 1:
            plan.append({
                "route": spec["name"],
                "decision": spec["decision"],
                "action": "ERROR",
                "reason": "missing_live_route" if not matches else "duplicate_live_route",
            })
            continue

        route = matches[0]
        current = upstream_for(route, service_by_id)
        decision = spec["decision"]
        item = {
            "route": spec["name"],
            "decision": decision,
            "current": current,
        }

        authority = authority_routes.get(spec["name"])
        if authority is not None:
            expected_plugins = sorted(authority.get("plugins") or [])
            current_plugins = plugin_names_for(route, plugins)
            item["security_plugins"] = {
                "expected": expected_plugins,
                "current": current_plugins,
            }
            if current_plugins != expected_plugins:
                item["action"] = "ERROR"
                item["reason"] = "plugin_security_drift"
                plan.append(item)
                continue
            shape_drift = [key for key in ROUTE_SHAPE_FIELDS
                           if key in authority and _matching_value(route.get(key)) != _matching_value(authority[key])]
            if shape_drift:
                item.update(action="ERROR", reason="route_shape_drift", fields=shape_drift)
                plan.append(item)
                continue
            service = service_by_id.get((route.get("service") or {}).get("id"), {})
            # REPOINT governs host/port only. It must not silently bless drift
            # in the preserved service identity, protocol or timeout policy.
            transport_drift = [key for key, value in (authority.get("service") or {}).items()
                               if key not in {"host", "port"} and service.get(key) != value]
            if transport_drift:
                item.update(action="ERROR", reason="service_transport_drift", fields=sorted(transport_drift))
                plan.append(item)
                continue

        if decision == "REPOINT":
            target = spec["target"]
            item["target"] = target
            item["action"] = (
                "KEEP"
                if current["host"] == target["host"] and current["port"] == target["port"]
                else "UPDATE"
            )
        elif decision == "RETIRE":
            item["action"] = "DELETE"
            if spec.get("successor"):
                item["successor"] = spec["successor"]
                item["successor_present"] = len(by_route.get(spec["successor"], [])) == 1
                if not item["successor_present"]:
                    item["action"] = "ERROR"
                    item["reason"] = "required_successor_missing"
            else:
                item["deny_authority"] = spec.get("deny_authority")
                item["deny_authority_present"] = spec["name"] in activation_blocked_routes
                if not item["deny_authority_present"]:
                    item["action"] = "ERROR"
                    item["reason"] = "required_deny_authority_missing"
        else:
            expected = spec["expected"]
            item["expected"] = expected
            item["action"] = (
                "KEEP"
                if current["host"] == expected["host"] and current["port"] == expected["port"]
                else "ERROR"
            )
            if item["action"] == "ERROR":
                item["reason"] = "exception_upstream_drift"
        if spec.get("note"):
            item["note"] = spec["note"]
        plan.append(item)

    counts = {}
    for item in plan:
        counts[item["action"]] = counts.get(item["action"], 0) + 1
    return {
        "schema": "codestra.kong.route-reconciliation-plan.pas236.v2",
        "mode": "dry-run",
        "admin_channel": PRIVATE_ADMIN_URL,
        "runtime_apply_performed": False,
        "runtime_apply_authorized": False,
        "required_release_gates": list(REQUIRED_RELEASE_GATES),
        "source_main_sha": manifest["source_main_sha"],
        "canonical_public_upstream": CANONICAL_UPSTREAM,
        "summary": dict(sorted(counts.items())),
        "plan": plan,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/kong-route-reconciliation.pas236.json"),
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=Path("config/kong-production-route-inventory.v2.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--container", default=DEFAULT_CONTAINER,
                        help="private Admin container; role and listeners are verified by the Admin channel")
    parser.add_argument("--traditional-approval", help="review reference required for the Traditional management node")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    authority_routes = {
        row["name"]: row
        for row in inventory.get("routes", [])
        if isinstance(row.get("name"), str)
    }
    activation_blocked_routes = {
        row["route"]
        for row in inventory.get("activationBlockedRoutes", [])
        if isinstance(row.get("route"), str) and row.get("activationAuthorized") is False
    }
    result = build_plan(
        manifest,
        all_rows("/routes?size=1000", container=args.container, traditional_approval=args.traditional_approval),
        all_rows("/services?size=1000", container=args.container, traditional_approval=args.traditional_approval),
        all_rows("/plugins?size=1000", container=args.container, traditional_approval=args.traditional_approval),
        authority_routes,
        activation_blocked_routes,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if any(item["action"] == "ERROR" for item in result["plan"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
