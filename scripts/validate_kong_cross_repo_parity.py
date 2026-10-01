#!/usr/bin/env python3
"""Validate Kong V3 cross-repository route/digest/transport parity.

PAS-149 is source-only. This validator never contacts Kong, Caddy, Keycloak,
Middleware, Redis, PostgreSQL, or any provider. It validates checked-out source
trees when paths are supplied.

During the four-lane parallel wave, Lane C may be validated with
--allow-pending-lane-a because its frozen Kong base intentionally still carries
the pre-Lane-A Middleware contract. The strict final gate omits that flag and
therefore requires Kong's checked-in contract to equal the final Middleware
digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PARITY_PATH = ROOT / "config" / "kong-cross-repo-parity.v1.json"
# Caddy rows name the gateway by this repository's current full name; the
# release registry contract is the single authority for that identity.
KONG_REPOSITORY = json.loads(
    (ROOT / "config" / "kong-release-registry-contract.v1.json").read_text(encoding="utf-8")
)["repository"]["fullName"]


class ParityError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParityError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ParityError(f"{path} must contain a JSON object")
    return value


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def resolve_repo_path(repo: Path, relative: str) -> Path:
    path = (repo / relative).resolve()
    try:
        path.relative_to(repo.resolve())
    except ValueError as exc:
        raise ParityError(f"path escapes repository: {relative}") from exc
    return path


def route_callers(row: dict[str, Any]) -> list[str]:
    value = row.get("calling_client")
    if isinstance(value, list):
        return [str(v) for v in value]
    return [] if value is None else [str(value)]


def validate_config(config: dict[str, Any]) -> None:
    if config.get("schema_version") != 1 or config.get("kind") != "codestra.kong.cross-repo-parity.v1":
        raise ParityError("invalid parity schema")
    if config.get("runtime_apply_authorized") is not False:
        raise ParityError("runtime apply must remain prohibited")
    if config.get("provider_effects_enabled") is not False:
        raise ParityError("provider effects must remain disabled")
    sources = config.get("sources")
    if not isinstance(sources, dict):
        raise ParityError("sources must be an object")
    for name in ("kong", "middleware", "caddy", "keycloak"):
        if name not in sources:
            raise ParityError(f"missing source pin: {name}")
    final = sources["middleware"]["contract_sha256"]
    if final != "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b":
        raise ParityError("unexpected final Middleware digest")
    if sources["kong"]["final_contract_sha256"] != final:
        raise ParityError("Kong final digest target differs from Middleware")
    if sources["caddy"]["required_middleware_contract_sha256"] != final:
        raise ParityError("Caddy final digest target differs from Middleware")
    if sources["keycloak"]["canonical_audience"] != "middleware-api":
        raise ParityError("Keycloak canonical audience must be middleware-api")
    transport = config["transport_invariants"]
    if transport["side_effecting_gateway_retries"] != 0:
        raise ParityError("side-effecting gateway retries must be zero")
    if transport["direct_provider_routing_allowed"] is not False:
        raise ParityError("direct provider routing must remain forbidden")
    if transport["direct_odoo_routing_allowed"] is not False:
        raise ParityError("direct Odoo routing must remain forbidden")
    if transport["direct_n8n_execution_routing_allowed"] is not False:
        raise ParityError("direct n8n execution routing must remain forbidden")


def matches_family(path: str, rule: dict[str, Any]) -> bool:
    prefix = rule.get("path_prefix")
    contains = rule.get("path_contains")
    if prefix is not None:
        return path.startswith(str(prefix))
    if contains is not None:
        return str(contains) in path
    return False


def validate_middleware(config: dict[str, Any], repo: Path) -> dict[str, Any]:
    source = config["sources"]["middleware"]
    contract = load_json(resolve_repo_path(repo, source["contract_path"]))
    digest = canonical_digest(contract)
    if digest != source["contract_sha256"]:
        raise ParityError(f"Middleware contract digest mismatch: {digest}")
    sha_path = resolve_repo_path(repo, source["contract_sha256_path"])
    if sha_path.read_text(encoding="utf-8").strip() != digest:
        raise ParityError("Middleware .sha256 pin disagrees with contract bytes")

    routes = contract.get("routes")
    if not isinstance(routes, list):
        raise ParityError("Middleware routes must be a list")
    counts = Counter(str(row.get("classification")) for row in routes)
    expected = source["route_counts"]
    observed = {
        "total": len(routes),
        "shared_edge": counts["shared_edge"],
        "denied": counts["denied"],
        "private_only": counts["private_only"],
    }
    if observed != expected:
        raise ParityError(f"Middleware route counts mismatch: {observed}")

    family_counts = Counter()
    family_rules = config["required_route_families"]
    for family, rule in family_rules.items():
        family_counts[family] = sum(
            1
            for row in routes
            if matches_family(str(row.get("path", "")), rule)
        )
        observed_count = family_counts[family]
        if "exact_routes" in rule and observed_count != rule["exact_routes"]:
            raise ParityError(f"{family} route count {observed_count} != {rule['exact_routes']}")
        if "minimum_routes" in rule and observed_count < rule["minimum_routes"]:
            raise ParityError(f"{family} route count {observed_count} < {rule['minimum_routes']}")

    selected_mutations = [
        row for row in routes
        if any(
            matches_family(str(row.get("path", "")), rule)
            for rule in family_rules.values()
        )
        and str(row.get("method")) in {"POST", "PUT", "PATCH", "DELETE"}
    ]
    for row in selected_mutations:
        idem = row.get("idempotency") or {}
        if idem.get("required") is not True:
            raise ParityError(f"mutation lacks idempotency: {row.get('method')} {row.get('path')}")
        if idem.get("carrier") in (None, "", "none"):
            raise ParityError(f"mutation has no idempotency carrier: {row.get('path')}")

    callers = sorted(
        {
            caller
            for row in routes
            for caller in route_callers(row)
            if caller and caller != "none"
        }
    )
    return {
        "digest": digest,
        "route_counts": observed,
        "family_counts": dict(sorted(family_counts.items())),
        "caller_selectors": callers,
    }


def _yaml_middleware_services(path: Path) -> list[dict[str, Any]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("host") == "middleware-integration-api" and int(value.get("port", 0) or 0) == 8095:
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    return found


def validate_kong(
    config: dict[str, Any],
    repo: Path,
    *,
    allow_pending_lane_a: bool,
) -> dict[str, Any]:
    source = config["sources"]["kong"]
    contract = load_json(resolve_repo_path(repo, source["contract_path"]))
    observed = canonical_digest(contract)
    final_digest = source["final_contract_sha256"]
    base_digest = source["base_contract_sha256"]
    pending = False
    if observed != final_digest:
        if allow_pending_lane_a and observed == base_digest:
            pending = True
        else:
            raise ParityError(
                f"Kong Middleware contract not final: observed={observed} expected={final_digest}"
            )

    for relative in (
        "config/kong-middleware-routes.production.yml",
        "config/staging/kong-middleware-routes.staging.yml",
    ):
        services = _yaml_middleware_services(resolve_repo_path(repo, relative))
        if not services:
            raise ParityError(f"{relative}: no middleware-integration-api:8095 service found")
        for service in services:
            if service.get("retries") != 0:
                raise ParityError(f"{relative}: Middleware gateway retries must be 0")

    authority = load_json(resolve_repo_path(repo, source["authority_path"]))
    upstream = authority.get("upstream") or {}
    if upstream.get("host") != "middleware-integration-api" or upstream.get("port") != 8095:
        raise ParityError("Kong authority upstream is not middleware-integration-api:8095")
    if authority.get("runtime_apply_authorized") is not False:
        raise ParityError("Kong authority runtime apply must remain false")
    if authority.get("provider_effects_enabled") is not False:
        raise ParityError("Kong authority provider effects must remain false")

    return {
        "observed_contract_sha256": observed,
        "final_contract_sha256": final_digest,
        "pending_lane_a": pending,
        "upstream": "middleware-integration-api:8095",
        "side_effecting_gateway_retries": 0,
    }


def validate_caddy(config: dict[str, Any], repo: Path) -> dict[str, Any]:
    source = config["sources"]["caddy"]
    edge = load_json(resolve_repo_path(repo, source["public_edge_registry"]))
    final_digest = config["sources"]["middleware"]["contract_sha256"]
    if edge.get("middleware_public_contract_sha256") != final_digest:
        raise ParityError("Caddy public-edge registry does not pin final Middleware digest")
    entries = edge.get("entries")
    if not isinstance(entries, list):
        raise ParityError("Caddy edge entries must be a list")

    by_path = {str(row.get("path")): row for row in entries}
    for path in source["required_public_namespaces"]:
        row = by_path.get(path)
        if not row or row.get("classification") != "CANONICAL" or row.get("gateway") != KONG_REPOSITORY:
            raise ParityError(f"Caddy canonical Kong namespace missing: {path}")
        if row.get("legacy_fallback") is not False:
            raise ParityError(f"Caddy namespace may fall back to legacy: {path}")
    for path in source["required_private_denials"]:
        row = by_path.get(path)
        if not row or row.get("classification") != "PRIVATE" or row.get("expected_public_status") != 404:
            raise ParityError(f"Caddy private denial missing: {path}")

    chain = load_json(resolve_repo_path(repo, source["edge_contract_chain"]))
    if chain.get("middleware", {}).get("public_contract_sha256") != final_digest:
        raise ParityError("Caddy edge chain Middleware digest mismatch")
    if chain.get("kong", {}).get("required_sha256") != final_digest:
        raise ParityError("Caddy edge chain does not require final Kong digest")

    return {
        "middleware_contract_sha256": final_digest,
        "required_namespaces": len(source["required_public_namespaces"]),
        "private_denials": len(source["required_private_denials"]),
        "caddy_requires_final_kong_digest": True,
        "caddy_snapshot_kong_status": chain.get("kong", {}).get("status"),
    }


def validate_keycloak(config: dict[str, Any], repo: Path) -> dict[str, Any]:
    source = config["sources"]["keycloak"]
    callers = load_json(resolve_repo_path(repo, source["caller_contract_path"]))
    token_matrix = load_json(resolve_repo_path(repo, source["token_matrix_path"]))
    caller_map = callers.get("callers")
    if not isinstance(caller_map, dict):
        raise ParityError("Keycloak caller contract lacks callers")
    if "platform-command-client" not in caller_map:
        raise ParityError("Keycloak caller contract lacks platform-command-client")
    if callers.get("middleware", {}).get("canonicalAudience") != "middleware-api":
        raise ParityError("Keycloak caller contract audience mismatch")
    dimensions = set(token_matrix.get("requiredDimensions") or [])
    required = {"issuer", "audience", "azp", "tenant", "scope", "role", "expiry", "replay"}
    if dimensions != required:
        raise ParityError("Keycloak token matrix dimensions incomplete")
    return {
        "caller_count": len(caller_map),
        "token_dimensions": len(dimensions),
        "audience": "middleware-api",
    }


def certify(
    *,
    kong_repo: Path,
    middleware_repo: Path,
    caddy_repo: Path,
    keycloak_repo: Path | None,
    allow_pending_lane_a: bool,
) -> dict[str, Any]:
    config = load_json(PARITY_PATH)
    validate_config(config)
    middleware = validate_middleware(config, middleware_repo)
    kong = validate_kong(config, kong_repo, allow_pending_lane_a=allow_pending_lane_a)
    caddy = validate_caddy(config, caddy_repo)
    keycloak = validate_keycloak(config, keycloak_repo) if keycloak_repo else None

    status = "PENDING_LANE_A" if kong["pending_lane_a"] else "PASS"
    return {
        "verdict": status,
        "middleware": middleware,
        "kong": kong,
        "caddy": caddy,
        "keycloak": keycloak,
        "runtime_apply_authorized": False,
        "provider_effects_enabled": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kong-repo", type=Path, default=ROOT)
    parser.add_argument("--middleware-repo", type=Path, required=True)
    parser.add_argument("--caddy-repo", type=Path, required=True)
    parser.add_argument("--keycloak-repo", type=Path)
    parser.add_argument("--allow-pending-lane-a", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = certify(
            kong_repo=args.kong_repo.resolve(),
            middleware_repo=args.middleware_repo.resolve(),
            caddy_repo=args.caddy_repo.resolve(),
            keycloak_repo=args.keycloak_repo.resolve() if args.keycloak_repo else None,
            allow_pending_lane_a=args.allow_pending_lane_a,
        )
    except ParityError as exc:
        print("KONG_CROSS_REPO_PARITY=FAIL")
        print(f"ERROR={exc}")
        return 1

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"KONG_CROSS_REPO_PARITY={report['verdict']}")
        print("MIDDLEWARE_FINAL_CONTRACT=PASS")
        print(f"MIDDLEWARE_ROUTE_COUNT={report['middleware']['route_counts']['total']}")
        print("CRM_AUTOMATION_ROUTE_PARITY=PASS")
        print("CADDY_EXPECTS_FINAL_KONG_DIGEST=PASS")
        print(
            "CADDY_KONG_MIDDLEWARE_DIGEST_CHAIN="
            + ("PENDING_LANE_A" if report["kong"]["pending_lane_a"] else "PASS")
        )
        print(
            "KONG_FINAL_CONTRACT_REPIN="
            + ("PENDING_LANE_A" if report["kong"]["pending_lane_a"] else "PASS")
        )
        print("GATEWAY_RETRIES_SIDE_EFFECTING=0")
        if report["keycloak"]:
            print("KEYCLOAK_CALLER_TOKEN_CONTRACT=PASS")
        print("RUNTIME_APPLY_AUTHORIZED=NO")
        print("PROVIDER_EFFECTS_ENABLED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
