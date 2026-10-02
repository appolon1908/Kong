from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/middleware-public-api-route-contract.v1.json"
PIN_PATH = ROOT / "config/middleware-public-api-route-contract.sha256"
CANONICAL_PATH = ROOT / "config/kong-canonical-middleware-routes.json"
AUTHORITY_PATH = ROOT / "config/kong-middleware-authority.v2.json"
PRODUCTION_PATH = ROOT / "config/kong-middleware-routes.production.yml"
STAGING_PATH = ROOT / "config/staging/kong-middleware-routes.staging.yml"

UPSTREAM_HOST = "middleware-integration-api"
UPSTREAM_PORT = 8095
EXPECTED_CONTRACT_SCHEMA = "codestra.middleware.public-api-route-contract.v2"
EXPECTED_CONTRACT_DIGEST = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
EXPECTED_CLASSIFICATION_COUNTS = {"shared_edge": 105, "denied": 10, "private_only": 2}
EXPECTED_ROUTE_COUNT = 117
REQUIRED_PLUGINS = [
    "openid-connect",
    "post-function",
    "correlation-id",
    "rate-limiting",
    "request-size-limiting",
]
PARAMETER_PATTERN = re.compile(r"\{[^{}]+\}")
PATH_VALUE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
# Client-asserted identity headers the gateway never trusts: cleared before the
# generated post-function mints the contract metadata. Kong's own X-Consumer-*
# headers are set by openid-connect after signature verification and are not
# in this list because they are gateway-owned, not client-supplied.
UNTRUSTED_IDENTITY_HEADERS = (
    "X-User-ID",
    "X-Username",
    "X-Email",
    "X-Roles",
    "X-Scopes",
    "X-Authenticated-UserID",
    "X-Authenticated-User",
    "X-Authenticated-Client",
    "X-Authenticated-Subject",
    "X-Authenticated-Tenant",
    "X-Authenticated-Campaign",
    "X-Authenticated-Role",
    "X-Authenticated-Email",
    "X-Codestra-Tenant",
    "X-Codestra-Scopes",
    "X-Codestra-Gateway-Secret",
    "X-Internal-Service",
    "X-Admin",
)


def canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_final_contract(contract: dict[str, Any], digest: str) -> None:
    if contract.get("schema") != EXPECTED_CONTRACT_SCHEMA:
        raise SystemExit(
            f"unexpected contract schema: {contract.get('schema')!r}; expected={EXPECTED_CONTRACT_SCHEMA}"
        )
    if digest != EXPECTED_CONTRACT_DIGEST:
        raise SystemExit(
            f"unexpected final Middleware digest: actual={digest} expected={EXPECTED_CONTRACT_DIGEST}"
        )

    routes = contract.get("routes")
    if not isinstance(routes, list) or len(routes) != EXPECTED_ROUTE_COUNT:
        raise SystemExit(
            f"unexpected final Middleware route count: actual={len(routes) if isinstance(routes, list) else 'invalid'} "
            f"expected={EXPECTED_ROUTE_COUNT}"
        )

    counts = {
        classification: sum(1 for row in routes if row.get("classification") == classification)
        for classification in EXPECTED_CLASSIFICATION_COUNTS
    }
    if counts != EXPECTED_CLASSIFICATION_COUNTS:
        raise SystemExit(
            f"unexpected final Middleware classification counts: actual={counts} "
            f"expected={EXPECTED_CLASSIFICATION_COUNTS}"
        )

    expected_upstream = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
    wrong_upstream = [
        (row.get("method"), row.get("path"), row.get("upstream"))
        for row in routes
        if row.get("classification") == "shared_edge" and row.get("upstream") != expected_upstream
    ]
    if wrong_upstream:
        raise SystemExit(
            "shared-edge Middleware upstream drift: "
            + json.dumps(wrong_upstream, sort_keys=True, separators=(",", ":"))
        )


def route_regex(path_template: str) -> str:
    cursor = 0
    parts: list[str] = []
    for match in PARAMETER_PATTERN.finditer(path_template):
        parts.append(re.escape(path_template[cursor : match.start()]))
        parts.append(PATH_VALUE_PATTERN)
        cursor = match.end()
    parts.append(re.escape(path_template[cursor:]))
    return "~^" + "".join(parts) + "$"


def safe_name(operation_id: str) -> str:
    return "middleware-" + re.sub(r"[^a-z0-9-]+", "-", operation_id.lower().replace("_", "-")).strip("-")


def regex_priority(path_template: str) -> int:
    """Kong prefers the higher ``regex_priority`` among regex routes of equal
    match weight. Every generated route is anchored, so two routes can only
    admit the same request at the same depth when one has a literal segment
    where the other has a parameter (``/tenants/authorized`` vs
    ``/tenants/{tenant_id}``); counting literal segments makes the literal
    route win deterministically instead of leaving the tie to the router."""
    return sum(1 for segment in path_template.strip("/").split("/") if not PARAMETER_PATTERN.fullmatch(segment))


def route_tags(row: dict[str, Any], classification: str) -> list[str]:
    """Kong tags restricted to [A-Za-z0-9_.~-]; the template is carried by the safe operation id."""
    return [f"codestra.classification.{classification}", f"codestra.operation.{safe_name(row['operation_id'])}"]


def service_tags(environment: str) -> list[str]:
    return [
        f"codestra.environment.{environment}",
        "codestra.runtime-apply-authorized.false",
        "codestra.provider-effects-enabled.false",
        "codestra.contract.middleware-public-api-route-contract",
    ]


def canonical_route(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": safe_name(row["operation_id"]),
        "hosts": ["api.codestra.co"],
        "paths": [route_regex(row["path"])],
        "pathTemplate": row["path"],
        "regexPriority": regex_priority(row["path"]),
        "methods": [row["method"]],
        "protocols": ["http"],
        "stripPath": False,
        "preserveHost": True,
        "serviceHost": UPSTREAM_HOST,
        "servicePort": UPSTREAM_PORT,
        "securityAuthority": "config/kong-middleware-authority.v2.json",
        "requiredPlugins": REQUIRED_PLUGINS,
    }


def denied_route(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": safe_name(row["operation_id"]),
        "method": row["method"],
        "pathTemplate": row["path"],
        "path": route_regex(row["path"]),
        "regexPriority": regex_priority(row["path"]),
        "statusCode": 404,
    }


def authority_route(row: dict[str, Any], issuer: str) -> dict[str, Any]:
    return {
        "operation_id": row["operation_id"],
        "method": row["method"],
        "path": row["path"],
        "issuer": issuer,
        "audience": row["audience"],
        "scope": row["scope"],
        "azp": row["calling_client"],
        "authentication": row["auth"],
        "correlation_fields": row["correlation_fields"],
        "rate_limit": {"minute": 120, "policy": "redis", "fault_tolerant": False},
        "request_size_limit_mb": 2,
    }


def post_function(row: dict[str, Any]) -> str:
    operation_id = json.dumps(row["operation_id"])
    expected_azp_value = row["calling_client"]
    if not isinstance(expected_azp_value, str):
        expected_azp_value = json.dumps(
            expected_azp_value,
            sort_keys=True,
            separators=(",", ":"),
        )
    expected_azp = json.dumps(expected_azp_value)
    required_scope = json.dumps(row["scope"])
    untrusted = ", ".join(json.dumps(name) for name in UNTRUSTED_IDENTITY_HEADERS)
    return "\n".join(
        [
            "-- Generated fail-closed authorization metadata.",
            f"local operation_id = {operation_id}",
            f"local expected_azp = {expected_azp}",
            f"local required_scope = {required_scope}",
            "-- Strip client-asserted identity before minting trusted contract metadata;",
            "-- X-Consumer-* are set by openid-connect after signature verification.",
            f"for _, name in ipairs({{{untrusted}}}) do",
            "  kong.service.request.clear_header(name)",
            "end",
            "kong.service.request.set_header('X-Codestra-Contract-Operation', operation_id)",
            "kong.service.request.set_header('X-Codestra-Expected-Azp', expected_azp)",
            "kong.service.request.set_header('X-Codestra-Required-Scope', required_scope)",
            "-- openid-connect validates issuer/audience/scope; Middleware re-authorizes",
            "-- symbolic client-family selectors and tenant/resource ownership.",
        ]
    )


def route_plugins(row: dict[str, Any], issuer: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "openid-connect",
            "config": {
                "issuer": issuer + "/.well-known/openid-configuration",
                "auth_methods": ["bearer"],
                "audience": [row["audience"]],
                "scopes_required": [row["scope"]],
                "consumer_claim": ["azp"],
                # decK >= 1.66 (the CI-pinned version) refuses to build state
                # without an explicit salt; the value is a vault reference, never
                # a literal, exactly as the other reviewed OIDC renderers do.
                "cache_tokens_salt": "{vault://env/kong-oidc-cache-tokens-salt}",
            },
        },
        {"name": "post-function", "config": {"access": [post_function(row)]}},
        {
            "name": "correlation-id",
            "config": {
                "header_name": "X-Correlation-ID",
                "generator": "uuid",
                "echo_downstream": True,
            },
        },
        {
            "name": "rate-limiting",
            "config": {
                "minute": 120,
                "policy": "redis",
                "fault_tolerant": False,
                "hide_client_headers": False,
                "redis": {
                    "host": "codestra-redis",
                    "port": 6379,
                    "database": 0,
                    "timeout": 2000,
                    "password": "{vault://env/kong-rate-limit-redis-password}",
                },
            },
        },
        {"name": "request-size-limiting", "config": {"allowed_payload_size": 2}},
    ]


def manifest_route(row: dict[str, Any], issuer: str) -> dict[str, Any]:
    return {
        "name": safe_name(row["operation_id"]),
        "hosts": ["api.codestra.co"],
        "paths": [route_regex(row["path"])],
        "regex_priority": regex_priority(row["path"]),
        "methods": [row["method"]],
        "protocols": ["http"],
        "strip_path": False,
        "preserve_host": True,
        "path_handling": "v0",
        "tags": route_tags(row, "shared_edge"),
        "plugins": route_plugins(row, issuer),
    }


def manifest_denied_route(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": safe_name(row["operation_id"]),
        "hosts": ["api.codestra.co"],
        "paths": [route_regex(row["path"])],
        "regex_priority": regex_priority(row["path"]),
        "methods": [row["method"]],
        "protocols": ["http"],
        "strip_path": False,
        "preserve_host": True,
        "tags": route_tags(row, "denied"),
        "plugins": [
            {
                "name": "request-termination",
                "config": {"status_code": 404, "message": "not found"},
            }
        ],
    }


def build_manifest(
    shared: list[dict[str, Any]], denied: list[dict[str, Any]], issuer: str, environment: str
) -> dict[str, Any]:
    return {
        "_format_version": "3.0",
        "_transform": True,
        "services": [
            {
                "name": "middleware-integration-api",
                "host": UPSTREAM_HOST,
                "port": UPSTREAM_PORT,
                "protocol": "http",
                "tags": service_tags(environment),
                "connect_timeout": 5000,
                "read_timeout": 30000,
                "write_timeout": 30000,
                "retries": 0,
                "routes": [manifest_route(row, issuer) for row in shared],
            }
        ],
        "routes": [manifest_denied_route(row) for row in denied],
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    digest = canonical_digest(contract)
    pinned = PIN_PATH.read_text(encoding="utf-8").strip()
    if pinned != digest:
        raise SystemExit(f"contract digest mismatch: pinned={pinned} actual={digest}")
    validate_final_contract(contract, digest)

    shared = [row for row in contract["routes"] if row["classification"] == "shared_edge"]
    denied = [row for row in contract["routes"] if row["classification"] == "denied"]

    canonical = json.loads(CANONICAL_PATH.read_text(encoding="utf-8"))
    canonical["runtimeApplyAuthorized"] = False
    canonical["providerEffectsEnabled"] = False
    canonical["middlewareEdgeContract"] = {
        "source": "appolon1908/Middleware-:deploy/public-api-route-contract.json",
        "vendoredCopy": "config/middleware-public-api-route-contract.v1.json",
        "schema": contract["schema"],
        "sha256": digest,
        "hashRule": "sha256 over json.dumps(contract, sort_keys=True, separators=(',', ':')).encode('utf-8')",
        "generator": "scripts/generate_middleware_routes.py",
    }
    canonical["contractRoutes"] = [canonical_route(row) for row in shared]
    canonical["deniedRoutes"] = [denied_route(row) for row in denied]
    write_json(CANONICAL_PATH, canonical)

    production_issuer = "https://auth.codestra.co/realms/codestra"
    authority = {
        "schema": "codestra.kong.middleware-authority.v2",
        "runtime_apply_authorized": False,
        "provider_effects_enabled": False,
        "contract": {"path": str(CONTRACT_PATH.relative_to(ROOT)).replace("\\", "/"), "sha256": digest},
        "upstream": {"host": UPSTREAM_HOST, "port": UPSTREAM_PORT},
        "routes": [authority_route(row, production_issuer) for row in shared],
    }
    write_json(AUTHORITY_PATH, authority)

    manifests = (
        (PRODUCTION_PATH, production_issuer, "production"),
        (STAGING_PATH, "https://auth-staging.codestra.co/realms/codestra", "staging"),
    )
    for path, issuer, environment in manifests:
        path.parent.mkdir(parents=True, exist_ok=True)
        manifest = build_manifest(shared, denied, issuer, environment)
        path.write_text(yaml.safe_dump(manifest, sort_keys=False, width=1000), encoding="utf-8", newline="\n")

    print(f"generated {len(shared)} shared routes and {len(denied)} denied routes ({digest})")


if __name__ == "__main__":
    main()
