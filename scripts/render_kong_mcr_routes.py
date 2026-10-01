#!/usr/bin/env python3
"""Render the reviewed MCR route contract as Kong declarative fragments.

Source-only: this never contacts the Kong Admin API. The fragments attach
top-level routes to the existing ``middleware-integration-api`` service that
``scripts/generate_middleware_routes.py`` renders, so the MCR surface cannot
introduce a second upstream or a direct provider route.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_middleware_routes import UNTRUSTED_IDENTITY_HEADERS, regex_priority  # noqa: E402

CONTRACT_PATH = ROOT / "config/kong-mcr-routes.v1.json"
OUTPUTS = {
    "production": ROOT / "config/kong-mcr-routes.production.yml",
    "staging": ROOT / "config/staging/kong-mcr-routes.staging.yml",
}
SERVICE_NAME = "middleware-integration-api"


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def lua_list(values: list[str]) -> str:
    return "{" + ", ".join(json.dumps(v) for v in values) + "}"


def required_headers_guard(route: dict[str, Any], codes: dict[str, str], status: int) -> str:
    """Fail closed on missing caller context before correlation-id can mint a
    replacement value. Raw metadata only; authentication stays in openid-connect."""
    pairs = ", ".join(
        "{" + json.dumps(name) + ", " + json.dumps(codes[name]) + "}" for name in route["requiredHeaders"]
    )
    return "\n".join(
        [
            "-- Generated MCR required-header guard (raw request metadata only).",
            "-- Echo the caller's correlation id only when it is a safe identifier,",
            "-- the same rule codestra-request-context applies, so it is never reflected raw.",
            "local response_headers = { [\"Content-Type\"] = \"application/json\" }",
            "local correlation = kong.request.get_header(\"X-Correlation-ID\")",
            "if type(correlation) == \"string\" and #correlation <= 128",
            "    and correlation:match(\"^[A-Za-z0-9][A-Za-z0-9._:-]*$\") then",
            "  response_headers[\"X-Correlation-ID\"] = correlation",
            "end",
            f"for _, pair in ipairs({{{pairs}}}) do",
            "  local value = kong.request.get_header(pair[1])",
            "  if type(value) ~= \"string\" or value == \"\" then",
            f"    return kong.response.exit({status}, {{ error = pair[2] }}, response_headers)",
            "  end",
            "end",
        ]
    )


def post_function(route: dict[str, Any]) -> str:
    return "\n".join(
        [
            "-- Generated fail-closed MCR authorization metadata.",
            f"local operation_id = {json.dumps(route['name'])}",
            f"local required_scope = {json.dumps(route['requiredScope'])}",
            "-- Strip client-asserted identity before minting trusted contract metadata;",
            "-- X-Consumer-* are set by openid-connect after signature verification.",
            f"for _, name in ipairs({lua_list(list(UNTRUSTED_IDENTITY_HEADERS))}) do",
            "  kong.service.request.clear_header(name)",
            "end",
            "kong.service.request.set_header('X-Codestra-Contract-Operation', operation_id)",
            "kong.service.request.set_header('X-Codestra-Required-Scope', required_scope)",
            "-- Middleware owns azp, tenant/resource ownership, idempotency replay and effects.",
        ]
    )


def route_plugins(contract: dict[str, Any], route: dict[str, Any], issuer: str) -> list[dict[str, Any]]:
    identity = contract["identity"]
    headers = contract["headerPolicy"]
    errors = headers["gatewayErrors"]
    limits = contract["limits"]
    return [
        {
            "name": "pre-function",
            "config": {"access": [required_headers_guard(route, errors["missingHeaderCodes"], errors["missingHeaderStatus"])]},
        },
        {
            "name": "openid-connect",
            "config": {
                "issuer": issuer + "/.well-known/openid-configuration",
                "auth_methods": list(identity["authMethods"]),
                "audience": [identity["audience"]],
                "scopes_required": [route["requiredScope"]],
                "consumer_claim": [identity["consumerClaim"]],
                "cache_tokens_salt": "{vault://env/kong-oidc-cache-tokens-salt}",
            },
        },
        {"name": "post-function", "config": {"access": [post_function(route)]}},
        {
            "name": "correlation-id",
            "config": {
                "header_name": headers["correlation"]["header"],
                "generator": "uuid",
                "echo_downstream": headers["correlation"]["echoDownstream"],
            },
        },
        {
            "name": "rate-limiting",
            "config": {
                "minute": limits["rateLimitPerMinute"],
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
        {
            "name": "request-size-limiting",
            "config": {"allowed_payload_size": limits["requestBodyMb"], "size_unit": "megabytes"},
        },
    ]


def kong_route(contract: dict[str, Any], route: dict[str, Any], issuer: str) -> dict[str, Any]:
    return {
        "name": route["name"],
        "service": SERVICE_NAME,
        "hosts": [route["host"]],
        "paths": [route["pathRegex"]],
        "regex_priority": regex_priority(route["pathTemplate"]),
        "methods": [route["method"]],
        "protocols": ["http"],
        "strip_path": route["stripPath"],
        "preserve_host": route["preserveHost"],
        "path_handling": "v0",
        "tags": [
            "codestra.contract.kong-mcr-routes",
            "codestra.runtime-apply-authorized.false",
            f"codestra.mcr.effects.{route['effects']}",
        ],
        "plugins": route_plugins(contract, route, issuer),
    }


def render(contract: dict[str, Any], environment: str) -> dict[str, Any]:
    issuer = contract["identity"]["issuers"][environment]
    return {
        "_format_version": "3.0",
        "_transform": True,
        "routes": [kong_route(contract, route, issuer) for route in contract["routes"]],
    }


def dump(document: dict[str, Any]) -> str:
    return yaml.safe_dump(document, sort_keys=False, width=1000)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true", help="refused by design")
    args = parser.parse_args(argv)
    if args.apply:
        parser.error("runtime apply is not authorized by this source-only renderer")
    contract = load_contract()
    stale = []
    for environment, path in OUTPUTS.items():
        rendered = dump(render(contract, environment))
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered, encoding="utf-8", newline="\n")
        elif args.check:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current.replace("\r\n", "\n") != rendered:
                stale.append(str(path.relative_to(ROOT)))
        else:
            print(rendered, end="")
    if stale:
        print("KONG_MCR_RENDER=STALE")
        for path in stale:
            print(f"STALE={path}")
        return 1
    if args.write or args.check:
        print("KONG_MCR_RENDER=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
