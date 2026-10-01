#!/usr/bin/env python3
"""Prove the Kong campaign-automation source agrees with the pinned Middleware edge contract.

The Middleware repository pins ``deploy/public-api-route-contract.json`` by the
SHA-256 of its canonical JSON form. This repository vendors that document and
pins the same digest in ``config/kong-canonical-middleware-routes.json``. This
validator fails closed when:

* the vendored copy no longer hashes to the pinned digest;
* a scoped contract route is not declared in the canonical manifest with the
  same method, or its security authority grants a different scope;
* the staging campaign manifest drifts from production for a certified route;
* any campaign consumer holds a forbidden scope, or a route has no consumer;
* a retired campaign surface reappears.

Nothing here reads or mutates a Kong node.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import reconcile_kong_campaign_automation as campaign  # noqa: E402

CANONICAL = ROOT / "config/kong-canonical-middleware-routes.json"
PRODUCTION = ROOT / "config/kong-campaign-automation-routes.json"
STAGING = ROOT / "config/staging/kong-campaign-automation-routes.json"
CERTIFIED_SCOPES = {"n8n.results.submit", "n8n.results.read", "odoo.campaigns.read"}
CERTIFIED_ROUTES = {
    ("POST", "/api/v1/integrations/n8n/results"),
    ("GET", "/api/v1/integrations/n8n/results/{event_id}"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}"),
    ("GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state"),
}
RETIRED = ("campaign-actions", "campaign-commands")
STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"


def load(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit(f"{path.relative_to(ROOT).as_posix()} must contain an object")
    return document


def canonical_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(f"MIDDLEWARE_EDGE_CONTRACT=FAIL {message}")


def validate() -> list[str]:
    canonical = load(CANONICAL)
    pin = canonical.get("middlewareEdgeContract")
    if not isinstance(pin, dict):
        fail("canonical manifest does not pin middlewareEdgeContract")
    vendored_path = ROOT / pin["vendoredCopy"]
    if not vendored_path.is_file():
        fail(f"vendored contract missing: {pin['vendoredCopy']}")
    contract = load(vendored_path)
    digest = canonical_sha256(contract)
    if digest != pin["sha256"]:
        fail(f"vendored contract sha256 {digest} != pinned {pin['sha256']}")
    if contract.get("schema") != pin["schema"]:
        fail("vendored contract schema drift")
    if not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]):
        fail("pinned sha256 is malformed")

    production = load(PRODUCTION)
    staging = load(STAGING)
    for manifest in (production, staging):
        campaign.validate_manifest_routes(manifest)

    production_by_key = {
        (row["method"], row.get("path_template", row["path"])): row
        for row in production["routes"]
    }
    declared: dict[tuple[str, str], dict] = {}
    for route in canonical["contractRoutes"]:
        template = route["pathTemplate"]
        key = (route["methods"][0], template)
        if key not in CERTIFIED_ROUTES:
            continue
        authority = production_by_key.get(key)
        if authority is None:
            fail(f"canonical route {key[0]} {key[1]} has no production authority row")
        if route["methods"] != [campaign.route_method(authority)]:
            fail(f"canonical route {route['name']} method drift")
        if template != authority.get("path_template", authority["path"]):
            fail(f"canonical route {route['name']} pathTemplate drift")
        generated = route["paths"][0]
        if not generated.startswith("~/") or not generated.endswith("$"):
            fail(f"canonical route {route['name']} is not an exact Kong regex path")
        if route["serviceHost"] != "middleware-integration-api" or route["servicePort"] != 8095:
            fail(f"canonical route {route['name']} upstream drift")
        declared[key] = {"name": route["name"], "scope": authority["scope"]}

    rows = []
    for row in contract["routes"]:
        if row["classification"] != "shared_edge":
            continue
        key = (row["method"], row["path"])
        if key not in CERTIFIED_ROUTES:
            continue
        entry = declared.get(key)
        if entry is None:
            fail(f"contract route not declared in Kong: {row['method']} {row['path']}")
        if entry["scope"] != row["scope"]:
            fail(f"scope drift for {row['method']} {row['path']}: kong {entry['scope']} contract {row['scope']}")
        rows.append(f"ROUTE={row['method']}|{row['path']}|{row['scope']}|{entry['name']}|PASS")
    if {row["scope"] for row in contract["routes"] if (row["method"], row["path"]) in CERTIFIED_ROUTES} != CERTIFIED_SCOPES:
        fail("contract scope set drift")

    production_routes = {row["name"]: row for row in production["routes"]}
    for row in staging["routes"]:
        expected = production_routes.get(row["name"])
        if expected is None:
            fail(f"staging route {row['name']} has no production counterpart")
        for field in ("method", "path", "path_template", "scope", "rate_per_minute", "max_body_mb"):
            if row.get(field) != expected.get(field):
                fail(f"staging route {row['name']} drifts from production on {field}")
    certified = {row["name"] for row in production["routes"] if row["scope"] in CERTIFIED_SCOPES}
    if {row["name"] for row in staging["routes"]} != certified:
        fail("staging manifest must declare exactly the certified production routes")
    for field in ("service", "audience", "host", "forbidden_scopes"):
        if staging.get(field) != production.get(field):
            fail(f"staging manifest drifts from production on {field}")
    if staging["environment"] != "staging" or production["environment"] != "production":
        fail("environment claims must name their own deployment")
    if staging["issuer"] != STAGING_ISSUER or "auth.codestra.co" in json.dumps(staging):
        fail("staging manifest must use the staging realm only")
    if staging["safety"]["reconciliation_apply"] is not False:
        fail("staging manifest must not authorize runtime apply")
    for consumer in staging["consumers"]:
        if not consumer["custom_id"].startswith("test-syn-"):
            fail(f"staging consumer {consumer['custom_id']} is not a certification identity")
        if set(consumer["scopes"]) - CERTIFIED_SCOPES:
            fail(f"staging consumer {consumer['custom_id']} holds a non-certified scope")
    for manifest in (production, staging):
        text = json.dumps(manifest)
        if any(marker in text for marker in RETIRED):
            fail("retired campaign surface referenced")
    active = json.dumps(canonical["contractRoutes"])
    if any(marker in active for marker in RETIRED):
        fail("retired campaign surface active in canonical routes")
    contract_active = json.dumps(
        [row for row in contract["routes"] if row["classification"] != "denied"]
    )
    if any(marker in contract_active for marker in RETIRED):
        fail("retired campaign surface is not classified denied")
    return [
        f"MIDDLEWARE_EDGE_CONTRACT_SHA256={digest}",
        f"MIDDLEWARE_EDGE_CONTRACT=PASS ROUTES={len(rows)} STAGING_IDENTITIES={len(staging['consumers'])}",
        *rows,
    ]


def main() -> int:
    print("\n".join(validate()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
