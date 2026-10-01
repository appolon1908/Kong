#!/usr/bin/env python3
"""Render the Middleware V3 staging manifest with the Kong OSS JWT fallback.

This is a staging-only renderer for PAS-151. It replaces licensed
`openid-connect` route plugins with Kong's bundled `jwt` plugin, keyed by the
Keycloak issuer. The RS256 public key is fetched from the staging JWKS endpoint
(or supplied explicitly for offline tests) and embedded only in the rendered
runtime artifact.

The route post-function remains fail closed and is extended to verify issuer,
audience, scope, token lifetime, and caller-selector semantics after signature
verification. Symbolic/client-family selectors are never accepted as literal
AZP values; concrete caller selectors require exact AZP equality. Middleware
remains authoritative for reviewed family membership and resource/tenant policy.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from reconcile_kong_campaign_automation import active_rsa_key, rsa_public_key_pem

DEFAULT_SOURCE = ROOT / "config" / "staging" / "kong-middleware-routes.staging.yml"
PROFILES = ROOT / "config" / "kong-authentication-profiles.v1.json"
STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
STAGING_JWKS = STAGING_ISSUER + "/protocol/openid-connect/certs"
CONSUMER_USERNAME = "codestra-keycloak-staging-jwks"
DUMMY_RS256_SECRET = "unused-rs256-public-key-only"

LOCAL_ASSIGNMENT = re.compile(
    r'local\s+(operation_id|expected_azp|required_scope)\s*=\s*("(?:(?:\\.)|[^"])*")'
)


class FallbackError(ValueError):
    pass


def _load_profiles() -> dict:
    value = json.loads(PROFILES.read_text(encoding="utf-8"))
    return value["v3CallerAuthority"]["callers"]


def _extract_metadata(code: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, encoded in LOCAL_ASSIGNMENT.findall(code):
        values[key] = json.loads(encoded)
    missing = {"operation_id", "expected_azp", "required_scope"} - values.keys()
    if missing:
        raise FallbackError(f"post-function metadata missing: {sorted(missing)}")
    return values


def _normalize_selector(value: str) -> str:
    """Normalize generator-encoded one-member caller lists to one selector."""
    if value.startswith("["):
        decoded = json.loads(value)
        if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], str):
            raise FallbackError(f"unsupported caller selector shape: {value!r}")
        return decoded[0]
    return value


def _claim_guard(*, issuer: str, audience: str, scope: str, expected_azp: str, caller_class: str) -> str:
    concrete = caller_class in {"CONCRETE_SERVICE_CLIENT", "CONCRETE_HUMAN_CLIENT"}
    concrete_lua = "true" if concrete else "false"
    return "\n".join(
        [
            "-- PAS-151 JWT/JWKS fallback guard; signature already verified by Kong jwt.",
            "local cjson = require('cjson.safe')",
            "local function contains(value, expected)",
            "  if type(value) == 'string' then return value == expected end",
            "  if type(value) ~= 'table' then return false end",
            "  for _, item in ipairs(value) do if item == expected then return true end end",
            "  return false",
            "end",
            "local function claims_from_verified_jwt()",
            "  local shared = kong.ctx.shared.authenticated_jwt_token",
            "  if type(shared) == 'table' and type(shared.claims) == 'table' then return shared.claims end",
            "  local header = kong.request.get_header('authorization') or ''",
            "  local token = header:match('[Bb]earer%s+(.+)') or ''",
            "  local segment = token:match('^[^.]+%.([^.]+)%.') or ''",
            "  if segment == '' then return {} end",
            "  segment = segment:gsub('-', '+'):gsub('_', '/')",
            "  segment = segment .. string.rep('=', (4 - #segment % 4) % 4)",
            "  local raw = ngx.decode_base64(segment)",
            "  local decoded = raw and cjson.decode(raw) or nil",
            "  return type(decoded) == 'table' and decoded or {}",
            "end",
            "if not kong.client.get_credential() and not kong.client.get_consumer() then",
            "  return kong.response.exit(401,{error='unauthenticated'})",
            "end",
            "local claims = claims_from_verified_jwt()",
            f"local expected_issuer = {json.dumps(issuer)}",
            f"local expected_audience = {json.dumps(audience)}",
            f"local required_scope = {json.dumps(scope)}",
            f"local expected_azp = {json.dumps(expected_azp)}",
            f"local concrete_caller = {concrete_lua}",
            "if claims.iss ~= expected_issuer then return kong.response.exit(401,{error='invalid_issuer'}) end",
            "if not contains(claims.aud, expected_audience) then return kong.response.exit(401,{error='invalid_audience'}) end",
            "local now = ngx.time()",
            "if type(claims.exp) ~= 'number' or claims.exp <= now then return kong.response.exit(401,{error='expired_token'}) end",
            "if type(claims.nbf) == 'number' and claims.nbf > now then return kong.response.exit(401,{error='token_not_yet_valid'}) end",
            "if type(claims.iat) ~= 'number' or claims.iat > now or claims.exp - claims.iat > 300 then",
            "  return kong.response.exit(401,{error='invalid_token_lifetime'})",
            "end",
            "local scopes = {}",
            "for value in string.gmatch(claims.scope or '', '%S+') do scopes[value] = true end",
            "if not scopes[required_scope] then return kong.response.exit(403,{error='insufficient_scope'}) end",
            "if type(claims.azp) ~= 'string' or claims.azp == '' then return kong.response.exit(403,{error='missing_azp'}) end",
            "if concrete_caller and claims.azp ~= expected_azp then return kong.response.exit(403,{error='unauthorized_azp'}) end",
            "if not concrete_caller and claims.azp == expected_azp then",
            "  return kong.response.exit(403,{error='symbolic_selector_not_concrete_identity'})",
            "end",
            "-- Family/symbolic membership is re-authorized by Middleware against its reviewed registry.",
        ]
    )


def _jwt_plugin() -> dict:
    return {
        "name": "jwt",
        "config": {
            "key_claim_name": "iss",
            "claims_to_verify": ["exp", "nbf"],
            "header_names": ["authorization"],
            "run_on_preflight": True,
        },
    }


def transform_manifest(manifest: dict, public_key: str) -> dict:
    callers = _load_profiles()
    services = manifest.get("services")
    if not isinstance(services, list) or len(services) != 1:
        raise FallbackError("expected exactly one Middleware service")

    transformed = json.loads(json.dumps(manifest))
    issuer_seen: set[str] = set()

    for route in transformed["services"][0].get("routes", []):
        plugins = route.get("plugins", [])
        oidc = [plugin for plugin in plugins if plugin.get("name") == "openid-connect"]
        if len(oidc) != 1:
            raise FallbackError(f"{route.get('name')}: expected exactly one openid-connect plugin")
        oidc_conf = oidc[0].get("config", {})
        issuer = str(oidc_conf.get("issuer", "")).removesuffix("/.well-known/openid-configuration")
        if issuer != STAGING_ISSUER:
            raise FallbackError(f"{route.get('name')}: unexpected staging issuer {issuer!r}")
        issuer_seen.add(issuer)
        audiences = oidc_conf.get("audience") or []
        scopes = oidc_conf.get("scopes_required") or []
        if len(audiences) != 1 or len(scopes) != 1:
            raise FallbackError(f"{route.get('name')}: expected one audience and one scope")

        post = [plugin for plugin in plugins if plugin.get("name") == "post-function"]
        if len(post) != 1:
            raise FallbackError(f"{route.get('name')}: expected exactly one post-function")
        access = post[0].get("config", {}).get("access") or []
        if len(access) != 1:
            raise FallbackError(f"{route.get('name')}: expected one post-function access script")
        metadata = _extract_metadata(access[0])
        expected_azp = _normalize_selector(metadata["expected_azp"])
        caller = callers.get(expected_azp)
        if caller is None:
            raise FallbackError(f"{route.get('name')}: unknown caller selector {expected_azp!r}")

        guard = _claim_guard(
            issuer=issuer,
            audience=audiences[0],
            scope=scopes[0],
            expected_azp=expected_azp,
            caller_class=caller["class"],
        )
        post[0]["config"]["access"] = [guard + "\n" + access[0]]
        new_plugins = []
        for plugin in plugins:
            if plugin.get("name") == "openid-connect":
                new_plugins.append(_jwt_plugin())
            else:
                new_plugins.append(plugin)
        route["plugins"] = new_plugins

    if issuer_seen != {STAGING_ISSUER}:
        raise FallbackError(f"issuer set drift: {sorted(issuer_seen)}")

    transformed["consumers"] = [
        {
            "username": CONSUMER_USERNAME,
            "custom_id": CONSUMER_USERNAME,
            "jwt_secrets": [
                {
                    "key": STAGING_ISSUER,
                    "algorithm": "RS256",
                    "secret": DUMMY_RS256_SECRET,
                    "rsa_public_key": public_key,
                }
            ],
        }
    ]
    return transformed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jwks-url", default=STAGING_JWKS)
    parser.add_argument("--active-kid")
    parser.add_argument("--public-key-file", type=Path, help="offline/test public PEM; skips JWKS fetch")
    args = parser.parse_args()

    manifest = yaml.safe_load(args.source.read_text(encoding="utf-8"))
    if args.public_key_file:
        public_key = args.public_key_file.read_text(encoding="utf-8")
    else:
        public_key = rsa_public_key_pem(active_rsa_key(args.jwks_url, args.active_kid))
    if "BEGIN PUBLIC KEY" not in public_key:
        raise FallbackError("RS256 public key PEM is invalid")

    rendered = transform_manifest(manifest, public_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(rendered, sort_keys=False, width=1000),
        encoding="utf-8",
        newline="\n",
    )
    print("KONG_PAS151_JWT_FALLBACK=PASS")
    print(f"OUTPUT={args.output}")
    print(f"ISSUER={STAGING_ISSUER}")
    print(f"SHARED_ROUTES={len(rendered['services'][0].get('routes', []))}")
    print("OPENID_CONNECT_PLUGINS=0")
    print("JWT_CONSUMERS=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
