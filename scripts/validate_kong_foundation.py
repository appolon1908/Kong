#!/usr/bin/env python3
"""Validate the Kong API Gateway Control Plane V1 foundation registry.

The registry (``config/kong-gateway-foundation.v1.json``) is the reviewed
authority map for every Kong service, route and plugin declared anywhere in this
repository. It does not duplicate mutable match data; every route and service is
*bound* to the reviewed source that declares it, and this validator materializes
the match from that source and proves:

* every route in every reviewed source is registered (no undocumented routes);
* every registered binding still resolves and every DESIRED binding agrees with
  every other DESIRED binding on the fields both declare (contract drift);
* every OBSERVED (runtime readback) binding differs from the DESIRED state only
  where the registry declares the drift (runtime drift ledger);
* route precedence is deterministic under the Kong 3.x router priority model and
  every overlapping pair is declared with its expected winner;
* every gateway-architecture-debt finding the rules detect is explicitly accepted
  on the route or service that carries it, and canonical routes carry none;
* every route has an explicit authentication class, traffic class, lifecycle,
  activation state and disposition, and an unauthenticated route can only be an
  explicitly reasoned read-only PUBLIC route or BLOCKED;
* every plugin used by any source is governed, authentication plugins are never
  global, and claim guards run after an authentication plugin;
* the node configuration keeps Admin/Manager/Status private, trusts only the
  configured Caddy source, keeps TLS verification on and runs least-privilege;
* every ``{vault://env/...}`` reference used by the deployed candidate is declared
  in the runtime environment template;
* a route without a service is a gateway-terminated (request-termination)
  PUBLIC 404 responder for a retired alias and nothing else, and nothing
  activatable targets a retired Middleware upstream alias;
* (Mission 2) every route has an access-policy entry whose class, profile,
  issuer, audience, scopes, authorized parties, principal classes, identity
  propagation and tenant policy agree with the foundation and with the
  authentication-profile catalogue; public routes are allowlisted; no identity
  header is an authority; no profile is weaker than its class allows; token
  cache and time settings are bounded; and no secret value is committed.

Source-only. Nothing here contacts a Kong Admin API, Caddy, Keycloak, Middleware
or Redis, and nothing here can authorize a runtime apply.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import yaml

try:
    from scripts.validate_kong_runtime_mode import validate_authority as validate_runtime_authority
except ModuleNotFoundError:
    # Direct CLI invocation places scripts/, rather than the repo root, on sys.path.
    from validate_kong_runtime_mode import validate_authority as validate_runtime_authority

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "config/kong-gateway-foundation.v1.json"
SCHEMA = "codestra.kong.gateway-foundation.v1"
ACCESS_POLICY = "config/kong-access-policy.v1.json"
ACCESS_POLICY_SCHEMA = "codestra.kong.access-policy.v1"
AUTH_PROFILES = "config/kong-authentication-profiles.v1.json"
AUTH_PROFILES_SCHEMA = "codestra.kong.authentication-profiles.v1"
FINAL_MIDDLEWARE_SOURCE_SHA = "bd406a6508c8095a3f23b35149a2eebcb94c94c6"
FINAL_MIDDLEWARE_CONTRACT_SHA256 = "9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b"
FINAL_MIDDLEWARE_ROUTE_COUNTS = {"shared_edge": 105, "denied": 10, "private_only": 2}
CANONICAL_MIDDLEWARE_HOST = "middleware-integration-api"
CANONICAL_MIDDLEWARE_PORT = 8095
PROVIDER_HOST_MARKERS = ("odoo", "n8n", "telnexa", "klyrow", "vicidial", "postly", "kyqra")
ACCESS_CLASSES = ("PUBLIC", "AUTHENTICATED", "SERVICE_AUTHENTICATED", "ADMIN_INTERNAL", "INTERNAL")
SECRET_SCAN_ROOTS = ("config", "deploy", "kong", "scripts", "tools", "tests", ".github/workflows", "operations", "orbit", "contracts")
SECRET_PATTERNS = {
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    "jwt_compact_token": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "client_secret_literal": re.compile(rb"client[_-]?secret[\"']?\s*[:=]\s*[\"']?(?P<value>(?!\{vault|\$\{|REQUIRED|<|null|None|\s)[A-Za-z0-9+/=_-]{16,})"),
    "password_literal": re.compile(rb"password[\"']?\s*[:=]\s*[\"']?(?P<value>(?!\{vault|\$\{|REQUIRED|<|/run/secrets|None|null|\s)[A-Za-z0-9+/=_!@#$%^&*-]{12,})"),
    "cache_salt_literal": re.compile(rb"cache_tokens_salt[\"']?\s*[:=]\s*[\"']?(?P<value>(?!\{vault)[A-Za-z0-9+/=_-]{8,})"),
    "api_key_literal": re.compile(rb"(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?(?P<value>(?!\{vault|\$\{|REQUIRED|<)[A-Za-z0-9+/=_-]{20,})"),
    "bearer_literal": re.compile(rb"Bearer\s+(?P<value>[A-Za-z0-9+/=_-]{30,})"),
    "keycloak_admin_credential": re.compile(rb"KEYCLOAK_ADMIN(?:_PASSWORD)?\s*[:=]\s*[\"']?(?P<value>(?!\{vault|\$\{|REQUIRED|<)[^\s\"']{6,})"),
}
SYNTHETIC_MARKER = re.compile(rb"sentinel|do-not-|synthetic|placeholder|example|REQUIRED_|redacted|fixture", re.IGNORECASE)

MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
ALL_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
AUTHENTICATION_PLUGINS = {
    "openid-connect", "jwt", "key-auth", "mtls-auth", "hmac-auth", "basic-auth",
    "ip-restriction", "codestra-webhook-verifier", "codestra-authz",
}
CLAIM_GUARD_PLUGINS = {"post-function", "codestra-authz"}
KONG_DEFAULT_RETRIES = 5
KONG_DEFAULT_TIMEOUT_MS = 60000
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
VAULT_ENV = re.compile(r"\{vault://env/([a-z0-9-]+)\}")


class FoundationError(ValueError):
    """A registry, source, boundary or drift check failed."""


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class SourceRoute:
    source: str
    name: str
    hosts: tuple[str, ...] | None = None
    paths: tuple[str, ...] | None = None
    methods: tuple[str, ...] | None = None
    protocols: tuple[str, ...] | None = None
    strip_path: bool | None = None
    preserve_host: bool | None = None
    regex_priority: int = 0
    service_name: str | None = None
    upstream_protocol: str | None = None
    upstream_host: str | None = None
    upstream_port: int | None = None
    plugins: tuple[str, ...] | None = None
    rate_per_minute: int | None = None
    max_body_bytes: int | None = None
    required_scope: str | None = None
    audience: str | None = None
    issuer: str | None = None
    enabled: bool | None = None
    client_id: str | None = None
    expected_azp: str | None = None  # contracted azp (literal or symbolic family), canonical JSON for lists

    def field_values(self) -> dict[str, Any]:
        return {
            "hosts": self.hosts, "paths": self.paths, "methods": self.methods,
            "protocols": self.protocols, "strip_path": self.strip_path,
            "preserve_host": self.preserve_host, "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port, "upstream_protocol": self.upstream_protocol,
            "plugins": self.plugins, "rate_per_minute": self.rate_per_minute,
            "max_body_bytes": self.max_body_bytes, "required_scope": self.required_scope,
            "audience": self.audience, "expected_azp": self.expected_azp,
        }


@dataclass(frozen=True)
class SourceService:
    source: str
    name: str
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    connect_timeout: int | None = None
    read_timeout: int | None = None
    write_timeout: int | None = None
    retries: int | None = None
    plugins: tuple[str, ...] = ()
    carries_timeouts: bool = True
    carries_retries: bool = True

    def field_values(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol, "host": self.host, "port": self.port,
            "connect_timeout": self.connect_timeout, "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout, "retries": self.retries,
        }


@dataclass
class SourceDocument:
    path: str
    format: str
    routes: dict[str, SourceRoute] = field(default_factory=dict)
    services: dict[str, SourceService] = field(default_factory=dict)
    global_plugins: tuple[str, ...] = ()
    edge_paths: tuple[str, ...] = ()
    declared_status: str | None = None
    declared_environment: str | None = None
    issuer: str | None = None


# --------------------------------------------------------------------------- helpers


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _tuple(values: Any) -> tuple[Any, ...] | None:
    if values is None:
        return None
    if isinstance(values, (str, int)):
        values = [values]
    return tuple(values)


def _methods(values: Any) -> tuple[str, ...] | None:
    values = _tuple(values)
    return None if values is None else tuple(str(v).upper() for v in values)


def _mb(value: Any) -> int | None:
    return None if value is None else int(value) * 1024 * 1024


def _url_parts(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, parts.hostname or "", port


def _issuer_realm(value: str | None) -> str | None:
    if not value:
        return None
    return value.split("/.well-known/")[0]


# --------------------------------------------------------------------------- loaders


def _declarative_upstream(svc: dict) -> tuple[str, str, int]:
    """decK accepts either ``url`` or the ``protocol``/``host``/``port`` triple."""
    if svc.get("url"):
        return _url_parts(svc["url"])
    return svc.get("protocol", "http"), svc["host"], int(svc["port"])


def canonical_azp(value: Any) -> str | None:
    """A contracted azp as the generated post-function forwards it: a literal or
    symbolic client string, or the canonical JSON of a client list."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


EXPECTED_AZP_LUA = re.compile(r'local expected_azp = ("(?:[^"\\]|\\.)*")')


def _post_function_expected_azp(plugins: list[dict]) -> str | None:
    """The azp the generated post-function forwards as X-Codestra-Expected-Azp."""
    for plugin in plugins or []:
        if plugin.get("name") == "post-function":
            for chunk in (plugin.get("config", {}) or {}).get("access", []) or []:
                match = EXPECTED_AZP_LUA.search(str(chunk))
                if match:
                    return json.loads(match.group(1))
    return None


def _oidc_identity(plugins: list[dict]) -> tuple[str | None, str | None, str | None]:
    """(issuer realm, single audience, single required scope) of the first
    openid-connect block in ``plugins``; every element None when there is none."""
    for plugin in plugins or []:
        if plugin.get("name") == "openid-connect":
            config = plugin.get("config", {}) or {}
            aud = config.get("audience") or []
            scopes = config.get("scopes_required") or []
            return (_issuer_realm(config.get("issuer")), aud[0] if len(aud) == 1 else None,
                    scopes[0] if len(scopes) == 1 else None)
    return None, None, None


def load_kong_declarative(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="kong-declarative")
    out.global_plugins = tuple(p["name"] for p in doc.get("plugins", []) or [])
    issuers: set[str] = set()
    for svc in doc.get("services", []) or []:
        protocol, host, port = _declarative_upstream(svc)
        svc_plugins = tuple(p["name"] for p in svc.get("plugins", []) or [])
        out.services[svc["name"]] = SourceService(
            source=path, name=svc["name"], protocol=protocol, host=host, port=port,
            connect_timeout=svc.get("connect_timeout"), read_timeout=svc.get("read_timeout"),
            write_timeout=svc.get("write_timeout"), retries=svc.get("retries"), plugins=svc_plugins,
        )
        svc_issuer, svc_audience, _ = _oidc_identity(svc.get("plugins", []) or [])
        for route in svc.get("routes", []) or []:
            route_plugins = tuple(p["name"] for p in route.get("plugins", []) or [])
            # A route-level openid-connect block (generated Middleware manifests)
            # owns the route scope; a service-level block (control plane) only
            # supplies issuer and audience because its scopes_required is the
            # baseline OIDC scope and the route scopes live in the claim guard.
            issuer, audience, scope = _oidc_identity(route.get("plugins", []) or [])
            issuer, audience = issuer or svc_issuer, audience or svc_audience
            if issuer:
                issuers.add(issuer)
            out.routes[route["name"]] = SourceRoute(
                source=path, name=route["name"], hosts=_tuple(route.get("hosts")),
                paths=_tuple(route.get("paths")), methods=_methods(route.get("methods")),
                protocols=_tuple(route.get("protocols")), strip_path=route.get("strip_path"),
                preserve_host=route.get("preserve_host"), regex_priority=route.get("regex_priority", 0) or 0,
                service_name=svc["name"], upstream_protocol=protocol, upstream_host=host, upstream_port=port,
                plugins=tuple(sorted(set(route_plugins) | set(svc_plugins) | set(out.global_plugins))),
                max_body_bytes=_declared_body_limit(route.get("plugins", []) or []),
                rate_per_minute=_declared_rate(list(route.get("plugins", []) or []) + list(svc.get("plugins", []) or [])),
                issuer=issuer, audience=audience, required_scope=scope, enabled=svc.get("enabled"),
                expected_azp=_post_function_expected_azp(route.get("plugins", []) or []),
            )
    for route in doc.get("routes", []) or []:
        # Service-less routes: the generated deny manifests terminate retired
        # aliases at the gateway (request-termination) and never reach an upstream.
        route_plugins = tuple(p["name"] for p in route.get("plugins", []) or [])
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=_tuple(route.get("hosts")),
            paths=_tuple(route.get("paths")), methods=_methods(route.get("methods")),
            protocols=_tuple(route.get("protocols")), strip_path=route.get("strip_path"),
            preserve_host=route.get("preserve_host"), regex_priority=route.get("regex_priority", 0) or 0,
            plugins=tuple(sorted(set(route_plugins) | set(out.global_plugins))),
            max_body_bytes=_declared_body_limit(route.get("plugins", []) or []),
            rate_per_minute=_declared_rate(list(route.get("plugins", []) or [])),
        )
    if len(issuers) == 1:
        out.issuer = issuers.pop()
    return out


def _declared_body_limit(plugins: list[dict]) -> int | None:
    for plugin in plugins:
        if plugin.get("name") == "request-size-limiting":
            config = plugin.get("config", {})
            size = config.get("allowed_payload_size")
            unit = config.get("size_unit", "megabytes")
            if size is None:
                return None
            factor = {"bytes": 1, "kilobytes": 1024, "megabytes": 1024 * 1024}[unit]
            return int(size) * factor
    return None


def _declared_rate(plugins: list[dict]) -> int | None:
    for plugin in plugins:
        if plugin.get("name") == "rate-limiting":
            return plugin.get("config", {}).get("minute")
    return None


def load_production_inventory(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="production-route-inventory")
    out.declared_status = doc.get("status")
    for route in doc["routes"]:
        svc = route["service"]
        out.services.setdefault(svc["name"], SourceService(
            source=path, name=svc["name"], protocol=svc["protocol"], host=svc["host"], port=svc["port"],
            connect_timeout=svc.get("connect_timeout"), read_timeout=svc.get("read_timeout"),
            write_timeout=svc.get("write_timeout"), retries=svc.get("retries"), carries_retries=False,
        ))
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=_tuple(route["hosts"]), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]),
            strip_path=route["strip_path"], preserve_host=route["preserve_host"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(route["plugins"])),
        )
    return out


def load_canonical_middleware_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="canonical-middleware-contract")
    out.global_plugins = tuple(sorted(doc.get("globalPlugins", [])))
    for route in doc["contractRoutes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=_tuple(route["hosts"]), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]),
            strip_path=route["stripPath"], preserve_host=route["preserveHost"],
            regex_priority=route.get("regexPriority", 0) or 0,
            upstream_protocol="http", upstream_host=route["serviceHost"], upstream_port=route["servicePort"],
            plugins=tuple(sorted(route["requiredPlugins"])),
        )
    for route in doc.get("routes", []):
        # The legacy block names only the shared-key auth marker, rate and body
        # limit; hosts and the full plugin set are observed through the inventory.
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], paths=(route["path"],), methods=_methods(route["methods"]),
            max_body_bytes=_mb(route.get("maxBodyMb")), rate_per_minute=route.get("ratePerMinute"),
        )
    for route in doc.get("deniedRoutes", []):
        # Retired aliases the canonical contract terminates at the gateway (404,
        # no upstream); host and transport come from the generated manifest.
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], paths=(route["path"],), methods=_methods(route["method"]),
            regex_priority=route.get("regexPriority", 0) or 0,
            plugins=tuple(sorted(set(out.global_plugins) | {"request-termination"})),
        )
    return out


CALLBACK_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")
CAMPAIGN_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")
N8N_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")


def _service_from_contract(path: str, svc: dict) -> SourceService:
    return SourceService(
        source=path, name=svc["name"], protocol=svc.get("protocol"), host=svc.get("host"), port=svc.get("port"),
        connect_timeout=svc.get("connect_timeout", svc.get("connectTimeoutMs")),
        read_timeout=svc.get("read_timeout", svc.get("readTimeoutMs")),
        write_timeout=svc.get("write_timeout", svc.get("writeTimeoutMs")),
        retries=svc.get("retries"),
    )


def load_callback_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="callback-contract", issuer=doc["issuer"])
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=("http",), strip_path=route["strip_path"],
            preserve_host=True, service_name=svc["name"], upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], plugins=CALLBACK_PLUGINS,
            rate_per_minute=route["ratePerMinute"], max_body_bytes=_mb(route["maxBodyMb"]),
            required_scope=route["requiredScope"], audience=doc["audience"], issuer=doc["issuer"],
        )
    return out


def load_campaign_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="campaign-contract", issuer=doc["issuer"])
    out.declared_environment = doc.get("environment")
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["method"]), protocols=("http",), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], plugins=CAMPAIGN_PLUGINS, rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"],
        )
    return out


def load_intake_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="intake-contract")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=("http",), strip_path=route["stripPath"],
            preserve_host=route["preserveHost"], service_name=svc["name"], upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], plugins=tuple(sorted(route["requiredPlugins"])),
            rate_per_minute=route["ratePerMinute"], max_body_bytes=_mb(route["maxBodyMb"]),
            required_scope=route["requiredScope"], audience=route["requiredClientId"],
            client_id=route["requiredClientId"],
        )
    return out


def load_n8n_control_plane_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="n8n-control-plane-contract", issuer=doc["issuer"])
    out.declared_environment = doc.get("environment")
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["method"]), protocols=("http",), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], plugins=N8N_PLUGINS, rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"], enabled=svc.get("enabled"),
            client_id=doc["client_id"],
        )
    return out


def load_n8n_editor_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="n8n-editor-contract", issuer=doc["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), strip_path=route["strip_path"], preserve_host=route["preserve_host"],
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), issuer=doc["issuer"], enabled=svc.get("enabled"),
        )
    return out


def load_moneybee_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="moneybee-contract", issuer=doc["identity"]["issuer"])
    out.declared_status = doc.get("state")
    up = doc["upstream"]
    # Transport policy is owned by scripts/render_kong_moneybee_identity.py.
    out.services[up["serviceName"]] = SourceService(
        source=path, name=up["serviceName"], protocol=up["protocol"], host=up["host"], port=up["port"],
        connect_timeout=3000, read_timeout=30000, write_timeout=30000, retries=0,
    )
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["canonicalHost"],), paths=(route["path"],),
            methods=_methods(route["methods"]), service_name=up["serviceName"], upstream_protocol=up["protocol"],
            upstream_host=up["host"], upstream_port=up["port"], plugins=tuple(sorted(route["requiredPlugins"])),
            rate_per_minute=route["rateLimitPerMinute"], max_body_bytes=route["maxBodyBytes"],
            audience=doc["identity"]["requiredAudience"], issuer=doc["identity"]["issuer"],
            client_id=doc["identity"]["registrationClient"],
        )
    return out


def load_provider_control_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="provider-control-contract", issuer=doc["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services["provider-control-middleware"] = SourceService(
        source=path, name="provider-control-middleware", protocol=svc["protocol"], host=svc["host"],
        port=svc["port"], carries_timeouts=False, carries_retries=False,
    )
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], paths=(route["path"],), methods=_methods(route["method"]),
            service_name="provider-control-middleware", upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"], client_id=route["clientId"],
        )
    return out


def load_calling_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="calling-contract", issuer=_issuer_realm(doc["identity"]["issuer"]))
    out.declared_status = doc.get("status")
    svc = doc["service"]
    # The pinned contract carries timeouts; retries are owned by
    # scripts/render_kong_calling_routes.py (repository retry policy NONE).
    out.services[svc["name"]] = SourceService(**{**_service_from_contract(path, svc).__dict__, "retries": 0})
    common = doc["commonPolicy"]
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), protocols=_tuple(common["protocols"]),
            strip_path=common["stripPath"], preserve_host=common["preserveHost"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(common["requiredPlugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=_mb(common["requestBodyLimitMb"]), required_scope=route["requiredScope"],
            audience=doc["identity"]["audience"], issuer=out.issuer,
        )
    return out


def authority_route_name(operation_id: str) -> str:
    """The generated route name for a contract operation
    (``scripts/generate_middleware_routes.py`` ``safe_name``)."""
    return "middleware-" + re.sub(r"[^a-z0-9-]+", "-", operation_id.lower().replace("_", "-")).strip("-")


def load_middleware_authority_v2(path: str, doc: dict) -> SourceDocument:
    """Per-operation security authority of the canonical Middleware edge (PR #105):
    issuer, audience, scope, expected azp, rate and body limit. Match data
    (host, regex path) is owned by the canonical contract and the generated
    manifests; only the fields the authority declares are compared."""
    out = SourceDocument(path=path, format="middleware-authority-v2")
    _require(doc.get("runtime_apply_authorized") is False and doc.get("provider_effects_enabled") is False,
             f"{path}: runtime_apply_authorized and provider_effects_enabled must both stay false")
    issuers = {route["issuer"] for route in doc["routes"]}
    out.issuer = issuers.pop() if len(issuers) == 1 else None
    upstream = doc["upstream"]
    for operation in doc["routes"]:
        azp = operation.get("azp")
        out.routes[authority_route_name(operation["operation_id"])] = SourceRoute(
            source=path, name=authority_route_name(operation["operation_id"]),
            methods=_methods(operation["method"]), upstream_protocol="http",
            upstream_host=upstream["host"], upstream_port=upstream["port"],
            rate_per_minute=operation["rate_limit"]["minute"], max_body_bytes=_mb(operation["request_size_limit_mb"]),
            required_scope=operation["scope"], audience=operation["audience"], issuer=operation["issuer"],
            client_id=azp if isinstance(azp, str) else None, expected_azp=canonical_azp(azp),
        )
    return out


def load_platform_api_read_contract(path: str, doc: dict) -> SourceDocument:
    """PR #104 read-side platform API contract: calling-contract shape, but no
    renderer pins retries, so the service keeps whatever the contract declares."""
    out = SourceDocument(path=path, format="platform-api-read-contract", issuer=_issuer_realm(doc["identity"]["issuer"]))
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    common = doc["commonPolicy"]
    client = doc.get("activation", {}).get("requiresKeycloakClient")
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), protocols=_tuple(common["protocols"]),
            strip_path=common["stripPath"], preserve_host=common["preserveHost"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(common["requiredPlugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=_mb(common["requestBodyLimitMb"]), required_scope=route["requiredScope"],
            audience=doc["identity"]["audience"], issuer=out.issuer, client_id=client, expected_azp=client,
        )
    return out


def load_middleware_v3_command_contract(path: str, doc: dict) -> SourceDocument:
    """Prepared, disabled routes for the Middleware V3 platform kernel. Fails closed
    unless the file says it is still pending the frozen Middleware V3 contract and
    binds the canonical 8095 upstream; the frozen contract, not this file, is the
    authority for names, azp allowlists and scopes once it exists."""
    if doc.get("status") != "V3_PENDING_FINAL_MIDDLEWARE_CONTRACT" or doc.get("V3_PENDING_FINAL_MIDDLEWARE_CONTRACT") is not True:
        raise FoundationError(f"{path}: V3 command routes must remain V3_PENDING_FINAL_MIDDLEWARE_CONTRACT")
    if doc.get("runtimeApplyAuthorized") is not False or doc.get("activation", {}).get("runtimeApplyAuthorized") is not False:
        raise FoundationError(f"{path}: V3 command routes may not authorise runtime apply")
    svc = doc["service"]
    if (svc.get("host"), svc.get("port")) != ("middleware-integration-api", 8095):
        raise FoundationError(f"{path}: V3 command routes must bind middleware-integration-api:8095")
    if doc.get("security", {}).get("businessAuthorizationInKong") is not False:
        raise FoundationError(f"{path}: business authorization stays in Middleware")
    out = SourceDocument(path=path, format="middleware-v3-command-contract", issuer=_issuer_realm(doc["identity"]["issuer"]))
    out.declared_status = doc.get("status")
    out.services[svc["name"]] = _service_from_contract(path, svc)
    common = doc["commonPolicy"]
    for route in doc["routes"]:
        if "POST" in route["methods"] and route.get("idempotencyRequired") is not True:
            raise FoundationError(f"{path}: V3 command route {route['name']} must require Idempotency-Key")
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), protocols=_tuple(common["protocols"]),
            strip_path=common["stripPath"], preserve_host=common["preserveHost"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(common["requiredPlugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=_mb(common["requestBodyLimitMb"]), required_scope=route["requiredScope"],
            audience=doc["identity"]["audience"], issuer=out.issuer,
        )
    return out


def load_community_n8n_egress_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="community-n8n-egress-contract", issuer=doc["identity"]["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    route = doc["route"]
    out.services[svc["name"]] = SourceService(
        source=path, name=svc["name"], protocol=svc["protocol"], host=f"${{{svc['host_source']}}}", port=svc["port"],
        carries_timeouts=False, carries_retries=False,
    )
    out.routes[svc["name"] + "-route"] = SourceRoute(
        source=path, name=svc["name"] + "-route", hosts=(route["host"],), paths=(route["path"],),
        methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]), strip_path=route["strip_path"],
        service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=f"${{{svc['host_source']}}}",
        upstream_port=svc["port"], plugins=tuple(sorted(doc["plugins"]["names"])),
        audience=doc["identity"]["audience"], issuer=doc["identity"]["issuer"],
    )
    return out


STANDBY_PLUGINS = ("ip-restriction", "rate-limiting", "request-size-limiting", "request-transformer")


def load_standby_design(path: str, doc: dict) -> SourceDocument:
    # Match, plugin and transport facts come from scripts/apply_kong_standby.py, the
    # only writer of these entities; standby.json carries the per-service policy.
    out = SourceDocument(path=path, format="standby-design", issuer=doc["issuer"])
    for svc in doc["services"]:
        out.services[svc["name"]] = SourceService(
            source=path, name=svc["name"], protocol="http", host="codestra-kong-standby-auth", port=8080,
            connect_timeout=svc["connectTimeoutMs"], read_timeout=svc["readTimeoutMs"],
            write_timeout=svc["writeTimeoutMs"], retries=svc["retries"],
        )
        out.routes[svc["name"] + "-route"] = SourceRoute(
            source=path, name=svc["name"] + "-route", hosts=(doc["stagingHostname"],), paths=(svc["path"],),
            methods=_methods(svc["methods"]), protocols=("http", "https"), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol="http", upstream_host="codestra-kong-standby-auth",
            upstream_port=8080, plugins=STANDBY_PLUGINS, rate_per_minute=svc["ratePerMinute"],
            max_body_bytes=svc["bodyLimitBytes"], required_scope=svc["requiredScope"], audience=doc["audience"],
            issuer=doc["issuer"],
        )
    return out


DESIGN_UPSTREAMS = "codestra-design-cell-upstreams"


def load_design_route_registry(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="design-route-registry")
    out.declared_status = doc.get("state")
    out.services[DESIGN_UPSTREAMS] = SourceService(
        source=path, name=DESIGN_UPSTREAMS, carries_timeouts=False, carries_retries=False,
    )
    for route in doc["routes"]:
        out.routes[route["id"]] = SourceRoute(
            source=path, name=route["id"], hosts=(route["host"],), paths=(route["path_prefix"],),
            methods=_methods(route["methods"]), service_name=DESIGN_UPSTREAMS, upstream_host=route["upstream"],
        )
    return out


def load_gateway_integration(path: str, doc: dict) -> SourceDocument:
    spec = doc["spec"]
    out = SourceDocument(path=path, format="gateway-integration", issuer=spec["authentication"]["issuer"])
    out.declared_environment = doc["metadata"]["environment"]
    up = spec["upstream"]
    out.services[up["service"]] = SourceService(
        source=path, name=up["service"], protocol=up["protocol"], host=up["dnsName"], port=up["port"],
        connect_timeout=up["timeouts"]["connectMs"], read_timeout=up["timeouts"]["readMs"],
        write_timeout=up["timeouts"]["writeMs"], retries=up["retries"],
    )
    policy = load_json(CURRENT_ROOT / "config/integrations/policies" / (spec["authentication"]["template"] + ".json"))
    for route in spec["routes"]:
        out.routes[doc["metadata"]["id"] + ":" + route["id"]] = SourceRoute(
            source=path, name=doc["metadata"]["id"] + ":" + route["id"], hosts=(spec["host"],),
            paths=(route["path"],), methods=_methods(route["methods"]), service_name=up["service"],
            upstream_protocol=up["protocol"], upstream_host=up["dnsName"], upstream_port=up["port"],
            plugins=tuple(sorted(policy["plugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=route["maxBodyBytes"], audience=spec["authentication"]["audience"],
            issuer=spec["authentication"]["issuer"],
        )
    return out


def load_public_readonly_canary(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="public-readonly-canary")
    out.declared_status = doc.get("status")
    if any(route.get("kongRoute") is not None for route in doc["routes"]):
        raise FoundationError(f"{path}: canary paths must not declare Kong routes")
    out.edge_paths = tuple(route["path"] for route in doc["routes"])
    return out


def load_oidc_plugin_template(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="oidc-plugin-template")
    if doc.get("services") or doc.get("routes"):
        raise FoundationError(f"{path}: plugin template must not declare services or routes")
    out.global_plugins = tuple(p["name"] for p in doc.get("plugins", []) or [])
    for plugin in doc.get("plugins", []) or []:
        if plugin.get("name") == "openid-connect":
            out.issuer = _issuer_realm(plugin.get("config", {}).get("issuer"))
    return out


LOADERS = {
    "kong-declarative": (load_yaml, load_kong_declarative),
    "production-route-inventory": (load_json, load_production_inventory),
    "canonical-middleware-contract": (load_json, load_canonical_middleware_contract),
    "callback-contract": (load_json, load_callback_contract),
    "campaign-contract": (load_json, load_campaign_contract),
    "intake-contract": (load_json, load_intake_contract),
    "n8n-control-plane-contract": (load_json, load_n8n_control_plane_contract),
    "n8n-editor-contract": (load_json, load_n8n_editor_contract),
    "moneybee-contract": (load_json, load_moneybee_contract),
    "provider-control-contract": (load_json, load_provider_control_contract),
    "calling-contract": (load_json, load_calling_contract),
    "community-n8n-egress-contract": (load_json, load_community_n8n_egress_contract),
    "middleware-authority-v2": (load_json, load_middleware_authority_v2),
    "platform-api-read-contract": (load_json, load_platform_api_read_contract),
    "middleware-v3-command-contract": (load_json, load_middleware_v3_command_contract),
    "standby-design": (load_json, load_standby_design),
    "design-route-registry": (load_json, load_design_route_registry),
    "gateway-integration": (load_json, load_gateway_integration),
    "public-readonly-canary": (load_json, load_public_readonly_canary),
    "oidc-plugin-template": (load_yaml, load_oidc_plugin_template),
}


CURRENT_ROOT = ROOT


def load_sources(foundation: dict, root: Path = ROOT) -> dict[str, SourceDocument]:
    global CURRENT_ROOT
    CURRENT_ROOT = root
    documents: dict[str, SourceDocument] = {}
    for source in foundation["sources"]:
        path = root / source["path"]
        if not path.is_file():
            raise FoundationError(f"registered source does not exist: {source['path']}")
        if source["format"] not in LOADERS:
            raise FoundationError(f"{source['path']}: unknown source format {source['format']}")
        reader, loader = LOADERS[source["format"]]
        documents[source["path"]] = loader(source["path"], reader(path))
    return documents


# --------------------------------------------------------------------------- precedence


def is_regex_path(path: str) -> bool:
    return path.startswith("~")


def literal_prefix(path: str) -> str:
    """The longest literal prefix a Kong path can match: itself for prefix paths,
    the leading literal run for regex paths."""
    if not is_regex_path(path):
        return path
    body = path[1:]
    if body.startswith("^"):
        body = body[1:]
    match = re.match(r"[A-Za-z0-9/._-]*", body)
    return match.group(0) if match else ""


def route_priority(route: SourceRoute) -> tuple[int, int, int, int, int]:
    """Kong 3.x ``traditional_compatible`` router priority, highest wins.

    Bit layout (kong/router/transform.lua): match weight (number of matched
    criteria among methods/hosts/paths/headers/snis/sources/destinations),
    then plain hosts before wildcard hosts, then regex paths before prefix paths,
    then ``regex_priority``, then the longest prefix path. Headers, SNIs and
    L4 criteria are not used by any reviewed source, so they carry no weight here.
    """
    weight = sum(1 for values in (route.methods, route.hosts, route.paths) if values)
    hosts = route.hosts or ()
    plain_host = 1 if hosts and all("*" not in host for host in hosts) else 0
    paths = route.paths or ()
    regex = 1 if any(is_regex_path(p) for p in paths) else 0
    regex_priority = route.regex_priority if regex else 0
    max_len = max((len(p) for p in paths if not is_regex_path(p)), default=0)
    return (weight, plain_host, regex, regex_priority, max_len)


def _host_matches(pattern: str, host: str) -> bool:
    """Kong wildcard hosts: a leading or trailing ``*`` matches any label run."""
    if "*" not in pattern and "*" not in host:
        return pattern == host
    left, right = (pattern, host) if "*" in pattern else (host, pattern)
    if "*" in right:
        return left.replace("*", "") in right or right.replace("*", "") in left
    return re.fullmatch(re.escape(left).replace(re.escape("*"), ".+"), right) is not None


def _intersects(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return any(_host_matches(left, right) for left in a for right in b)


def _methods_intersect(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return bool(set(a) & set(b))


def regex_sample(path: str) -> str:
    """A representative concrete path admitted by a Kong regex path.

    Character classes become a single ``a`` (or ``n`` of them for exact
    quantifiers) and anchors are dropped. Used only to decide whether two regex
    paths, or a regex and a prefix path, can admit the same request.
    """
    body = path[1:]
    body = body[1:] if body.startswith("^") else body
    body = body[:-1] if body.endswith("$") else body
    body = re.sub(r"\[[^\]]*\]\{(\d+)\}", lambda m: "a" * int(m.group(1)), body)
    body = re.sub(r"\[[^\]]*\]\{\d*,\d*\}", "a", body)
    body = re.sub(r"\[[^\]]*\][+*?]?", "a", body)
    body = re.sub(r"\.[+*]", "a", body)
    return body.replace("\\", "")


def _regex_admits(path: str, candidate: str) -> bool:
    body = path[1:]
    body = body if body.startswith("^") else "^" + body
    try:
        return re.match(body, candidate) is not None
    except re.error:
        return True


def _pair_overlaps(left: str, right: str) -> bool:
    if is_regex_path(left) and is_regex_path(right):
        return _regex_admits(left, regex_sample(right)) or _regex_admits(right, regex_sample(left))
    if is_regex_path(left):
        return regex_sample(left).startswith(right) or right.startswith(literal_prefix(left))
    if is_regex_path(right):
        return regex_sample(right).startswith(left) or left.startswith(literal_prefix(right))
    return left.startswith(right) or right.startswith(left)


def _paths_overlap(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return any(_pair_overlaps(left, right) for left in a for right in b)


def routes_overlap(a: SourceRoute, b: SourceRoute) -> bool:
    return _intersects(a.hosts, b.hosts) and _methods_intersect(a.methods, b.methods) and _paths_overlap(a.paths, b.paths)


@dataclass(frozen=True)
class Overlap:
    left: str
    right: str
    winner: str  # route id or "AMBIGUOUS"


def analyze_precedence(routes: dict[str, SourceRoute]) -> list[Overlap]:
    result: list[Overlap] = []
    ids = sorted(routes)
    for index, left_id in enumerate(ids):
        for right_id in ids[index + 1:]:
            left, right = routes[left_id], routes[right_id]
            if not routes_overlap(left, right):
                continue
            lp, rp = route_priority(left), route_priority(right)
            winner = left_id if lp > rp else right_id if rp > lp else "AMBIGUOUS"
            result.append(Overlap(left_id, right_id, winner))
    return result


# --------------------------------------------------------------------------- registry


def _index(items: Iterable[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items:
        if item[key] in out:
            raise FoundationError(f"duplicate {key}: {item[key]}")
        out[item[key]] = item
    return out


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FoundationError(message)


def merge_route(desired: list[SourceRoute], observed: list[SourceRoute]) -> SourceRoute:
    """What the gateway would actually do: observed runtime facts win for match,
    transport, upstream and plugin set; desired contracts supply the policy values
    (rate, body, scope, audience) a readback never carries. A field one side
    leaves unspecified is taken from the other."""
    ordered = list(observed) + list(desired)
    values = dict(ordered[0].__dict__)
    for key in values:
        if key in ("source", "name", "regex_priority"):
            continue
        for candidate in ordered:
            value = getattr(candidate, key)
            if value is not None:
                values[key] = value
                break
    return SourceRoute(**values)


def materialize_route(entry: dict, documents: dict[str, SourceDocument]) -> tuple[SourceRoute, list[SourceRoute], list[SourceRoute]]:
    """Return (merged effective route, all desired, all observed) source routes for a registry entry."""
    desired: list[SourceRoute] = []
    observed: list[SourceRoute] = []
    for binding in entry["bindings"]:
        document = documents.get(binding["source"])
        _require(document is not None, f"route {entry['routeId']}: binding source not registered: {binding['source']}")
        route = document.routes.get(binding["route"])
        _require(route is not None, f"route {entry['routeId']}: {binding['source']} does not declare route {binding['route']}")
        (desired if binding["role"] == "DESIRED" else observed).append(route)
    _require(bool(desired or observed), f"route {entry['routeId']}: no bindings")
    return merge_route(desired, observed), desired, observed


def materialize_service(entry: dict, documents: dict[str, SourceDocument]) -> tuple[list[SourceService], list[SourceService]]:
    desired: list[SourceService] = []
    observed: list[SourceService] = []
    for binding in entry["bindings"]:
        document = documents.get(binding["source"])
        _require(document is not None, f"service {entry['serviceId']}: binding source not registered: {binding['source']}")
        service = document.services.get(binding["service"])
        _require(service is not None, f"service {entry['serviceId']}: {binding['source']} does not declare service {binding['service']}")
        (desired if binding["role"] == "DESIRED" else observed).append(service)
    return desired, observed


def _compare_specified(left: dict[str, Any], right: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    diffs = []
    for key, value in left.items():
        other = right.get(key)
        if value is None or other is None:
            continue
        if isinstance(value, tuple) and isinstance(other, tuple):
            if sorted(value) != sorted(other):
                diffs.append((key, value, other))
        elif value != other:
            diffs.append((key, value, other))
    return diffs


# --------------------------------------------------------------------------- findings


def detect_route_findings(entry: dict, route: SourceRoute, service_entry: dict | None, foundation: dict) -> set[str]:
    rules = foundation["debtRules"]
    findings: set[str] = set()
    methods = set(route.methods or ())
    if route.hosts is None or not route.hosts:
        findings.add("HOST_UNSPECIFIED")
    else:
        if any("*" in host for host in route.hosts):
            findings.add("WILDCARD_HOST")
        if any(host in rules["legacyHosts"] for host in route.hosts):
            findings.add("LEGACY_HOST")
        if any(host.endswith(tuple(rules["placeholderHostSuffixes"])) for host in route.hosts):
            findings.add("PLACEHOLDER_HOST")
    if route.methods is None or not route.methods:
        findings.add("METHODS_UNSPECIFIED")
    elif len(methods & ALL_METHODS) >= 6:
        findings.add("ALL_METHODS")
    paths = route.paths or ()
    if not paths:
        findings.add("PATH_UNSPECIFIED")
    for path in paths:
        prefix = literal_prefix(path)
        if prefix in ("", "/") or path in ("/*", "~/.*", "~/"):
            findings.add("CATCH_ALL_PATH")
        elif prefix.rstrip("/") in rules["catchAllPrefixes"]:
            findings.add("CATCH_ALL_PREFIX")
        if any(segment in rules["adminPathSegments"] for segment in prefix.strip("/").split("/")):
            findings.add("ADMIN_PATH")
    if route.plugins is None:
        findings.add("PLUGIN_SET_UNSPECIFIED")
    else:
        plugins = set(route.plugins)
        # A service-less route whose only job is request-termination answers a
        # constant status at the gateway: nothing is authenticated, buffered or
        # proxied, so the upstream-protection findings do not apply to it.
        terminated = "request-termination" in plugins and route.upstream_host is None and not plugins & AUTHENTICATION_PLUGINS
        if terminated:
            findings.add("GATEWAY_TERMINATED")
        if not plugins & AUTHENTICATION_PLUGINS and not terminated:
            findings.add("NO_GATEWAY_AUTHENTICATION")
        if "key-auth" in plugins:
            findings.add("LEGACY_SHARED_KEY")
        if "cors" in plugins and "key-auth" in plugins:
            findings.add("CORS_WITH_SHARED_KEY")
        if methods & MUTATION_METHODS and "request-size-limiting" not in plugins and route.max_body_bytes is None and not terminated:
            findings.add("UNBOUNDED_REQUEST_BODY")
        if "rate-limiting" not in plugins and route.rate_per_minute is None and not terminated:
            findings.add("NO_RATE_LIMIT")
        if plugins & CLAIM_GUARD_PLUGINS and not plugins & {"jwt", "openid-connect"}:
            findings.add("CLAIM_GUARD_WITHOUT_TOKEN_AUTHENTICATION")
    if route.audience is not None and route.client_id is not None and route.audience == route.client_id:
        findings.add("AUDIENCE_IS_CLIENT_ID")
    host = route.upstream_host or ""
    if host.startswith("${"):
        findings.add("UPSTREAM_HOST_UNRESOLVED")
    if host and IPV4.fullmatch(host):
        findings.add("HARD_CODED_UPSTREAM_IP")
    if host and any(marker in host.lower() for marker in rules["providerUpstreamMarkers"]):
        findings.add("DIRECT_PROVIDER_UPSTREAM")
    if host in rules["legacyUpstreams"]:
        findings.add("LEGACY_UPSTREAM")
    if host in rules["testUpstreams"]:
        findings.add("TEST_UPSTREAM")
    if (route.upstream_host, route.upstream_port) in retired_middleware_aliases(foundation):
        findings.add("RETIRED_UPSTREAM_ALIAS")
    if service_entry is not None:
        if service_entry["upstreamClass"] in rules["directApplicationUpstreamClasses"]:
            findings.add("DIRECT_APPLICATION_UPSTREAM")
    return findings


def retired_middleware_aliases(foundation: dict) -> set[tuple[str, int]]:
    """Middleware upstream aliases the reconciled contract denies (PR #105 retired
    ``appolon-middleware-integration-api:8080``): nothing activatable may target them."""
    return {(a["host"], a["port"]) for a in foundation["boundaryRules"]["middlewareUpstreamAliases"]
            if str(a.get("role", "")).startswith("RETIRED")}


def detect_service_findings(entry: dict, desired: list[SourceService], observed: list[SourceService]) -> set[str]:
    findings: set[str] = set()
    for service in desired or observed:
        if service.carries_retries and service.retries is None:
            findings.add("IMPLICIT_RETRIES")
        if service.carries_timeouts and None in (service.connect_timeout, service.read_timeout, service.write_timeout):
            findings.add("IMPLICIT_TIMEOUTS")
        if service.carries_timeouts and (service.connect_timeout, service.read_timeout, service.write_timeout) == (
            KONG_DEFAULT_TIMEOUT_MS, KONG_DEFAULT_TIMEOUT_MS, KONG_DEFAULT_TIMEOUT_MS
        ):
            findings.add("KONG_DEFAULT_TIMEOUTS")
        if not service.carries_retries:
            findings.add("RETRIES_UNDECLARED" if desired else "RETRIES_UNRECORDED")
        if not service.carries_timeouts:
            findings.add("TIMEOUTS_UNDECLARED")
    return findings


# --------------------------------------------------------------------------- validation


def validate_registry_shape(foundation: dict) -> None:
    _require(foundation["schema"] == SCHEMA, "foundation schema mismatch")
    _require(foundation["runtimeApplyAuthorized"] is False, "foundation must remain source-only")
    _require(foundation["status"] == "SOURCE_CANDIDATE_NO_RUNTIME_APPLY", "foundation status must remain a source candidate")
    _require(set(foundation["environments"]) == {"development", "staging", "production"},
             "development, staging, and production must be explicit")
    rules = foundation["boundaryRules"]
    for key, expected in (
        ("edgeAuthority", "caddy"), ("identityAuthority", "keycloak"),
        ("businessAuthorizationAuthority", "middleware"), ("directProviderRoutesAllowed", False),
        ("fallbackRoutesAllowed", False), ("adminPubliclyReachable", False),
        ("unknownVersionBehavior", "controlled-rejection"), ("wildcardRoutesAllowed", False),
        ("corsCredentialsWithWildcardOriginAllowed", False), ("clientSuppliedIdentityHeadersTrusted", False),
    ):
        _require(rules.get(key) == expected, f"boundaryRules.{key} must be {expected!r}")
    for name in ("timeout", "retry", "rateLimit", "requestSize"):
        _require(isinstance(foundation["profiles"].get(name), dict) and foundation["profiles"][name], f"profiles.{name} missing")
    for name, profile in foundation["profiles"]["timeout"].items():
        for key in ("connectMs", "readMs", "writeMs"):
            _require(isinstance(profile.get(key), int) and profile[key] > 0, f"timeout profile {name}.{key} must be a positive integer")
            _require(profile[key] <= foundation["profiles"]["limits"]["maxTimeoutMs"], f"timeout profile {name}.{key} exceeds the maximum")
    for name, profile in foundation["profiles"]["retry"].items():
        _require(isinstance(profile.get("retries"), int) and 0 <= profile["retries"] <= foundation["profiles"]["limits"]["maxRetries"],
                 f"retry profile {name} must declare bounded retries")
    for name, profile in foundation["profiles"]["rateLimit"].items():
        _require(profile.get("perMinute") is None or (isinstance(profile["perMinute"], int) and profile["perMinute"] > 0),
                 f"rate-limit profile {name}.perMinute must be a positive integer or null")
    for name, profile in foundation["profiles"]["requestSize"].items():
        _require(profile.get("maxBodyBytes") is None or (isinstance(profile["maxBodyBytes"], int) and profile["maxBodyBytes"] > 0),
                 f"request-size profile {name}.maxBodyBytes must be a positive integer or null")
    _require(set(foundation["authenticationClasses"]) == {"PUBLIC", "AUTHENTICATED", "SERVICE_AUTHENTICATED", "ADMIN_INTERNAL", "INTERNAL"},
             "authentication classes must be exactly the five gateway classes")


def validate_source_discovery(foundation: dict, root: Path = ROOT) -> None:
    """Every file that looks like a Kong route/plugin source must be registered or
    excluded with a reason, so a new contract cannot arrive undocumented."""
    discovery = foundation["sourceDiscovery"]
    registered = {source["path"] for source in foundation["sources"]}
    excluded = {item["path"]: item["reason"] for item in discovery["excluded"]}
    for path, reason in excluded.items():
        _require(bool(reason), f"sourceDiscovery exclusion {path} needs a reason")
        _require(path not in registered, f"sourceDiscovery exclusion {path} is also a registered source")
    found: set[str] = set()
    for pattern in discovery["patterns"]:
        for match in sorted(root.glob(pattern)):
            if match.is_file():
                found.add(match.relative_to(root).as_posix())
    # K1 is a typed runtime authority, not a route/plugin manifest. Validate it
    # rather than silently excluding it from the route-source discovery gate.
    runtime_path = "config/kong-runtime-config-mode.v1.json"
    try:
        validate_runtime_authority(load_json(root / runtime_path))
    except (ValueError, OSError) as error:
        raise FoundationError(f"K1 runtime authority invalid: {error}") from error
    unregistered = sorted(found - registered - set(excluded) - {runtime_path})
    _require(not unregistered, f"unregistered Kong source files (register them in sources[] or exclude with a reason): {unregistered}")
    stale = sorted(set(excluded) - found)
    _require(not stale, f"sourceDiscovery exclusions for files that no longer exist: {stale}")


def validate_sources(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    for source in foundation["sources"]:
        for key in ("path", "format", "environment", "role", "activation"):
            _require(key in source, f"source {source.get('path')} lacks {key}")
        _require(source["environment"] in set(foundation["environments"]) | {"none"}, f"source {source['path']} has unknown environment")
        _require(source["role"] in foundation["enums"]["sourceRoles"], f"source {source['path']} has unknown role {source['role']}")
        _require(source["activation"] in foundation["enums"]["activations"], f"source {source['path']} has unknown activation")
        document = documents[source["path"]]
        environment = foundation["environments"].get(source["environment"], {})
        if document.issuer and source["environment"] in ("staging", "production"):
            _require(document.issuer == environment["issuer"],
                     f"source {source['path']} binds issuer {document.issuer} but {source['environment']} requires {environment['issuer']}")
        if document.declared_environment is not None:
            _require(document.declared_environment == source["environment"],
                     f"source {source['path']} declares environment {document.declared_environment} but is registered as {source['environment']}")
        if source["role"] in ("DEPLOYED_CANDIDATE", "RUNTIME_READBACK", "CONTRACT", "OVERLAY"):
            pass
        if document.global_plugins and source["role"] != "PLUGIN_TEMPLATE":
            for plugin in document.global_plugins:
                _require(plugin in foundation["pluginGovernance"]["globalPluginsAllowed"],
                         f"source {source['path']} declares global plugin {plugin} which is not allowed globally")
                _require(plugin not in AUTHENTICATION_PLUGINS, f"authentication plugin {plugin} must never be global")
        if source["role"] == "PLUGIN_TEMPLATE":
            _require(source["activation"] == "TEMPLATE_NOT_LOADABLE", f"plugin template {source['path']} must be TEMPLATE_NOT_LOADABLE")


def validate_no_undocumented_routes(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    bound: dict[str, set[str]] = {path: set() for path in documents}
    for entry in foundation["routes"]:
        for binding in entry["bindings"]:
            bound[binding["source"]].add(binding["route"])
    for path, document in documents.items():
        missing = sorted(set(document.routes) - bound[path])
        _require(not missing, f"undocumented routes in {path}: {missing}")
    bound_services: dict[str, set[str]] = {path: set() for path in documents}
    for entry in foundation["services"]:
        for binding in entry["bindings"]:
            bound_services[binding["source"]].add(binding["service"])
    for path, document in documents.items():
        missing = sorted(set(document.services) - bound_services[path])
        _require(not missing, f"undocumented services in {path}: {missing}")


def validate_services(foundation: dict, documents: dict[str, SourceDocument]) -> dict[str, dict]:
    services = _index(foundation["services"], "serviceId")
    enums = foundation["enums"]
    profiles = foundation["profiles"]
    drift = {(d["subject"], d["field"]): d for d in foundation["knownDrift"]}
    seen_drift: set[tuple[str, str]] = set()
    for entry in services.values():
        for key in ("owner", "environment", "purpose", "trafficClass", "upstreamClass", "upstream", "healthProfile",
                    "timeoutProfile", "retryProfile", "authenticationProfile", "authorizationPrerequisiteProfile",
                    "rateLimitProfile", "requestSizeProfile", "observabilityProfile", "lifecycle", "disposition",
                    "acceptedFindings", "bindings"):
            _require(key in entry, f"service {entry['serviceId']} lacks {key}")
        _require(entry["environment"] in foundation["environments"], f"service {entry['serviceId']} has unknown environment")
        _require(entry["trafficClass"] in enums["trafficClasses"], f"service {entry['serviceId']} has unknown traffic class")
        _require(entry["upstreamClass"] in enums["upstreamClasses"], f"service {entry['serviceId']} has unknown upstream class")
        _require(entry["lifecycle"] in enums["lifecycles"], f"service {entry['serviceId']} has unknown lifecycle")
        _require(entry["disposition"] in enums["dispositions"], f"service {entry['serviceId']} has unknown disposition")
        _require(entry["timeoutProfile"] in profiles["timeout"], f"service {entry['serviceId']} uses unknown timeout profile")
        _require(entry["retryProfile"] in profiles["retry"], f"service {entry['serviceId']} uses unknown retry profile")
        _require(entry["healthProfile"] in profiles["health"], f"service {entry['serviceId']} uses unknown health profile")
        _require(entry["authenticationProfile"] in foundation["authenticationClasses"], f"service {entry['serviceId']} has unknown authentication profile")
        _require(entry["observabilityProfile"] in profiles["observability"], f"service {entry['serviceId']} uses unknown observability profile")
        _require(entry["rateLimitProfile"] in profiles["rateLimit"], f"service {entry['serviceId']} uses unknown rate-limit profile")
        _require(entry["requestSizeProfile"] in profiles["requestSize"], f"service {entry['serviceId']} uses unknown request-size profile")
        _require(entry["authorizationPrerequisiteProfile"] in enums["authorizationPrerequisiteProfiles"],
                 f"service {entry['serviceId']} has unknown authorization prerequisite profile")
        if entry["upstreamClass"] in foundation["debtRules"]["directApplicationUpstreamClasses"]:
            _require(bool(entry.get("directUpstreamReason")), f"direct application service {entry['serviceId']} requires directUpstreamReason")
        if entry["upstreamClass"] in foundation["debtRules"]["middlewareUpstreamClasses"]:
            aliases = {(a["host"], a["port"]) for a in foundation["boundaryRules"]["middlewareUpstreamAliases"]}
            _require((entry["upstream"]["host"], entry["upstream"]["port"]) in aliases,
                     f"service {entry['serviceId']} targets an undeclared Middleware alias {entry['upstream']['host']}:{entry['upstream']['port']}")
        desired, observed = materialize_service(entry, documents)
        _require(bool(desired or observed), f"service {entry['serviceId']} has no bindings")
        expected_upstream = entry["upstream"]
        for service in desired:
            for key, registry_key in (("protocol", "protocol"), ("host", "host"), ("port", "port")):
                value = getattr(service, key)
                if value is not None:
                    _require(value == expected_upstream[registry_key],
                             f"service {entry['serviceId']}: {service.source} declares {key}={value!r} but registry says {expected_upstream[registry_key]!r}")
        timeout = profiles["timeout"][entry["timeoutProfile"]]
        retry = profiles["retry"][entry["retryProfile"]]
        for service in desired:
            if service.carries_timeouts and service.connect_timeout is not None:
                actual = (service.connect_timeout, service.read_timeout, service.write_timeout)
                expected = (timeout["connectMs"], timeout["readMs"], timeout["writeMs"])
                _require(actual == expected, f"service {entry['serviceId']}: {service.source} timeouts {actual} do not match profile {entry['timeoutProfile']} {expected}")
            if service.carries_retries and service.retries is not None:
                _require(service.retries == retry["retries"], f"service {entry['serviceId']}: {service.source} retries={service.retries} do not match profile {entry['retryProfile']}")
        if desired and desired[0].carries_retries and desired[0].retries is None:
            _require(retry["retries"] == KONG_DEFAULT_RETRIES, f"service {entry['serviceId']} leaves retries implicit; retry profile must be the Kong default profile")
        for service in observed:
            reference = desired[0] if desired else None
            if reference is None:
                continue
            for key, observed_value, desired_value in _compare_specified(service.field_values(), reference.field_values()):
                if key == "retries" and not service.carries_retries:
                    continue
                subject = (entry["serviceId"], key)
                declared = drift.get(subject)
                _require(declared is not None,
                         f"service {entry['serviceId']}: undeclared runtime drift on {key}: observed {observed_value!r} desired {desired_value!r}")
                _require(declared["observed"] == _plain(observed_value) and declared["desired"] == _plain(desired_value),
                         f"service {entry['serviceId']}: knownDrift for {key} is stale")
                seen_drift.add(subject)
        findings = detect_service_findings(entry, desired, observed)
        if (entry["upstream"]["host"], entry["upstream"]["port"]) in retired_middleware_aliases(foundation):
            findings.add("RETIRED_UPSTREAM_ALIAS")
            _require(entry["lifecycle"] in foundation["debtRules"]["retiredAliasLifecycles"],
                     f"service {entry['serviceId']} targets a retired Middleware alias and is not a non-activatable lifecycle")
        accepted = set(entry["acceptedFindings"])
        _require(findings == accepted,
                 f"service {entry['serviceId']}: detected findings {sorted(findings)} != accepted {sorted(accepted)}")
        if entry["lifecycle"] == "CANONICAL":
            forbidden = accepted & set(foundation["debtRules"]["forbiddenOnCanonical"])
            _require(not forbidden, f"canonical service {entry['serviceId']} carries forbidden findings {sorted(forbidden)}")
        if entry["lifecycle"] == "CANONICAL" and retry["retries"] > 0:
            _require(retry.get("transportSafe") is True, f"canonical service {entry['serviceId']} uses retry profile {entry['retryProfile']} which is not marked transport safe")
        if entry["lifecycle"] == "DESIGN_ONLY":
            continue
    stale = {(d["subject"], d["field"]) for d in foundation["knownDrift"] if d["kind"] == "service"} - seen_drift
    _require(not stale, f"stale knownDrift entries: {sorted(stale)}")
    return services


def _plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return sorted(value)
    return value


def validate_routes(foundation: dict, documents: dict[str, SourceDocument], services: dict[str, dict]) -> dict[str, SourceRoute]:
    routes = _index(foundation["routes"], "routeId")
    enums = foundation["enums"]
    profiles = foundation["profiles"]
    rules = foundation["debtRules"]
    drift = {(d["subject"], d["field"]): d for d in foundation["knownDrift"] if d["kind"] == "route"}
    seen_drift: set[tuple[str, str]] = set()
    materialized: dict[str, SourceRoute] = {}
    for entry in routes.values():
        route_id = entry["routeId"]
        for key in ("serviceId", "environment", "bindings", "trafficClass", "authentication", "mechanism",
                    "rateLimitProfile", "requestSizeProfile", "lifecycle", "activation", "disposition",
                    "acceptedFindings"):
            _require(key in entry, f"route {route_id} lacks {key}")
        _require(entry["environment"] in foundation["environments"], f"route {route_id} has unknown environment")
        if entry["serviceId"] is None:
            service_entry = None  # gateway-terminated route: proven below
        else:
            _require(entry["serviceId"] in services, f"route {route_id} references unknown service {entry['serviceId']}")
            service_entry = services[entry["serviceId"]]
            _require(entry["environment"] == service_entry["environment"], f"route {route_id} environment differs from its service")
        _require(entry["trafficClass"] in enums["trafficClasses"], f"route {route_id} has unknown traffic class")
        _require(entry["authentication"] in foundation["authenticationClasses"], f"route {route_id} has unknown authentication class")
        _require(entry["mechanism"] in enums["mechanisms"], f"route {route_id} has unknown mechanism {entry['mechanism']}")
        _require(entry["lifecycle"] in enums["lifecycles"], f"route {route_id} has unknown lifecycle")
        _require(entry["activation"] in enums["activations"], f"route {route_id} has unknown activation")
        _require(entry["disposition"] in enums["dispositions"], f"route {route_id} has unknown disposition")
        _require(entry["rateLimitProfile"] in profiles["rateLimit"], f"route {route_id} uses unknown rate-limit profile")
        _require(entry["requestSizeProfile"] in profiles["requestSize"], f"route {route_id} uses unknown request-size profile")
        primary, desired, observed = materialize_route(entry, documents)
        for binding in entry["bindings"]:
            source = next(s for s in foundation["sources"] if s["path"] == binding["source"])
            _require(source["environment"] == entry["environment"],
                     f"route {route_id}: binding {binding['source']} is a {source['environment']} source but the route is {entry['environment']}")
        for index, left in enumerate(desired):
            for other in desired[index + 1:]:
                diffs = _compare_specified(left.field_values(), other.field_values())
                _require(not diffs, f"route {route_id}: desired sources disagree {left.source} vs {other.source}: {diffs}")
        for obs in observed:
            reference = desired[0] if desired else None
            if reference is None:
                continue
            for key, observed_value, desired_value in _compare_specified(obs.field_values(), reference.field_values()):
                subject = (route_id, key)
                declared = drift.get(subject)
                _require(declared is not None,
                         f"route {route_id}: undeclared runtime drift on {key}: observed {_plain(observed_value)!r} desired {_plain(desired_value)!r}")
                _require(declared["observed"] == _plain(observed_value) and declared["desired"] == _plain(desired_value),
                         f"route {route_id}: knownDrift for {key} is stale")
                seen_drift.add(subject)
        materialized[route_id] = primary
        for binding_route in desired + observed:
            if binding_route.service_name is not None:
                _require(service_entry is not None, f"route {route_id}: {binding_route.source} binds a service but the registry declares none")
                _require(any(b["service"] == binding_route.service_name and b["source"] == binding_route.source for b in service_entry["bindings"]),
                         f"route {route_id}: {binding_route.source} binds service {binding_route.service_name} which is not a binding of {entry['serviceId']}")
        # profile cross-checks
        rate = profiles["rateLimit"][entry["rateLimitProfile"]]
        if primary.rate_per_minute is not None:
            _require(rate["perMinute"] == primary.rate_per_minute,
                     f"route {route_id}: source rate {primary.rate_per_minute}/min does not match profile {entry['rateLimitProfile']}")
        size = profiles["requestSize"][entry["requestSizeProfile"]]
        if primary.max_body_bytes is not None:
            _require(size["maxBodyBytes"] == primary.max_body_bytes,
                     f"route {route_id}: source body limit {primary.max_body_bytes} does not match profile {entry['requestSizeProfile']}")
        if primary.required_scope is not None:
            _require(primary.required_scope in entry.get("requiredScopes", []),
                     f"route {route_id}: source scope {primary.required_scope} is not registered")
        if primary.audience is not None:
            _require(entry.get("audience") == primary.audience,
                     f"route {route_id}: source audience {primary.audience} != registered {entry.get('audience')}")
        # wildcard / explicit posture
        for values, label in ((primary.hosts, "hosts"), (primary.paths, "paths"), (primary.methods, "methods")):
            for value in values or ():
                _require(value not in ("*", "/*"), f"route {route_id}: wildcard {label} are forbidden")
        # findings
        findings = detect_route_findings(entry, primary, service_entry, foundation)
        accepted = set(entry["acceptedFindings"])
        _require(findings == accepted, f"route {route_id}: detected findings {sorted(findings)} != accepted {sorted(accepted)}")
        # classification rules
        methods = set(primary.methods or ())
        terminated = "GATEWAY_TERMINATED" in findings
        _require(terminated == (entry["serviceId"] is None),
                 f"route {route_id}: a route without a service must be gateway-terminated and vice versa")
        if terminated:
            _require(primary.upstream_host is None and entry["mechanism"] == "NONE" and entry["authentication"] == "PUBLIC",
                     f"terminated route {route_id} must have no upstream, mechanism NONE and be an explicit PUBLIC 404 responder")
            _require(entry["trafficClass"] == "DENIED_ALIAS", f"terminated route {route_id} must carry the DENIED_ALIAS traffic class")
        if entry["authentication"] == "PUBLIC":
            _require(bool(entry.get("publicReason")), f"public route {route_id} requires publicReason")
            if methods & MUTATION_METHODS:
                _require(entry["lifecycle"] in rules["publicMutationLifecycles"] or entry["activation"] == "BLOCKED" or terminated,
                         f"public mutation route {route_id} must be legacy, blocked or gateway-terminated")
        not_activatable = entry["activation"] in rules["nonActivatableActivations"]
        if "NO_GATEWAY_AUTHENTICATION" in findings:
            _require(entry["mechanism"] == "NONE", f"route {route_id} has no authentication plugin but claims mechanism {entry['mechanism']}")
            _require(entry["authentication"] == "PUBLIC" or entry["activation"] == "BLOCKED"
                     or (not_activatable and bool(entry.get("authenticationGap"))),
                     f"route {route_id} has no gateway authentication and is neither PUBLIC, BLOCKED nor a design with a declared authenticationGap")
        if entry["mechanism"] == "NONE":
            _require("NO_GATEWAY_AUTHENTICATION" in findings or "PLUGIN_SET_UNSPECIFIED" in findings or terminated,
                     f"route {route_id} claims mechanism NONE but an authentication plugin is present")
        if "RETIRED_UPSTREAM_ALIAS" in findings:
            _require(entry["lifecycle"] in rules["retiredAliasLifecycles"],
                     f"route {route_id} targets a retired Middleware alias and is not a non-activatable or retiring lifecycle")
        if entry["mechanism"] == "KEY_AUTH_SHARED":
            _require(entry["lifecycle"] in rules["sharedKeyLifecycles"], f"shared-key route {route_id} must be legacy")
            _require("LEGACY_SHARED_KEY" in findings, f"route {route_id} claims KEY_AUTH_SHARED without key-auth")
        if entry["authentication"] in ("AUTHENTICATED", "SERVICE_AUTHENTICATED", "ADMIN_INTERNAL", "INTERNAL"):
            # The class states the required posture; a NONE mechanism records the
            # observed gap and is tolerated only while the route cannot be activated.
            _require(entry["mechanism"] != "NONE" or entry["activation"] == "BLOCKED"
                     or (not_activatable and bool(entry.get("authenticationGap"))),
                     f"route {route_id} is {entry['authentication']} without a mechanism and is not blocked")
            if entry["mechanism"] in rules["tokenMechanisms"]:
                _require(bool(entry.get("audience")), f"token-authenticated route {route_id} requires an audience")
        if entry["authentication"] == "ADMIN_INTERNAL" and entry["activation"] != "BLOCKED":
            _require(entry["mechanism"] != "NONE" and entry.get("requiredScopes"), f"admin route {route_id} requires a mechanism and scopes")
        if "ADMIN_PATH" in findings:
            _require(entry["authentication"] == "ADMIN_INTERNAL" or entry["activation"] == "BLOCKED",
                     f"route {route_id} exposes an administrative path without ADMIN_INTERNAL classification")
        if "PLACEHOLDER_HOST" in findings:
            _require(entry["activation"] != "RUNTIME_OBSERVED", f"route {route_id} runs on a placeholder host")
        if "DIRECT_PROVIDER_UPSTREAM" in findings or "HARD_CODED_UPSTREAM_IP" in findings:
            _require(entry["activation"] == "BLOCKED", f"route {route_id} targets a provider or hard-coded IP upstream and is not blocked")
        for path in primary.paths or ():
            _require(path not in foundation["edgeOwnedPaths"] or not (set(primary.hosts or ()) & set(foundation["edgeOwnedHosts"])),
                     f"route {route_id} declares an edge-owned path {path}")
        if entry["lifecycle"] == "CANONICAL":
            forbidden = accepted & set(rules["forbiddenOnCanonical"])
            _require(not forbidden, f"canonical route {route_id} carries forbidden findings {sorted(forbidden)}")
            _require(entry["activation"] in ("RUNTIME_OBSERVED", "SOURCE_CANDIDATE"), f"canonical route {route_id} has activation {entry['activation']}")
            _require(bool(desired), f"canonical route {route_id} must have a DESIRED binding")
        if entry["activation"] == "RUNTIME_OBSERVED":
            _require(bool(observed), f"route {route_id} claims RUNTIME_OBSERVED without an OBSERVED binding")
        if observed and entry["activation"] not in ("RUNTIME_OBSERVED", "BLOCKED"):
            raise FoundationError(f"route {route_id} has an OBSERVED binding but activation {entry['activation']}")
        if entry["activation"] == "BLOCKED":
            _require(bool(entry.get("blockedReason")), f"blocked route {route_id} requires blockedReason")
        if entry["lifecycle"] in ("DESIGN_ONLY", "PREPARED_DISABLED", "PROPOSED"):
            _require(entry["activation"] in ("DESIGN_ONLY", "PREPARED_DISABLED", "PROPOSED"),
                     f"route {route_id} lifecycle {entry['lifecycle']} cannot have activation {entry['activation']}")
        if entry["lifecycle"] == "LEGACY":
            _require(bool(entry.get("retirement")), f"legacy route {route_id} requires a retirement statement")
        if entry.get("supersededBy"):
            _require(entry["supersededBy"] in routes, f"route {route_id} supersededBy unknown route {entry['supersededBy']}")
            _require(entry["lifecycle"] in ("LEGACY", "TRANSITIONAL"), f"superseded route {route_id} must be legacy or transitional")
        if entry.get("legacyRetirement"):
            pass
    stale = set(drift) - seen_drift
    _require(not stale, f"stale route knownDrift entries: {sorted(stale)}")
    return materialized


def validate_precedence(foundation: dict, routes: dict[str, dict], materialized: dict[str, SourceRoute]) -> list[Overlap]:
    universes: dict[str, dict[str, SourceRoute]] = {}
    for route_id, route in materialized.items():
        entry = routes[route_id]
        if entry["activation"] not in foundation["precedence"]["analyzedActivations"]:
            continue
        universes.setdefault(entry["environment"], {})[route_id] = route
    declared = {(c["left"], c["right"]): c for c in foundation["precedence"]["knownConflicts"]}
    service_index = _index(foundation["services"], "serviceId")
    seen: set[tuple[str, str]] = set()
    overlaps: list[Overlap] = []
    for environment, universe in universes.items():
        for overlap in analyze_precedence(universe):
            key = (overlap.left, overlap.right)
            conflict = declared.get(key)
            _require(conflict is not None,
                     f"undeclared route overlap in {environment}: {overlap.left} vs {overlap.right} (winner {overlap.winner})")
            _require(conflict["winner"] == overlap.winner,
                     f"conflict {overlap.left} vs {overlap.right}: registry expects winner {conflict['winner']} but router yields {overlap.winner}")
            _require(conflict["resolution"] in foundation["enums"]["conflictResolutions"],
                     f"conflict {overlap.left} vs {overlap.right} has unknown resolution")
            if overlap.winner == "AMBIGUOUS":
                _require(conflict["resolution"] != "DETERMINISTIC_SPECIFICITY", "ambiguous overlaps cannot be resolved by specificity")
                for route_id in key:
                    _require(routes[route_id]["lifecycle"] != "CANONICAL" or routes[route_id]["activation"] == "SOURCE_CANDIDATE",
                             f"canonical runtime route {route_id} is in an ambiguous overlap")
            else:
                loser = overlap.right if overlap.winner == overlap.left else overlap.left
                winner_entry, loser_entry = routes[overlap.winner], routes[loser]
                # A canonical successor shadowed by the legacy/transitional route (or
                # service family) it replaces must be acknowledged as such; unrelated
                # routes that win by specificity keep their own authority.
                replaces = (winner_entry.get("supersededBy") == loser
                            or (winner_entry["serviceId"] is not None and loser_entry["serviceId"] is not None
                                and service_index[winner_entry["serviceId"]].get("supersededBy") == loser_entry["serviceId"]))
                if loser_entry["lifecycle"] == "CANONICAL" and winner_entry["lifecycle"] in ("LEGACY", "TRANSITIONAL") and replaces:
                    _require(conflict["resolution"] == "LEGACY_SHADOWS_SUCCESSOR_UNTIL_RETIRED",
                             f"canonical route {loser} is shadowed by the route it replaces, {overlap.winner}; resolution must acknowledge it")
            seen.add(key)
            overlaps.append(overlap)
    stale = set(declared) - seen
    _require(not stale, f"stale knownConflicts: {sorted(stale)}")
    return overlaps


def validate_plugins(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    registry = _index(foundation["plugins"], "plugin")
    governance = foundation["pluginGovernance"]
    for name, entry in registry.items():
        for key in governance["requiredMetadata"]:
            _require(key in entry and entry[key] not in (None, "", []), f"plugin {name} lacks {key}")
        _require(set(entry["allowedScopes"]) <= set(governance["scopeValues"]), f"plugin {name} has unknown scopes")
        if entry["authentication"]:
            _require("GLOBAL" not in entry["allowedScopes"], f"authentication plugin {name} must not allow GLOBAL scope")
            _require(name in AUTHENTICATION_PLUGINS, f"plugin {name} is marked authentication but is not an authentication plugin")
        if "GLOBAL" in entry["allowedScopes"]:
            _require(name in governance["globalPluginsAllowed"], f"plugin {name} allows GLOBAL scope but is not in the global allowlist")
    for plugin in governance["globalPluginsAllowed"]:
        _require(plugin in registry and "GLOBAL" in registry[plugin]["allowedScopes"], f"global allowlist entry {plugin} is not registered with GLOBAL scope")
    used: dict[str, set[str]] = {}
    for path, document in documents.items():
        for plugin in document.global_plugins:
            used.setdefault(plugin, set()).add(path)
        for route in document.routes.values():
            for plugin in route.plugins or ():
                used.setdefault(plugin, set()).add(path)
        for service in document.services.values():
            for plugin in service.plugins:
                used.setdefault(plugin, set()).add(path)
    for plugin, paths in used.items():
        _require(plugin in registry, f"plugin {plugin} used by {sorted(paths)} is not governed")
        for path in paths:
            _require(path in registry[plugin]["configurationSources"],
                     f"plugin {plugin}: {path} uses it but is not a registered configuration source")
    for name, entry in registry.items():
        for path in entry["configurationSources"]:
            _require(path in used.get(name, set()) or (CURRENT_ROOT / path).is_file(),
                     f"plugin {name}: configuration source {path} does not exist")
    priorities = {name: entry["priority"] for name, entry in registry.items()}
    readback = {s["path"] for s in foundation["sources"] if s["role"] == "RUNTIME_READBACK"}
    for path, document in documents.items():
        if path in readback:
            continue  # observed plugin phases are reconciled through knownDrift
        for route in document.routes.values():
            plugins = set(route.plugins or ())
            guards = plugins & CLAIM_GUARD_PLUGINS
            auth = plugins & {"jwt", "openid-connect"}
            for guard in guards:
                _require(all(priorities[a] > priorities[guard] for a in auth) if auth else True,
                         f"{path}:{route.name}: claim guard {guard} would run before its authentication plugin")
            if "pre-function" in plugins:
                _require(path in governance["preFunctionAllowedSources"],
                         f"{path}:{route.name}: pre-function is only allowed for raw-metadata guards in {governance['preFunctionAllowedSources']}")


def validate_environments(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    environments = foundation["environments"]
    _require(environments["staging"]["issuer"] != environments["production"]["issuer"], "staging and production must not share an issuer")
    _require(environments["development"]["issuer"] is None, "development must not bind a shared issuer")
    for overlay in foundation["environments"]["staging"]["overlays"]:
        base = documents[overlay["base"]]
        over = documents[overlay["overlay"]]
        _require(set(over.routes) <= set(base.routes), f"overlay {overlay['overlay']} declares routes absent from {overlay['base']}")
        excluded = set(base.routes) - set(over.routes)
        _require(excluded == set(overlay["excludedRoutes"]),
                 f"overlay {overlay['overlay']} excludes {sorted(excluded)} but registry says {sorted(overlay['excludedRoutes'])}")
        for name, route in over.routes.items():
            diffs = [d for d in _compare_specified(route.field_values(), base.routes[name].field_values()) if d[0] not in ("audience",)]
            _require(not diffs, f"overlay {overlay['overlay']} route {name} drifts from base: {diffs}")
        _require(over.issuer == environments["staging"]["issuer"], f"overlay {overlay['overlay']} must use the staging issuer")
        _require(base.issuer == environments["production"]["issuer"], f"base {overlay['base']} must use the production issuer")
        for name, service in over.services.items():
            base_service = base.services.get(name)
            _require(base_service is not None, f"overlay {overlay['overlay']} service {name} has no base service")
            if (service.host, service.port) == (base_service.host, base_service.port):
                _require(overlay.get("sharedUpstreamAliases") is True,
                         f"overlay {overlay['overlay']} reuses production upstream alias {service.host}:{service.port} without declaring sharedUpstreamAliases")


def validate_node(foundation: dict, root: Path = ROOT) -> None:
    node = foundation["node"]
    compose = load_yaml(root / node["compose"])
    gateway = compose["services"][node["composeService"]]
    environment = gateway["environment"]
    _require(environment.get("KONG_ADMIN_LISTEN") == "off", "Admin API must remain disabled on data planes")
    _require(environment.get("KONG_ADMIN_GUI_LISTEN") == "off", "Kong Manager must remain off")
    ports = [str(p) for p in gateway.get("ports", [])]
    _require(all(p.startswith("127.0.0.1:") for p in ports), "every published port must bind host loopback")
    _require(not any(":8001" in p or ":8100" in p or ":8002" in p for p in ports), "Admin, Manager and Status must not be published")
    _require(environment.get("KONG_ROLE") == "data_plane" and environment.get("KONG_DATABASE") == "off",
             "K1 requires a hybrid data plane")
    _require(not any(key.startswith("KONG_PG_") for key in environment), "data plane database settings forbidden")
    _require("@${KONG_IMAGE_DIGEST:?" in gateway.get("image", ""), "gateway image must use an immutable digest")
    _require(str(environment.get("KONG_TRUSTED_IPS", "")).startswith("${KONG_TRUSTED_IPS:?"), "trusted_ips must be required from the deployment with no default")
    _require(environment.get("KONG_REAL_IP_HEADER") == "X-Forwarded-For" and environment.get("KONG_REAL_IP_RECURSIVE") == "on",
             "forwarded client address must be taken from X-Forwarded-For recursively")
    _require(environment.get("KONG_UNTRUSTED_LUA") == "sandbox", "untrusted_lua must stay sandboxed")
    _require(environment.get("KONG_UNTRUSTED_LUA_SANDBOX_REQUIRES") == "cjson.safe", "sandbox requires must be exactly cjson.safe")
    _require(environment.get("KONG_VAULTS") == "env", "env vault must be enabled")
    _require(environment.get("KONG_HEADERS") == "off", "server headers must be off")
    _require(environment.get("KONG_STATUS_LISTEN") == "0.0.0.0:8100", "status listener must be the private 8100 listener")
    _require(environment.get("KONG_ADMIN_ACCESS_LOG") == "off" and environment.get("KONG_STATUS_ACCESS_LOG") == "off", "admin/status access logs stay off")
    _require(environment.get("KONG_PROXY_ACCESS_LOG") == "/dev/stdout" and environment.get("KONG_PROXY_ERROR_LOG") == "/dev/stderr", "proxy logs go to the container streams")
    _require(gateway.get("read_only") is True, "container root must be read-only")
    _require(gateway.get("cap_drop") == ["ALL"], "all capabilities must be dropped")
    _require("no-new-privileges:true" in gateway.get("security_opt", []), "no-new-privileges is required")
    _require("healthcheck" in gateway, "a health check is required")
    _require("docker.sock" not in json.dumps(gateway), "the Docker socket must never be mounted")
    _require(not gateway.get("privileged") and not gateway.get("network_mode"), "privileged and host networking are forbidden")
    for secret in ("kong_license", "cluster_ca", "dp_cert", "dp_key"):
        _require(secret in gateway.get("secrets", []), f"secret {secret} must be mounted as a file")
    for name, definition in compose.get("secrets", {}).items():
        _require(set(definition) == {"file"} and definition["file"].startswith("/etc/codestra/secrets/"), f"secret {name} must be a root-owned host file path")
    for network in compose.get("networks", {}).values():
        _require(network.get("external") is True, "every network must be an existing external network")
    conf = (root / node["confExample"]).read_text(encoding="utf-8")
    settings = dict(re.findall(r"^([a-z_]+)\s*=\s*(\S+)", conf, flags=re.MULTILINE))
    # Frozen K1 mode authority supersedes the earlier node's combined DB/Admin
    # topology only; all route, identity and sandbox foundation policy remains.
    expected_conf = dict(node["confMustEqual"])
    expected_conf.pop("pg_ssl", None)
    expected_conf.pop("pg_ssl_verify", None)
    expected_conf.update(admin_listen="off", role="data_plane", database="off", cluster_mtls="pki")
    for key, expected in expected_conf.items():
        _require(settings.get(key) == expected, f"kong.conf.example {key} must be {expected!r} (found {settings.get(key)!r})")
    # env template completeness
    declared = set(re.findall(r"^([A-Z0-9_]+)=", (root / node["runtimeEnvExample"]).read_text(encoding="utf-8"), flags=re.MULTILINE))
    for candidate in node["vaultReferenceSources"]:
        text = (root / candidate).read_text(encoding="utf-8")
        for reference in set(VAULT_ENV.findall(text)):
            variable = reference.upper().replace("-", "_")
            _require(variable in declared, f"{candidate} references {{vault://env/{reference}}} but {node['runtimeEnvExample']} does not declare {variable}")
    observability = dict(re.findall(r"^([A-Z_]+)=(\S+)", (root / node["observabilityEnvExample"]).read_text(encoding="utf-8"), flags=re.MULTILINE))
    _require(observability.get("KONG_STATUS_LISTEN") == "0.0.0.0:8100", "observability template must bind the private status listener")


def validate_inventory_gates(foundation: dict, root: Path = ROOT) -> None:
    inventory = load_json(root / "config/kong-production-route-inventory.v2.json")
    blocked = {item["route"]: item for item in inventory.get("activationBlockedRoutes", [])}
    for entry in foundation["routes"]:
        observed = [b for b in entry["bindings"] if b["source"] == "config/kong-production-route-inventory.v2.json"]
        if not observed:
            continue
        if entry["activation"] == "BLOCKED" and entry.get("inventoryGate") == "activationBlockedRoutes":
            _require(observed[0]["route"] in blocked,
                     f"route {entry['routeId']} is BLOCKED but the production inventory does not list it in activationBlockedRoutes")
    for name, item in blocked.items():
        entry = next((r for r in foundation["routes"] if any(b["route"] == name and b["source"] == "config/kong-production-route-inventory.v2.json" for b in r["bindings"])), None)
        _require(entry is not None and entry["activation"] == "BLOCKED", f"inventory blocks {name} but the registry does not")
        _require(item.get("activationAuthorized") is False, f"inventory activationBlockedRoutes entry {name} must not authorize activation")


def validate_foundation(root: Path = ROOT, foundation_path: Path | None = None) -> dict:
    foundation = load_json(foundation_path or (root / "config/kong-gateway-foundation.v1.json"))
    validate_registry_shape(foundation)
    validate_source_discovery(foundation, root)
    documents = load_sources(foundation, root)
    validate_sources(foundation, documents)
    validate_no_undocumented_routes(foundation, documents)
    services = validate_services(foundation, documents)
    materialized = validate_routes(foundation, documents, services)
    routes = _index(foundation["routes"], "routeId")
    overlaps = validate_precedence(foundation, routes, materialized)
    validate_plugins(foundation, documents)
    validate_environments(foundation, documents)
    validate_node(foundation, root)
    validate_inventory_gates(foundation, root)
    profiles, policy = validate_access_policy(foundation, documents, routes, materialized, root)
    validate_token_settings(documents, profiles, root)
    validate_denied_aliases(foundation, documents, root)
    secret_hits = validate_secret_boundary(root)
    return {
        "foundation": foundation, "documents": documents, "services": services,
        "routes": routes, "materialized": materialized, "overlaps": overlaps,
        "profiles": profiles, "policy": policy, "secret_scan": secret_hits,
    }


# --------------------------------------------------------------------------- identity & access (Mission 2)


def validate_access_policy(foundation: dict, documents: dict[str, SourceDocument], routes: dict[str, dict],
                           materialized: dict[str, SourceRoute], root: Path = ROOT) -> tuple[dict, dict]:
    profiles = load_json(root / AUTH_PROFILES)
    policy = load_json(root / ACCESS_POLICY)
    _require(profiles["schema"] == AUTH_PROFILES_SCHEMA and profiles["runtimeApplyAuthorized"] is False, "authentication profiles must be the source-only v1 catalogue")
    _require(policy["schema"] == ACCESS_POLICY_SCHEMA and policy["runtimeApplyAuthorized"] is False, "access policy must be the source-only v1 policy")
    _require(policy["identityHeaders"]["headerAuthorityAllowed"] is False, "identity headers must never be an authority")
    rules = profiles["rules"]
    _require(rules["wildcardAudienceAllowed"] is False and rules["wildcardScopeAllowed"] is False and rules["identityHeaderAuthorityAllowed"] is False,
             "wildcard audiences, wildcard scopes and identity-header authority must remain forbidden")
    catalogue = profiles["profiles"]
    issuers = profiles["issuerProfiles"]
    audiences = profiles["audienceProfiles"]
    propagation = profiles["identityPropagationProfiles"]
    tenant_policies = profiles["tenantPolicies"]
    failure_policies = profiles["failurePolicies"]
    cache_policies = profiles["tokenCachePolicies"]
    principal_classes = set(profiles["principalClasses"])
    for name, profile in catalogue.items():
        for key in ("accessClasses", "principalClasses", "mechanisms", "issuerProfile", "audienceProfiles", "scopes", "authorizedParties",
                    "failurePolicy", "tokenCache", "strength"):
            _require(key in profile, f"authentication profile {name} lacks {key}")
        _require(set(profile["accessClasses"]) <= set(ACCESS_CLASSES), f"profile {name} names an unknown access class")
        _require(set(profile["principalClasses"]) <= principal_classes, f"profile {name} names an unknown principal class")
        _require(set(profile["mechanisms"]) <= set(foundation["enums"]["mechanisms"]), f"profile {name} names an unknown mechanism")
        _require(profile["issuerProfile"] in issuers or profile["issuerProfile"] == "environment", f"profile {name} names an unknown issuer profile")
        _require(set(profile["audienceProfiles"]) <= set(audiences), f"profile {name} names an unknown audience profile")
        _require(profile["failurePolicy"] in failure_policies and profile["tokenCache"] in cache_policies, f"profile {name} names an unknown failure or cache policy")
        if "HUMAN" in profile["principalClasses"]:
            _require(not set(profile["accessClasses"]) & set(rules["humanProfilesForbiddenOn"]) or name.startswith("DESIGN_"),
                     f"human profile {name} may not serve a service, internal or admin access class")
        if profile["principalClasses"] == ["SERVICE"] or profile["principalClasses"] == ["SERVICE", "ANONYMOUS"]:
            _require("ADMIN_INTERNAL" not in profile["accessClasses"], f"service profile {name} may not serve ADMIN_INTERNAL")
        if "ADMIN_INTERNAL" in profile["accessClasses"] and name != "BLOCKED_NONE_V1":
            _require(profile["principalClasses"] == ["ADMIN"] and "platform.admin" in profile.get("requiredScopes", []),
                     f"admin profile {name} must be ADMIN-only and require platform.admin")
    for name, aud in audiences.items():
        _require(aud["audience"] not in ("*", ""), f"audience profile {name} must not be a wildcard")
        if aud.get("clientIdIsAudience"):
            _require(bool(aud.get("contractuallyDefinedBy")), f"audience profile {name} equates client id and audience without a contract")
    for name, issuer in issuers.items():
        if issuer["issuer"] is not None:
            _require(issuer["environment"] in foundation["environments"], f"issuer profile {name} has an unknown environment")
            _require(issuer["issuer"] == foundation["environments"][issuer["environment"]]["issuer"], f"issuer profile {name} does not match the environment issuer")
            _require(issuer["algorithms"] == ["RS256"], f"issuer profile {name} must accept RS256 only")
            _require(0 <= issuer["clockSkewSeconds"] <= rules["maximumLeewaySeconds"], f"issuer profile {name} clock skew is unbounded")
            _require("*" not in issuer["issuer"], "issuer wildcards are forbidden")
    for name, cache in cache_policies.items():
        if "cacheTokensSalt" in cache:
            _require(cache["cacheTokensSalt"].startswith("{vault://env/") and cache["saltInGit"] is False, f"cache policy {name} must reference the salt through the vault")
        if "cacheTtlSeconds" in cache:
            _require(0 < cache["cacheTtlSeconds"] <= rules["maximumCacheTtlSeconds"], f"cache policy {name} ttl is unbounded")

    entries = _index(policy["routes"], "routeId")
    _require(set(entries) == set(routes), f"access policy and foundation disagree on the route set: missing {sorted(set(routes) - set(entries))}, extra {sorted(set(entries) - set(routes))}")
    allowlist = {item["routeId"]: item["reason"] for item in policy["publicAllowlist"]}
    for route_id, reason in allowlist.items():
        _require(route_id in entries and bool(reason), f"public allowlist entry {route_id} is unknown or unreasoned")
    for route_id, item in entries.items():
        entry = routes[route_id]
        route = materialized[route_id]
        for key in ("accessClass", "authenticationProfile", "issuerProfile", "audienceProfile", "requiredScopes", "authorizedParties",
                    "principalClasses", "identityPropagation", "tenantPolicy", "failurePolicy", "tokenCache", "acceptedFindings"):
            _require(key in item, f"access policy {route_id} lacks {key}")
        _require(item["accessClass"] in ACCESS_CLASSES, f"access policy {route_id} has an unknown access class")
        _require(item["accessClass"] == entry["authentication"], f"access policy {route_id} class {item['accessClass']} != foundation {entry['authentication']}")
        _require(item["environment"] == entry["environment"], f"access policy {route_id} environment drift")
        profile = catalogue.get(item["authenticationProfile"])
        _require(profile is not None, f"access policy {route_id} uses unknown profile {item['authenticationProfile']}")
        _require(item["accessClass"] in profile["accessClasses"], f"route {route_id}: profile {item['authenticationProfile']} does not serve class {item['accessClass']}")
        _require(entry["mechanism"] in profile["mechanisms"], f"route {route_id}: mechanism {entry['mechanism']} is not part of profile {item['authenticationProfile']}")
        if profile.get("lifecycles"):
            _require(entry["lifecycle"] in profile["lifecycles"], f"route {route_id}: profile {item['authenticationProfile']} is not allowed for lifecycle {entry['lifecycle']}")
        if profile.get("activations"):
            _require(entry["activation"] in profile["activations"], f"route {route_id}: profile {item['authenticationProfile']} is not allowed for activation {entry['activation']}")
        if profile.get("newProductionAllowed") is False:
            _require(entry["lifecycle"] != "CANONICAL", f"route {route_id}: profile {item['authenticationProfile']} may not be used on a canonical route")
        # strength / downgrade
        minimum = profiles["classMinimumStrength"][item["accessClass"]]
        if entry["activation"] in ("RUNTIME_OBSERVED", "SOURCE_CANDIDATE"):
            _require(profile["strength"] >= minimum, f"route {route_id}: profile strength {profile['strength']} below class minimum {minimum} (authentication downgrade)")
        elif entry["activation"] != "BLOCKED" and profile["strength"] < minimum:
            _require(bool(entry.get("authenticationGap")), f"route {route_id}: weaker-than-class profile on a non-activatable route requires a declared authenticationGap")
        if entry["lifecycle"] == "CANONICAL":
            _require(profile["strength"] >= profiles["canonicalMinimumStrength"][item["accessClass"]], f"canonical route {route_id} uses a profile weaker than its class allows")
        # issuer
        _require(item["issuerProfile"] in issuers, f"route {route_id}: unknown issuer profile")
        issuer = issuers[item["issuerProfile"]]
        if profile["issuerProfile"] == "environment":
            _require(issuer["environment"] == entry["environment"], f"route {route_id}: issuer profile {item['issuerProfile']} is not the {entry['environment']} realm")
            if route.issuer is not None:
                _require(route.issuer == issuer["issuer"], f"route {route_id}: source issuer {route.issuer} != profile issuer")
        else:
            _require(item["issuerProfile"] == "NONE", f"route {route_id}: profile {item['authenticationProfile']} does not validate an issuer")
        # audience
        _require(item["audienceProfile"] in audiences, f"route {route_id}: unknown audience profile")
        aud = audiences[item["audienceProfile"]]
        _require(aud["audience"] == entry.get("audience"), f"route {route_id}: audience profile {item['audienceProfile']} ({aud['audience']}) != foundation audience {entry.get('audience')}")
        _require(item["audienceProfile"] in profile["audienceProfiles"], f"route {route_id}: audience profile {item['audienceProfile']} is not allowed by profile {item['authenticationProfile']}")
        if entry["mechanism"] in foundation["debtRules"]["tokenMechanisms"]:
            _require(aud["audience"] is not None, f"token route {route_id} has no audience")
        if aud.get("clientIdIsAudience"):
            _require("AUDIENCE_IS_CLIENT_ID" in entry["acceptedFindings"], f"route {route_id}: client-id audience must be an accepted foundation finding")
        # scopes
        _require(item["requiredScopes"] == entry.get("requiredScopes", []), f"route {route_id}: required scopes drift between access policy and foundation")
        _require(all(scope not in ("*", "") and not scope.endswith("*") for scope in item["requiredScopes"]), f"route {route_id}: wildcard scope")
        if item.get("scopeAuthority") or entry.get("scopeAuthority"):
            _require(item.get("scopeAuthority") == entry.get("scopeAuthority"), f"route {route_id}: scope authority drift")
        # authorized parties
        parties = item["authorizedParties"]
        if profile["authorizedParties"] in ("explicit", "explicit-admin"):
            _require(isinstance(parties, list), f"route {route_id}: profile requires an explicit authorized-party list")
            if profile["authorizedParties"] == "explicit":
                _require(len(parties) > 0, f"route {route_id}: explicit authorized parties must not be empty")
            if route.client_id is not None and parties:
                _require(route.client_id in parties, f"route {route_id}: source client {route.client_id} is not an authorized party")
            if not parties:
                _require("ADMIN_PARTIES_UNDECLARED" in item["acceptedFindings"] and item.get("activationPrerequisites"),
                         f"route {route_id}: empty authorized parties must be an accepted finding with activation prerequisites")
        elif profile["authorizedParties"] == "consumer-mapped":
            _require(parties == "consumer-mapped", f"route {route_id}: profile maps azp to a registered consumer")
        elif profile["authorizedParties"] == "none":
            _require(parties in (None, []), f"route {route_id}: an unauthenticated profile cannot name authorized parties")
        else:
            _require(parties == profile["authorizedParties"] or (isinstance(parties, list) and parties),
                     f"route {route_id}: authorized parties must be the profile marker {profile['authorizedParties']!r} or an explicit list")
        # the contracted azp (literal client or symbolic family) the policy records must be
        # exactly what the authority declares and what the generated guard forwards upstream
        if route.expected_azp is not None or "contractExpectedAzp" in item:
            _require(route.expected_azp is not None and "contractExpectedAzp" in item
                     and canonical_azp(item["contractExpectedAzp"]) == route.expected_azp,
                     f"route {route_id}: access policy contractExpectedAzp {item.get('contractExpectedAzp')!r} != contracted/forwarded azp {route.expected_azp!r}")
        # principals
        _require(set(item["principalClasses"]) <= set(profile["principalClasses"]) and item["principalClasses"], f"route {route_id}: principal classes outside the profile")
        if item["accessClass"] == "ADMIN_INTERNAL" and entry["activation"] != "BLOCKED":
            _require(item["principalClasses"] == ["ADMIN"], f"admin route {route_id} must be ADMIN-only")
        if item["accessClass"] in ("SERVICE_AUTHENTICATED", "INTERNAL") and entry["activation"] != "BLOCKED":
            _require("HUMAN" not in item["principalClasses"] or entry["lifecycle"] == "DESIGN_ONLY", f"route {route_id}: a human principal cannot reach a service/internal class")
        # identity propagation
        _require(item["identityPropagation"] in propagation, f"route {route_id}: unknown identity propagation profile")
        prop = propagation[item["identityPropagation"]]
        if not prop["stripsClientIdentity"]:
            _require("IDENTITY_HEADERS_NOT_STRIPPED" in item["acceptedFindings"], f"route {route_id}: forwards client identity headers without accepting the finding")
            if entry["lifecycle"] == "CANONICAL":
                _require(bool(prop.get("mitigation")), f"canonical route {route_id} forwards client identity headers with no recorded mitigation")
        else:
            _require("IDENTITY_HEADERS_NOT_STRIPPED" not in item["acceptedFindings"], f"route {route_id}: finding claims unstripped headers but the profile strips them")
        # tenant
        _require(item["tenantPolicy"] in tenant_policies, f"route {route_id}: unknown tenant policy")
        _require("AUTHORITY" not in item["tenantPolicy"] or "CLAIM_AUTHORITY" in item["tenantPolicy"], f"route {route_id}: a header may not be the tenant authority")
        # failure / cache
        _require(item["failurePolicy"] == profile["failurePolicy"] and item["tokenCache"] == profile["tokenCache"], f"route {route_id}: failure or cache policy drift from profile")
        if entry["lifecycle"] == "CANONICAL" and item["accessClass"] != "PUBLIC":
            _require(item["failurePolicy"] == "FAIL_CLOSED_V1", f"canonical protected route {route_id} must fail closed")
        _require(failure_policies[item["failurePolicy"]].get("downgradeToPublic") is False, f"route {route_id}: failure policy allows downgrade to public")
        # public governance
        if item["accessClass"] == "PUBLIC":
            _require(route_id in allowlist, f"public route {route_id} is not on the public allowlist")
            _require(bool(item.get("publicAllowlistReason")), f"public route {route_id} lacks its allowlist reason")
        else:
            _require(route_id not in allowlist, f"non-public route {route_id} is on the public allowlist")
        if "NO_GATEWAY_AUTHENTICATION" in entry["acceptedFindings"] and item["accessClass"] != "PUBLIC":
            _require(item["authenticationProfile"] == "BLOCKED_NONE_V1", f"route {route_id} has no gateway authentication and is not classified as blocked")
        if "CORS_WITH_SHARED_KEY" in entry["acceptedFindings"]:
            _require(item.get("corsPolicy") in policy["corsPolicies"], f"route {route_id}: cors route without a cors policy")
        for finding in item["acceptedFindings"]:
            _require(finding in policy["findingCodes"], f"route {route_id}: unknown access-policy finding {finding}")
    stale_allowlist = set(allowlist) - {r for r, i in entries.items() if i["accessClass"] == "PUBLIC"}
    _require(not stale_allowlist, f"public allowlist names non-public routes: {sorted(stale_allowlist)}")
    log_rules = policy["logging"]
    for plugin in log_rules["logPluginsRegistered"]:
        registered = next((p for p in foundation["plugins"] if p["plugin"] == plugin), None)
        _require(registered is not None and registered.get("redactsCredentials") is True, f"log plugin {plugin} must be registered with credential redaction")
    for plugin in foundation["plugins"]:
        if plugin["plugin"] in ("file-log", "http-log", "tcp-log", "udp-log", "syslog", "loggly", "datadog"):
            _require(plugin["plugin"] in log_rules["logPluginsRegistered"] and plugin.get("redactsCredentials") is True,
                     f"log plugin {plugin['plugin']} is governed without credential redaction")
    return profiles, policy


def validate_denied_aliases(foundation: dict, documents: dict[str, SourceDocument], root: Path = ROOT) -> None:
    """Every retired alias the canonical contract denies is answered by
    request-termination 404 alone: no service, no upstream, no other plugin, in
    the contract and in every generated manifest."""
    for source in foundation["sources"]:
        document = documents[source["path"]]
        if document.format == "canonical-middleware-contract":
            for denied in load_json(root / source["path"]).get("deniedRoutes", []):
                _require(denied.get("statusCode") == 404 and "serviceHost" not in denied and "servicePort" not in denied,
                         f"{source['path']}: denied alias {denied.get('name')} must be a 404 with no upstream")
        if document.format == "kong-declarative":
            raw = load_yaml(root / source["path"])
            for route in raw.get("routes", []) or []:
                plugins = route.get("plugins", []) or []
                _require([p.get("name") for p in plugins] == ["request-termination"] and "service" not in route,
                         f"{source['path']}: service-less route {route.get('name')} must carry request-termination only")
                _require((plugins[0].get("config", {}) or {}).get("status_code") == 404,
                         f"{source['path']}: denied alias {route.get('name')} must terminate with 404")
    for entry in foundation["routes"]:
        if "GATEWAY_TERMINATED" in entry["acceptedFindings"]:
            _require(entry.get("deniedStatus") == 404, f"route {entry['routeId']}: gateway-terminated route must record deniedStatus 404")


def validate_token_settings(documents: dict[str, SourceDocument], profiles: dict, root: Path = ROOT) -> None:
    """openid-connect configurations in declarative sources must keep the vault salt,
    bounded leeway and bounded caches; jwt configurations must verify exp."""
    rules = profiles["rules"]
    for path, document in documents.items():
        if document.format not in ("kong-declarative", "oidc-plugin-template"):
            continue
        raw = load_yaml(root / path)
        plugin_blocks = list(raw.get("plugins", []) or [])
        for svc in raw.get("services", []) or []:
            plugin_blocks += list(svc.get("plugins", []) or [])
            for route in svc.get("routes", []) or []:
                plugin_blocks += list(route.get("plugins", []) or [])
        for route in raw.get("routes", []) or []:
            plugin_blocks += list(route.get("plugins", []) or [])
        for plugin in plugin_blocks:
            config = plugin.get("config", {}) or {}
            if plugin.get("name") == "openid-connect":
                if path in {
                    "config/kong-middleware-routes.production.yml",
                    "config/staging/kong-middleware-routes.staging.yml",
                    "kong/plugins/oidc/keycloak.yml",
                }:
                    _require(config.get("verify_signature") is True, f"{path}: token signature verification required")
                    _require(config.get("verify_claims") is True and config.get("ssl_verify") is True,
                             f"{path}: claim and TLS verification required")
                    _require(config.get("audience_required") == config.get("audience"),
                             f"{path}: token audience enforcement required")
                    issuer = str(config.get("issuer", "")).removesuffix("/.well-known/openid-configuration")
                    _require(config.get("issuers_allowed") == [issuer], f"{path}: exact token issuer required")
                    _require(config.get("consumer_by") == ["username"] and config.get("consumer_optional") is False,
                             f"{path}: mandatory consumer mapping required")
                    _require(config.get("bearer_token_param_type") == ["header"],
                             f"{path}: header-only bearer required")
                    _require(config.get("cache_ttl") == 300 and config.get("cache_ttl_max") == 300
                             and config.get("rediscovery_lifetime") == 30 and config.get("leeway") == 0,
                             f"{path}: bounded identity cache and rediscovery required")
                    _require(not config.get("extra_jwks_uris") and not config.get("ignore_signature"),
                             f"{path}: additional identity authority forbidden")
                _require(str(config.get("cache_tokens_salt", "")).startswith("{vault://env/"), f"{path}: openid-connect must reference cache_tokens_salt through the vault")
                if document.format == "kong-declarative":
                    _require(bool(config.get("scopes_required")) and all(s not in ("*", "") for s in config["scopes_required"]),
                             f"{path}: every deployable openid-connect block must require at least one explicit scope (scopes_required)")
                _require(config.get("leeway", 0) <= rules["maximumLeewaySeconds"], f"{path}: openid-connect leeway exceeds the bound")
                _require(config.get("cache_ttl", 3600) <= rules["maximumCacheTtlSeconds"], f"{path}: openid-connect cache_ttl exceeds the bound")
                _require(config.get("anonymous") in (None, ""), f"{path}: openid-connect must not fall back to an anonymous consumer")
                _require(config.get("auth_methods") == ["bearer"] or config.get("auth_methods") is None, f"{path}: only bearer authentication is approved for API routes")
                _require(bool(config.get("audience")) and "*" not in config.get("audience", []), f"{path}: openid-connect must pin a non-wildcard audience")
                _require("/.well-known/openid-configuration" in str(config.get("issuer", "")), f"{path}: openid-connect issuer must be a discovery document")
            if plugin.get("name") == "jwt":
                _require("exp" in (config.get("claims_to_verify") or []), f"{path}: jwt must verify exp")
                _require(config.get("anonymous") in (None, ""), f"{path}: jwt must not fall back to an anonymous consumer")


def scan_secrets(root: Path = ROOT) -> list[tuple[str, str, int]]:
    hits: list[tuple[str, str, int]] = []
    for top in SECRET_SCAN_ROOTS:
        base = root / top
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            data = path.read_bytes()
            if b"\0" in data[:8000]:
                continue
            for name, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(data):
                    value = match.groupdict().get("value") or match.group(0)
                    if SYNTHETIC_MARKER.search(value) and path.relative_to(root).parts[0] == "tests":
                        continue
                    hits.append((name, path.relative_to(root).as_posix(), data.count(b"\n", 0, match.start()) + 1))
    return hits


def validate_secret_boundary(root: Path = ROOT) -> int:
    hits = scan_secrets(root)
    _require(not hits, "committed secret material detected (pattern, file:line): " + ", ".join(f"{n} {f}:{l}" for n, f, l in hits))
    return len(hits)


def m1_dependency_status(foundation: dict, root: Path = ROOT) -> dict:
    """Whether the Mission 1 reconciliation (PR #105) has landed in this tree and
    what residue of the retired ``:8080`` alias the registry still records."""
    reconciled = (root / "config/kong-middleware-authority.v2.json").is_file()
    aliases = foundation["boundaryRules"]["middlewareUpstreamAliases"]
    transitional = [a for a in aliases if a["port"] == 8080 and not str(a.get("role", "")).startswith("RETIRED")]
    retired = [a for a in aliases if str(a.get("role", "")).startswith("RETIRED")]
    residue_services = sorted(s["serviceId"] for s in foundation["services"] if "RETIRED_UPSTREAM_ALIAS" in s["acceptedFindings"])
    residue_routes = sorted(r["routeId"] for r in foundation["routes"] if "RETIRED_UPSTREAM_ALIAS" in r["acceptedFindings"])
    return {"reconciled": reconciled, "transitional8080Aliases": [a["host"] for a in transitional],
            "retiredAliases": [f"{a['host']}:{a['port']}" for a in retired],
            "residueServices": residue_services, "residueRoutes": residue_routes,
            "state": "MERGED" if reconciled and not transitional else "M1_DEPENDENCY_PENDING"}



def _canonical_json_sha256(document: dict) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _candidate_route_is_active(entry: dict, foundation: dict) -> bool:
    return (
        entry.get("disposition") == "KEEP"
        and entry.get("lifecycle") == "CANONICAL"
        and entry.get("activation") in set(foundation["precedence"]["analyzedActivations"])
    )


def v3_certification_status(result: dict, root: Path = ROOT) -> dict[str, Any]:
    """Return source-only Kong V3 candidate counters.

    This function deliberately separates parallel Lane-D safety validation from
    the final integrated candidate. It never mutates manifests or runtime state.
    """
    contract_path = root / "config/middleware-public-api-route-contract.v1.json"
    contract_digest_path = root / "config/middleware-public-api-route-contract.sha256"
    authority_path = root / "config/kong-middleware-authority.v2.json"
    production_path = root / "config/kong-middleware-routes.production.yml"
    staging_path = root / "config/staging/kong-middleware-routes.staging.yml"

    contract = load_json(contract_path)
    authority = load_json(authority_path)
    production = load_yaml(production_path)
    staging = load_yaml(staging_path)

    digest = _canonical_json_sha256(contract)
    digest_file = contract_digest_path.read_text(encoding="utf-8").strip()
    _require(digest == digest_file, "vendored Middleware contract digest file is stale")
    _require(authority.get("contract", {}).get("sha256") == digest, "Kong Middleware authority pins a different contract digest")
    _require(contract.get("listener_port") == CANONICAL_MIDDLEWARE_PORT, "Middleware public contract must use port 8095")
    _require(contract.get("provider_effects_enabled") is False, "vendored Middleware contract must keep provider effects disabled")
    _require(authority.get("runtime_apply_authorized") is False, "Kong Middleware authority must keep runtime apply disabled")
    _require(authority.get("provider_effects_enabled") is False, "Kong Middleware authority must keep provider effects disabled")

    upstream = authority.get("upstream") or {}
    _require(
        (upstream.get("host"), upstream.get("port")) == (CANONICAL_MIDDLEWARE_HOST, CANONICAL_MIDDLEWARE_PORT),
        "Kong Middleware authority must target middleware-integration-api:8095",
    )

    class_counts = Counter(route.get("classification") for route in contract.get("routes") or [])
    shared_operations = {
        route["operation_id"]
        for route in contract.get("routes") or []
        if route.get("classification") == "shared_edge"
    }
    authority_operations = {route["operation_id"] for route in authority.get("routes") or []}
    missing_from_current_contract = shared_operations - authority_operations
    stale_authority = authority_operations - shared_operations
    missing_final = max(
        FINAL_MIDDLEWARE_ROUTE_COUNTS["shared_edge"] - len(authority_operations),
        len(missing_from_current_contract),
        0,
    )

    def rendered_counts(document: dict, label: str) -> tuple[int, int]:
        services = document.get("services") or []
        _require(len(services) == 1, f"{label}: exactly one Middleware service is required")
        service = services[0]
        _require(
            (service.get("host"), service.get("port")) == (CANONICAL_MIDDLEWARE_HOST, CANONICAL_MIDDLEWARE_PORT),
            f"{label}: Middleware service must target middleware-integration-api:8095",
        )
        _require(service.get("retries") == 0, f"{label}: side-effecting Middleware service retries must be zero")
        return len(service.get("routes") or []), len(document.get("routes") or [])

    production_routes, production_denies = rendered_counts(production, "production")
    staging_routes, staging_denies = rendered_counts(staging, "staging")

    services = result["services"]
    routes = result["routes"]
    foundation = result["foundation"]
    active_routes = [entry for entry in routes.values() if _candidate_route_is_active(entry, foundation)]
    active_8080: list[str] = []
    direct_provider: list[str] = []
    direct_n8n: list[str] = []
    direct_odoo: list[str] = []
    public_data_plane: list[str] = []

    for entry in active_routes:
        service_id = entry.get("serviceId")
        if service_id is None:
            continue
        service = services[service_id]
        upstream_value = service.get("upstream") or {}
        host = str(upstream_value.get("host") or "").lower()
        port = upstream_value.get("port")
        if port == 8080:
            active_8080.append(entry["routeId"])
        if any(marker in host for marker in PROVIDER_HOST_MARKERS):
            direct_provider.append(entry["routeId"])
        if "n8n" in host:
            direct_n8n.append(entry["routeId"])
        if "odoo" in host:
            direct_odoo.append(entry["routeId"])
        if port in {5432, 6379} or any(marker in host for marker in ("postgres", "redis")):
            public_data_plane.append(entry["routeId"])

    provisional_path = root / "config/kong-middleware-v3-command-routes.v1.json"
    provisional_state = "ABSENT"
    provisional_independent_authority = False
    if provisional_path.is_file():
        provisional = load_json(provisional_path)
        provisional_state = str(provisional.get("status") or "PRESENT")
        provisional_independent_authority = (
            provisional.get("V3_PENDING_FINAL_MIDDLEWARE_CONTRACT") is True
            or provisional_state == "V3_PENDING_FINAL_MIDDLEWARE_CONTRACT"
        )

    c_artifacts = (
        root / "config/kong-webhook-registry.v1.json",
        root / "config/kong-cross-repo-parity.v1.json",
    )
    c_integrated = all(path.is_file() for path in c_artifacts)
    contract_final = (
        digest == FINAL_MIDDLEWARE_CONTRACT_SHA256
        and dict(class_counts) == FINAL_MIDDLEWARE_ROUTE_COUNTS
        and len(authority_operations) == FINAL_MIDDLEWARE_ROUTE_COUNTS["shared_edge"]
    )
    final_authority_rendered = (
        production_routes == FINAL_MIDDLEWARE_ROUTE_COUNTS["shared_edge"]
        and staging_routes == FINAL_MIDDLEWARE_ROUTE_COUNTS["shared_edge"]
        and production_denies == FINAL_MIDDLEWARE_ROUTE_COUNTS["denied"]
        and staging_denies == FINAL_MIDDLEWARE_ROUTE_COUNTS["denied"]
    )
    integrated = contract_final and c_integrated and final_authority_rendered and not provisional_independent_authority

    ambiguous = sum(1 for overlap in result["overlaps"] if overlap.winner == "AMBIGUOUS")
    status: dict[str, Any] = {
        "phase": "INTEGRATED" if integrated else "PARALLEL",
        "middlewareContractSha256": digest,
        "middlewareContractSourceSha": FINAL_MIDDLEWARE_SOURCE_SHA if contract_final else None,
        "classificationCounts": dict(class_counts),
        "authorityRoutes": len(authority_operations),
        "productionRoutes": production_routes,
        "productionDenyGuards": production_denies,
        "stagingRoutes": staging_routes,
        "stagingDenyGuards": staging_denies,
        "missingMiddlewareRoutes": missing_final,
        "staleMiddlewareRoutes": len(stale_authority),
        "active8080Aliases": len(active_8080),
        "active8080RouteIds": sorted(active_8080),
        "directProviderRoutes": len(direct_provider),
        "directProviderRouteIds": sorted(direct_provider),
        "directN8nExecutionRoutes": len(direct_n8n),
        "directOdooRoutes": len(direct_odoo),
        "publicPostgresRedisRoutes": len(public_data_plane),
        "governedOverlaps": len(result["overlaps"]),
        "governedAmbiguities": ambiguous,
        "undeclaredOverlaps": 0,
        "staleKnownDrift": 0,
        "secretHits": result["secret_scan"],
        "runtimeApplyAuthorized": foundation["runtimeApplyAuthorized"],
        "providerEffectsEnabled": authority.get("provider_effects_enabled"),
        "provisionalV3Authority": provisional_state,
        "provisionalIndependentAuthority": provisional_independent_authority,
        "laneCArtifactsIntegrated": c_integrated,
        "finalContractIntegrated": contract_final,
        "finalAuthorityRendered": final_authority_rendered,
    }
    return status


def validate_v3_certification(result: dict, phase: str, root: Path = ROOT) -> dict[str, Any]:
    status = v3_certification_status(result, root)
    _require(status["active8080Aliases"] == 0, f"active 8080 aliases remain: {status['active8080RouteIds']}")
    _require(status["directProviderRoutes"] == 0, f"direct provider routes remain: {status['directProviderRouteIds']}")
    _require(status["directN8nExecutionRoutes"] == 0, "direct n8n execution routes remain")
    _require(status["directOdooRoutes"] == 0, "direct Odoo routes remain")
    _require(status["publicPostgresRedisRoutes"] == 0, "PostgreSQL/Redis is publicly reachable through an active route")
    _require(status["undeclaredOverlaps"] == 0 and status["staleKnownDrift"] == 0, "route ambiguity/drift ledger is not closed")
    _require(status["secretHits"] == 0, "foundation secret scan must remain zero")
    _require(status["runtimeApplyAuthorized"] is False and status["providerEffectsEnabled"] is False,
             "runtime/provider effects must remain disabled")

    selected = status["phase"] if phase == "auto" else phase.upper()
    _require(selected in {"PARALLEL", "INTEGRATED"}, f"unknown V3 certification phase: {phase}")
    if selected == "INTEGRATED":
        _require(status["phase"] == "INTEGRATED", "A/B/C are not fully integrated into the final V3 source candidate")
        _require(status["middlewareContractSha256"] == FINAL_MIDDLEWARE_CONTRACT_SHA256,
                 "final Middleware contract digest is not pinned")
        _require(status["classificationCounts"] == FINAL_MIDDLEWARE_ROUTE_COUNTS,
                 f"final Middleware route universe must be {FINAL_MIDDLEWARE_ROUTE_COUNTS}")
        _require(status["missingMiddlewareRoutes"] == 0, "final Middleware routes are missing")
        _require(status["staleMiddlewareRoutes"] == 0, "stale Middleware routes remain")
        _require(status["provisionalIndependentAuthority"] is False,
                 "provisional V3 command file remains an independent authority")
        _require(status["laneCArtifactsIntegrated"] is True, "Lane C parity/webhook authority is not integrated")
        _require(status["finalAuthorityRendered"] is True, "production/staging declarative manifests do not render the final authority")
    return status


# --------------------------------------------------------------------------- rendering


def _fmt(values: Any) -> str:
    if values is None:
        return "*unspecified*"
    if isinstance(values, (tuple, list)):
        return ", ".join(f"`{v}`" for v in values) if values else "*none*"
    if isinstance(values, bool):
        return "true" if values else "false"
    return f"`{values}`"


def render_services(result: dict) -> str:
    rows = ["| Service | Env | Owner | Class | Upstream | Timeout | Retry | Auth | Rate | Size | Health | Lifecycle | Disposition | Findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(result["services"].values(), key=lambda e: (e["environment"], e["serviceId"])):
        up = entry["upstream"]
        rows.append("| " + " | ".join([
            f"`{entry['serviceId']}`", entry["environment"], entry["owner"], entry["upstreamClass"],
            f"`{up['protocol']}://{up['host']}:{up['port']}`", entry["timeoutProfile"], entry["retryProfile"],
            entry["authenticationProfile"], entry["rateLimitProfile"], entry["requestSizeProfile"], entry["healthProfile"],
            entry["lifecycle"], entry["disposition"], ", ".join(entry["acceptedFindings"]) or "—",
        ]) + " |")
    return "\n".join(rows)


def render_routes(result: dict) -> str:
    rows = ["| Route | Service | Env | Hosts | Paths | Methods | Strip | Preserve | Auth | Mechanism | Audience | Scopes | Rate | Size | Class | Lifecycle | Activation | Disposition | Findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for route_id, entry in sorted(result["routes"].items(), key=lambda kv: (kv[1]["environment"], kv[0])):
        route = result["materialized"][route_id]
        rows.append("| " + " | ".join([
            f"`{route_id}`", f"`{entry['serviceId']}`" if entry["serviceId"] else "*none (terminated)*", entry["environment"], _fmt(route.hosts), _fmt(route.paths),
            _fmt(route.methods), _fmt(route.strip_path), _fmt(route.preserve_host), entry["authentication"],
            entry["mechanism"], _fmt(entry.get("audience")), _fmt(entry.get("requiredScopes") or None),
            entry["rateLimitProfile"], entry["requestSizeProfile"], entry["trafficClass"], entry["lifecycle"],
            entry["activation"], entry["disposition"], ", ".join(entry["acceptedFindings"]) or "—",
        ]) + " |")
    return "\n".join(rows)


def render_plugins(result: dict) -> str:
    rows = ["| Plugin | Kind | Auth | Priority | Allowed scopes | Owner | Purpose | Security impact | Ordering dependency | Environments | Configuration sources |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(result["foundation"]["plugins"], key=lambda e: -e["priority"]):
        rows.append("| " + " | ".join([
            f"`{entry['plugin']}`", entry["kind"], "yes" if entry["authentication"] else "no", str(entry["priority"]),
            ", ".join(entry["allowedScopes"]), entry["owner"], entry["purpose"], entry["securityImpact"],
            entry["orderingDependency"], ", ".join(entry["environments"]), ", ".join(f"`{s}`" for s in entry["configurationSources"]),
        ]) + " |")
    return "\n".join(rows)


def render_conflicts(result: dict) -> str:
    rows = ["| Route A | Route B | Router winner | Resolution | Note |", "| --- | --- | --- | --- | --- |"]
    for conflict in result["foundation"]["precedence"]["knownConflicts"]:
        rows.append(f"| `{conflict['left']}` | `{conflict['right']}` | `{conflict['winner']}` | {conflict['resolution']} | {conflict['note']} |")
    return "\n".join(rows)


def render_drift(result: dict) -> str:
    rows = ["| Kind | Subject | Field | Observed (readback 2026-09-06) | Desired (contract) | Severity | Resolution |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for item in result["foundation"]["knownDrift"]:
        rows.append(f"| {item['kind']} | `{item['subject']}` | `{item['field']}` | `{json.dumps(item['observed'])}` | `{json.dumps(item['desired'])}` | {item['severity']} | {item['resolution']} |")
    return "\n".join(rows)


RENDERERS = {
    "services": render_services, "routes": render_routes, "plugins": render_plugins,
    "conflicts": render_conflicts, "drift": render_drift,
}
MARKER = re.compile(r"(<!-- BEGIN GENERATED: (?P<name>[a-z]+) -->\n)(?P<body>.*?)(<!-- END GENERATED: (?P=name) -->)", re.DOTALL)


def sync_docs(result: dict, root: Path = ROOT, write: bool = False) -> list[str]:
    stale: list[str] = []
    for doc_path in result["foundation"]["generatedDocs"]:
        path = root / doc_path
        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")

        def replace(match: re.Match) -> str:
            body = RENDERERS[match.group("name")](result)
            return match.group(1) + body + "\n" + match.group(4)

        updated = MARKER.sub(replace, text)
        if updated != text:
            stale.append(doc_path)
            if write:
                path.write_text(updated, encoding="utf-8", newline="\n")
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write-docs", action="store_true", help="refresh generated registry tables in the docs")
    parser.add_argument("--summary", action="store_true", help="print a machine-readable summary")
    parser.add_argument("--v3-phase", choices=("none", "parallel", "integrated", "auto"), default="none",
                        help="run the Lane-D V3 candidate gate without mutating manifests")
    args = parser.parse_args(argv)
    result = validate_foundation()
    stale = sync_docs(result, write=args.write_docs)
    if stale and not args.write_docs:
        print("KONG_GATEWAY_FOUNDATION=FAIL generated documentation is stale: " + ", ".join(stale))
        return 1
    routes = result["routes"]
    print("KONG_GATEWAY_FOUNDATION=PASS")
    print(f"SOURCES={len(result['documents'])} SERVICES={len(result['services'])} ROUTES={len(routes)} "
          f"PLUGINS={len(result['foundation']['plugins'])} OVERLAPS={len(result['overlaps'])} "
          f"KNOWN_DRIFT={len(result['foundation']['knownDrift'])}")
    counts: dict[str, int] = {}
    for entry in routes.values():
        counts[entry["lifecycle"]] = counts.get(entry["lifecycle"], 0) + 1
    print("LIFECYCLE=" + ",".join(f"{k}:{v}" for k, v in sorted(counts.items())))
    classes: dict[str, int] = {}
    for item in result["policy"]["routes"]:
        classes[item["accessClass"]] = classes.get(item["accessClass"], 0) + 1
    print("ACCESS_CLASSES=" + ",".join(f"{k}:{v}" for k, v in sorted(classes.items())))
    print(f"PUBLIC_ALLOWLIST={len(result['policy']['publicAllowlist'])} AUTH_PROFILES={len(result['profiles']['profiles'])} SECRET_HITS={result['secret_scan']}")
    dependency = m1_dependency_status(result["foundation"])
    print(f"M1_DEPENDENCY={dependency['state']} TRANSITIONAL_8080_ALIASES={len(dependency['transitional8080Aliases'])} "
          f"RETIRED_ALIAS_RESIDUE={len(dependency['residueServices'])}+{len(dependency['residueRoutes'])}")
    if args.v3_phase != "none":
        v3 = validate_v3_certification(result, args.v3_phase)
        print(f"V3_PHASE={v3['phase']}")
        print(f"MIDDLEWARE_CONTRACT_SHA256={v3['middlewareContractSha256']}")
        print("MIDDLEWARE_CLASSIFICATIONS=" + ",".join(f"{k}:{v3['classificationCounts'].get(k, 0)}" for k in ("shared_edge", "denied", "private_only")))
        print(f"MISSING_MIDDLEWARE_ROUTES={v3['missingMiddlewareRoutes']}")
        print(f"STALE_MIDDLEWARE_ROUTES={v3['staleMiddlewareRoutes']}")
        print(f"ACTIVE_8080_ALIASES={v3['active8080Aliases']}")
        print(f"DIRECT_PROVIDER_ROUTES={v3['directProviderRoutes']}")
        print(f"DIRECT_N8N_EXECUTION_ROUTES={v3['directN8nExecutionRoutes']}")
        print(f"DIRECT_ODOO_ROUTES={v3['directOdooRoutes']}")
        print(f"PUBLIC_POSTGRES_REDIS_ROUTES={v3['publicPostgresRedisRoutes']}")
        print(f"UNDECLARED_ROUTE_OVERLAPS={v3['undeclaredOverlaps']}")
        print(f"GOVERNED_ROUTE_OVERLAPS={v3['governedOverlaps']}")
        print(f"GOVERNED_AMBIGUITIES={v3['governedAmbiguities']}")
        print(f"STALE_KNOWN_DRIFT={v3['staleKnownDrift']}")
        print(f"LANE_C_ARTIFACTS_INTEGRATED={'YES' if v3['laneCArtifactsIntegrated'] else 'NO'}")
        print(f"FINAL_AUTHORITY_RENDERED={'YES' if v3['finalAuthorityRendered'] else 'NO'}")
        print(f"PROVISIONAL_V3_AUTHORITY={v3['provisionalV3Authority']}")
        print("PROVIDER_EFFECTS=0")
    print("RUNTIME_APPLY_AUTHORIZED=NO")
    if args.summary:
        print(json.dumps({
            "routes": {k: {"lifecycle": v["lifecycle"], "activation": v["activation"], "authentication": v["authentication"],
                           "findings": v["acceptedFindings"]} for k, v in routes.items()},
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FoundationError as error:
        print(f"KONG_GATEWAY_FOUNDATION=FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
