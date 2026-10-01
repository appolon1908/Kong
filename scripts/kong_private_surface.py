"""Private-surface checks for the existing governed route contract.

This is a deny boundary, not an additional route catalog. The integration
compiler still owns authentication, upstream authority and source enforcement.
The matching policy is mirrored in the small Lua access plugin and exercised
against the same behavioral fixtures in test_kong_private_surface.py.
"""
from __future__ import annotations

import ipaddress
import re


_PRIVATE_ROOTS = (
    "internal", "_internal", "metrics", "admin", "administration", "management",
    "manage", "_management", "worker", "workers", "debug", "_debug", "database",
    "databases", "db", "postgres", "postgresql", "redis", "pgadmin", "phpmyadmin",
    "actuator", "server-status", "server-info", "provider-admin", "provider-administration",
)
_KONG_ROOTS = (
    "services", "routes", "plugins", "consumers", "consumer_groups", "upstreams",
    "targets", "certificates", "ca_certificates", "snis", "vaults", "key-auths",
    "jwt", "acls", "clustering", "cache", "config", "schemas", "licenses",
    "workspaces", "admins", "rbac", "vitals", "status", "endpoints",
)
# '*' is one provider segment; '#version' is v followed by decimal digits.
_API_MOUNTS = ((), ("api",), ("#version",), ("api", "#version"),
               ("platform", "#version"), ("#version", "platform"))
_PROVIDER_MOUNTS = tuple(api + (kind, "*") for api in _API_MOUNTS
                         for kind in ("provider", "providers", "integrations"))
_MOUNTS = _API_MOUNTS + _PROVIDER_MOUNTS + (("kong",), ("n8n",), ("odoo",), ("keycloak",))
_FORBIDDEN = tuple(mount + (root,) for mount in _MOUNTS for root in _PRIVATE_ROOTS) + tuple(
    mount + (root,) for mount in ((), ("kong",)) + _PROVIDER_MOUNTS
    for root in _KONG_ROOTS
) + (
    ("rest",), ("n8n", "rest"), ("n8n", "api"), ("n8n", "settings"),
    ("web", "database"), ("odoo", "web", "database"), ("xmlrpc", "db"),
    ("odoo", "xmlrpc", "db"),
) + tuple(mount + suffix for mount in _PROVIDER_MOUNTS
          for suffix in (("rest",), ("web", "database"), ("xmlrpc", "db")))


def _source_restricted(source_allowlist):
    if not isinstance(source_allowlist, (list, tuple)) or not source_allowlist:
        return False
    try:
        if not all(isinstance(network, str) for network in source_allowlist):
            return False
        networks = [ipaddress.ip_network(network, strict=True) for network in source_allowlist]
        # Two /1s are as public as /0; assess the effective set, not each row.
        return all(network.prefixlen > 0 for family in (4, 6)
                   for network in ipaddress.collapse_addresses(n for n in networks if n.version == family))
    except (ValueError, TypeError):
        return False


def _segments(path):
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./{}-]*", path):
        return None
    if path != "/" and (path.endswith("/") or "//" in path):
        return None
    parts = path.strip("/").split("/") if path != "/" else []
    if any(p in {".", ".."} or (("{" in p or "}" in p)
            and not re.fullmatch(r"\{[a-z][a-z0-9_]*\}", p)) for p in parts):
        return None
    return [part.lower() for part in parts]


def _overlaps_private(parts, match, forbidden):
    for declared, reserved in zip(parts, forbidden):
        if declared.startswith("{") or reserved == "*" or declared == reserved:
            continue
        if reserved == "#version" and re.fullmatch(r"v[0-9]+", declared):
            continue
        return False
    # Each forbidden tuple reserves its entire subtree. A shorter declared
    # prefix overlaps it; a shorter exact route does not.
    return len(parts) >= len(forbidden) or match == "prefix"


def private_surface_error(route, *, exposure, source_allowlist):
    """Return a stable error code, or None for a governed safe declaration.

    Call after the existing JSON schema validation. Errors deliberately omit
    caller-supplied paths and source ranges. Methods cannot exempt a route.
    """
    if exposure not in {"public", "private"}:
        return "route_exposure_required"
    parts = _segments(route.get("path"))
    if parts is None or route.get("match") not in {"exact", "prefix"}:
        return "private_surface_noncanonical_path"
    if exposure == "private":
        return None if _source_restricted(source_allowlist) else "private_source_allowlist_required"
    if any(_overlaps_private(parts, route["match"], forbidden) for forbidden in _FORBIDDEN):
        return "public_private_surface_forbidden"
    return None


def runtime_plugin_config(*, exposure, source_allowlist):
    """Route override; private callers still require compiled ip-restriction.

    Install a global {'allow_private': False} instance. Only route-scoped
    instances returned here may opt out, alongside the existing source policy.
    No header, consumer claim, method or authentication state grants this flag.
    """
    if exposure not in {"public", "private"}:
        raise ValueError("route_exposure_required")
    if exposure == "private" and not _source_restricted(source_allowlist):
        raise ValueError("private_source_allowlist_required")
    return {"allow_private": exposure == "private"}
