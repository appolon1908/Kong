#!/usr/bin/env python3
"""Private Kong Admin channel for host-side operational clients.

Admin listens on container loopback and is not published on the host, so
operational clients enter the existing verified gateway namespace instead of
reopening a management port. Requests are method- and path-checked, bounded in
time and size, carry bodies on stdin rather than argv, and never use a shell.
Docker access must already be authorized; this module grants no privileges.
"""
from __future__ import annotations

import json
import re
import subprocess
from urllib.parse import unquote, urlencode, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
ADMIN_ORIGIN = "http://127.0.0.1:8001"
# Historical transport alias; it never selects the legacy data-plane service.
PRIVATE_ADMIN_URL = "container://kong-gateway"
DEFAULT_CONTAINER = "codestra-gateway-hybrid-kong-cp-1"
COMPOSE_SERVICE = "kong-cp"
REQUIRED_LISTENERS = {"KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_GUI_LISTEN=off"}
ADMIN_PORTS = ("8001/tcp", "8444/tcp", "8002/tcp", "8445/tcp")
METHODS = frozenset({"GET", "POST", "PATCH", "DELETE"})
SUCCESS_BY_METHOD = {
    "GET": frozenset({200}),
    "POST": frozenset({200, 201}),
    "PATCH": frozenset({200}),
    "DELETE": frozenset({200, 204}),
}
MAX_BYTES = 2 * 1024 * 1024
CONNECT_TIMEOUT = "2"
REQUEST_TIMEOUT = "10"
PROCESS_TIMEOUT = 20
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ADMIN_PATH = re.compile(r"/[A-Za-z0-9._~%!$&'()*+,;:@/=?-]{0,2048}\Z")
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
ENTITY_ID = re.compile(
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z", re.IGNORECASE
)
# Only the two listener settings are selected, never the whole environment.
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"running":{{json .State.Running}},'
    '"network_mode":{{json .HostConfig.NetworkMode}},'
    '"ports":{{json .HostConfig.PortBindings}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"listeners":[{{range .Config.Env}}'
    '{{if or (eq (index (split . "=") 0) "KONG_ADMIN_LISTEN") '
    '(eq (index (split . "=") 0) "KONG_ADMIN_GUI_LISTEN")}}{{json .}},{{end}}'
    '{{end}}null]}'
)
# Inspect only nonsecret authority fields, in the same snapshot as the runtime
# identity/listeners. The basic format remains shared with read-only capture.
MANAGEMENT_INSPECT_FORMAT = INSPECT_FORMAT[:-1] + (
    ',"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"runtime":[{{range .Config.Env}}'
    '{{if or (eq (index (split . "=") 0) "KONG_ROLE") '
    '(eq (index (split . "=") 0) "KONG_DATABASE") '
    '(eq (index (split . "=") 0) "KONG_PROXY_LISTEN") '
    '(eq (index (split . "=") 0) "CODESTRA_TRADITIONAL_APPROVAL")}}{{json .}},{{end}}'
    '{{end}}null]}'
)

_IDENTIFIED: dict[str, str] = {}


class AdminError(RuntimeError):
    """Raised for any channel, topology, or Kong Admin failure."""


def form_payload(payload: dict, path: str) -> bytes:
    """Encode Kong's flat form contract with canonical boolean tokens."""
    path = urlsplit(path).path
    normalized = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise AdminError(f"invalid Kong Admin form payload: {path}")
        values = value if isinstance(value, (list, tuple)) else (value,)
        normalized[key] = [
            "true" if item is True else "false" if item is False else item
            for item in values
        ]
    try:
        return urlencode(normalized, doseq=True).encode()
    except (TypeError, UnicodeError):
        raise AdminError(f"invalid Kong Admin form payload: {path}") from None


def run_json(argv: list[str]) -> dict:
    try:
        result = subprocess.run(argv, input=b"", capture_output=True,
                                timeout=PROCESS_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdminError("kong gateway inspection failed") from exc
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise AdminError("kong gateway inspection failed")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdminError("invalid kong gateway metadata") from exc
    if not isinstance(value, dict):
        raise AdminError("invalid kong gateway metadata")
    return value


def verify_container(container: str, *, traditional_approval: str | None = None) -> str:
    """Select a CP or explicitly approved, isolated Traditional management node."""
    if not isinstance(container, str) or not CONTAINER_NAME.fullmatch(container):
        raise AdminError("invalid kong gateway container name")
    value = run_json(DOCKER + ["inspect", "--format", MANAGEMENT_INSPECT_FORMAT, container])
    identifier = value.get("id", "")
    if not isinstance(identifier, str) or not IDENTITY.fullmatch(identifier):
        raise AdminError("invalid kong gateway identity")
    service = value.get("service")
    if value.get("running") is not True or service not in (COMPOSE_SERVICE, "kong-management"):
        raise AdminError("selected container is not a running Kong management node")
    expected_runtime = {"KONG_DATABASE=postgres", "KONG_PROXY_LISTEN=off"}
    if service == "kong-management":
        if not isinstance(traditional_approval, str) or not re.fullmatch(r"KONG:[A-Za-z0-9:_-]+", traditional_approval):
            raise AdminError("traditional management requires explicit KONG fallback approval")
        expected_project = "codestra-gateway-traditional"
        expected_runtime.update({"KONG_ROLE=traditional", "CODESTRA_TRADITIONAL_APPROVAL=" + traditional_approval})
    else:
        expected_project = "codestra-gateway-hybrid"
        expected_runtime.add("KONG_ROLE=control_plane")
    runtime = value.get("runtime")
    if (value.get("project") != expected_project or not isinstance(runtime, list)
            or len(runtime) != len(expected_runtime) + 1 or runtime[-1] is not None
            or {item for item in runtime if isinstance(item, str)} != expected_runtime):
        raise AdminError("unapproved Kong management role or project")
    mode = value.get("network_mode")
    if not isinstance(mode, str) or mode in {"host", "none"} or mode.startswith("container:"):
        raise AdminError("kong gateway shares a network namespace")
    listeners = value.get("listeners")
    if (not isinstance(listeners, list) or len(listeners) != 3
            or {item for item in listeners if isinstance(item, str)} != REQUIRED_LISTENERS
            or listeners[-1] is not None):
        raise AdminError("unapproved kong admin listener configuration")
    ports = value.get("ports") or {}
    if not isinstance(ports, dict) or any(ports.get(port) for port in ADMIN_PORTS):
        raise AdminError("kong admin is published on the host")
    return identifier


def container_identity(container: str = DEFAULT_CONTAINER, *, traditional_approval: str | None = None) -> str:
    """Resolve the named gateway and reject replacement during this process."""
    previous = _IDENTIFIED.get(container)
    current = verify_container(container, traditional_approval=traditional_approval)
    if previous is not None and current != previous:
        raise AdminError("kong gateway container changed during the operation")
    _IDENTIFIED[container] = current
    return current


def confirm_unchanged(container: str = DEFAULT_CONTAINER, *, traditional_approval: str | None = None) -> str:
    """Fail if the gateway container was replaced while the operation ran."""
    previous = _IDENTIFIED.get(container)
    current = verify_container(container, traditional_approval=traditional_approval)
    if previous is not None and current != previous:
        raise AdminError("kong gateway container changed during the operation")
    _IDENTIFIED[container] = current
    return current


def entity_id(value, kind: str = "entity") -> str:
    """Return a validated Kong UUID before it is interpolated into a path."""
    if not isinstance(value, str) or not ENTITY_ID.fullmatch(value):
        raise AdminError(f"invalid Kong {kind} identity")
    return value


def validate_admin_path(path) -> str:
    """Accept only a bounded origin-relative path without traversal."""
    if not isinstance(path, str) or not ADMIN_PATH.fullmatch(path):
        raise AdminError("unsafe Kong Admin path")
    parsed = urlsplit(path)
    decoded_path = unquote(parsed.path)
    if (parsed.scheme or parsed.netloc or parsed.fragment or path.startswith("//")
            or any(segment in {".", ".."} for segment in decoded_path.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in decoded_path)):
        raise AdminError("unsafe Kong Admin path")
    return path


def normalize_admin_reference(value: str) -> str:
    """Convert Kong's same-origin pagination URL to a private-channel path."""
    if not isinstance(value, str):
        raise AdminError("unsafe Kong Admin URL")
    if value.startswith(ADMIN_ORIGIN + "/"):
        value = value[len(ADMIN_ORIGIN):]
    elif value.startswith(("http://", "https://")):
        raise AdminError("unsafe Kong Admin URL")
    return validate_admin_path(value)


def http_admin_url(base: str, reference: str) -> str:
    """Bind direct requests, including absolute pagination, to one Admin origin."""
    try:
        if not isinstance(base, str) or any(c.isspace() for c in base):
            raise ValueError
        origin = urlsplit(base)
        if (origin.scheme not in {"http", "https"} or not origin.hostname
                or origin.username is not None or origin.password is not None
                or origin.path not in {"", "/"} or origin.query or origin.fragment):
            raise ValueError
        port = origin.port or (443 if origin.scheme == "https" else 80)
        if not isinstance(reference, str) or not reference or any(c.isspace() for c in reference):
            raise ValueError
        target = urlsplit(reference)
        if target.scheme or target.netloc:
            target_port = target.port or (443 if target.scheme == "https" else 80)
            if (target.scheme, target.hostname, target_port) != (origin.scheme, origin.hostname, port):
                raise ValueError
            if target.username is not None or target.password is not None or target.fragment:
                raise ValueError
            reference = target.path + ("?" + target.query if target.query else "")
        path = validate_admin_path(reference)
        return origin._replace(path="", query="", fragment="").geturl() + path
    except (ValueError, TypeError):
        raise AdminError("unsafe Kong Admin URL") from None


class RejectAdminRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AdminError("Kong Admin redirect rejected")


def open_admin_request(request: Request, timeout: float):
    # Private management traffic must not inherit a caller's HTTP proxy or
    # follow a redirect. HTTPS keeps urllib's default certificate validation.
    return build_opener(ProxyHandler({}), RejectAdminRedirects()).open(request, timeout=timeout)


def response_value(method: str, path: str, code: int, raw: bytes):
    label = f"Kong Admin {method} {urlsplit(path).path}"
    if code not in SUCCESS_BY_METHOD[method]:
        raise AdminError(f"{label}: HTTP {code}")
    if len(raw) > MAX_BYTES:
        raise AdminError(f"{label}: oversized response")
    if code == 204 or (not raw.strip() and method != "GET"):
        return None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AdminError(f"{label}: invalid JSON response") from None
    if not isinstance(value, dict):
        raise AdminError(f"{label}: unexpected response shape")
    return value


def http_admin_request(base: str, method: str, path: str, payload=None, *,
                       payload_encoding: str = "form", timeout: float = 10,
                       opener=None):
    """Direct isolated-runner transport with the same response/body contract."""
    if method not in METHODS or payload_encoding not in {"json", "form"}:
        raise AdminError("unsupported Kong Admin request")
    url = http_admin_url(base, path)
    label = f"Kong Admin {method} {urlsplit(url).path}"
    if payload is not None and method == "GET":
        raise AdminError(f"{label}: GET must not carry a body")
    data, headers = None, {}
    if payload is not None:
        try:
            if payload_encoding == "form":
                if not isinstance(payload, dict):
                    raise ValueError
                data = form_payload(payload, urlsplit(url).path)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(payload, allow_nan=False).encode()
                headers["Content-Type"] = "application/json"
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise AdminError(f"{label}: invalid payload") from None
        if len(data) > MAX_BYTES:
            raise AdminError(f"{label}: oversized payload")
    try:
        with (opener or open_admin_request)(Request(url, data=data, method=method, headers=headers),
                                           timeout=timeout) as response:
            return response_value(method, url, response.status, response.read(MAX_BYTES + 1))
    except HTTPError as error:
        code = error.code
        error.close()
        raise AdminError(f"{label}: HTTP {code}") from None
    except (URLError, OSError, ValueError):
        raise AdminError(f"{label}: direct channel transport failure") from None


def collect_admin_rows(fetch_page, path: str, normalize, *, max_pages: int = 100,
                       max_rows: int = 10000) -> list[dict]:
    """Reject incomplete/malformed inventory and bound changing pagination."""
    rows, seen, identities = [], set(), set()
    for _ in range(max_pages):
        path = normalize(path)
        if not isinstance(path, str) or not path:
            raise AdminError("unsafe Kong pagination URL")
        if path in seen:
            raise AdminError("Kong pagination loop detected")
        seen.add(path)
        page = fetch_page(path)
        if (not isinstance(page, dict) or not isinstance(page.get("data"), list)
                or any(not isinstance(row, dict) for row in page["data"])):
            raise AdminError("invalid Kong collection response")
        if len(rows) + len(page["data"]) > max_rows:
            raise AdminError("Kong collection row limit exceeded")
        for row in page["data"]:
            if "id" in row:
                if not isinstance(row["id"], str) or not row["id"] or row["id"] in identities:
                    raise AdminError("invalid or duplicate Kong collection identity")
                identities.add(row["id"])
        rows.extend(page["data"])
        path = page.get("next")
        if path is None or path == "":
            return rows
        if not isinstance(path, str):
            raise AdminError("unsafe Kong pagination URL")
    raise AdminError("Kong collection page limit exceeded")


def admin_request(
    method: str,
    path: str,
    payload=None,
    container: str = DEFAULT_CONTAINER,
    *,
    payload_encoding: str = "json",
    traditional_approval: str | None = None,
):
    """Run one bounded Admin request inside the verified gateway container."""
    if method not in METHODS:
        raise AdminError(f"unsupported Kong Admin method: {method}")
    if payload_encoding not in {"json", "form"}:
        raise AdminError(f"unsupported Kong Admin payload encoding: {payload_encoding}")
    path = validate_admin_path(path)
    label = f"Kong Admin {method} {urlsplit(path).path}"
    if payload is not None and method == "GET":
        raise AdminError(f"{label}: GET must not carry a body")
    identifier = container_identity(container, traditional_approval=traditional_approval)
    argv = DOCKER + ["exec"]
    body = None
    content_type = None
    if payload is not None:
        try:
            if payload_encoding == "form":
                if not isinstance(payload, dict):
                    raise ValueError
                body = form_payload(payload, path)
                content_type = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(payload, allow_nan=False).encode()
                content_type = "application/json"
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise AdminError(f"{label}: invalid payload") from None
        if len(body) > MAX_BYTES:
            raise AdminError(f"{label}: oversized payload")
        # Bodies travel on stdin so they never reach argv or the process table.
        argv.append("--interactive")
    argv += [identifier, "curl", "--disable", "--noproxy", "*", "--proto", "=http",
             "--request", method, "--silent", "--show-error",
             "--connect-timeout", CONNECT_TIMEOUT, "--max-time", REQUEST_TIMEOUT,
             "--max-filesize", str(MAX_BYTES), "--write-out", "\n%{http_code}"]
    if body is not None:
        argv += ["--header", f"Content-Type: {content_type}", "--data-binary", "@-"]
    argv.append(ADMIN_ORIGIN + path)
    try:
        result = subprocess.run(argv, input=body or b"", capture_output=True,
                                timeout=PROCESS_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        raise AdminError(
            f"{label}: private channel transport failure"
        ) from None
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise AdminError(f"{label}: private channel transport failure")
    # Do not accept even a successful response if the named gateway changed
    # between identity resolution and completion of docker exec.
    confirm_unchanged(container, traditional_approval=traditional_approval)
    raw, separator, status = result.stdout.rpartition(b"\n")
    if not separator or not re.fullmatch(rb"[0-9]{3}", status):
        raise AdminError(f"{label}: unreadable response")
    return response_value(method, path, int(status), raw)
