#!/usr/bin/env python3
"""Bounded, sanitized Admin GET capture inside a verified Kong container.

No TCP Admin publication, shell execution, arbitrary URLs, credentials, or writes
are offered. Docker access must already be authorized; this grants no privileges.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
MAX_BYTES = 2 * 1024 * 1024
CONTAINER_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
ROOT = Path(__file__).resolve().parents[1]
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


class CaptureError(ValueError):
    pass


def command_bytes(argv: list[str]) -> bytes:
    result = subprocess.run(argv, capture_output=True, timeout=15, check=False)
    if result.returncode or len(result.stdout) > MAX_BYTES:
        raise CaptureError('read_failed')
    return result.stdout


def run_json(argv: list[str]) -> dict:
    value = json.loads(command_bytes(argv))
    if not isinstance(value, dict):
        raise CaptureError('invalid_response')
    return value


def verify_container(container: str) -> str:
    if not CONTAINER_NAME.fullmatch(container):
        raise CaptureError('invalid_container')
    value = run_json(DOCKER + ['inspect', '--format', INSPECT_FORMAT, container])
    identifier = value.get('id', '')
    if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{64}', identifier):
        raise CaptureError('invalid_identity')
    if value.get('running') is not True or value.get('service') not in ('kong-gateway', 'kong-cp'):
        raise CaptureError('wrong_service')
    mode = value.get('network_mode')
    if not isinstance(mode, str) or mode in {'host', 'none'} or mode.startswith('container:'):
        raise CaptureError('shared_namespace')
    listeners = value.get('listeners')
    if (not isinstance(listeners, list) or len(listeners) != 3
            or set(item for item in listeners if isinstance(item, str)) != {
                'KONG_ADMIN_LISTEN=127.0.0.1:8001', 'KONG_ADMIN_GUI_LISTEN=off'}
            or listeners[-1] is not None):
        raise CaptureError('unsafe_admin_configuration')
    ports = value.get('ports') or {}
    if not isinstance(ports, dict) or any(ports.get(port) for port in (
        '8001/tcp', '8444/tcp', '8002/tcp', '8445/tcp')):
        raise CaptureError('published_admin')
    return identifier


def admin_get(identifier: str, path: str) -> dict:
    if not re.fullmatch(r'[0-9a-f]{64}', identifier):
        raise CaptureError('invalid_identity')
    if path not in {'/status', '/routes?size=1000', '/services?size=1000'}:
        match = re.fullmatch(r'/routes/([^/]+)/plugins\?size=1000', path)
        if not match or not UUID.fullmatch(match.group(1)):
            raise CaptureError('unapproved_resource')
    raw = command_bytes(DOCKER + ['exec', identifier, 'curl', '--disable', '--noproxy', '*',
        '--proto', '=http', '--request', 'GET', '--fail', '--silent', '--show-error',
        '--connect-timeout', '2', '--max-time', '8', '--max-filesize', str(MAX_BYTES),
        '--write-out', '\n%{http_code}', 'http://127.0.0.1:8001' + path])
    body, separator, status = raw.rpartition(b'\n')
    if not separator or status != b'200':
        raise CaptureError('unexpected_admin_status')
    value = json.loads(body)
    if not isinstance(value, dict):
        raise CaptureError('invalid_response')
    return value


def rows(page: dict) -> list[dict]:
    # Fail instead of certifying a partial collection; no remote pagination URLs.
    data = page.get('data')
    if page.get('next') or not isinstance(data, list) or len(data) > 1000:
        raise CaptureError('incomplete_collection')
    if not all(isinstance(item, dict) for item in data):
        raise CaptureError('invalid_collection')
    return data


def capture(container: str, expected: int) -> dict:
    if type(expected) is not int or expected not in {27, 29}:
        raise CaptureError('unreviewed_route_contract')
    identifier = verify_container(container)
    status = admin_get(identifier, '/status')
    if status.get('database', {}).get('reachable') is not True:
        raise CaptureError('database_unreachable')
    route_rows = rows(admin_get(identifier, '/routes?size=1000'))
    service_rows = rows(admin_get(identifier, '/services?size=1000'))
    services = {item['id']: item for item in service_rows}
    if len(services) != len(service_rows) or len(route_rows) != expected:
        raise CaptureError('inventory_mismatch')
    names, ids, output = set(), set(), []
    for route in route_rows:
        identifier_route, name = route.get('id'), route.get('name')
        if (not isinstance(identifier_route, str) or not UUID.fullmatch(identifier_route)
                or not isinstance(name, str) or not name or name in names or identifier_route in ids):
            raise CaptureError('duplicate_or_invalid_route')
        names.add(name); ids.add(identifier_route)
        service = services[route['service']['id']]
        plugins = rows(admin_get(identifier, f'/routes/{identifier_route}/plugins?size=1000'))
        enabled = [item['name'] for item in plugins if item.get('enabled') is True]
        if not all(isinstance(name, str) for name in enabled) or len(enabled) != len(set(enabled)):
            raise CaptureError('invalid_plugins')
        record = {key: route.get(key) for key in ('name', 'strip_path', 'preserve_host')}
        for key in ('hosts', 'paths', 'methods', 'protocols'):
            values = route.get(key) or []
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise CaptureError('invalid_route_shape')
            record[key] = values
        record['service'] = {key: service[key] for key in (
            'name', 'protocol', 'host', 'port', 'connect_timeout', 'read_timeout', 'write_timeout')}
        record['plugins'] = sorted(enabled)
        output.append(record)
    # Detect a replaced/stopped target; do not silently switch to a newer name.
    if verify_container(container) != identifier:
        raise CaptureError('container_changed')
    return {
        'schema': 'codestra.kong.production-route-readback.v2',
        'capturedAt': datetime.now(timezone.utc).isoformat(),
        'captureMode': 'READ_ONLY_CONTAINER_ADMIN_GET_SANITIZED',
        'adminExposure': 'CONTAINER_LOOPBACK_CONFIGURED',
        'peerNetworkDenialVerified': False,
        'databaseReachable': True, 'expectedRouteCount': expected,
        'actualRouteCount': len(output), 'secretsCaptured': False, 'runtimeMutated': False,
        'routes': sorted(output, key=lambda item: item['name']),
    }


def require_reviewed_routes(result: dict, authority: Path) -> None:
    """Bind a live capture to the complete reviewed active-route authority."""
    raw = authority.read_bytes()
    if len(raw) > MAX_BYTES:
        raise CaptureError('invalid_active_route_authority')
    expected = json.loads(raw)
    routes = expected.get('routes') if isinstance(expected, dict) else None
    if (expected.get('schema') != 'codestra.kong.production-route-readback.v1'
            or expected.get('expectedRouteCount') != 29
            or expected.get('actualRouteCount') != 29
            or expected.get('secretsCaptured') is not False
            or expected.get('runtimeMutated') is not False
            or not isinstance(routes, list) or len(routes) != 29
            or not all(isinstance(route, dict) for route in routes)):
        raise CaptureError('invalid_active_route_authority')
    reviewed = sorted(routes, key=lambda route: route.get('name', ''))
    if result.get('routes') != reviewed:
        raise CaptureError('active_route_contract_mismatch')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--container', default='codestra-kong-kong-gateway-1')
    parser.add_argument('--expected-route-count', type=int, choices=(27, 29), default=27)
    parser.add_argument('--expected-inventory', type=Path)
    args = parser.parse_args()
    try:
        if os.getenv('KONG_ADMIN_READ_ONLY_URL'):
            raise CaptureError('legacy_host_admin_path_not_supported')
        result = capture(args.container, args.expected_route_count)
        if args.expected_inventory is not None:
            require_reviewed_routes(result, args.expected_inventory)
        raw = json.dumps(result, sort_keys=True, indent=2) + '\n'
        fd, temporary = tempfile.mkstemp(prefix='.kong-readback-', dir=args.output.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, args.output)
        finally:
            Path(temporary).unlink(missing_ok=True)
        print('KONG_READ_ONLY_BASELINE=PASS')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        # Never include raw Admin output, subprocess stderr, or environment values.
        print('KONG_READ_ONLY_BASELINE=FAIL')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
