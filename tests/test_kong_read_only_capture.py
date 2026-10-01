from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location('capture', ROOT / 'tools/capture_kong_server_baseline.py')
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def metadata():
    return {'id': 'a' * 64, 'running': True, 'network_mode': 'codestra_edge', 'ports': {},
            'service': 'kong-gateway', 'listeners': [
                'KONG_ADMIN_LISTEN=127.0.0.1:8001', 'KONG_ADMIN_GUI_LISTEN=off', None]}


def test_compose_admin_container_loopback_without_host_publication():
    service = yaml.safe_load((ROOT / 'deploy/gateway-platform/compose.hybrid.yaml').read_text())['services']['kong-cp']
    assert service['environment']['KONG_ADMIN_LISTEN'] == '127.0.0.1:8001'
    assert service['environment']['KONG_ADMIN_GUI_LISTEN'] == 'off'
    assert not service.get('ports')
    assert service['environment']['KONG_PROXY_LISTEN'] == 'off'
    data_plane = yaml.safe_load((ROOT / 'deploy/kong/compose.kong.yaml').read_text())['services']['kong-gateway']
    assert data_plane['environment']['KONG_ADMIN_LISTEN'] == 'off'
    assert data_plane['ports'] == ['127.0.0.1:8000:8000']
    assert data_plane['networks']['codestra_backend'] == {}


@pytest.mark.parametrize('change', [
    {'running': False}, {'network_mode': 'host'}, {'network_mode': 'container:other'},
    {'service': 'middleware'}, {'id': '--privileged'},
    {'ports': {'8001/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8001'}]}},
    {'ports': {'8444/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8444'}]}},
    {'listeners': ['KONG_ADMIN_LISTEN=0.0.0.0:8001', 'KONG_ADMIN_GUI_LISTEN=off', None]},
    {'listeners': ['KONG_ADMIN_LISTEN=127.0.0.1:8001', None]},
    {'listeners': ['KONG_ADMIN_LISTEN=127.0.0.1:8001', 'KONG_ADMIN_LISTEN=0.0.0.0:8001', 'KONG_ADMIN_GUI_LISTEN=off', None]},
])
def test_unapproved_admin_topology_fails(monkeypatch, change):
    capture = module(); info = metadata(); info.update(change)
    monkeypatch.setattr(capture, 'run_json', lambda args: info)
    with pytest.raises(capture.CaptureError): capture.verify_container('codestra-kong-kong-gateway-1')


def test_local_daemon_and_read_only_get_no_redirects_or_shell(monkeypatch):
    capture = module(); calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'{"data": []}\n200')
    monkeypatch.setattr(capture.subprocess, 'run', run)
    assert capture.admin_get('a' * 64, '/routes?size=1000') == {'data': []}
    args, kwargs = calls[0]
    assert args[:3] == ['docker', '--host', 'unix:///var/run/docker.sock']
    assert args[3:7] == ['exec', 'a'*64, 'curl', '--disable']
    assert args[args.index('--request') + 1] == 'GET'
    assert '--location' not in args and '--privileged' not in args
    assert '--max-filesize' in args and kwargs['timeout'] == 15
    assert not kwargs.get('shell')
    assert '--noproxy' in args


@pytest.mark.parametrize('path', ['/consumers', '/config', '/routes/../consumers/plugins?size=1000',
    '/routes/invalid/plugins?size=1000', 'https://example.invalid/status'])
def test_resource_allowlist_rejects_unapproved_paths(path):
    capture = module()
    with pytest.raises(capture.CaptureError): capture.admin_get('a'*64, path)


@pytest.mark.parametrize('status', ['301', '302', '403', '500'])
def test_redirect_and_error_status_not_success(monkeypatch, status):
    capture = module()
    monkeypatch.setattr(capture, 'command_bytes', lambda args: b'{}\n' + status.encode())
    with pytest.raises(capture.CaptureError): capture.admin_get('a'*64, '/status')


def capture_fixture(count=27):
    service = {'id': str(uuid.uuid4()), 'name': 'middleware', 'protocol': 'http', 'host': 'middleware',
               'port': 8095, 'connect_timeout': 5000, 'read_timeout': 10000, 'write_timeout': 10000,
               'untrusted_extra': 'do-not-export'}
    routes = [{'id': str(uuid.uuid4()), 'name': f'route-{i}', 'hosts': [], 'paths': [f'/v1/item/{i}'],
               'methods': ['GET'], 'protocols': ['https'], 'strip_path': False, 'preserve_host': True,
               'service': {'id': service['id']}} for i in range(count)]
    def getter(identifier, path):
        if path == '/status': return {'database': {'reachable': True}}
        if path == '/routes?size=1000': return {'data': routes, 'next': None}
        if path == '/services?size=1000': return {'data': [service]}
        return {'data': [{'name': 'openid-connect', 'enabled': True, 'config': {'secret': 'do-not-export'}}]}
    return routes, getter


@pytest.mark.parametrize('count', [27, 29])
def test_complete_sanitized_capture_supports_versioned_route_contracts(monkeypatch, count):
    capture = module(); routes, getter = capture_fixture(count)
    monkeypatch.setattr(capture, 'verify_container', lambda name: 'a'*64)
    monkeypatch.setattr(capture, 'admin_get', getter)
    result = capture.capture('kong', count)
    assert len(result['routes']) == result['actualRouteCount'] == count
    assert result['secretsCaptured'] is result['runtimeMutated'] is False
    assert result['peerNetworkDenialVerified'] is False
    assert result['adminExposure'] == 'CONTAINER_LOOPBACK_CONFIGURED'
    assert 'do-not-export' not in json.dumps(result)
    assert result['routes'][0]['hosts'] == []


def test_active_capture_requires_exact_reviewed_route_definitions(monkeypatch, tmp_path):
    capture = module(); _, getter = capture_fixture(29)
    monkeypatch.setattr(capture, 'verify_container', lambda name: 'a'*64)
    monkeypatch.setattr(capture, 'admin_get', getter)
    result = capture.capture('kong', 29)
    authority = tmp_path / 'active-routes.json'
    document = {
        'schema': 'codestra.kong.production-route-readback.v1',
        'expectedRouteCount': 29,
        'actualRouteCount': 29,
        'secretsCaptured': False,
        'runtimeMutated': False,
        'routes': copy.deepcopy(result['routes']),
    }
    authority.write_text(json.dumps(document))
    capture.require_reviewed_routes(result, authority)
    document['routes'][0]['service']['host'] = 'mixed-candidate.internal'
    authority.write_text(json.dumps(document))
    with pytest.raises(capture.CaptureError, match='active_route_contract_mismatch'):
        capture.require_reviewed_routes(result, authority)


@pytest.mark.parametrize('damage', ['count', 'duplicate-name', 'duplicate-id', 'missing-service'])
def test_partial_or_ambiguous_capture_rejected(monkeypatch, damage):
    capture = module(); routes, getter = capture_fixture()
    if damage == 'count': routes.pop()
    elif damage == 'duplicate-name': routes[1]['name'] = routes[0]['name']
    elif damage == 'duplicate-id': routes[1]['id'] = routes[0]['id']
    else: routes[0]['service']['id'] = 'absent'
    monkeypatch.setattr(capture, 'verify_container', lambda name: 'a'*64)
    monkeypatch.setattr(capture, 'admin_get', getter)
    with pytest.raises((capture.CaptureError, KeyError)): capture.capture('kong', 27)


def test_container_replacement_fails_instead_of_mixing_evidence(monkeypatch):
    capture = module(); _, getter = capture_fixture(); identities = iter(['a'*64, 'b'*64])
    monkeypatch.setattr(capture, 'verify_container', lambda name: next(identities))
    monkeypatch.setattr(capture, 'admin_get', getter)
    with pytest.raises(capture.CaptureError): capture.capture('kong', 27)


def test_partial_paginated_data_is_never_called_complete():
    capture = module()
    with pytest.raises(capture.CaptureError): capture.rows({'data': [], 'next': 'https://example.invalid'})


def test_cli_failure_sanitizes_raw_errors(monkeypatch, tmp_path, capsys):
    capture = module()
    monkeypatch.setattr('sys.argv', ['capture', str(tmp_path/'result.json')])
    monkeypatch.setattr(capture, 'capture', lambda *args: (_ for _ in ()).throw(ValueError('do-not-export')))
    assert capture.main() == 2
    assert capsys.readouterr().out == 'KONG_READ_ONLY_BASELINE=FAIL\n'
    assert not (tmp_path/'result.json').exists()

def test_hybrid_control_plane_is_accepted_by_capture_validator(monkeypatch):
    capture = module()
    info = metadata()
    info["service"] = "kong-cp"
    monkeypatch.setattr(capture, "run_json", lambda args: info)
    assert capture.verify_container("codestra-gateway-hybrid-kong-cp-1") == "a" * 64

def test_hybrid_data_plane_is_rejected_by_capture_validator(monkeypatch):
    capture = module()
    info = metadata()
    info["service"] = "kong-dp-1"
    info["listeners"] = ["KONG_ADMIN_LISTEN=off", "KONG_ADMIN_GUI_LISTEN=off", None]
    monkeypatch.setattr(capture, "run_json", lambda args: info)
    with pytest.raises(capture.CaptureError):
        capture.verify_container("codestra-gateway-hybrid-kong-dp-1")
