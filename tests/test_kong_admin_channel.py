"""The private Admin channel that replaces the removed host Admin publication."""
from __future__ import annotations
import importlib.util
import json
import io
from pathlib import Path
from types import SimpleNamespace
import traceback
from urllib.error import HTTPError
from urllib.request import Request

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HOST_ADMIN = "http://127.0.0.1:8001"
STANDBY_CLIENTS = ("scripts/apply_kong_standby.py", "scripts/rollback_kong_standby.py")
REHEARSAL = "operations/kong-database/kong-database-restore-rehearsal.sh"
# Naming the container-loopback origin is only safe inside the channel itself and
# in clients that reach it exclusively through the channel.
CHANNEL_MEDIATED = {"scripts/kong_admin_channel.py", REHEARSAL}
PRIVATE_CLIENTS = (
    "scripts/reconcile_kong_canonical_routes.py",
    "scripts/reconcile_kong_callback_routes.py",
    "scripts/reconcile_kong_campaign_automation.py",
    "scripts/reconcile_kong_n8n_control_plane.py",
    "scripts/export_kong_public_route_contracts.py",
)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def module():
    return load(ROOT / "scripts/kong_admin_channel.py", "kong_admin_channel")


def metadata():
    return {"id": "a" * 64, "running": True, "network_mode": "codestra_edge", "ports": {},
            "service": "kong-cp", "project": "codestra-gateway-hybrid",
            "runtime": ["KONG_ROLE=control_plane", "KONG_DATABASE=postgres", "KONG_PROXY_LISTEN=off", None],
            "listeners": [
                "KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_GUI_LISTEN=off", None]}


def stubbed(channel, monkeypatch, stdout=b'{"data": []}\n200', returncode=0):
    calls = []
    monkeypatch.setattr(channel, "verify_container", lambda container, **kwargs: "a" * 64)

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"")

    monkeypatch.setattr(channel.subprocess, "run", run)
    return calls


def test_standby_clients_reach_admin_only_through_the_private_channel():
    for name in STANDBY_CLIENTS:
        source = (ROOT / name).read_text()
        assert HOST_ADMIN not in source, f"{name} still dials a host Admin endpoint"
        assert "from kong_admin_channel import" in source
        assert "admin_request(" in source and "confirm_unchanged()" in source


def test_restore_rehearsal_reads_live_admin_inside_the_gateway_container():
    value = (ROOT / REHEARSAL).read_text()
    assert "verify_live_gateway" in value
    assert 'live_channel="container:$live_gateway_container"' in value
    for collection in ("services", "routes", "plugins"):
        assert f'kong_inventory "$live_channel" {HOST_ADMIN} {collection}' in value
        # The isolated restore gateway keeps its own private-network endpoint.
        assert f'kong_inventory direct "http://$restore_ip:8001" {collection}' in value
    assert 'page="$(kong_admin_get "$channel" "$next")"' in value
    assert 'curl -fsS "$next"' not in value


def test_no_other_operational_client_assumes_a_published_host_admin_port():
    sources = list((ROOT / "scripts").rglob("*.py")) + list((ROOT / "operations").rglob("*.sh"))
    offenders = sorted(path.relative_to(ROOT).as_posix() for path in sources
                       if HOST_ADMIN in path.read_text()
                       and path.relative_to(ROOT).as_posix() not in CHANNEL_MEDIATED)
    assert offenders == []


def test_remaining_admin_clients_default_to_the_private_channel():
    for name in PRIVATE_CLIENTS:
        source = (ROOT / name).read_text()
        assert "default=PRIVATE_ADMIN_URL" in source
        assert "admin_request(" in source


@pytest.mark.parametrize("name", PRIVATE_CLIENTS[:-1])
def test_reconcilers_dispatch_private_requests_without_urlopen(monkeypatch, name):
    client = load(ROOT / name, "private_" + Path(name).stem)
    calls = []
    monkeypatch.setattr(
        client,
        "admin_request",
        lambda method, path, payload=None, **kwargs: calls.append(
            (method, path, payload, kwargs)
        ) or {"data": []},
    )
    assert client.request(client.PRIVATE_ADMIN_URL, "GET", "/routes?size=1000") == {"data": []}
    assert calls == [
        ("GET", "/routes?size=1000", None, {"payload_encoding": "form"})
    ]


@pytest.mark.parametrize("name", PRIVATE_CLIENTS[:-1])
def test_reconcilers_normalize_form_booleans_on_direct_transport(monkeypatch, name):
    client = load(ROOT / name, "direct_" + Path(name).stem)
    calls = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return b'{"id":"updated"}'

    def open_request(request, timeout):
        calls.append((request, timeout))
        return Response()

    monkeypatch.setattr(client, "urlopen", open_request)
    result = client.request(
        "http://127.0.0.1:8001",
        "PATCH",
        "/plugins/00000000-0000-0000-0000-000000000000",
        {"config.fault_tolerant": False, "config.flags[]": [True, False]},
    )
    assert result == {"id": "updated"}
    request, _timeout = calls[0]
    assert request.data == (
        b"config.fault_tolerant=false&"
        b"config.flags%5B%5D=true&config.flags%5B%5D=false"
    )


def test_exporter_dispatches_private_get_without_urlopen(monkeypatch):
    client = load(ROOT / PRIVATE_CLIENTS[-1], "private_exporter")
    calls = []
    monkeypatch.setattr(
        client,
        "admin_request",
        lambda method, path: calls.append((method, path)) or {"data": []},
    )
    assert client.request(
        client.PRIVATE_ADMIN_URL,
        HOST_ADMIN + "/routes?offset=next",
    ) == {"data": []}
    assert calls == [("GET", "/routes?offset=next")]


def test_channel_and_read_only_capture_require_the_same_admin_contract():
    channel = module()
    capture = load(ROOT / "tools/capture_kong_server_baseline.py", "capture")
    assert channel.INSPECT_FORMAT == capture.INSPECT_FORMAT
    assert channel.DOCKER == capture.DOCKER
    assert channel.ADMIN_ORIGIN == HOST_ADMIN
    assert channel.ADMIN_PORTS == ("8001/tcp", "8444/tcp", "8002/tcp", "8445/tcp")
    # Administrative capture belongs to the hybrid CP; the DP has no Admin API.
    environment = yaml.safe_load((ROOT / "deploy/gateway-platform/compose.hybrid.yaml").read_text())[
        "services"]["kong-cp"]["environment"]
    assert channel.REQUIRED_LISTENERS == {
        f"KONG_ADMIN_LISTEN={environment['KONG_ADMIN_LISTEN']}",
        f"KONG_ADMIN_GUI_LISTEN={environment['KONG_ADMIN_GUI_LISTEN']}"}


@pytest.mark.parametrize("change", [
    {"running": False}, {"network_mode": "host"}, {"network_mode": "none"},
    {"network_mode": "container:other"}, {"service": "middleware"}, {"id": "--privileged"},
    {"ports": {"8001/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8001"}]}},
    {"ports": {"8444/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8444"}]}},
    {"listeners": ["KONG_ADMIN_LISTEN=0.0.0.0:8001", "KONG_ADMIN_GUI_LISTEN=off", None]},
    {"listeners": ["KONG_ADMIN_LISTEN=127.0.0.1:8001", None]},
    {"listeners": ["KONG_ADMIN_LISTEN=127.0.0.1:8001", "KONG_ADMIN_LISTEN=0.0.0.0:8001",
                   "KONG_ADMIN_GUI_LISTEN=off", None]},
])
def test_unapproved_gateway_topology_fails_closed(monkeypatch, change):
    channel = module()
    info = metadata()
    info.update(change)
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container("codestra-kong-kong-gateway-1")


def test_requests_run_inside_the_container_on_the_local_daemon(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch)
    assert channel.admin_request("GET", "/routes?size=1000") == {"data": []}
    argv, kwargs = calls[0]
    assert argv[:3] == ["docker", "--host", "unix:///var/run/docker.sock"]
    assert argv[3:6] == ["exec", "a" * 64, "curl"]
    assert argv[argv.index("--request") + 1] == "GET"
    assert argv[-1] == HOST_ADMIN + "/routes?size=1000"
    assert "--location" not in argv and "--privileged" not in argv
    assert "--noproxy" in argv and "--max-filesize" in argv
    assert "--interactive" not in argv
    assert not kwargs.get("shell")
    assert kwargs["timeout"] == channel.PROCESS_TIMEOUT


def test_write_payloads_travel_on_stdin_not_argv(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch, stdout=b'{"id": "created"}\n201')
    payload = {"name": "standby", "tags": ["codestra-kong-standby-20260820"]}
    assert channel.admin_request("POST", "/services", payload) == {"id": "created"}
    argv, kwargs = calls[0]
    assert "--interactive" in argv
    assert argv[argv.index("--data-binary") + 1] == "@-"
    assert kwargs["input"] == json.dumps(payload).encode()
    assert not any("standby" in item for item in argv)


def test_form_payloads_preserve_kong_field_encoding(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch, stdout=b'{"id": "created"}\n201')
    payload = {
        "config.redis.host": "redis",
        "config.fault_tolerant": False,
        "config.flags[]": [True, False],
        "hosts[]": ["a.example", "b.example"],
    }
    assert channel.admin_request(
        "POST", "/plugins", payload, payload_encoding="form"
    ) == {"id": "created"}
    argv, kwargs = calls[0]
    assert "Content-Type: application/x-www-form-urlencoded" in argv
    assert kwargs["input"] == (
        b"config.redis.host=redis&config.fault_tolerant=false&"
        b"config.flags%5B%5D=true&config.flags%5B%5D=false&"
        b"hosts%5B%5D=a.example&hosts%5B%5D=b.example"
    )
    assert not any("redis" in item or "a.example" in item for item in argv)


def test_unknown_payload_encoding_is_refused():
    channel = module()
    with pytest.raises(channel.AdminError, match="payload encoding"):
        channel.admin_request("POST", "/services", {}, payload_encoding="yaml")


@pytest.mark.parametrize("method", ["PUT", "OPTIONS", "HEAD", "get", "POST;rm"])
def test_unsupported_methods_are_refused(method):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request(method, "/services")


@pytest.mark.parametrize("path", [
    "services", "//evil.invalid/services", "/routes/../consumers",
    "/routes/%2e%2e/consumers", "/routes/%2E/consumers",
    "http://evil.invalid/services", "/routes\n/x", "/routes?tags=a b", "/" + "a" * 4096])
def test_unsafe_admin_paths_are_refused(path):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", path)


def test_get_must_not_carry_a_body():
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/services", {"name": "x"})


@pytest.mark.parametrize("status", [b"201", b"204", b"301", b"302", b"400", b"409", b"500"])
def test_non_success_status_raises_with_bounded_detail(monkeypatch, status):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"x" * 4000 + b"\n" + status)
    with pytest.raises(channel.AdminError) as error:
        channel.admin_request("PATCH", "/services/abc", {"name": "x"})
    assert status.decode() in str(error.value)
    assert len(str(error.value)) < 700


def test_delete_accepts_no_content(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"\n204")
    assert channel.admin_request("DELETE", "/services/abc") is None


@pytest.mark.parametrize("stdout,returncode", [
    (b'{"data": []}\n200', 7), (b"{}", 0), (b"{}\nnot-a-status", 0), (b'"text"\n200', 0)])
def test_transport_and_response_failures_fail_closed(monkeypatch, stdout, returncode):
    channel = module()
    stubbed(channel, monkeypatch, stdout=stdout, returncode=returncode)
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/status")


def test_malformed_json_raises_the_channel_error(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"{not-json}\n200")
    with pytest.raises(channel.AdminError, match="invalid JSON"):
        channel.admin_request("GET", "/status")


def test_subprocess_failures_raise_the_channel_error(monkeypatch):
    channel = module()

    def fail(*args, **kwargs):
        raise channel.subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))

    monkeypatch.setattr(channel.subprocess, "run", fail)
    with pytest.raises(channel.AdminError, match="inspection failed"):
        channel.verify_container("codestra-kong-kong-gateway-1")


@pytest.mark.parametrize("value", [None, "", "../services", "a" * 64,
                                    "00000000-0000-0000-0000-00000000000g"])
def test_entity_ids_must_be_kong_uuids(value):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.entity_id(value)


def test_same_origin_pagination_is_normalized_for_private_channel():
    channel = module()
    assert channel.normalize_admin_reference(
        channel.ADMIN_ORIGIN + "/routes?offset=next"
    ) == "/routes?offset=next"
    with pytest.raises(channel.AdminError, match="unsafe Kong Admin URL"):
        channel.normalize_admin_reference("https://attacker.invalid/routes")


def test_oversized_replies_fail_closed(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b"x" * (channel.MAX_BYTES + 1) + b"\n200")
    with pytest.raises(channel.AdminError):
        channel.admin_request("GET", "/status")


def test_container_replacement_during_the_operation_is_detected(monkeypatch):
    channel = module()
    identities = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(channel, "verify_container", lambda container, **kwargs: next(identities))
    assert channel.container_identity() == "a" * 64
    with pytest.raises(channel.AdminError):
        channel.confirm_unchanged()


def test_every_private_request_rechecks_the_named_container(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch)
    identities = iter(["a" * 64, "a" * 64, "b" * 64])
    monkeypatch.setattr(channel, "verify_container", lambda container, **kwargs: next(identities))
    assert channel.admin_request("GET", "/status") == {"data": []}
    with pytest.raises(channel.AdminError, match="container changed"):
        channel.admin_request("GET", "/status")
    assert len(calls) == 1


def test_private_response_is_rejected_if_container_changes_during_request(monkeypatch):
    channel = module()
    calls = stubbed(channel, monkeypatch)
    identities = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(channel, "verify_container", lambda container, **kwargs: next(identities))
    with pytest.raises(channel.AdminError, match="container changed"):
        channel.admin_request("GET", "/status")
    assert len(calls) == 1


def test_private_errors_never_disclose_response_body_or_query(monkeypatch):
    channel = module()
    stubbed(channel, monkeypatch, stdout=b'{"password":"response-sentinel"}\n400')
    path = "/plugins/abc?token=query-sentinel"
    with pytest.raises(channel.AdminError) as error:
        channel.admin_request("PATCH", path, {})
    rendered = "".join(traceback.format_exception(error.value))
    assert "400" in str(error.value)
    assert "response-sentinel" not in rendered
    assert "query-sentinel" not in rendered


@pytest.mark.parametrize("path", ["https://other.invalid/plugins", "//other.invalid/plugins",
                                  "/routes/%2e%2e/plugins", "/routes#fragment"])
@pytest.mark.parametrize("name", PRIVATE_CLIENTS)
def test_direct_clients_reject_unsafe_references_before_opening(monkeypatch, name, path):
    client = load(ROOT / name, "unsafe_direct_" + Path(name).stem)
    calls = []
    monkeypatch.setattr(client, "urlopen", lambda *a, **k: calls.append(a))
    with pytest.raises(RuntimeError):
        if name == PRIVATE_CLIENTS[-1]:
            client.request(HOST_ADMIN, path)
        else:
            client.request(HOST_ADMIN, "GET", path)
    assert calls == []


def test_direct_errors_suppress_untrusted_http_reason_and_url(monkeypatch):
    client = load(ROOT / PRIVATE_CLIENTS[1], "direct_http_error")

    def rejected(request, timeout):
        raise HTTPError(request.full_url, 400, "reason-sentinel", {}, io.BytesIO(b"body-sentinel"))

    monkeypatch.setattr(client, "urlopen", rejected)
    path = "/plugins/abc?token=query-sentinel"
    with pytest.raises(RuntimeError) as error:
        client.request(HOST_ADMIN, "PATCH", path, {})
    rendered = "".join(traceback.format_exception(error.value))
    assert "400" in str(error.value)
    for secret in ("reason-sentinel", "body-sentinel", "query-sentinel"):
        assert secret not in rendered


def test_direct_callback_json_keeps_content_type_and_boolean_encoding(monkeypatch):
    client = load(ROOT / PRIVATE_CLIENTS[1], "direct_callback_json")
    requests = []

    class Response(io.BytesIO):
        status = 200

    def accepted(request, timeout):
        requests.append(request)
        return Response(b'{"id":"updated"}')

    monkeypatch.setattr(client, "urlopen", accepted)
    payload = {"enabled": False, "config": {"anonymous": None}}
    assert client.request_json(HOST_ADMIN, "PATCH", "/plugins/abc", payload) == {"id": "updated"}
    assert requests[0].get_header("Content-type") == "application/json"
    assert json.loads(requests[0].data) == payload


def test_canonical_drift_errors_handle_sets_and_redact_values():
    client = load(ROOT / PRIVATE_CLIENTS[0], "canonical_redacted_drift")
    for actual, expected in [({"unexpected"}, {"required"}),
                             ({"password": "actual-sentinel"}, {"password": "expected-sentinel"})]:
        with pytest.raises(RuntimeError, match="route_plugins drift") as error:
            client.require_equal(actual, expected, "route_plugins")
        assert "actual-sentinel" not in str(error.value)
        assert "expected-sentinel" not in str(error.value)


@pytest.mark.parametrize("status,body", [(200, b""), (200, b"[]"), (201, b"{}"),
                                        (302, b"{}"), (200, b"not-json")])
def test_direct_get_requires_a_successful_json_object(status, body):
    channel = module()

    class Response(io.BytesIO):
        pass

    response = Response(body)
    response.status = status
    with pytest.raises(channel.AdminError):
        channel.http_admin_request(HOST_ADMIN, "GET", "/routes",
                                   opener=lambda *a, **k: response)


def test_direct_response_read_is_bounded_and_oversize_is_rejected():
    channel = module()
    sizes = []

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    with pytest.raises(channel.AdminError, match="oversized response"):
        channel.http_admin_request(HOST_ADMIN, "GET", "/routes",
            opener=lambda *a, **k: Response(b"x" * (channel.MAX_BYTES + 5)))
    assert sizes == [channel.MAX_BYTES + 1]


@pytest.mark.parametrize("target", [HOST_ADMIN + "/routes", "https://other.invalid/routes"])
def test_admin_opener_rejects_redirects_without_a_second_request(monkeypatch, target):
    import urllib.request
    from email.message import Message
    channel = module()
    calls = []

    def redirect(_handler, request):
        assert request.host == "127.0.0.1:8001"
        calls.append(request.full_url)
        headers = Message()
        headers["Location"] = target
        reply = urllib.request.addinfourl(io.BytesIO(b""), headers, request.full_url, code=302)
        reply.msg = "Found"
        return reply

    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", redirect)
    monkeypatch.setenv("HTTP_PROXY", "http://unselected-proxy.invalid:8080")
    with pytest.raises(channel.AdminError, match="redirect rejected"):
        channel.http_admin_request(HOST_ADMIN, "POST", "/plugins", {"enabled": False})
    assert calls == [HOST_ADMIN + "/plugins"]


@pytest.mark.parametrize("base", ["file:///tmp/admin", "https://user:secret@admin.invalid",
                                  "http://admin.invalid?token=secret", "http://admin.invalid/prefix",
                                  "http://admin.invalid:bad", "http://admin.invalid\n"])
def test_direct_admin_origin_must_be_explicit_and_credential_free(base):
    channel = module()
    with pytest.raises(channel.AdminError):
        channel.http_admin_url(base, "/routes")


COLLECTION_CLIENTS = (PRIVATE_CLIENTS[0], PRIVATE_CLIENTS[1], PRIVATE_CLIENTS[3], PRIVATE_CLIENTS[4])


@pytest.mark.parametrize("name", COLLECTION_CLIENTS)
@pytest.mark.parametrize("page", [{}, {"data": {}}, {"data": ["not-an-entity"]},
                                  {"data": [], "next": False}])
def test_collection_clients_reject_malformed_inventory(monkeypatch, name, page):
    client = load(ROOT / name, "malformed_collection_" + Path(name).stem)
    monkeypatch.setattr(client, "request", lambda *a: page)
    with pytest.raises(RuntimeError):
        client.all_rows(client.PRIVATE_ADMIN_URL, "/routes")


@pytest.mark.parametrize("name", COLLECTION_CLIENTS)
@pytest.mark.parametrize("base", [HOST_ADMIN, "container://kong-gateway"])
def test_collection_clients_accept_same_origin_absolute_pagination(monkeypatch, name, base):
    client = load(ROOT / name, "paginated_" + Path(name).stem)
    replies = iter([{"data": [{"id": "first"}], "next": HOST_ADMIN + "/routes?offset=next"},
                    {"data": [{"id": "second"}], "next": None}])
    monkeypatch.setattr(client, "request", lambda *a: next(replies))
    assert client.all_rows(base, "/routes") == [{"id": "first"}, {"id": "second"}]


@pytest.mark.parametrize("name", COLLECTION_CLIENTS)
def test_collection_clients_reject_normalized_pagination_loops(monkeypatch, name):
    client = load(ROOT / name, "loop_collection_" + Path(name).stem)
    calls = []

    def page(*args):
        calls.append(args)
        return {"data": [], "next": HOST_ADMIN + "/routes"}

    monkeypatch.setattr(client, "request", page)
    with pytest.raises(RuntimeError, match="pagination loop"):
        client.all_rows(client.PRIVATE_ADMIN_URL, "/routes")
    assert len(calls) == 1


def test_collection_limits_and_duplicate_identities_fail_closed():
    channel = module()
    pages = iter([{"data": [{"id": "same"}], "next": "/routes?offset=next"},
                  {"data": [{"id": "same"}], "next": None}])
    with pytest.raises(channel.AdminError, match="duplicate"):
        channel.collect_admin_rows(lambda _: next(pages), "/routes", channel.normalize_admin_reference)
    with pytest.raises(channel.AdminError, match="row limit"):
        channel.collect_admin_rows(lambda _: {"data": [{}, {}]}, "/routes",
                                   channel.normalize_admin_reference, max_rows=1)
    calls = []

    def changing_page(path):
        calls.append(path)
        return {"data": [], "next": f"/routes?offset={len(calls)}"}

    with pytest.raises(channel.AdminError, match="page limit"):
        channel.collect_admin_rows(changing_page, "/routes", channel.normalize_admin_reference, max_pages=2)
    assert len(calls) == 2


@pytest.mark.parametrize("name", COLLECTION_CLIENTS)
def test_collection_rejects_pagination_traversal_before_second_fetch(monkeypatch, name):
    client = load(ROOT / name, "traversal_collection_" + Path(name).stem)
    calls = []

    def page(*args):
        calls.append(args)
        return {"data": [], "next": "/routes/../plugins"}

    monkeypatch.setattr(client, "request", page)
    with pytest.raises(RuntimeError):
        client.all_rows(HOST_ADMIN, "/routes")
    assert len(calls) == 1

def test_hybrid_control_plane_is_accepted_by_admin_validator(monkeypatch):
    channel = module()
    info = management_metadata()
    monkeypatch.setattr(channel, "run_json", lambda args: info)
    assert channel.verify_container("codestra-gateway-hybrid-kong-cp-1") == "a" * 64

def test_hybrid_data_plane_is_rejected_by_admin_validator(monkeypatch):
    channel = module()
    info = metadata()
    info["service"] = "kong-dp-1"
    info["listeners"] = ["KONG_ADMIN_LISTEN=off", "KONG_ADMIN_GUI_LISTEN=off", None]
    monkeypatch.setattr(channel, "run_json", lambda args: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container("codestra-gateway-hybrid-kong-dp-1")


def management_metadata(service="kong-cp", approval=None):
    info = metadata()
    info.update(service=service,
                project="codestra-gateway-hybrid" if service == "kong-cp" else "codestra-gateway-traditional",
                runtime=["KONG_ROLE=" + ("control_plane" if service == "kong-cp" else "traditional"),
                         "KONG_DATABASE=postgres", "KONG_PROXY_LISTEN=off"])
    if approval is not None:
        info["runtime"].append("CODESTRA_TRADITIONAL_APPROVAL=" + approval)
    info["runtime"].append(None)
    return info


def test_default_admin_target_resolves_to_hybrid_control_plane(monkeypatch):
    channel = module()
    hybrid = yaml.safe_load((ROOT / "deploy/gateway-platform/compose.hybrid.yaml").read_text())
    selected = []
    def inspect(argv):
        selected.append(argv[-1])
        assert argv[-1] == hybrid["name"] + "-kong-cp-1"
        return management_metadata()
    monkeypatch.setattr(channel, "run_json", inspect)
    assert channel.container_identity() == "a" * 64
    assert selected == ["codestra-gateway-hybrid-kong-cp-1"]
    assert hybrid["services"]["kong-cp"]["environment"]["KONG_ADMIN_LISTEN"] == "127.0.0.1:8001"


@pytest.mark.parametrize("service", ["kong-gateway", "kong-dp-1", "kong-dp-2", "kong-proxy-1"])
def test_data_plane_cannot_be_selected_even_with_loopback_admin(monkeypatch, service):
    channel = module()
    info = management_metadata()
    info["service"] = service
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container("selected-node")


@pytest.mark.parametrize("damage", ["wrong-project", "data-plane-role", "database-off", "proxy-enabled", "duplicate-role"])
def test_control_plane_selection_requires_reviewed_management_role(monkeypatch, damage):
    channel = module()
    info = management_metadata()
    if damage == "wrong-project":
        info["project"] = "unreviewed-stack"
    elif damage == "data-plane-role":
        info["runtime"][0] = "KONG_ROLE=data_plane"
    elif damage == "database-off":
        info["runtime"][1] = "KONG_DATABASE=off"
    elif damage == "proxy-enabled":
        info["runtime"][2] = "KONG_PROXY_LISTEN=0.0.0.0:8443 ssl"
    else:
        info["runtime"].insert(0, "KONG_ROLE=control_plane")
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container(channel.DEFAULT_CONTAINER)


def test_traditional_management_requires_matching_explicit_approval(monkeypatch):
    channel = module()
    info = management_metadata("kong-management", "KONG:fallback-approved")
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    assert channel.verify_container("codestra-gateway-traditional-kong-management-1",
        traditional_approval="KONG:fallback-approved") == "a" * 64


@pytest.mark.parametrize("approval", [None, "", "yes", "KONG:", "KONG:different"])
def test_traditional_management_rejects_missing_or_mismatched_approval(monkeypatch, approval):
    channel = module()
    info = management_metadata("kong-management", "KONG:fallback-approved")
    monkeypatch.setattr(channel, "run_json", lambda argv: info)
    with pytest.raises(channel.AdminError):
        channel.verify_container("codestra-gateway-traditional-kong-management-1",
            traditional_approval=approval)


def test_selected_approved_management_is_reverified_after_private_request(monkeypatch):
    channel = module()
    inspections = []
    commands = []
    def inspect(argv):
        inspections.append(argv[-1])
        return management_metadata("kong-management", "KONG:fallback-approved")
    def execute(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout=b'{"data": []}\n200', stderr=b"")
    monkeypatch.setattr(channel, "run_json", inspect)
    monkeypatch.setattr(channel.subprocess, "run", execute)
    target = "codestra-gateway-traditional-kong-management-1"
    assert channel.admin_request("GET", "/routes", container=target,
        traditional_approval="KONG:fallback-approved") == {"data": []}
    assert inspections == [target, target]
    assert commands[0][3:6] == ["exec", "a" * 64, "curl"]
