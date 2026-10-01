"""Offline lifecycle/configuration proof; never licensed Kong runtime certification."""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import socket
import subprocess
import sys
from threading import Thread

import pytest
import yaml

from scripts.validate_kong_runtime_mode import validate_profile

ROOT = Path(__file__).resolve().parents[1]


def profile(mode="hybrid", legacy=False):
    path = ("deploy/kong/compose.kong.yaml" if legacy else
            f"deploy/gateway-platform/compose.{mode}.yaml")
    return yaml.safe_load((ROOT / path).read_text())


def validate(document, mode="hybrid", legacy=False):
    validate_profile(document, mode, "KONG:lifecycle-fallback-review" if mode == "traditional" else None, legacy)


@pytest.mark.parametrize("mode,legacy", [("hybrid", False), ("traditional", False), ("hybrid", True)])
@pytest.mark.parametrize("cidrs", ["0.0.0.0/1,128.0.0.0/1", "::/1,8000::/1",
    "0.0.0.0/2,64.0.0.0/2,128.0.0.0/2,192.0.0.0/2,fd00::/8"])
def test_validator_rejects_combined_universal_proxy_trust(mode, legacy, cidrs):
    document = profile(mode, legacy)
    for service in document["services"].values():
        if "KONG_TRUSTED_IPS" in service["environment"]:
            service["environment"]["KONG_TRUSTED_IPS"] = cidrs
    with pytest.raises(ValueError, match="universal proxy trust"):
        validate(document, mode, legacy)


@pytest.mark.parametrize("mode,legacy", [("hybrid", False), ("traditional", False), ("hybrid", True)])
def test_profiles_explicitly_budget_graceful_shutdown(mode, legacy):
    document = profile(mode, legacy)
    for service in document["services"].values():
        # Docker must signal graceful quit and wait longer than Nginx's drain window.
        assert service.get("stop_signal") == "SIGQUIT"
        assert service.get("stop_grace_period") == "300s"
        assert service["environment"].get("KONG_NGINX_MAIN_WORKER_SHUTDOWN_TIMEOUT") == "240s"
        assert service["environment"].get("KONG_NGINX_DAEMON") == "off"
    validate(document, mode, legacy)


@pytest.mark.parametrize("field,value", [
    ("stop_signal", "SIGTERM"), ("stop_grace_period", "10s"),
    ("restart", "always"), ("build", "."),
    ("image", "kong/kong-gateway:latest"),
    ("image", "kong/kong-gateway@sha256:bad"),
])
@pytest.mark.parametrize("mode,legacy", [("hybrid", False), ("traditional", False), ("hybrid", True)])
def test_validator_rejects_unsafe_boot_and_shutdown_policy(field, value, mode, legacy):
    document = profile(mode, legacy)
    next(iter(document["services"].values()))[field] = value
    with pytest.raises(ValueError):
        validate(document, mode, legacy)


@pytest.mark.parametrize("field,value", [
    ("KONG_NGINX_DAEMON", "on"),
    ("KONG_NGINX_MAIN_WORKER_SHUTDOWN_TIMEOUT", "0s"),
    ("KONG_NGINX_MAIN_WORKER_SHUTDOWN_TIMEOUT", "600s"),
])
def test_validator_rejects_unbounded_or_background_workers(field, value):
    document = profile()
    document["services"]["kong-dp-1"]["environment"][field] = value
    with pytest.raises(ValueError):
        validate(document)


@pytest.mark.parametrize("field,value", [
    ("interval", "1h"), ("timeout", "1h"), ("start_period", "1h"),
    ("retries", 0), ("retries", True),
])
def test_validator_rejects_health_policy_that_masks_boot_or_dependency_failure(field, value):
    document = profile()
    document["services"]["kong-dp-1"]["healthcheck"][field] = value
    with pytest.raises(ValueError):
        validate(document)


@pytest.mark.parametrize("mode", ["hybrid", "traditional"])
@pytest.mark.parametrize("field,value", [
    ("KONG_PG_SSL_REQUIRED", "off"), ("KONG_PG_TIMEOUT", "0"),
    ("KONG_PG_TIMEOUT", "60000"), ("KONG_PG_HOST", "database.public.example"),
    ("KONG_PG_USER", "postgres"), ("KONG_PG_MAX_CONCURRENT_QUERIES", "0"),
])
def test_validator_rejects_database_downgrade_or_unbounded_dependency_wait(mode, field, value):
    document = profile(mode)
    service = next(s for s in document["services"].values() if s["environment"]["KONG_DATABASE"] == "postgres")
    service["environment"][field] = value
    with pytest.raises(ValueError):
        validate(document, mode)


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("damage", ["missing", "tmpfs", "wrong-prefix", "unmanaged"])
def test_validator_rejects_loss_of_persistent_config_cache(legacy, damage):
    document = profile(legacy=legacy)
    name, volume, prefix = ("kong-gateway", "dp_prefix", "/var/run/kong") if legacy else (
        "kong-dp-1", "dp1_prefix", "/usr/local/kong")
    service = document["services"][name]
    if damage == "missing":
        service["volumes"] = [v for v in service["volumes"] if not isinstance(v, str)]
    elif damage == "tmpfs":
        service["tmpfs"].append(prefix)
    elif damage == "wrong-prefix":
        service["environment"]["KONG_PREFIX"] = "/tmp/new-kong"
    else:
        document.setdefault("volumes", {})[volume] = {"external": False}
    with pytest.raises(ValueError):
        validate(document, legacy=legacy)


def test_data_planes_cannot_share_a_configuration_cache_volume():
    document = profile()
    document["volumes"]["dp1_prefix"]["name"] = "reviewed-shared-cache"
    document["volumes"]["dp2_prefix"]["name"] = "reviewed-shared-cache"
    with pytest.raises(ValueError):
        validate(document)


def test_nodes_require_one_immutable_image_for_plugin_and_config_compatibility():
    document = profile()
    document["services"]["kong-dp-1"]["image"] = "registry.example/kong@sha256:" + "a" * 64
    with pytest.raises(ValueError):
        validate(document)


def test_valid_immutable_prior_image_can_be_validated_for_rollback(tmp_path):
    current = profile()
    prior = deepcopy(current)
    for service in prior["services"].values():
        service["image"] = "registry.example/kong@sha256:" + "a" * 64
    current_path = tmp_path / "current.yaml"
    prior_path = tmp_path / "rollback.yaml"
    current_path.write_text(yaml.safe_dump(current))
    prior_path.write_text(yaml.safe_dump(prior))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/validate_kong_runtime_mode.py"),
        "--compose", str(current_path), "--rollback-compose", str(prior_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "runtime apply unauthorized" in result.stdout
    assert yaml.safe_load(prior_path.read_text()) == prior


@pytest.mark.parametrize("damage", ["mutable-image", "admin", "apply", "standalone", "cache"])
def test_rollback_configuration_cannot_bypass_runtime_authority(tmp_path, damage):
    current = profile()
    prior = deepcopy(current)
    service = prior["services"]["kong-dp-1"]
    if damage == "mutable-image":
        for item in prior["services"].values():
            item["image"] = "kong/kong-gateway:latest"
    elif damage == "admin":
        service["environment"]["KONG_ADMIN_LISTEN"] = "0.0.0.0:8001"
    elif damage == "apply":
        service["environment"]["CODESTRA_RUNTIME_APPLY_AUTHORIZED"] = "true"
    elif damage == "standalone":
        service["environment"]["KONG_ROLE"] = "traditional"
    else:
        prior["volumes"]["dp1_prefix"]["external"] = False
    current_path = tmp_path / "current.yaml"
    prior_path = tmp_path / "rollback.yaml"
    current_path.write_text(yaml.safe_dump(current))
    prior_path.write_text(yaml.safe_dump(prior))
    result = subprocess.run([sys.executable, str(ROOT / "scripts/validate_kong_runtime_mode.py"),
        "--compose", str(current_path), "--rollback-compose", str(prior_path)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "FAIL" in result.stderr and "Traceback" not in result.stderr


def test_readiness_ignores_liveness_until_config_is_ready():
    class Status(BaseHTTPRequestHandler):
        ready = False
        def do_GET(self):
            self.send_response(200 if self.path == "/status" or self.ready else 503)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Status)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        command = profile()["services"]["kong-dp-1"]["healthcheck"]["test"][1:]
        command[-1] = f"http://127.0.0.1:{server.server_port}/status"
        assert subprocess.run(command, capture_output=True).returncode == 0
        command[-1] += "/ready"
        assert subprocess.run(command, capture_output=True).returncode != 0
        Status.ready = True
        assert subprocess.run(command, capture_output=True).returncode == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_readiness_probe_times_out_when_status_dependency_stalls():
    # Local TCP accepts but never responds. The real configured curl must time out.
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        command = profile()["services"]["kong-dp-1"]["healthcheck"]["test"][1:]
        command[-1] = f"http://127.0.0.1:{server.getsockname()[1]}/status/ready"
        result = subprocess.run(command, capture_output=True, timeout=5)
        assert result.returncode == 28
    result = subprocess.run(command, capture_output=True, timeout=5)
    assert result.returncode != 0


def test_readiness_cannot_be_forged_by_an_inherited_http_proxy():
    import os
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass
    proxy = HTTPServer(("127.0.0.1", 0), Proxy)
    thread = Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.socket() as closed_port:
            closed_port.bind(("127.0.0.1", 0))
            port = closed_port.getsockname()[1]
        command = profile()["services"]["kong-dp-1"]["healthcheck"]["test"][1:]
        command[-1] = f"http://127.0.0.1:{port}/status/ready"
        result = subprocess.run(command, capture_output=True, timeout=5,
            env={"PATH": os.environ["PATH"], "http_proxy": f"http://127.0.0.1:{proxy.server_port}",
                 "no_proxy": "", "NO_PROXY": ""})
        assert result.returncode != 0
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join()
