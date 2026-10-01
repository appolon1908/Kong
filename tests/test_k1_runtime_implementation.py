"""K1 source and startup gates; no production processes are started."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_kong_runtime_mode.py"

def validate(tmp_path, document, mode="hybrid", approval=None):
    path = tmp_path / "compose.yaml"
    path.write_text(yaml.safe_dump(document))
    command = [sys.executable, str(VALIDATOR), "--compose", str(path), "--mode", mode]
    if approval:
        command += ["--traditional-approval", approval]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)

def profile(mode="hybrid"):
    return yaml.safe_load((ROOT / f"deploy/gateway-platform/compose.{mode}.yaml").read_text())

def test_hybrid_profile_is_executable_validation_authority(tmp_path):
    result = validate(tmp_path, profile())
    assert result.returncode == 0, result.stdout + result.stderr

@pytest.mark.parametrize("damage", ["dbless", "admin", "cp-admin", "mtls", "ca",
    "ports", "host-network", "declarative", "dp-db", "cp-proxy", "readiness", "apply"])
def test_invalid_hybrid_profile_fails_closed(tmp_path, damage):
    doc = profile()
    dp = doc["services"]["kong-dp-1"]
    cp = doc["services"]["kong-cp"]
    env = dp["environment"]
    if damage == "dbless": env["KONG_ROLE"] = "traditional"
    elif damage == "admin": env["KONG_ADMIN_LISTEN"] = "0.0.0.0:8001"
    elif damage == "cp-admin": cp["environment"]["KONG_ADMIN_LISTEN"] = "0.0.0.0:8001"
    elif damage == "mtls": env["KONG_CLUSTER_MTLS"] = "shared"
    elif damage == "ca": env.pop("KONG_CLUSTER_CA_CERT")
    elif damage == "ports": cp["ports"] = ["8005:8005"]
    elif damage == "host-network": dp["network_mode"] = "host"
    elif damage == "declarative": env["KONG_DECLARATIVE_CONFIG"] = "/tmp/routes.yml"
    elif damage == "dp-db": env["KONG_PG_HOST"] = "db"
    elif damage == "cp-proxy": cp["environment"]["KONG_PROXY_LISTEN"] = "0.0.0.0:8000"
    elif damage == "readiness": dp["healthcheck"] = {"test": ["CMD", "kong", "health"]}
    elif damage == "apply": env["CODESTRA_RUNTIME_APPLY_AUTHORIZED"] = "true"
    result = validate(tmp_path, doc)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL" in result.stderr

def test_traditional_requires_explicit_approval(tmp_path):
    assert validate(tmp_path, profile("traditional"), "traditional").returncode == 1
    result = validate(tmp_path, profile("traditional"), "traditional", "KONG:K1-FALLBACK-123")
    assert result.returncode == 0, result.stderr

@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "10.0.0.1/8", "*", ""])
def test_invalid_proxy_trust_rejected(tmp_path, value):
    doc = profile()
    doc["services"]["kong-dp-1"]["environment"]["KONG_TRUSTED_IPS"] = value
    assert validate(tmp_path, doc).returncode == 1

def test_legacy_runtime_is_hybrid_data_plane_only():
    service = yaml.safe_load((ROOT / "deploy/kong/compose.kong.yaml").read_text())["services"]["kong-gateway"]
    env = service["environment"]
    assert env["KONG_ROLE"] == "data_plane"
    assert env["KONG_DATABASE"] == "off"
    assert env["KONG_ADMIN_LISTEN"] == "off"
    assert not any(k.startswith("KONG_PG_") for k in env)

def test_startup_cannot_bypass_apply_gate():
    entrypoint = ROOT / "deploy/gateway-platform/codestra-kong-entrypoint.sh"
    result = subprocess.run(["sh", str(entrypoint), "kong", "docker-start"],
        env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "runtime_apply_unauthorized" in result.stderr

def test_guard_mounted_on_every_runtime():
    for doc in (profile(), profile("traditional"),
                yaml.safe_load((ROOT / "deploy/kong/compose.kong.yaml").read_text())):
        for service in doc["services"].values():
            assert service["environment"]["CODESTRA_RUNTIME_APPLY_AUTHORIZED"] == "false"
            assert any(isinstance(v, dict) and v.get("target") == "/etc/codestra/runtime-guard.sh"
                       and v.get("read_only") is True for v in service["volumes"])
            assert "/status/ready" in str(service["healthcheck"]["test"])

@pytest.mark.parametrize("damage", ["guard-source", "guard-write", "entrypoint-source", "cluster-network",
                                    "dp-db-secret", "cp-key-reuse", "unknown-network"])
def test_profile_cannot_replace_guards_or_widen_cluster_authority(tmp_path, damage):
    doc = profile()
    dp = doc["services"]["kong-dp-1"]
    if damage == "guard-source":
        next(v for v in dp["volumes"] if isinstance(v, dict) and v.get("target") == "/etc/codestra/runtime-guard.sh")["source"] = "/tmp/bypass.sh"
    elif damage == "guard-write":
        next(v for v in dp["volumes"] if isinstance(v, dict) and v.get("target") == "/etc/codestra/runtime-guard.sh")["read_only"] = False
    elif damage == "entrypoint-source":
        next(v for v in dp["volumes"] if isinstance(v, dict) and v.get("target") == "/usr/local/bin/codestra-kong-entrypoint")["source"] = "/tmp/bypass.sh"
    elif damage == "cluster-network":
        doc["networks"]["kong_cluster"]["name"] = "public"
    elif damage == "dp-db-secret":
        dp["secrets"].append("kong_runtime_password")
    elif damage == "cp-key-reuse":
        dp["environment"]["KONG_CLUSTER_CERT_KEY"] = "/run/secrets/cp_key"
        dp["secrets"].append("cp_key")
    elif damage == "unknown-network":
        dp["networks"].append("public")
    result = validate(tmp_path, doc)
    assert result.returncode == 1, result.stdout + result.stderr

@pytest.mark.parametrize("environment", [{}, {"CODESTRA_RUNTIME_APPLY_AUTHORIZED": "true"},
    {"KONG_DATABASE": "off"}, {"KONG_PG_HOST": "unavailable.invalid"},
    {"KONG_CLUSTER_CONTROL_PLANE": "unavailable.invalid:8005"}])
def test_startup_denial_is_independent_of_env_and_dependencies(environment):
    result = subprocess.run(["sh", str(ROOT / "deploy/gateway-platform/runtime-guard.sh"), "kong", "docker-start"],
        env={"PATH": os.environ["PATH"], **environment}, capture_output=True, text=True)
    assert result.returncode == 78
    assert "runtime_apply_unauthorized" in result.stderr

def test_readiness_probe_rejects_dependency_unavailable():
    # Real HTTP and curl; synthetic Kong responses. This is not live Kong evidence.
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    class Status(BaseHTTPRequestHandler):
        ready = False
        def do_GET(self):
            self.send_response(200 if self.ready else 503)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Status)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        command = profile()["services"]["kong-dp-1"]["healthcheck"]["test"][1:]
        command[-1] = f"http://127.0.0.1:{server.server_port}/status/ready"
        assert subprocess.run(command, capture_output=True).returncode != 0
        Status.ready = True
        assert subprocess.run(command, capture_output=True).returncode == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

@pytest.mark.parametrize("damage", ["public-ca", "disable-readiness", "public-proxy-network", "null-services"])
def test_additional_review_regressions(tmp_path, damage):
    doc = profile()
    if damage == "public-ca":
        doc["secrets"]["cluster_ca"]["file"] = "/etc/ssl/certs/ca-certificates.crt"
    elif damage == "disable-readiness":
        doc["services"]["kong-dp-1"]["healthcheck"]["disable"] = True
    elif damage == "public-proxy-network":
        doc["networks"]["kong_proxy"]["name"] = "public_edge"
    elif damage == "null-services":
        doc["services"] = None
    result = validate(tmp_path, doc)
    assert result.returncode == 1
    assert "FAIL" in result.stderr
    assert "Traceback" not in result.stderr
