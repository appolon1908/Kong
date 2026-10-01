"""Frozen apply authority and reconciliation failure recovery regressions."""
import copy
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import kong_reconciliation_executor as runtime
from kong_reconciliation_api import ReconciliationAPI, Handler
from test_kong_desired_state_executor import FakeAdapter, INVENTORY, MANIFEST, executor, live_state


def test_environment_cannot_enable_frozen_apply_or_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("CODESTRA_KONG_RECONCILIATION_APPLY_ENABLED", "true")
    exe = runtime.DesiredStateExecutor(FakeAdapter(), runtime.ExecutionStore(tmp_path), MANIFEST, INVENTORY)
    with pytest.raises(PermissionError, match="disabled"):
        exe.apply(idempotency_key="frozen", correlation_id="c", expected_hash=exe.desired_hash)
    with pytest.raises(PermissionError, match="disabled"):
        exe.rollback("unknown")


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
def test_native_adapter_has_independent_frozen_mutation_gate(monkeypatch, method):
    def unexpected_transport(*args, **kwargs):
        pytest.fail("frozen runtime must not reach mutation transport")
    monkeypatch.setattr(runtime, "admin_request", unexpected_transport)
    with pytest.raises(PermissionError, match="disabled"):
        runtime.KongAdminAdapter()._request(method, "/routes", {})


def test_native_adapter_cannot_be_activated_by_explicit_simulation_flag(tmp_path, monkeypatch):
    def unexpected_transport(*args, **kwargs):
        pytest.fail("disabled executor must not reach native transport")
    monkeypatch.setattr(runtime, "admin_request", unexpected_transport)
    exe = runtime.load_default_executor(ROOT, store_root=tmp_path, apply_enabled=True)
    with pytest.raises(PermissionError, match="disabled"):
        exe.apply(idempotency_key="frozen", correlation_id="c", expected_hash=exe.desired_hash)
    status, payload = ReconciliationAPI(exe).handle("POST", "/platform/v1/kong/reconciliation/rollback",
        {}, b'{"execution_id":"unknown"}')
    assert status == 403
    assert payload["error"]["code"] == "APPLY_DISABLED"


def test_disabled_executor_does_not_replay_previous_success(tmp_path):
    exe = executor(tmp_path, enabled=True)
    result = exe.apply(idempotency_key="once", correlation_id="c", expected_hash=exe.desired_hash)
    before = exe.adapter.snapshot()
    exe.apply_enabled = False
    with pytest.raises(PermissionError, match="disabled"):
        exe.rollback(result["id"])
    assert exe.adapter.snapshot() == before


def test_semantic_snapshot_preserves_config_order_ids_and_relationship_bindings():
    state = {"services": [{"id": "s1", "name": "first"}, {"id": "s2", "name": "second"}],
        "routes": [{"id": "r1", "name": "first-route", "service": {"id": "s1"}},
                   {"id": "r2", "name": "second-route", "service": {"id": "s2"}}],
        "plugins": [{"id": "p1", "name": "openid-connect", "route": {"id": "r1"},
                     "config": {"id": "policy-1", "consumer_claim": ["realm", "client"]}}]}
    normalized = runtime.semantic_snapshot(state)
    for mutate in (
        lambda s: s["plugins"][0]["config"]["consumer_claim"].reverse(),
        lambda s: s["plugins"][0]["config"].update(id="policy-2"),
        lambda s: s["plugins"][0]["route"].update(id="r2"),
        lambda s: s["routes"][0]["service"].update(id="s2"),
    ):
        changed = copy.deepcopy(state)
        mutate(changed)
        assert runtime.semantic_snapshot(changed) != normalized
    reordered = copy.deepcopy(state)
    reordered["routes"].reverse()
    reordered["services"].reverse()
    assert runtime.semantic_snapshot(reordered) == normalized


@pytest.mark.parametrize("change", ["plugin_disable", "plugin_config", "route_binding", "extra_route"])
def test_readback_rejects_security_drift_even_when_upstream_matches(tmp_path, change):
    exe = executor(tmp_path, enabled=True)
    real_snapshot = exe.adapter.snapshot
    calls = 0
    def readback():
        nonlocal calls
        calls += 1
        result = real_snapshot()
        if calls == 2:
            plugin = next(p for p in result["plugins"] if any(
                r["id"] == p.get("route", {}).get("id") for r in result["routes"]))
            if change == "plugin_disable":
                plugin["enabled"] = False
            elif change == "plugin_config":
                plugin["config"] = {"skip_signature_validation": True}
            elif change == "route_binding":
                plugin["route"]["id"] = next(r["id"] for r in result["routes"]
                    if r["id"] != plugin["route"]["id"])
            else:
                result["routes"].append({"id": "unplanned", "name": "unplanned", "paths": ["/"]})
        return result
    exe.adapter.snapshot = readback
    result = exe.apply(idempotency_key=change, correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] != "SUCCEEDED"
    assert result["post_apply_verification"]["matches"] is False


def create_plan():
    return {"plan": [{"action": "CREATE", "route": "created", "desired": {
        "service": {"name": "created-service", "host": "middleware-integration-api", "port": 8095},
        "route": {"name": "created", "paths": ["/created"]},
        "plugins": [{"name": "key-auth", "config": {"key_names": ["X-API-Key"]}}],
    }}], "summary": {"CREATE": 1}}


@pytest.mark.parametrize("fail_path", ["/routes", "/plugins"])
@pytest.mark.parametrize("after_mutation", [False, True])
def test_partial_create_is_journaled_and_recovered_without_orphans(tmp_path, fail_path, after_mutation):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    original = exe.adapter.snapshot()
    real_create = exe.adapter.create
    failed = False
    def create(path, payload):
        nonlocal failed
        if path == fail_path and not failed:
            failed = True
            if after_mutation:
                real_create(path, payload)
            raise RuntimeError("transport response lost; password=do-not-persist")
        return real_create(path, payload)
    exe.adapter.create = create
    result = exe.apply(idempotency_key="create", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["operations"], "partial operation must survive for rollback"
    assert result["status"] == "ROLLED_BACK"
    assert runtime.semantic_snapshot(exe.adapter.snapshot()) == runtime.semantic_snapshot(original)
    assert "do-not-persist" not in json.dumps(exe.store.load(result["id"]))


def test_journal_records_mutation_intent_before_transport(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    real_create = exe.adapter.create
    def create(path, payload):
        records = list(exe.store.root.glob("*.json"))
        record = json.loads(records[0].read_text())
        assert record["operations"], "no mutation may precede its durable intent"
        return real_create(path, payload)
    exe.adapter.create = create
    result = exe.apply(idempotency_key="journal", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "SUCCEEDED"


def test_idempotency_key_cannot_replay_a_different_desired_state(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe.dry_run(idempotency_key="bound", correlation_id="c")
    exe.desired_hash = "f" * 64
    with pytest.raises(RuntimeError, match="idempotency"):
        exe.dry_run(idempotency_key="bound", correlation_id="c")


def test_api_does_not_expose_untrusted_exception_text():
    class Failing:
        def plan(self):
            raise RuntimeError("Authorization: Bearer do-not-expose")
    status, payload = ReconciliationAPI(Failing()).handle("GET", "/platform/v1/kong/reconciliation/plan", {}, b"")
    assert status == 409
    assert "do-not-expose" not in json.dumps(payload)


def test_api_rejects_invalid_utf8_and_unsafe_correlation_without_echo():
    class Unused:
        pass
    api = ReconciliationAPI(Unused())
    status, _ = api.handle("POST", "/invalid", {}, b"\xff")
    assert status == 400
    status, payload = api.handle("GET", "/invalid", {"x-correlation-id": "bad\r\nsecret"}, b"")
    assert status == 400
    assert "secret" not in json.dumps(payload)


def test_parallel_idempotent_requests_do_not_repeat_mutations(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    real_create = exe.adapter.create
    calls = []
    def create(path, payload):
        calls.append(path)
        time.sleep(0.01)
        return real_create(path, payload)
    exe.adapter.create = create
    start = threading.Barrier(4)
    def apply():
        start.wait(timeout=2)
        return exe.apply(idempotency_key="concurrent", correlation_id="c", expected_hash=exe.desired_hash)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: apply(), range(4)))
    assert len({result["id"] for result in results}) == 1
    assert calls.count("/services") == 1
    assert results[0]["status"] == "SUCCEEDED"


def test_rollback_does_not_overwrite_newer_upstream_changes(tmp_path):
    state = live_state()
    route = next(r for r in state["routes"] if r["name"] == "breero-production-api-route")
    service = next(s for s in state["services"] if s["id"] == route["service"]["id"])
    service["host"] = "old.internal"
    exe = executor(tmp_path, state=state, enabled=True)
    result = exe.apply(idempotency_key="apply", correlation_id="c", expected_hash=exe.desired_hash)
    target = next(s for s in exe.adapter.state["services"] if s["id"] == service["id"])
    target["host"] = "newer-review.internal"
    rolled = exe.rollback(result["id"])
    assert rolled["status"] == "ROLLBACK_FAILED"
    assert target["host"] == "newer-review.internal"


def test_retry_failed_rollback_recovers_once_without_duplicate_routes(tmp_path):
    exe = executor(tmp_path, enabled=True)
    result = exe.apply(idempotency_key="retry", correlation_id="c", expected_hash=exe.desired_hash)
    original_create = exe.adapter.create
    failed = False
    def create(path, payload):
        nonlocal failed
        value = original_create(path, payload)
        if path == "/routes" and not failed:
            failed = True
            raise RuntimeError("response lost")
        return value
    exe.adapter.create = create
    assert exe.rollback(result["id"])["status"] == "ROLLBACK_FAILED"
    assert exe.rollback(result["id"])["status"] == "ROLLED_BACK"
    assert len(exe.adapter.state["routes"]) == len(live_state()["routes"])


def test_dry_run_record_cannot_be_reported_as_successful_rollback(tmp_path):
    exe = executor(tmp_path, enabled=True)
    result = exe.dry_run(idempotency_key="dry", correlation_id="c")
    with pytest.raises(RuntimeError, match="execution"):
        exe.rollback(result["id"])
    assert exe.store.load(result["id"])["status"] == "DRY_RUN"


def test_sanitized_journal_covers_private_keys_header_arrays_and_api_keys(tmp_path):
    store = runtime.ExecutionStore(tmp_path)
    store.save({"id": "safe", "config": {"key": "do-not-persist", "api-key": "do-not-persist",
        "rsa_private_key": "do-not-persist", "headers": ["Authorization: Bearer do-not-persist",
        "X-Codestra-Gateway-Secret:do-not-persist", "X-API-Key: do-not-persist",
        "X-Correlation-ID: safe"]}})
    saved = store.load("safe")
    assert "do-not-persist" not in json.dumps(saved)
    assert "X-Correlation-ID: safe" in saved["config"]["headers"]


def test_canonical_port_does_not_authorize_arbitrary_provider_host(tmp_path):
    exe = executor(tmp_path, enabled=True)
    with pytest.raises(RuntimeError, match="host"):
        exe._validate_upstream("provider-control.example", 8095)


def test_successful_create_response_cannot_hide_changed_security_policy(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    real_create = exe.adapter.create
    def create(path, payload):
        if path == "/plugins":
            payload = dict(payload, config={"key_names": ["Untrusted-Key"]})
        return real_create(path, payload)
    exe.adapter.create = create
    result = exe.apply(idempotency_key="tampered", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] != "SUCCEEDED"
    assert runtime.semantic_snapshot(exe.adapter.snapshot()) == runtime.semantic_snapshot(live_state())


def test_api_sanitizes_successful_adapter_results():
    class Sensitive:
        def plan(self):
            return {"config": {"password": "do-not-expose", "add": {"headers": [
                "X-Codestra-Gateway-Secret: do-not-expose", "X-API-Key:do-not-expose"]}}}
    status, result = ReconciliationAPI(Sensitive()).handle("GET", "/platform/v1/kong/reconciliation/plan", {}, b"")
    assert status == 200
    assert "do-not-expose" not in json.dumps(result)


def test_rollback_preserves_newer_protocol_setting(tmp_path):
    state = live_state()
    route = next(r for r in state["routes"] if r["name"] == "breero-production-api-route")
    service = next(s for s in state["services"] if s["id"] == route["service"]["id"])
    service["host"] = "old.internal"
    exe = executor(tmp_path, state=state, enabled=True)
    result = exe.apply(idempotency_key="new-protocol", correlation_id="c", expected_hash=exe.desired_hash)
    changed = next(s for s in exe.adapter.state["services"] if s["id"] == service["id"])
    changed["protocol"] = "https"
    assert exe.rollback(result["id"])["status"] == "ROLLBACK_FAILED"
    assert changed["protocol"] == "https"


def test_create_rollback_preserves_newer_owned_entity_configuration(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    result = exe.apply(idempotency_key="created-newer", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "SUCCEEDED"
    route = next(r for r in exe.adapter.state["routes"] if r["name"] == "created")
    route["paths"] = ["/newer-reviewed-route"]
    newer = exe.adapter.snapshot()
    assert exe.rollback(result["id"])["status"] == "ROLLBACK_FAILED"
    assert exe.adapter.snapshot() == newer


def test_create_rollback_preserves_newer_plugin_attachment(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    result = exe.apply(idempotency_key="new-attachment", correlation_id="c", expected_hash=exe.desired_hash)
    route = next(r for r in exe.adapter.state["routes"] if r["name"] == "created")
    exe.adapter.state["plugins"].append({"id": "newer-plugin", "name": "acl", "route": {"id": route["id"]}})
    newer = exe.adapter.snapshot()
    assert exe.rollback(result["id"])["status"] == "ROLLBACK_FAILED"
    assert exe.adapter.snapshot() == newer


def test_uncertain_create_with_unobserved_server_defaults_requires_review(tmp_path):
    exe = executor(tmp_path, enabled=True)
    exe._plan_from_snapshot = lambda snapshot: create_plan()
    real_create = exe.adapter.create
    def create(path, payload):
        if path == "/services":
            real_create(path, dict(payload, protocol="http", retries=0))
            raise RuntimeError("response lost after server defaults applied")
        return real_create(path, payload)
    exe.adapter.create = create
    result = exe.apply(idempotency_key="unobserved-defaults", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "ROLLBACK_FAILED"
    assert result["operations"][0]["status"] == "PENDING"
    assert any(row["name"] == "created-service" for row in exe.adapter.state["services"])


def test_adapter_propagates_explicit_private_node_selection(monkeypatch):
    selected = []
    def read(method, path, payload, **kwargs):
        selected.append((method, path, kwargs))
        return {"data": []}
    monkeypatch.setattr(runtime, "admin_request", read)
    config = runtime.AdapterConfig(container="codestra-gateway-traditional-kong-management-1",
        traditional_approval="KONG:reviewed-fallback")
    adapter = runtime.KongAdminAdapter(config)
    adapter.get("/routes")
    assert selected[0][2]["container"] == config.container
    assert selected[0][2]["traditional_approval"] == "KONG:reviewed-fallback"
    with pytest.raises(PermissionError):
        adapter.create("/routes", {})


def test_desired_hash_binds_inventory_and_retains_frozen_authority(tmp_path):
    supplied = copy.deepcopy(INVENTORY)
    first = runtime.DesiredStateExecutor(FakeAdapter(), runtime.ExecutionStore(tmp_path / "first"),
        MANIFEST, supplied)
    row = next(row for row in supplied["routes"] if row["name"] == "breero-production-api-route")
    row["paths"] = ["/entirely-different"]
    second = runtime.DesiredStateExecutor(FakeAdapter(), runtime.ExecutionStore(tmp_path / "second"),
        MANIFEST, supplied)
    assert first.desired_hash != second.desired_hash
    assert first.authority_routes[row["name"]]["paths"] == ["/health", "/api/v1"]


@pytest.mark.parametrize("length", ["-1", "invalid", "16385"])
def test_http_handler_rejects_bad_lengths_without_reading_body(length):
    class Headers(dict):
        def get_all(self, name):
            return [self[name]] if name in self else None
    class Unreadable:
        def read(self, size):
            pytest.fail("invalid framing must be rejected before reading the body")
    handler = Handler.__new__(Handler)
    handler.headers = Headers({"Content-Length": length})
    handler.rfile = Unreadable()
    handler.wfile = BytesIO()
    handler.command = "POST"
    handler.path = "/platform/v1/kong/reconciliation/dry-run"
    handler.send_response = lambda status: setattr(handler, "status", status)
    handler.send_header = lambda *args: None
    handler.end_headers = lambda: None
    handler.api = ReconciliationAPI(object())
    handler._run()
    assert handler.status in {400, 413}
