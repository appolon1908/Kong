import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_reconciliation_executor import DesiredStateExecutor, ExecutionStore, semantic_snapshot

MANIFEST = json.loads((ROOT / "config/kong-route-reconciliation.pas236.json").read_text())
INVENTORY = json.loads((ROOT / "config/kong-production-route-inventory.v2.json").read_text())


def live_state():
    authority = {row["name"]: row for row in INVENTORY["routes"] if row.get("name")}
    services, routes, plugins = [], [], []
    for idx, spec in enumerate(MANIFEST["routes"], start=1):
        sid = f"service-{idx}"
        rid = f"route-{idx}"
        if spec["decision"] == "REPOINT":
            upstream = spec["target"]
        elif spec["decision"] == "EXCEPTION":
            upstream = spec["expected"]
        else:
            upstream = {"host": "legacy-upstream", "port": 9000}
        governed = authority.get(spec["name"], {})
        service = copy.deepcopy(governed.get("service", {"name": f"svc-{idx}", "protocol": "http"}))
        existing = next((row for row in services if row["name"] == service["name"]), None)
        if existing is None:
            service.update(id=sid, host=upstream["host"], port=upstream["port"])
            services.append(service)
        else:
            sid = existing["id"]
        route = {key: copy.deepcopy(value) for key, value in governed.items() if key not in {"service", "plugins"}}
        route.update(id=rid, name=spec["name"], service={"id": sid})
        routes.append(route)
        for pidx, name in enumerate(authority.get(spec["name"], {}).get("plugins") or [], start=1):
            plugins.append({
                "id": f"plugin-{idx}-{pidx}",
                "name": name,
                "enabled": True,
                "route": {"id": rid},
            })
    return {
        "services": services,
        "routes": routes,
        "plugins": plugins,
        "upstreams": [],
        "consumers": [],
    }


class FakeAdapter:
    def __init__(self, state=None):
        self.state = copy.deepcopy(state or live_state())
        self.fail_next = False
        self.force_mismatch = False

    def snapshot(self):
        value = copy.deepcopy(self.state)
        if self.force_mismatch and value["routes"]:
            sid = value["routes"][0]["service"]["id"]
            for service in value["services"]:
                if service["id"] == sid:
                    service["host"] = "mismatch.invalid"
        return value

    def update(self, path, payload):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected failure")
        collection, ident = path.strip("/").split("/", 1)
        rows = self.state[collection]
        row = next(r for r in rows if r["id"] == ident)
        row.update(copy.deepcopy(payload))
        return copy.deepcopy(row)

    def create(self, path, payload):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected failure")
        collection = path.strip("/")
        row = copy.deepcopy(payload)
        row.setdefault("id", f"{collection}-{len(self.state[collection]) + 1000}")
        self.state[collection].append(row)
        return copy.deepcopy(row)

    def delete(self, path):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("injected failure")
        collection, ident = path.strip("/").split("/", 1)
        before = len(self.state[collection])
        self.state[collection] = [r for r in self.state[collection] if r["id"] != ident]
        if len(self.state[collection]) == before:
            raise RuntimeError("not found")
        if collection == "routes":
            # Kong's plugins.route foreign key has on_delete='cascade'. A
            # retained orphan would now correctly fail full-state readback.
            self.state["plugins"] = [p for p in self.state["plugins"]
                if (p.get("route") or {}).get("id") != ident]


def executor(tmp_path, *, state=None, enabled=False):
    return DesiredStateExecutor(
        FakeAdapter(state),
        ExecutionStore(tmp_path / "journal"),
        copy.deepcopy(MANIFEST),
        copy.deepcopy(INVENTORY),
        apply_enabled=enabled,
    )


def test_plan_preserves_private_standby_and_legacy_n8n_aliases(tmp_path):
    exe = executor(tmp_path)
    plan = exe.plan()
    by_name = {row["route"]: row for row in plan["plan"]}
    for name in (
        "codestra-sms-standby-route",
        "codestra-sms-webhook-standby-route",
        "codestra-email-standby-route",
        "codestra-email-webhook-standby-route",
    ):
        assert by_name[name]["action"] == "KEEP"
        assert by_name[name]["expected"]["port"] == 8080
    for name in ("codestra-n8n-command-submit", "codestra-n8n-command-read"):
        assert by_name[name]["action"] == "KEEP"
        assert by_name[name]["target"] == {"host": "middleware-integration-api", "port": 8095}


def test_apply_disabled_by_default(tmp_path):
    exe = executor(tmp_path, enabled=False)
    with pytest.raises(PermissionError, match="disabled"):
        exe.apply(idempotency_key="k1", correlation_id="c1", expected_hash=exe.desired_hash)


def test_desired_hash_must_match(tmp_path):
    exe = executor(tmp_path, enabled=True)
    with pytest.raises(RuntimeError, match="hash mismatch"):
        exe.apply(idempotency_key="k1", correlation_id="c1", expected_hash="0" * 64)


def test_apply_update_delete_and_exact_readback(tmp_path):
    state = live_state()
    target_route = next(r for r in state["routes"] if r["name"] == "breero-production-api-route")
    service = next(s for s in state["services"] if s["id"] == target_route["service"]["id"])
    service["host"], service["port"] = "old.internal", 9000
    exe = executor(tmp_path, state=state, enabled=True)
    result = exe.apply(idempotency_key="apply-1", correlation_id="corr-1", expected_hash=exe.desired_hash)
    assert result["status"] == "SUCCEEDED"
    assert any(op["action"] == "UPDATE" for op in result["operations"])
    assert sum(op["action"] == "DELETE" for op in result["operations"]) == 4
    assert result["post_apply_verification"]["matches"] is True
    names = {r["name"] for r in exe.adapter.state["routes"]}
    assert "cod-web-out-email-production" not in names
    current = next(s for s in exe.adapter.state["services"] if s["id"] == service["id"])
    assert (current["host"], current["port"]) == ("middleware-integration-api", 8095)


def test_duplicate_apply_is_idempotent(tmp_path):
    exe = executor(tmp_path, enabled=True)
    first = exe.apply(idempotency_key="same", correlation_id="c1", expected_hash=exe.desired_hash)
    second = exe.apply(idempotency_key="same", correlation_id="c2", expected_hash=exe.desired_hash)
    assert first["id"] == second["id"]
    assert second["correlation_id"] == "c1"


def test_reused_apply_key_with_changed_desired_state_is_rejected(tmp_path):
    first = executor(tmp_path, enabled=True)
    applied = first.apply(idempotency_key="reused", correlation_id="c1", expected_hash=first.desired_hash)
    assert applied["status"] == "SUCCEEDED"
    changed_manifest = copy.deepcopy(MANIFEST)
    changed_manifest["reviewRevision"] = "desired-state-changed"
    second = DesiredStateExecutor(FakeAdapter(first.adapter.state), ExecutionStore(tmp_path / "journal"),
                                  changed_manifest, copy.deepcopy(INVENTORY), apply_enabled=True)
    assert second.desired_hash != first.desired_hash
    with pytest.raises(RuntimeError, match="idempotency desired-state mismatch"):
        second.apply(idempotency_key="reused", correlation_id="c2", expected_hash=second.desired_hash)


def test_dry_run_and_apply_keys_are_scoped_by_operation(tmp_path):
    exe = executor(tmp_path, enabled=True)
    dry = exe.dry_run(idempotency_key="same", correlation_id="dry")
    applied = exe.apply(idempotency_key="same", correlation_id="apply", expected_hash=exe.desired_hash)
    assert dry["id"] != applied["id"]


def test_plan_error_prevents_mutation(tmp_path):
    state = live_state()
    state["routes"] = [r for r in state["routes"] if r["name"] != "codestra-communication-canonical-write"]
    exe = executor(tmp_path, state=state, enabled=True)
    result = exe.apply(idempotency_key="bad-plan", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "FAILED"
    assert result["failure"]["code"] == "PLAN_NOT_EXECUTABLE"
    assert result["operations"] == []


def test_partial_failure_automatically_rolls_back(tmp_path):
    state = live_state()
    target_route = next(r for r in state["routes"] if r["name"] == "breero-production-api-route")
    service = next(s for s in state["services"] if s["id"] == target_route["service"]["id"])
    service["host"], service["port"] = "old.internal", 9000
    exe = executor(tmp_path, state=state, enabled=True)
    original = exe.adapter.snapshot()
    calls = {"n": 0}
    real_delete = exe.adapter.delete

    def fail_second_delete(path):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("injected delete failure")
        return real_delete(path)

    exe.adapter.delete = fail_second_delete
    result = exe.apply(idempotency_key="partial", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "ROLLED_BACK"
    assert result["rollback"]["automatic"] is True
    assert semantic_snapshot(exe.adapter.snapshot()) == semantic_snapshot(original)


def test_rollback_failure_is_persisted_fail_closed(tmp_path):
    exe = executor(tmp_path, enabled=True)
    result = exe.apply(idempotency_key="ok", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] == "SUCCEEDED"
    exe.adapter.fail_next = True
    rolled = exe.rollback(result["id"])
    assert rolled["status"] == "ROLLBACK_FAILED"
    assert rolled["rollback"]["status"] == "FAILED"


def test_readback_mismatch_triggers_rollback(tmp_path):
    exe = executor(tmp_path, enabled=True)
    real_snapshot = exe.adapter.snapshot
    count = {"n": 0}

    def snapshot():
        count["n"] += 1
        value = real_snapshot()
        if count["n"] >= 2 and value["routes"]:
            sid = value["routes"][0]["service"]["id"]
            next(s for s in value["services"] if s["id"] == sid)["host"] = "mismatch.invalid"
        return value

    exe.adapter.snapshot = snapshot
    result = exe.apply(idempotency_key="mismatch", correlation_id="c", expected_hash=exe.desired_hash)
    assert result["status"] in {"ROLLED_BACK", "ROLLBACK_FAILED"}


def test_forbidden_legacy_direct_upstream_rejected(tmp_path):
    exe = executor(tmp_path, enabled=True)
    with pytest.raises(RuntimeError, match="forbidden"):
        exe._validate_upstream("provider", 8080)
    with pytest.raises(RuntimeError, match="forbidden"):
        exe._validate_upstream("provider", 8096)


def test_create_requires_governed_payload_and_8095(tmp_path):
    exe = executor(tmp_path, enabled=True)
    with pytest.raises(RuntimeError, match="desired payload"):
        exe._execute_item({"action": "CREATE", "route": "x"}, exe.adapter.snapshot(), "e")
    op = exe._execute_item(
        {
            "action": "CREATE",
            "route": "x",
            "desired": {
                "service": {"name": "svc-x", "host": "middleware-integration-api", "port": 8095},
                "route": {"name": "x", "paths": ["/x"]},
                "plugins": [],
            },
        },
        exe.adapter.snapshot(),
        "e",
    )
    assert op["action"] == "CREATE"
    assert any(r["name"] == "x" for r in exe.adapter.state["routes"])


def test_evidence_redacts_secret_fields(tmp_path):
    exe = executor(tmp_path, enabled=False)
    record = exe.dry_run(idempotency_key="evidence", correlation_id="c")
    evidence = exe.evidence(record["id"])
    text = json.dumps(evidence)
    assert "evidence" not in text
    assert evidence["desired_state_sha256"] == exe.desired_hash
