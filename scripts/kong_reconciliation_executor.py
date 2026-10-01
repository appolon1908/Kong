#!/usr/bin/env python3
"""PAS-152 desired-state execution, readback, rollback and journal core.

Source activation remains frozen. The native adapter is read-only, regardless
of environment flags. Explicit dependency-injected adapters can exercise the
execution core in isolated simulations; they confer no runtime authority.
"""
from __future__ import annotations

import hashlib
import copy
import json
import os
import re
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kong_admin_channel import (
    DEFAULT_CONTAINER,
    PRIVATE_ADMIN_URL,
    AdminError,
    admin_request,
    collect_admin_rows,
    http_admin_request,
    normalize_admin_reference,
)
from plan_kong_route_reconciliation import build_plan, validate_manifest

CANONICAL_JSON = dict(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
MUTATIONS = {"CREATE", "UPDATE", "DELETE"}
TERMINAL = {"SUCCEEDED", "ROLLED_BACK", "ROLLBACK_FAILED", "FAILED"}
ALLOWED_UPSTREAM_PORTS = {8095}
FORBIDDEN_UPSTREAM_PORTS = {8080, 8096}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, **CANONICAL_JSON).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _contains_desired(actual, desired):
    """Server defaults may add fields; supplied security values must match."""
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and _contains_desired(actual[key], value)
                                               for key, value in desired.items())
    return actual == desired


VOLATILE_RUNTIME_FIELDS = {"id", "created_at", "updated_at", "ws_id", "cache_key"}


def _entity_fingerprint(entity):
    return sha256_json({key: value for key, value in entity.items() if key not in VOLATILE_RUNTIME_FIELDS})


def semantic_snapshot(value: Any) -> Any:
    """Ignore entity ordering/timestamps, retaining configuration and bindings.

    Only collection rows have volatile IDs. Foreign keys resolve to stable
    entity names; unknown references and every nested config ID are retained.
    Ordered plugin arrays must never be normalized as sets.
    """
    if not isinstance(value, dict):
        return copy.deepcopy(value)
    collections = {"services", "routes", "plugins", "upstreams", "consumers"}
    identities = {}
    for collection in collections:
        identities[collection] = {
            row["id"]: row.get("name") or row.get("username") or row.get("custom_id")
            for row in value.get(collection, [])
            if isinstance(row, dict) and row.get("id")
            and (row.get("name") or row.get("username") or row.get("custom_id"))
        }
    references = {"service": "services", "route": "routes", "consumer": "consumers",
                  "upstream": "upstreams"}
    result = copy.deepcopy(value)
    for collection in collections:
        if collection not in result:
            continue
        rows = []
        for original in result[collection]:
            row = {key: item for key, item in original.items() if key not in VOLATILE_RUNTIME_FIELDS}
            for key, target in references.items():
                reference = row.get(key)
                if isinstance(reference, dict) and reference.get("id") in identities[target]:
                    row[key] = {"entity_name": identities[target][reference["id"]]}
            rows.append(row)
        result[collection] = sorted(rows, key=canonical_json)
    return result


def _sensitive_name(name):
    lower = str(name).lower().replace("-", "_")
    return lower in {"key", "pem"} or any(token in lower for token in (
        "password", "secret", "token", "authorization", "apikey", "api_key", "private_key", "credential", "cookie"
    ))


def sanitize(value: Any) -> Any:
    """Remove fields whose names can contain credentials before persistence/API."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _sensitive_name(key):
                out[key] = "[REDACTED]"
            else:
                out[key] = sanitize(item)
        return out
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        header = value.partition(":")
        if (header[1] and _sensitive_name(header[0].strip())) or "PRIVATE KEY-----" in value:
            return "[REDACTED]"
    return value


@dataclass(frozen=True)
class AdapterConfig:
    base_url: str = PRIVATE_ADMIN_URL
    auth_ref: str = "local-docker-admin-channel"
    timeout_seconds: float = 10.0
    read_retries: int = 2
    container: str = DEFAULT_CONTAINER
    traditional_approval: str | None = None


class KongAdminAdapter:
    """Single bounded Admin API adapter. Mutations are never transport-retried."""

    def __init__(self, config: AdapterConfig | None = None):
        self.config = config or AdapterConfig()
        if not self.config.base_url:
            raise ValueError("Kong Admin base URL is required")
        if not self.config.auth_ref:
            raise ValueError("Kong Admin authentication reference is required")
        if self.config.timeout_seconds <= 0 or self.config.read_retries < 0:
            raise ValueError("invalid Admin API timeout/retry configuration")

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | None:
        if method != "GET":
            raise PermissionError("runtime apply disabled")
        attempts = self.config.read_retries + 1 if method == "GET" else 1
        last: Exception | None = None
        for index in range(attempts):
            try:
                if self.config.base_url == PRIVATE_ADMIN_URL:
                    return admin_request(
                        method,
                        normalize_admin_reference(path),
                        payload,
                        container=self.config.container,
                        traditional_approval=self.config.traditional_approval,
                        payload_encoding="json",
                    )
                return http_admin_request(
                    self.config.base_url,
                    method,
                    path,
                    payload,
                    payload_encoding="json",
                    timeout=self.config.timeout_seconds,
                )
            except AdminError as exc:
                last = exc
                if method != "GET" or index + 1 >= attempts:
                    break
                time.sleep(min(0.25 * (index + 1), 0.75))
        raise RuntimeError(f"Kong Admin {method} failed") from last

    def get(self, path: str) -> dict:
        return self._request("GET", path) or {}

    def create(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, payload) or {}

    def update(self, path: str, payload: dict) -> dict:
        return self._request("PATCH", path, payload) or {}

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    def rows(self, path: str) -> list[dict]:
        return collect_admin_rows(
            lambda ref: self.get(ref),
            path,
            normalize_admin_reference,
        )

    def snapshot(self) -> dict:
        return {
            "services": self.rows("/services?size=1000"),
            "routes": self.rows("/routes?size=1000"),
            "plugins": self.rows("/plugins?size=1000"),
            "upstreams": self.rows("/upstreams?size=1000"),
            "consumers": self.rows("/consumers?size=1000"),
        }


class ExecutionStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._thread_lock = threading.RLock()
        self._lock_depth = 0
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass

    @contextmanager
    def locked(self):
        """Serialize idempotency lookup and execution across local API workers."""
        import fcntl
        with self._thread_lock:
            if self._lock_depth:
                self._lock_depth += 1
                try:
                    yield
                finally:
                    self._lock_depth -= 1
                return
            fd = os.open(self.root / ".execution.lock", os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._lock_depth = 1
                yield
            finally:
                self._lock_depth = 0
                os.close(fd)

    def _path(self, execution_id: str) -> Path:
        if not SAFE_ID.fullmatch(execution_id):
            raise ValueError("invalid execution id")
        return self.root / f"{execution_id}.json"

    def save(self, record: dict) -> None:
        record = sanitize(record)
        target = self._path(record["id"])
        fd, name = tempfile.mkstemp(prefix=".execution-", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(name, 0o600)
            os.replace(name, target)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def load(self, execution_id: str) -> dict:
        return json.loads(self._path(execution_id).read_text(encoding="utf-8"))

    def find_idempotency(self, key: str, mode: str) -> dict | None:
        digest = hashlib.sha256(f"{mode}\0{key}".encode()).hexdigest()
        for path in self.root.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if value.get("idempotency_digest") == digest:
                return value
        return None


class DesiredStateExecutor:
    def __init__(
        self,
        adapter: KongAdminAdapter,
        store: ExecutionStore,
        manifest: dict,
        inventory: dict,
        *,
        apply_enabled: bool | None = None,
    ):
        validate_manifest(manifest)
        self.adapter = adapter
        self.store = store
        self.manifest = copy.deepcopy(manifest)
        self.inventory = copy.deepcopy(inventory)
        # Explicit enablement is for injected simulation adapters only. Neither
        # an environment variable nor a constructor flag opens the native API.
        self.apply_enabled = apply_enabled is True and not isinstance(adapter, KongAdminAdapter)
        self.desired_hash = sha256_json({"manifest": self.manifest, "inventory": self.inventory})
        self.authority_routes = {
            row["name"]: row for row in self.inventory.get("routes", [])
            if isinstance(row.get("name"), str)
        }
        self.blocked_routes = {
            row["route"] for row in self.inventory.get("activationBlockedRoutes", [])
            if isinstance(row.get("route"), str) and row.get("activationAuthorized") is False
        }

    def _plan_from_snapshot(self, snapshot: dict) -> dict:
        return build_plan(
            self.manifest,
            snapshot["routes"],
            snapshot["services"],
            snapshot["plugins"],
            self.authority_routes,
            self.blocked_routes,
        )

    def plan(self) -> dict:
        snapshot = self.adapter.snapshot()
        result = self._plan_from_snapshot(snapshot)
        result["desired_state_sha256"] = self.desired_hash
        return result

    def dry_run(self, *, idempotency_key: str, correlation_id: str) -> dict:
        return self._start(
            mode="DRY_RUN",
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            execute=False,
        )

    def apply(self, *, idempotency_key: str, correlation_id: str, expected_hash: str) -> dict:
        if not self.apply_enabled:
            raise PermissionError("runtime apply disabled")
        if expected_hash != self.desired_hash:
            raise RuntimeError("desired-state hash mismatch")
        return self._start(
            mode="APPLY",
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            execute=True,
        )

    def _start(self, *, mode: str, idempotency_key: str, correlation_id: str, execute: bool) -> dict:
        with self.store.locked():
            return self._start_locked(mode=mode, idempotency_key=idempotency_key,
                                      correlation_id=correlation_id, execute=execute)

    def _start_locked(self, *, mode: str, idempotency_key: str, correlation_id: str, execute: bool) -> dict:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValueError("valid Idempotency-Key required")
        if not correlation_id or len(correlation_id) > 200:
            raise ValueError("valid correlation id required")
        prior = self.store.find_idempotency(idempotency_key, mode)
        if prior is not None:
            if prior.get("desired_state_sha256") != self.desired_hash:
                raise RuntimeError("idempotency desired-state mismatch")
            return prior

        snapshot = self.adapter.snapshot()
        plan = self._plan_from_snapshot(snapshot)
        execution_id = str(uuid.uuid4())
        record = {
            "id": execution_id,
            "schema": "codestra.kong.reconciliation-execution.v1",
            "mode": mode,
            "status": "DRY_RUN" if not execute else "RUNNING",
            "correlation_id": correlation_id,
            "idempotency_digest": hashlib.sha256(f"{mode}\0{idempotency_key}".encode()).hexdigest(),
            "desired_state_sha256": self.desired_hash,
            "created_at_unix": int(time.time()),
            "plan": plan,
            "pre_apply_snapshot": sanitize(snapshot),
            "pre_apply_semantic_sha256": sha256_json(semantic_snapshot(snapshot)),
            "operations": [],
            "rollback": None,
        }
        self.store.save(record)
        if not execute:
            return record
        errors = [item for item in plan["plan"] if item["action"] == "ERROR"]
        if errors:
            record["status"] = "FAILED"
            record["failure"] = {"code": "PLAN_NOT_EXECUTABLE", "count": len(errors)}
            self.store.save(record)
            return record

        try:
            for item in plan["plan"]:
                if item["action"] in MUTATIONS:
                    self._execute_item(item, snapshot, execution_id, record=record)
            readback = self.adapter.snapshot()
            verification = self._verify_readback(plan, readback, before=snapshot, operations=record["operations"])
            record["post_apply_readback"] = sanitize(readback)
            record["post_apply_verification"] = verification
            if not verification["matches"]:
                raise RuntimeError("post-apply readback mismatch")
            record["status"] = "SUCCEEDED"
            self.store.save(record)
            return record
        except Exception:
            record["status"] = "FAILED"
            record["failure"] = {"code": "APPLY_FAILED", "message": "mutation or readback failed"}
            self.store.save(record)
            self.rollback(execution_id, automatic=True)
            return self.store.load(execution_id)

    def _verify_readback(self, original_plan: dict, snapshot: dict, *, before=None, operations=()) -> dict:
        routes = {r.get("name"): r for r in snapshot["routes"] if r.get("name")}
        services = {s.get("id"): s for s in snapshot["services"] if s.get("id")}
        mismatches = []
        for item in original_plan["plan"]:
            action = item["action"]
            route = routes.get(item["route"])
            if action == "DELETE":
                if route is not None:
                    mismatches.append({"route": item["route"], "reason": "delete_not_applied"})
                continue
            if action in {"KEEP", "UPDATE"}:
                if route is None:
                    mismatches.append({"route": item["route"], "reason": "route_missing"})
                    continue
                current = services.get((route.get("service") or {}).get("id"), {})
                expected = item.get("target") or item.get("expected")
                if expected and (current.get("host"), current.get("port")) != (
                    expected.get("host"), expected.get("port")
                ):
                    mismatches.append({"route": item["route"], "reason": "upstream_mismatch"})
            elif action == "CREATE":
                if route is None:
                    mismatches.append({"route": item["route"], "reason": "create_missing"})
            elif action == "ERROR":
                mismatches.append({"route": item["route"], "reason": "plan_error"})
        if before is None:
            mismatches.append({"reason": "pre_apply_snapshot_required"})
        else:
            expected = copy.deepcopy(before)
            for operation in operations:
                if operation["action"] == "UPDATE":
                    service_id = operation["before"]["service"]["id"]
                    service = next(row for row in expected["services"] if row["id"] == service_id)
                    service.update(operation["target"])
                elif operation["action"] == "DELETE":
                    route_id = operation["before"]["route"]["id"]
                    expected["routes"] = [row for row in expected["routes"] if row["id"] != route_id]
                    expected["plugins"] = [row for row in expected["plugins"]
                        if (row.get("route") or {}).get("id") != route_id]
                elif operation["action"] == "CREATE":
                    for key, collection in (("service", "services"), ("route", "routes")):
                        expected[collection].append(operation["after"][key])
                    expected["plugins"].extend(operation["after"]["plugins"])
            if semantic_snapshot(expected) != semantic_snapshot(snapshot):
                mismatches.append({"reason": "configuration_or_security_drift"})
        return {"matches": not mismatches, "mismatches": mismatches}

    def _execute_item(self, item: dict, snapshot: dict, execution_id: str, *, record=None) -> dict:
        if not self.apply_enabled:
            raise PermissionError("runtime apply disabled")
        operation = {"action": item["action"], "route": item["route"], "status": "PENDING"}
        def checkpoint():
            if record is not None:
                if not any(row is operation for row in record["operations"]):
                    record["operations"].append(operation)
                self.store.save(record)
        action = item["action"]
        route = next((r for r in snapshot["routes"] if r.get("name") == item["route"]), None)
        if action == "UPDATE":
            if route is None:
                raise RuntimeError("update route missing")
            service_id = (route.get("service") or {}).get("id")
            service = next((s for s in snapshot["services"] if s.get("id") == service_id), None)
            if service is None:
                raise RuntimeError("update service missing")
            target = item["target"]
            self._validate_upstream(target["host"], target["port"])
            shared = [
                r for r in snapshot["routes"]
                if (r.get("service") or {}).get("id") == service_id
            ]
            if len(shared) > 1:
                raise RuntimeError("shared service update requires isolated service")
            before = {"route": sanitize(route), "service": sanitize(service)}
            operation.update(before=before, target={"host": target["host"], "port": target["port"]})
            checkpoint()
            changed = self.adapter.update(
                f"/services/{service_id}",
                {"host": target["host"], "port": target["port"]},
            )
            operation.update(after=sanitize(changed), status="APPLIED")
            checkpoint()
            return operation
        if action == "DELETE":
            if route is None:
                raise RuntimeError("delete route missing")
            plugins = [
                p for p in snapshot["plugins"]
                if (p.get("route") or {}).get("id") == route.get("id")
            ]
            if sanitize(plugins) != plugins or sanitize(route) != route:
                raise RuntimeError("delete rollback would require persisted secret material")
            operation["before"] = {"route": sanitize(route), "plugins": sanitize(plugins)}
            checkpoint()
            self.adapter.delete(f"/routes/{route['id']}")
            operation["status"] = "APPLIED"
            checkpoint()
            return operation
        if action == "CREATE":
            desired = item.get("desired")
            if not isinstance(desired, dict):
                raise RuntimeError("create missing governed desired payload")
            service_payload = desired.get("service")
            route_payload = desired.get("route")
            plugins = desired.get("plugins", [])
            if not isinstance(service_payload, dict) or not isinstance(route_payload, dict):
                raise RuntimeError("create desired payload incomplete")
            self._validate_upstream(service_payload.get("host"), service_payload.get("port"))
            service_payload = dict(service_payload, id=str(uuid.uuid4()))
            route_payload = dict(route_payload, id=str(uuid.uuid4()), service={"id": service_payload["id"]})
            plugin_payloads = [dict(plugin, id=str(uuid.uuid4()), route={"id": route_payload["id"]})
                               for plugin in plugins]
            operation["after"] = {"service": copy.deepcopy(service_payload), "route": copy.deepcopy(route_payload),
                                  "plugins": copy.deepcopy(plugin_payloads)}
            operation["created_entity_sha256"] = {entity["id"]: _entity_fingerprint(entity)
                for entity in [service_payload, route_payload, *plugin_payloads]}
            # Preassigned entity IDs make uncertain responses discoverable;
            # intent is durable before any create, including every substep.
            checkpoint()
            service = self.adapter.create("/services", service_payload)
            if service.get("id") != service_payload["id"]:
                raise RuntimeError("created entity identity mismatch")
            operation["after"]["service"] = copy.deepcopy(service)
            operation["created_entity_sha256"][service["id"]] = _entity_fingerprint(service)
            checkpoint()
            if not _contains_desired(service, service_payload):
                raise RuntimeError("created service readback mismatch")
            route_created = self.adapter.create("/routes", route_payload)
            if route_created.get("id") != route_payload["id"]:
                raise RuntimeError("created entity identity mismatch")
            operation["after"]["route"] = copy.deepcopy(route_created)
            operation["created_entity_sha256"][route_created["id"]] = _entity_fingerprint(route_created)
            checkpoint()
            if not _contains_desired(route_created, route_payload):
                raise RuntimeError("created route readback mismatch")
            for index, payload in enumerate(plugin_payloads):
                created = self.adapter.create("/plugins", payload)
                if created.get("id") != payload["id"]:
                    raise RuntimeError("created entity identity mismatch")
                operation["after"]["plugins"][index] = copy.deepcopy(created)
                operation["created_entity_sha256"][created["id"]] = _entity_fingerprint(created)
                checkpoint()
                if not _contains_desired(created, payload):
                    raise RuntimeError("created plugin readback mismatch")
            operation["status"] = "APPLIED"
            checkpoint()
            return operation
        raise RuntimeError(f"unsupported mutation action: {action}")

    @staticmethod
    def _validate_upstream(host: Any, port: Any) -> None:
        if not isinstance(host, str) or not host:
            raise RuntimeError("invalid upstream host")
        if port in FORBIDDEN_UPSTREAM_PORTS:
            raise RuntimeError("forbidden direct/legacy upstream port")
        if port not in ALLOWED_UPSTREAM_PORTS:
            raise RuntimeError("upstream port is not allowlisted")
        if host != "middleware-integration-api":
            raise RuntimeError("upstream host is not allowlisted")

    def rollback(self, execution_id: str, *, automatic: bool = False) -> dict:
        if not self.apply_enabled:
            raise PermissionError("runtime apply disabled")
        with self.store.locked():
            return self._rollback_locked(execution_id, automatic=automatic)

    def _rollback_locked(self, execution_id: str, *, automatic: bool = False) -> dict:
        record = self.store.load(execution_id)
        if record.get("mode") != "APPLY" or not record.get("pre_apply_semantic_sha256"):
            raise RuntimeError("execution lacks verified rollback authority")
        if record.get("status") == "ROLLED_BACK":
            return record
        outcomes = []
        try:
            for operation in reversed(record.get("operations", [])):
                current = self.adapter.snapshot()
                action = operation["action"]
                if action == "UPDATE":
                    service = operation["before"]["service"]
                    actual = next((row for row in current["services"] if row.get("id") == service["id"]), None)
                    original = {"host": service["host"], "port": service["port"]}
                    if actual is None or {"host": actual.get("host"), "port": actual.get("port")} not in (
                        original, operation["target"]
                    ) or actual.get("protocol") != service.get("protocol"):
                        raise RuntimeError("rollback would overwrite newer configuration")
                    self.adapter.update(
                        f"/services/{service['id']}",
                        {
                            "host": service["host"],
                            "port": service["port"],
                            "protocol": service.get("protocol"),
                        },
                    )
                elif action == "DELETE":
                    route = operation["before"]["route"]
                    route_fields = {
                        "name", "protocols", "methods", "hosts", "paths", "headers",
                        "https_redirect_status_code", "regex_priority", "strip_path",
                        "path_handling", "preserve_host", "request_buffering",
                        "response_buffering", "snis", "sources", "destinations",
                        "tags", "service", "id",
                    }
                    route_payload = {
                        key: value for key, value in route.items()
                        if key in route_fields
                    }
                    existing = next((r for r in current["routes"] if r.get("id") == route["id"]), None)
                    if existing and _entity_fingerprint(existing) != _entity_fingerprint(route):
                        raise RuntimeError("rollback would overwrite newer route configuration")
                    created = existing or self.adapter.create("/routes", route_payload)
                    plugin_fields = {
                        "name", "config", "enabled", "protocols", "tags",
                        "ordering", "instance_name", "service", "consumer", "id",
                    }
                    for plugin in operation["before"].get("plugins", []):
                        value = {
                            key: item for key, item in plugin.items()
                            if key in plugin_fields
                        }
                        value["route"] = {"id": created["id"]}
                        if not any(p.get("id") == plugin.get("id") for p in current["plugins"]):
                            self.adapter.create("/plugins", value)
                elif action == "CREATE":
                    after = operation["after"]
                    route = after.get("route") or {}
                    service = after.get("service") or {}
                    fingerprints = operation.get("created_entity_sha256", {})
                    # Inspect every owned entity before any delete. Their UUIDs
                    # establish ownership, but do not authorize erasing edits
                    # made after this execution's observed configuration.
                    for collection in ("services", "routes", "plugins"):
                        for entity in current[collection]:
                            if entity.get("id") in fingerprints and _entity_fingerprint(entity) != fingerprints[entity["id"]]:
                                raise RuntimeError("rollback would delete newer configuration")
                    if any((r.get("service") or {}).get("id") == service.get("id")
                           and r.get("id") != route.get("id") for r in current["routes"]):
                        raise RuntimeError("rollback would affect newer route attachment")
                    if any(p.get("id") not in fingerprints and (
                        (p.get("route") or {}).get("id") == route.get("id")
                        or (p.get("service") or {}).get("id") == service.get("id")
                    ) for p in current["plugins"]):
                        raise RuntimeError("rollback would affect newer plugin attachment")
                    for plugin in after.get("plugins", []):
                        if any(p.get("id") == plugin.get("id") for p in current["plugins"]):
                            self.adapter.delete(f"/plugins/{plugin['id']}")
                    if any(r.get("id") == route.get("id") for r in current["routes"]):
                        self.adapter.delete(f"/routes/{route['id']}")
                    if any(s.get("id") == service.get("id") for s in current["services"]):
                        self.adapter.delete(f"/services/{service['id']}")
                outcomes.append({"route": operation["route"], "action": action, "status": "ROLLED_BACK"})
            readback = self.adapter.snapshot()
            expected_hash = record.get("pre_apply_semantic_sha256")
            actual_hash = sha256_json(semantic_snapshot(readback))
            if actual_hash != expected_hash:
                raise RuntimeError("rollback readback mismatch")
            record["status"] = "ROLLED_BACK"
            record["rollback"] = {
                "automatic": automatic,
                "status": "SUCCEEDED",
                "operations": outcomes,
                "readback_sha256": actual_hash,
            }
        except Exception:
            record["status"] = "ROLLBACK_FAILED"
            record["rollback"] = {
                "automatic": automatic,
                "status": "FAILED",
                "operations": outcomes,
                "error": "rollback mutation or readback failed",
            }
        self.store.save(record)
        return record

    def evidence(self, execution_id: str) -> dict:
        record = self.store.load(execution_id)
        return {
            "id": record["id"],
            "status": record["status"],
            "correlation_id": record["correlation_id"],
            "desired_state_sha256": record["desired_state_sha256"],
            "plan_summary": record["plan"].get("summary", {}),
            "operations": record.get("operations", []),
            "rollback": record.get("rollback"),
            "pre_apply_sha256": sha256_json(record["pre_apply_snapshot"]),
            "post_apply_sha256": (
                sha256_json(record["post_apply_readback"])
                if record.get("post_apply_readback") is not None else None
            ),
        }


def load_default_executor(
    root: Path,
    *,
    adapter: KongAdminAdapter | None = None,
    store_root: Path | None = None,
    apply_enabled: bool | None = None,
) -> DesiredStateExecutor:
    manifest = json.loads((root / "config/kong-route-reconciliation.pas236.json").read_text())
    inventory = json.loads((root / "config/kong-production-route-inventory.v2.json").read_text())
    return DesiredStateExecutor(
        adapter or KongAdminAdapter(),
        ExecutionStore(store_root or root / ".runtime/kong-reconciliation"),
        manifest,
        inventory,
        apply_enabled=apply_enabled,
    )
