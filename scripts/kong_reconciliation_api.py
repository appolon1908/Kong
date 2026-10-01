#!/usr/bin/env python3
"""Private loopback control API for PAS-152 Kong reconciliation."""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_reconciliation_executor import DEFAULT_CONTAINER, AdapterConfig, KongAdminAdapter, load_default_executor, sanitize

MAX_REQUEST_BYTES = 16 * 1024
EXECUTION_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")


class ReconciliationAPI:
    def __init__(self, executor):
        self.executor = executor

    @staticmethod
    def error(code: str, message: str, correlation_id: str, status: int) -> tuple[int, dict]:
        return status, {
            "error": {"code": code, "message": message},
            "correlation_id": correlation_id,
        }

    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict]:
        status, payload = self._handle(method, path, headers, body)
        return status, sanitize(payload)

    def _handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict]:
        correlation_id = headers.get("x-correlation-id") or str(uuid.uuid4())
        if not isinstance(correlation_id, str) or not EXECUTION_ID.fullmatch(correlation_id):
            return self.error("INVALID_REQUEST", "valid correlation id required", str(uuid.uuid4()), 400)
        try:
            payload = {}
            if body:
                if len(body) > MAX_REQUEST_BYTES:
                    return self.error("REQUEST_TOO_LARGE", "request body exceeds limit", correlation_id, 413)
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError("object body required")

            if method == "GET" and path == "/platform/v1/kong/reconciliation/plan":
                return 200, {"correlation_id": correlation_id, "result": self.executor.plan()}

            if method == "POST" and path == "/platform/v1/kong/reconciliation/dry-run":
                key = headers.get("idempotency-key", "")
                return 200, {
                    "correlation_id": correlation_id,
                    "result": self.executor.dry_run(idempotency_key=key, correlation_id=correlation_id),
                }

            if method == "POST" and path == "/platform/v1/kong/reconciliation/apply":
                key = headers.get("idempotency-key", "")
                expected = payload.get("desired_state_sha256", "")
                result = self.executor.apply(
                    idempotency_key=key,
                    correlation_id=correlation_id,
                    expected_hash=expected,
                )
                status = 200 if result.get("status") == "SUCCEEDED" else 409
                return status, {"correlation_id": correlation_id, "result": result}

            if method == "POST" and path == "/platform/v1/kong/reconciliation/rollback":
                execution_id = payload.get("execution_id", "")
                if not EXECUTION_ID.fullmatch(str(execution_id)):
                    raise ValueError("valid execution_id required")
                result = self.executor.rollback(str(execution_id))
                status = 200 if result.get("status") == "ROLLED_BACK" else 409
                return status, {"correlation_id": correlation_id, "result": result}

            prefix = "/platform/v1/kong/reconciliation/executions/"
            if method == "GET" and path.startswith(prefix):
                tail = path[len(prefix):]
                evidence = tail.endswith("/evidence")
                execution_id = tail[:-len("/evidence")] if evidence else tail
                if not EXECUTION_ID.fullmatch(execution_id) or "/" in execution_id:
                    return self.error("NOT_FOUND", "resource not found", correlation_id, 404)
                result = (
                    self.executor.evidence(execution_id)
                    if evidence else self.executor.store.load(execution_id)
                )
                return 200, {"correlation_id": correlation_id, "result": result}

            return self.error("NOT_FOUND", "resource not found", correlation_id, 404)
        except PermissionError:
            return self.error("APPLY_DISABLED", "runtime apply is disabled", correlation_id, 403)
        except FileNotFoundError:
            return self.error("EXECUTION_NOT_FOUND", "execution not found", correlation_id, 404)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.error("INVALID_JSON", "request body is not valid JSON", correlation_id, 400)
        except ValueError:
            return self.error("INVALID_REQUEST", "request validation failed", correlation_id, 400)
        except RuntimeError:
            return self.error("RECONCILIATION_REJECTED", "reconciliation rejected", correlation_id, 409)


class Handler(BaseHTTPRequestHandler):
    api: ReconciliationAPI
    server_version = "CodestraKongReconciliation/1"
    sys_version = ""

    def log_message(self, _format, *_args):
        # Do not place request bodies, auth material, or execution evidence in logs.
        return

    def _run(self):
        length = self.headers.get("Content-Length", "0")
        try:
            if (len(self.headers.get_all("Content-Length") or []) > 1
                    or self.headers.get("Transfer-Encoding")
                    or not re.fullmatch(r"[0-9]+", length)):
                raise ValueError("invalid request framing")
            n = int(length)
        except ValueError:
            self.close_connection = True
            self._send(*self.api.error("INVALID_REQUEST", "invalid request framing", str(uuid.uuid4()), 400))
            return
        if n > MAX_REQUEST_BYTES:
            self.close_connection = True
            self._send(*self.api.error("REQUEST_TOO_LARGE", "request body exceeds limit", str(uuid.uuid4()), 413))
            return
        body = self.rfile.read(n) if n else b""
        headers = {k.lower(): v for k, v in self.headers.items()}
        status, payload = self.api.handle(
            self.command,
            urlsplit(self.path).path,
            headers,
            body,
        )
        self._send(status, payload)

    def _send(self, status, payload):
        raw = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _run
    do_POST = _run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8181)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--container", default=DEFAULT_CONTAINER,
                        help="private Admin container; role and listeners are verified by the Admin channel")
    parser.add_argument("--traditional-approval", help="review reference required for the Traditional management node")
    args = parser.parse_args()
    if args.bind not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("reconciliation API must bind to loopback")
    root = Path(__file__).resolve().parents[1]
    executor = load_default_executor(root, store_root=args.state_dir,
        adapter=KongAdminAdapter(AdapterConfig(container=args.container, traditional_approval=args.traditional_approval)))
    Handler.api = ReconciliationAPI(executor)
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
