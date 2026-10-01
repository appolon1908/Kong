"""Behavioral Lua tests; Redis is real, Kong/OpenResty PDK transport is a harness.

These tests do not certify a running Kong gateway or native request lifecycle.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from lupa import LuaRuntime
import pytest


ROOT = Path(__file__).resolve().parents[1] / "deploy/kong/plugins/codestra-resource-guard"


class RedisWire:
    """Minimal RESP transport to the test-only Redis Unix socket."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(2)
        self.sock.connect(str(path))
        self.stream = self.sock.makefile("rb")

    def command(self, *args):
        encoded = [str(arg).encode() for arg in args]
        self.sock.sendall(b"*%d\r\n" % len(encoded) + b"".join(
            b"$%d\r\n" % len(arg) + arg + b"\r\n" for arg in encoded))
        return self._read()

    def _read(self):
        line = self.stream.readline()
        if not line:
            raise OSError("Redis connection closed")
        kind, value = line[:1], line[1:-2]
        if kind == b"-":
            raise RuntimeError(value.decode())
        if kind == b"+":
            return value.decode()
        if kind == b":":
            return int(value)
        if kind == b"$":
            length = int(value)
            if length == -1:
                return None
            result = self.stream.read(length)
            assert self.stream.read(2) == b"\r\n"
            return result.decode()
        if kind == b"*":
            return [self._read() for _ in range(int(value))]
        raise AssertionError(f"unexpected Redis response: {line!r}")

    def close(self):
        self.stream.close()
        self.sock.close()


@pytest.fixture
def redis_server():
    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip("isolated Redis behavioral tests require redis-server")
    with tempfile.TemporaryDirectory(prefix="kong-guard-") as directory:
        path = Path(directory) / "redis.sock"
        process = subprocess.Popen([binary, "--port", "0", "--unixsocket", str(path),
            "--unixsocketperm", "700", "--save", "", "--appendonly", "no",
            "--maxmemory-policy", "noeviction"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if path.exists():
                    break
                assert process.poll() is None, "isolated Redis exited during startup"
                time.sleep(0.01)
            assert path.exists(), "isolated Redis socket never became ready"
            # Contention assertions intentionally exercise one fixed minute.
            # Keep a real clock boundary from splitting an otherwise fast test.
            wire = RedisWire(path)
            seconds, microseconds = map(int, wire.command("TIME"))
            wire.close()
            remaining = 60 - seconds % 60 - microseconds / 1_000_000
            if remaining < 3:
                time.sleep(remaining + 0.01)
            yield path
        finally:
            process.terminate()
            process.wait(timeout=5)


class Gateway:
    def __init__(self, redis_path=None):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.redis_path = redis_path
        self.connection = None
        self.lua.globals().redis_connect = self.connect
        self.lua.globals().redis_command = self.command
        self.lua.globals().redis_close = self.close
        self.lua.execute('''
          state = {now = 1800000000}
          package.preload["resty.redis"] = function()
            local function command(self, name, ...)
              if state.raise_command == name then error("injected transport exception") end
              if state.fail_command == name then return nil, "injected transport failure" end
              return redis_command(name, ...)
            end
            return {new = function()
              return {
                set_timeout = function(self, timeout) state.timeout = timeout end,
                connect = function(self, host, port)
                  if state.fail_command == "connect" then return nil, "unavailable" end
                  return redis_connect(host, port)
                end,
                auth = function(self, ...) return command(self, "AUTH", ...) end,
                select = function(self, ...) return command(self, "SELECT", ...) end,
                eval = function(self, ...) return command(self, "EVAL", ...) end,
                close = function() return redis_close() end,
                set_keepalive = function() return redis_close() end
              }
            end}
          end
          ngx = {time = function() return state.now end, arg = {"", false}}
          kong = {
            ctx = {plugin = {}, shared = {}},
            response = {
              exit = function(code, body, headers)
                state.status = code; state.error = body.error; state.source = "exit"
                for name, value in pairs(headers or {}) do state.headers[name] = value end
                return code
              end,
              get_status = function() return state.status end,
              get_source = function() return state.source end,
              set_header = function(name, value) state.headers[name] = value end,
              clear_header = function(name) state.headers[name] = nil end,
              set_raw_body = function(body) ngx.arg[1] = body; ngx.arg[2] = true end
            }
          }
        ''')
        source = ROOT / "handler.lua"
        assert source.exists(), "resource guard must implement the bounded runtime contract"
        self.plugin = self.lua.execute(source.read_text())
        self.conf = self.lua.table_from({"route_key": "route-a", "concurrency_limit_per_worker": 2,
            "tenant_quota_per_minute": 0, "redis": {"host": "isolated-redis", "port": 6379,
                "timeout": 1000, "database": 0}}, recursive=True)

    @property
    def state(self):
        return self.lua.globals().state

    def connect(self, host, port):
        assert host == "isolated-redis" and port == 6379
        if self.redis_path is None:
            raise AssertionError("Redis must not be touched when tenant quota is disabled")
        self.close()
        self.connection = RedisWire(self.redis_path)
        return True

    def command(self, name, *args):
        try:
            result = self.connection.command(name, *args)
            if isinstance(result, list):
                result = self.lua.table_from(result, recursive=True)
            return result
        except (OSError, RuntimeError) as error:
            return None, str(error)

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        return True

    def access(self, tenant=None):
        context = self.lua.table_from({"plugin": {}, "shared": {}}, recursive=True)
        if tenant is not None:
            context.shared.codestra_authenticated_tenant = tenant
        self.lua.globals().kong.ctx = context
        self.state.status = None
        self.state.error = None
        self.state.source = None
        self.state.headers = self.lua.table()
        self.plugin.access(self.plugin, self.conf)
        return context

    def finish(self, context):
        self.lua.globals().kong.ctx = context
        self.plugin.log(self.plugin, self.conf)


def test_concurrency_blocks_excess_until_log_even_after_a_long_request():
    gateway = Gateway()
    first = gateway.access()
    second = gateway.access()
    gateway.state.now += 86400
    rejected = gateway.access()
    assert (gateway.state.status, gateway.state.error) == (429, "concurrency_limit_exceeded")
    assert gateway.state.headers["Retry-After"] == "1"
    gateway.finish(rejected)
    gateway.access()
    assert gateway.state.status == 429
    gateway.finish(first)
    gateway.access()
    assert gateway.state.status is None
    gateway.finish(first)  # A duplicate log call must not release somebody else's slot.
    gateway.access()
    assert gateway.state.status == 429
    gateway.finish(second)


def test_concurrency_is_per_route_per_worker_and_config_changes_keep_inflight_count():
    gateway = Gateway()
    gateway.conf.concurrency_limit_per_worker = 1
    context = gateway.access()
    gateway.conf.route_key = "route-b"
    gateway.access()
    assert gateway.state.status is None
    gateway.conf.route_key = "route-a"
    gateway.access()
    assert gateway.state.status == 429
    other_worker = Gateway()
    other_worker.conf.concurrency_limit_per_worker = 1
    other_worker.access()
    assert other_worker.state.status is None
    gateway.finish(context)
    gateway.access()
    assert gateway.state.status is None


def test_concurrency_releases_on_timeout_abort_or_later_plugin_denial():
    gateway = Gateway()
    gateway.conf.concurrency_limit_per_worker = 1
    for code in (200, 401, 413, 499, 502, 503, 504):
        context = gateway.access()
        assert gateway.state.status is None
        gateway.state.status = code
        gateway.finish(context)


def test_tenant_quota_never_accepts_caller_headers_as_identity():
    gateway = Gateway()
    gateway.conf.tenant_quota_per_minute = 1
    gateway.lua.execute('kong.request = {get_header = function() return "forged-tenant" end}')
    gateway.access()
    assert (gateway.state.status, gateway.state.error) == (403, "authenticated_tenant_required")


@pytest.mark.parametrize("tenant", ["", "bad\r\ntenant", "x" * 129, 123])
def test_invalid_authenticated_tenant_is_denied(tenant):
    gateway = Gateway()
    gateway.conf.tenant_quota_per_minute = 1
    gateway.access(tenant)
    assert gateway.state.status == 403


def test_real_redis_quota_is_shared_between_workers_and_isolates_tenants_and_routes(redis_server):
    first, second = Gateway(redis_server), Gateway(redis_server)
    for gateway in (first, second):
        gateway.conf.tenant_quota_per_minute = 2
    first.finish(first.access("tenant-a"))
    second.finish(second.access("tenant-a"))
    first.access("tenant-a")
    assert (first.state.status, first.state.error) == (429, "tenant_quota_exceeded")
    assert 1 <= int(first.state.headers["Retry-After"]) <= 60
    first.finish(first.access("tenant-b"))
    assert first.state.status is None
    first.conf.route_key = "route-b"
    first.finish(first.access("tenant-a"))
    assert first.state.status is None


def test_real_redis_quota_is_atomic_under_contending_workers(redis_server):
    def request(_):
        gateway = Gateway(redis_server)
        gateway.conf.tenant_quota_per_minute = 7
        context = gateway.access("concurrent-tenant")
        status = gateway.state.status
        gateway.finish(context)
        return status

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(request, range(32)))
    assert results.count(None) == 7
    assert results.count(429) == 25


@pytest.mark.parametrize("failure", ["connect", "SELECT", "EVAL"])
def test_counter_failures_deny_and_release_concurrency_without_leaking_details(redis_server, failure):
    gateway = Gateway(redis_server)
    gateway.conf.concurrency_limit_per_worker = 1
    gateway.conf.tenant_quota_per_minute = 1
    gateway.state.fail_command = failure
    gateway.access("tenant-a")
    assert (gateway.state.status, gateway.state.error) == (503, "resource_counter_unavailable")
    gateway.state.fail_command = None
    gateway.access("tenant-a")
    assert gateway.state.status is None


def test_transport_exception_is_fail_closed_and_releases_slot(redis_server):
    gateway = Gateway(redis_server)
    gateway.conf.concurrency_limit_per_worker = 1
    gateway.conf.tenant_quota_per_minute = 1
    gateway.state.raise_command = "EVAL"
    gateway.access("tenant-a")
    assert gateway.state.status == 503
    gateway.state.raise_command = None
    gateway.access("tenant-a")
    assert gateway.state.status is None


def test_real_redis_eviction_policy_and_oom_are_fail_closed(redis_server):
    gateway = Gateway(redis_server)
    gateway.conf.tenant_quota_per_minute = 1
    wire = RedisWire(redis_server)
    try:
        wire.command("CONFIG", "SET", "maxmemory-policy", "allkeys-lru")
        gateway.access("tenant-a")
        assert gateway.state.status == 503
        wire.command("CONFIG", "SET", "maxmemory-policy", "noeviction")
        wire.command("CONFIG", "SET", "maxmemory", "1")
        gateway.access("tenant-a")
        assert gateway.state.status == 503
    finally:
        wire.close()


def test_real_redis_wrong_password_fails_closed(redis_server):
    gateway = Gateway(redis_server)
    gateway.conf.redis.password = "synthetic-wrong-password"
    gateway.conf.tenant_quota_per_minute = 1
    gateway.access("tenant-a")
    assert gateway.state.status == 503


@pytest.mark.parametrize("damage", ["missing-window", "missing-count", "negative-count",
    "fractional-count", "bad-window", "future-window"])
def test_real_redis_corrupt_or_future_counter_does_not_reset_and_admit(redis_server, damage):
    gateway = Gateway(redis_server)
    gateway.conf.tenant_quota_per_minute = 1
    context = gateway.access("tenant-a")
    assert gateway.state.status is None
    gateway.finish(context)
    wire = RedisWire(redis_server)
    try:
        key, = wire.command("KEYS", "codestra:resource-quota:*")
        if damage.startswith("missing-"):
            wire.command("HDEL", key, damage.removeprefix("missing-"))
        elif damage == "negative-count":
            wire.command("HSET", key, "count", -1)
        elif damage == "fractional-count":
            wire.command("HSET", key, "count", 0.5)
        elif damage == "bad-window":
            wire.command("HSET", key, "window", "invalid")
        else:
            window = int(wire.command("HGET", key, "window"))
            wire.command("HSET", key, "window", window + 1)
        gateway.access("tenant-a")
        assert (gateway.state.status, gateway.state.error) == (503, "resource_counter_unavailable")
    finally:
        wire.close()


def test_real_redis_clock_controls_window_and_old_windows_reset_with_bounded_ttl(redis_server):
    gateway = Gateway(redis_server)
    gateway.conf.tenant_quota_per_minute = 1
    gateway.finish(gateway.access("tenant-a"))
    gateway.state.now += 3600
    gateway.access("tenant-a")
    assert gateway.state.status == 429  # A node's clock cannot reset global quota.
    wire = RedisWire(redis_server)
    try:
        key, = wire.command("KEYS", "codestra:resource-quota:*")
        window = int(wire.command("HGET", key, "window"))
        wire.command("HSET", key, "window", window - 1)
        gateway.access("tenant-a")
        assert gateway.state.status is None
        assert wire.command("HGET", key, "count") == "1"
        assert 0 < wire.command("TTL", key) <= 120
    finally:
        wire.close()


def test_real_redis_acl_without_counter_privileges_denies(redis_server):
    wire = RedisWire(redis_server)
    try:
        wire.command("ACL", "SETUSER", "default", "-info")
        gateway = Gateway(redis_server)
        gateway.conf.tenant_quota_per_minute = 1
        gateway.access("tenant-a")
        assert gateway.state.status == 503
    finally:
        wire.close()


@pytest.mark.parametrize("status,error", [(502, "upstream_unavailable"),
    (503, "upstream_unavailable"), (504, "upstream_timeout")])
def test_kong_transport_errors_have_one_stable_json_body_without_stale_length(status, error):
    gateway = Gateway()
    gateway.access()
    gateway.state.status, gateway.state.source = status, "error"
    gateway.state.headers["Content-Length"] = "9999"
    gateway.state.headers["Content-Encoding"] = "gzip"
    gateway.plugin.header_filter(gateway.plugin, gateway.conf)
    assert gateway.state.status == status
    assert gateway.state.headers["Content-Type"] == "application/json; charset=utf-8"
    assert gateway.state.headers["Content-Length"] is None
    assert gateway.state.headers["Content-Encoding"] is None
    chunks = []
    for chunk, eof in [("<html>internal detail", False), ("more detail</html>", True)]:
        gateway.lua.globals().ngx.arg = gateway.lua.table_from([chunk, eof])
        gateway.plugin.body_filter(gateway.plugin, gateway.conf)
        chunks.append(gateway.lua.globals().ngx.arg[1] or "")
    assert json.loads("".join(chunks)) == {"error": error}


@pytest.mark.parametrize("source,status", [("service", 502), ("service", 503),
    ("service", 504), ("exit", 503), ("error", 500), ("service", 200)])
def test_transport_normalization_preserves_upstream_and_plugin_responses(source, status):
    gateway = Gateway()
    gateway.access()
    gateway.state.source, gateway.state.status = source, status
    gateway.state.headers["Content-Type"] = "application/problem+json"
    gateway.state.headers["Content-Length"] = "20"
    gateway.plugin.header_filter(gateway.plugin, gateway.conf)
    gateway.lua.globals().ngx.arg = gateway.lua.table_from(["application response", True])
    gateway.plugin.body_filter(gateway.plugin, gateway.conf)
    assert gateway.lua.globals().ngx.arg[1] == "application response"
    assert gateway.state.headers["Content-Type"] == "application/problem+json"
    assert gateway.state.headers["Content-Length"] == "20"


def test_schema_requires_redis_only_for_enabled_tenant_quota():
    lua = LuaRuntime(unpack_returned_tuples=True)
    source = ROOT / "schema.lua"
    assert source.exists(), "resource guard schema is required"
    schema = lua.execute(source.read_text())
    config = next(row.config for row in schema.fields.values() if row.config is not None)
    assert config.custom_validator(lua.table_from({"tenant_quota_per_minute": 0})) is True
    result = config.custom_validator(lua.table_from({"tenant_quota_per_minute": 1}))
    assert result[0] is None or result[0] is False
    assert config.custom_validator(lua.table_from({"tenant_quota_per_minute": 1,
        "redis": {"host": "isolated-redis"}}, recursive=True)) is True
    # Kong materializes record defaults, so a route without a quota still
    # carries a host-less redis record; a field-level required host rejects it.
    redis_fields = next(row.redis for row in config.fields.values() if row.redis is not None).fields
    host = next(row.host for row in redis_fields.values() if row.host is not None)
    assert host.required is None
    defaulted = {"port": 6379, "timeout": 1000, "database": 0}
    assert config.custom_validator(lua.table_from({"tenant_quota_per_minute": 0,
        "redis": defaulted}, recursive=True)) is True
    result = config.custom_validator(lua.table_from({"tenant_quota_per_minute": 1,
        "redis": defaulted}, recursive=True))
    assert result[0] is None or result[0] is False
