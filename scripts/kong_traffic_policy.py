"""Traffic authority shared by the existing compilers; never an apply grant.

Concurrency is explicitly per worker; IP rate/burst and optional verified-tenant
quotas use shared Redis across gateway nodes.
"""
import hashlib


def traffic_policy(route, upstream):
    selected = route.get("trafficPolicy", {})
    return {
        "ratePerMinute": route["ratePerMinute"],
        "burstPerSecond": selected.get("burstPerSecond", min(10, route["ratePerMinute"])),
        "maxConcurrentPerWorker": selected.get("maxConcurrentPerWorker", 32),
        "tenantQuotaPerMinute": selected.get("tenantQuotaPerMinute", 0),
        "concurrencyScope": "worker", "tenantQuotaScope": "shared-redis",
        "maxBodyBytes": route["maxBodyBytes"], "timeouts": dict(upstream["timeouts"]),
        "retries": upstream["retries"],
        "unsafeRetriesExplicitlyAuthorized": route.get("retrySafe", False),
    }


def resource_guard(route_key, policy, redis=None):
    if len(route_key) > 128:
        route_key = "route-" + hashlib.sha256(route_key.encode()).hexdigest()
    result = {"route_key": route_key,
        "concurrency_limit_per_worker": policy["maxConcurrentPerWorker"],
        "tenant_quota_per_minute": policy["tenantQuotaPerMinute"]}
    if result["tenant_quota_per_minute"]:
        result["redis"] = dict(redis)
    return {"name": "codestra-resource-guard", "config": result}


def passive_health():
    return {"type": "http", "healthy": {"successes": 2}, "unhealthy": {
        "http_statuses": [500, 502, 503, 504], "http_failures": 3,
        "tcp_failures": 2, "timeouts": 2}}


def middleware_policy():
    return traffic_policy({"ratePerMinute": 120, "maxBodyBytes": 2 * 1024 * 1024}, {
        "timeouts": {"connectMs": 5000, "readMs": 30000, "writeMs": 30000}, "retries": 0})
