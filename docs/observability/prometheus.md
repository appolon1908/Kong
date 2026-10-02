# Kong Prometheus contract

Kong owns metric collection and the private Status API listener. `appolon1908/Codestra-Prometheus` owns scraping, target labels, recording rules, alerts, and retention.

## Metric collection

`deploy/kong/control-plane.yml` contains one global `prometheus` plugin. The production profile enables status-code, latency, bandwidth, and upstream-health metrics. Consumer-level and AI metrics stay disabled to prevent tenant leakage and uncontrolled cardinality.

## Private listener

The runtime must load `deploy/kong/observability.env.example` through its secret-free environment rendering process and attach Kong to the external Docker network `codestra-observability` with alias `kong`.

Prometheus scrapes `http://kong:8100/metrics`. Port 8100 must not have a host `ports:` mapping, public firewall rule, Caddy route, Kong proxy route, or Internet DNS record. The Admin API remains a separate protected management surface and is not the Prometheus target.

## Required labels

Prometheus adds: `environment`, `server`, `application=gateway`, `service=kong`, and `tenant_scope=aggregate`. The central authority drops consumer, workspace, request, trace, raw path, URL, query, and identity labels.

## Validation

```bash
python3 -m pytest -q tests/test_kong_observability.py
/tmp/deck file validate deploy/kong/control-plane.yml
python3 tools/generate_migration_manifests.py --check
python3 tools/verify_migration_manifest.py
```

## Activation evidence

Before deployment, prove the global plugin is present exactly once; Status API port 8100 is reachable only from `codestra-observability`; `/metrics` returns Kong node, request, latency, bandwidth, and upstream-health series; no consumer or AI labels are emitted; Prometheus reports the target UP with required labels; and a rollback restores the prior immutable Kong configuration without opening the Admin API.

This repository change does not call the Kong Admin API, reconcile routes, reload Kong, or alter live traffic.
