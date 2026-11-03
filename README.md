# Codestra Kong Gateway

This repository is the source authority for Codestra's Kong Gateway configuration,
exact public route and plugin contracts, private standby design, PostgreSQL
operations and recovery, monitoring, reconciliation tooling, and Kong-specific
tests.

## Architecture boundary

```text
Public client
  -> host Caddy (public TLS edge)
  -> Docker upstream-gateway
  -> private Kong proxy
  -> private application services
```

Kong proxy, Kong Admin API, middleware ports, Redis, and PostgreSQL must not be
published to the public Internet. Host Caddy remains outside Docker.

## Repository layout

- `deploy/kong/` — route, service, plugin, and scope-policy authority, plus the
  node configuration required to run them: `kong.conf.example`,
  `compose.kong.yaml`, `runtime.env.example`.
- `deploy/kong-production-standby/` — private standby topology and auth middleware.
- `config/` — canonical route and route-security manifests.
- `scripts/` — dry-run reconciliation, export, validation, standby, and rollback.
- `operations/kong-database/` — PostgreSQL roles, HBA, TLS, backup, PITR, HA,
  monitoring, approvals, and systemd units.
- `operations/runbooks/` — bounded production activation and rollback procedures.
- `operations/community-n8n/` — proposed fail-closed HTTPS and Docker egress enforcement for the community n8n boundary.
- `tests/` — standalone route and database authority tests.
- `reports/` — Kong-specific historical evidence retained for traceability.

## Node runtime requirements

`deploy/kong/control-plane.yml` is not self-sufficient. Four node settings are
load-bearing; without them the gateway rejects or mishandles every request. They
are specified in `deploy/kong/kong.conf.example` and applied by
`deploy/kong/compose.kong.yaml`.

| Setting | Why it is required |
| --- | --- |
| `trusted_ips` | The scope policy calls `kong.request.get_forwarded_scheme()` and rejects non-https with `426`. Kong only honours `X-Forwarded-Proto` from a trusted peer, so with this unset every request over the Caddy -> Kong loopback hop is refused. Must be the exact Caddy source range, never `0.0.0.0/0`. |
| `untrusted_lua_sandbox_requires = cjson.safe` | The scope policy and every route claim guard decode the verified token with `cjson.safe`. The Lua sandbox does not expose it by default. Keep `untrusted_lua = sandbox`; `untrusted_lua = on` disables sandboxing for every serverless function on the node and is not an acceptable substitute. |
| `vaults = env` | The gateway secret and the rate-limit Redis password are `{vault://env/...}` references. Unresolved, the policy exits `503 gateway_identity_unavailable`. |
| `license_path` | `openid-connect` is a licensed plugin. It is absent from Kong OSS and does not load on `kong/kong-gateway` in free mode, so the declarative config is rejected at load. |

The scope policy is attached as `post-function`, never `pre-function`.
`pre-function` has plugin priority 1000000 and runs before every authentication
plugin, so a policy placed there observes no verified credential and no claims.

All canonical service and route renderers use the `redis` policy so one counter
is shared by every data-plane node, with `fault_tolerant` false so an unreachable
Redis fails closed. Kong and `codestra-redis` must share the external
`codestra_backend` network before a candidate can pass runtime preflight.

## Activation boundary

Reconciliation is dry-run by default. Live Admin API mutation, database cutover,
DNS promotion, fencing, deployment, or traffic activation requires a separate
reviewed change, exact-head approval, recovery evidence, and an active maintenance
window.

## Governance Git hooks

Enable the shared pre-push checks from your approved workstation using the [hook setup and lease instructions](docs/governance-git-hooks.md). Activation is explicit for each clone; existing CI and publication requirements still apply.
