# Kong API Gateway Control Plane V1

Source authority for how Codestra's Kong gateway is allowed to route, protect
and operate API traffic. This is a **source baseline**: it authorizes no
runtime apply, and `runtimeApplyAuthorized` is `false` in every artifact it
governs.

```text
                    INTERNET
                        │
                        ▼
                 ┌─────────────┐   HOW does traffic enter securely?
                 │    CADDY    │   public TLS, hostnames, edge logging  (appolon1908/Caddy)
                 └──────┬──────┘
                        │ 127.0.0.1:8000, X-Forwarded-* trusted only from KONG_TRUSTED_IPS
                        ▼
              ┌───────────────────┐  WHICH route is reachable and which prerequisites apply?
              │       KONG        │  host/path/method → route identity → authentication class,
              │ API GATEWAY PLANE │  audience/scope guard → rate/body/correlation → approved upstream
              └─────────┬─────────┘
                        │ declared Middleware alias (middleware-integration-api:8095 canonical; 8096 control plane; 8080 retired)
                        ▼
                  MIDDLEWARE           MAY this identity execute this command on this resource?
              Command Control Plane    business authorization, idempotency ledger, providers/Odoo/n8n
```

Keycloak answers WHO (issuer per environment); Odoo holds WHAT (business
state); n8n decides WHEN (automation). Kong never blurs into any of them.

## Artifacts

| Artifact | Role |
| --- | --- |
| `config/kong-gateway-foundation.v1.json` | the registry: authorities, pipeline, environments, boundary rules, precedence, profiles, 20 sources, 34 services, 79 routes, 19 plugins, declared conflicts and drift |
| `scripts/validate_kong_foundation.py` | loads every registered source, materializes each route/service from its bindings and proves the registry, sources, node configuration and docs agree; `--write-docs` regenerates the tables |
| `tests/test_kong_foundation.py` | 58 tests: positive validation plus mutation tests for every forbidden pattern |
| [`docs/mission1-current-state-audit.md`](mission1-current-state-audit.md) | forensic audit, 30 findings with dispositions, defect log |
| [`docs/service-registry-v1.md`](service-registry-v1.md) | service metadata contract, upstream classes, Middleware aliases, health/load-balancing posture, environment separation, generated table |
| [`docs/route-registry-v1.md`](route-registry-v1.md) | pipeline, classification rules, API versioning, precedence, declared drift, generated table |
| [`docs/caddy-kong-boundary-v1.md`](caddy-kong-boundary-v1.md) | listener, network, trusted proxy, forwarded headers, correlation, TLS expectation, health |
| [`docs/kong-middleware-boundary-v1.md`](kong-middleware-boundary-v1.md) | what Kong may check, listener split, provider/application bypass audit, idempotency |
| [`docs/token-validation-boundary-v1.md`](token-validation-boundary-v1.md) | realms per environment, validation stages, audience and scope boundaries, fail-closed rules |
| [`docs/plugin-governance-v1.md`](plugin-governance-v1.md) | plugin registry rules, scope, ordering, generated table |
| [`docs/timeout-profiles-v1.md`](timeout-profiles-v1.md) · [`docs/retry-policy-v1.md`](retry-policy-v1.md) | transport policy profiles and failure/circuit behaviour |
| [`docs/admin-boundary-v1.md`](admin-boundary-v1.md) | Admin/Manager/Status isolation, networks, secrets, container least privilege, logging |

Mission 2 (identity, authentication and API access security) layers on this
foundation: `config/kong-access-policy.v1.json`,
`config/kong-authentication-profiles.v1.json`, `tests/test_kong_identity_security.py`
and the [audit](mission2-identity-security-audit.md), [Keycloak token contract](keycloak-kong-token-contract-v1.md),
[scope contract](gateway-scope-contract-v1.md), [service authentication contract](service-authentication-contract-v1.md),
[tenant/identity boundary](tenant-identity-boundary-v1.md) and [evidence matrix](mission2-evidence-matrix.md).

Existing authorities remain in force and are referenced, not duplicated:
`docs/CADDY_EDGE_AUTHORITY.md`, `docs/MIDDLEWARE_EDGE_CONTRACT.md`,
`docs/KONG_RELEASE_AND_ADMIN_BOUNDARIES.md`, `docs/KONG_RUNTIME_CERTIFICATION.md`,
`docs/observability/prometheus.md`, `SECURITY.md`.

## Invariants the validator enforces

1. **No undocumented route or service.** Every route and service in every
   registered source is bound to exactly one registry entry; every binding
   resolves.
2. **Desired agrees with desired; observed drift is declared.** Contracts that
   describe the same route must agree on every field both declare; the
   production readback may differ only where `knownDrift` says so, and a stale
   declaration fails.
3. **Explicit match posture.** No wildcard or missing host, no missing methods,
   no catch-all path on any canonical route; unknown API versions get Kong's
   controlled `404`, never a legacy service.
4. **Deterministic precedence.** Every overlapping pair inside an environment
   is declared with the winner the Kong 3.x router would pick; identical
   matches are ambiguous and can only exist as a legacy route retired by the
   apply of its successor.
5. **Fail-closed authentication.** Every route has one of the five
   authentication classes and a mechanism; a route without an authentication
   plugin is a reasoned read-only `PUBLIC` route, `BLOCKED`, or a design with a
   declared gap — never authenticated by omission. Token routes name their
   audience; shared keys are legacy only; administrative paths are
   `ADMIN_INTERNAL` or blocked.
6. **Governed upstreams.** Middleware-governed services target a declared
   alias; direct application upstreams carry a recorded reason; provider
   markers and IP literals are blocked outright.
7. **Explicit transport policy.** Canonical services declare timeouts and
   retries matching a profile; Kong defaults are findings, and retries above 0
   must be transport-safe.
8. **Governed plugins.** Every plugin in use is registered with owner, purpose,
   scope, sources, impact, ordering and environments; only `prometheus` is
   global; authentication plugins are never global; claim guards run after a
   token plugin.
9. **Environment separation.** Staging and production issuers differ, each
   source binds its environment's realm, overlays are exact subsets of their
   base with shared aliases declared, and development binds no shared realm.
10. **Node boundary.** Admin on container loopback and unpublished, Manager
    off, Status private, proxy on host loopback only, `trusted_ips` required,
    Lua sandboxed, env vault, TLS-verified datastore, immutable digest,
    read-only root, no capabilities, no Docker socket, every vault reference
    declared in the runtime template.

## Route posture at this baseline

| Lifecycle | Routes | Meaning |
| --- | ---: | --- |
| CANONICAL | 30 | 7 control-plane candidate, 2 callback, 5 campaign (+4 staging), 2 intake, 2 n8n (+2 staging), 5 calling, 1 MoneyBee |
| LEGACY | 13 | shared-key CRM/email/SMS/DLR/webhooks, five website forms, website API, two key-auth communication routes superseded by the control plane |
| TRANSITIONAL | 3 | breero (blocked), mail API (blocked), token-validation probe |
| STANDBY | 4 | private standby rehearsal |
| RETIRE_CANDIDATE | 1 | gateway-test route (blocked) |
| PREPARED_DISABLED | 6 | provider-control contract |
| PROPOSED | 2 | n8n editor UI, community-n8n TLS egress |
| DESIGN_ONLY | 20 | cell design (15), marketing fragment (4), integration example (1) |

## How to run

```bash
python3 scripts/validate_kong_foundation.py            # PASS/FAIL, counts, no writes
python3 scripts/validate_kong_foundation.py --write-docs  # refresh generated tables
python3 -m pytest -q tests/test_kong_foundation.py
```

CI (`.github/workflows/validate.yml`, job `source-head`) runs the validator
and the tests on every push and pull request against the exact reviewed head.

## Freeze statement

The foundation is frozen at the commit that contains this document. It:

- authorizes no Admin API call, reload, migration, DNS, traffic or credential
  change;
- claims no runtime certification of Caddy, Keycloak, Middleware, Redis or the
  database;
- records every known defect either as fixed in source with a focused test or
  as a declared, validator-enforced disposition;
- must be re-validated (`validate.yml`) on every subsequent source commit; the
  migration manifests inventory every file this baseline touches.

Follow-ups that remain runtime or cross-repository work are listed in the
audit's residual blockers and in each service's `notes`.

## Post-#105 reconciliation (registry 1.3.0)

`main` at `6afd0bd` (PR #103, #104 and the Mission 1 reconciliation PR #105,
independently approved and merged on 2026-09-18) is merged into this branch and
the registry now binds the post-#105 universe:

- `config/kong-middleware-authority.v2.json` (CONTRACT) — the per-operation
  security authority of the canonical Middleware edge, pinned to the vendored
  Middleware contract sha256; `config/kong-middleware-routes.production.yml` and
  `config/staging/kong-middleware-routes.staging.yml` (DEPLOYED_CANDIDATE,
  generated by `scripts/generate_middleware_routes.py`) — 80 `middleware-*`
  openid-connect routes on `api.codestra.co` → `middleware-integration-api:8095`
  per environment plus 10 gateway-terminated (`request-termination` 404,
  no service, no upstream) retired aliases (`DENIED_ALIAS`, explicit PUBLIC
  allowlist entries).
- `config/kong-platform-api-read-routes.v1.json` (PR #104, CONTRACT) — its 20
  `/platform/v1/*` operations are all declared by the v2 authority as well, so
  the service and routes are `TRANSITIONAL`, `supersededBy` their `middleware-*`
  twin, and the generated regex routes win the router deterministically.
- The jwt reconciler routes the old canonical contract named (callbacks ×2,
  campaign ×5 and their staging twins) are `TRANSITIONAL` with `supersededBy`;
  the n8n control-plane routes are `RETIRE_CANDIDATE` (`retiredBy` the deny
  routes) with the live 8080 readback declared as `knownDrift`; the intake
  routes stay `CANONICAL` on their own contract (`contractCoverage`).
- `appolon-middleware-integration-api:8080` is `RETIRED_DENIED_PR105`: the
  validator detects `RETIRED_UPSTREAM_ALIAS` on anything that targets it and
  allows it only on `PREPARED_DISABLED` / `RETIRE_CANDIDATE` entries (the
  prepared provider-control contract, which must re-pin before activation, and
  the live n8n residue). `M1_DEPENDENCY=MERGED`, `TRANSITIONAL_8080_ALIASES=0`.
- The generator now assigns a deterministic `regex_priority` (literal segments
  win over parameters, e.g. `/platform/v1/tenants/authorized` over
  `/platform/v1/tenants/{tenant_id}`) and clears every client-asserted identity
  header before minting the `X-Codestra-*` contract metadata.
