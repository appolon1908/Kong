# Kong V3 integration parity — PAS-149 / Lane C

## Scope

Lane C owns cross-repository parity, webhook/event-ingress ownership, Caddy handoff checks, CRM/automation contract probes, and deterministic Postman artifacts.

It does **not** own the Kong Middleware route authority, access/authentication policy, gateway foundation, migration manifests, runtime apply, or provider effects. Those remain in the other parallel lanes or later staging/release checkpoints.

## Local source of truth used for this lane

The user's existing local repositories were used; no duplicate repository clone was created.

- Kong primary: `C:\Users\agent\Documents\GitHub\Kong`
- Kong Lane C worktree: `C:\Users\agent\Documents\GitHub\Kong.worktrees\wave-integration-parity-20260920`
- Lane C branch: `mission/kong-v3-integration-parity-20260920`
- frozen base: `ee86cdf870aebaac550a78a9617321ee48324589`
- Middleware exact-main worktree: `C:\Users\agent\Documents\GitHub\Middleware-.worktrees\main-current-20260920`
- Middleware SHA: `bd406a6508c8095a3f23b35149a2eebcb94c94c6`
- Caddy source used for parity: protected `main` after PR #175 (digest chain), #177/#178/#180 (PAS-145 certification) and #179 (PAS-146 staging prep) merged
- Caddy SHA: `22c6d51ed2f5340139177131fb810e787f0f7550`
- Keycloak exact-source worktree used for caller/token readback: `C:\Users\agent\Documents\GitHub\Keycloak.worktrees\kong-lane-c-keycloak-45a487d`
- Identity source revision: `45a487d71a516ae3039b00c250752897469ffe7a`

The primary local Middleware and Caddy checkouts are on other in-progress branches; Lane C does not overwrite or reset them.

## Exact contract pins

Middleware final public-edge authority:

- 117 routes
- 105 `shared_edge`
- 10 `denied`
- 2 `private_only`
- digest `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`
- canonical upstream `middleware-integration-api:8095`

Caddy PR #175 already expects that final digest and sends the canonical namespaces to Kong: `/platform/v1/*`, `/v2/automation/*`, `/api/v1/odoo/events`, and `/api/v1/integrations/n8n/results*`.

Caddy also keeps public `/metrics*` and `/internal/*` fail-closed at 404 and keeps pending provider webhook surfaces outside the legacy fallback.

## Parallel-Lane-A dependency

The frozen Kong branch still carries the pre-Lane-A contract digest `be25ea3a15687616fc1a17c451bb731c9e8bb85bbbd970e563d2baedc062b99e`.

Lane C therefore has two modes:

1. `--allow-pending-lane-a` validates all external final sources and accepts only the exact frozen-base Kong digest as the temporary dependency.
2. strict final mode fails until Lane A integrates the final `9c32daec…` contract into Kong.

This is deliberate. Lane C never edits Lane A's route-authority files to manufacture a false PASS.

Current local source result:

```text
KONG_CROSS_REPO_PARITY=PENDING_LANE_A
MIDDLEWARE_FINAL_CONTRACT=PASS
MIDDLEWARE_ROUTE_COUNT=117
CRM_AUTOMATION_ROUTE_PARITY=PASS
CADDY_EXPECTS_FINAL_KONG_DIGEST=PASS
KONG_FINAL_CONTRACT_REPIN=PENDING_LANE_A
GATEWAY_RETRIES_SIDE_EFFECTING=0
KEYCLOAK_CALLER_TOKEN_CONTRACT=PASS
RUNTIME_APPLY_AUTHORIZED=NO
PROVIDER_EFFECTS_ENABLED=NO
```

After Lane A is integrated, the same validator without `--allow-pending-lane-a` must report full PASS.

## CRM / automation coverage

The generated contract-probe cases cover CRM Contacts (9), CRM Tickets (4), CRM Opportunities (4), standalone CRM Tasks (2), all 13 `/v2/automation/*` operations, and three canonical webhook/event-ingress routes. Contact-scoped task routes remain in the Contacts family but are also checked by the cross-repo route-family validator.

All selected mutation routes are checked against Middleware's idempotency declaration. Kong's Middleware services are checked for `retries: 0`.

## Webhook/event-ingress ownership

`config/kong-webhook-registry.v1.json` declares only gateway transport/identity metadata.

Canonical shared-edge ingress:

- `POST /api/v1/odoo/events`
- `POST /api/v1/integrations/n8n/results`
- `POST /platform/v1/integrations/github/events`

For all three, Caddy hands traffic to Kong, Kong handles gateway identity/security and exact transport, upstream is `middleware-integration-api:8095`, Kong retries are zero, and Middleware owns replay state plus the durable event ledger.

The following remain 404 `DENIED_PENDING_CONTRACT` until a reviewed Middleware/Kong contract exists: Telnexa, VICIdial call-result, n8n acknowledgements, observability incidents/KPIs, and SMS inbound.

## Postman artifacts

Generated files:

- `postman/kong-v3-parity-route-cases.v1.json`
- `postman/Kong-V3-Integration-Parity.postman_collection.json`
- `postman/Kong-V3-Integration-Parity.postman_environment.json`

The route-case file is derived test data, not route authority. It is bound to the final Middleware contract digest.

The collection covers positive contract probes and negative cases for missing token, wrong issuer/audience/AZP, missing scope/idempotency, wrong method, oversize body, private metrics/internal routes, and pending provider ingress.

It also carries an `MCR Platform` folder generated from `config/kong-mcr-routes.v1.json` (all 8 MCR routes, with `X-Tenant-ID`, `X-Correlation-ID`, `Idempotency-Key` and the delivery-event signature headers the contract requires) and an `MCR Negative Security & Edge` folder: missing tenant/correlation/idempotency/signature (`400` with the normalized `{"error": "<code>_required"}` body), missing token, wrong method, a non-`klyrow:`/`whatsapp:` campaign namespace, an `/internal/` prefix and the private-only Odoo `actual-state` surface.

Every request asserts. Each item has its own test script that checks: no `5xx`; no internal leakage (Lua traces, DSNs, `odoo:8069`, `middleware-integration-api`, `codestra-redis`); the exact expected status set for every negative; that positive probes reached Middleware rather than a Kong route miss; that MCR `execute` never returns `2xx`; the normalized gateway error code where one applies; and that `X-Correlation-ID` is echoed unchanged wherever the `correlation-id` plugin runs.

Safety defaults: `base_url=http://127.0.0.1:8000`, `RUN_KONG_V3_PARITY=false`, token and signature variables empty. The collection-level pre-request guard calls `pm.execution.skipRequest()` before it throws, because Newman still sends a request whose pre-request script only throws. It refuses any `base_url` that is not loopback or a `staging` host, and it mints a fresh `TEST_SYN-` correlation ID and idempotency key for every request. Each item also skips itself when the token (or delivery signature) it needs is unset, so an empty credential cannot pass vacuously.

Local proof (Newman 6.2.2): the default environment and a non-loopback target both sent 0 requests. Against a loopback stub that emulates the contract, the run sent 67 requests with 256 assertions and 0 failures. Stub mutations were all caught: `execute` returning `2xx` (1 failure), missing correlation echo (50 failures), and an upstream `5xx` that leaks internals (84 failures).

No credentials or production tokens are stored in Git.

## Validation

Repository-only deterministic tests:

```text
python -m pytest -q tests/test_kong_cross_repo_parity.py tests/test_kong_webhook_registry.py tests/test_kong_postman_generation.py
```

Expected: all pass. MCR route contract, renderer and Postman MCR coverage:

```text
python scripts/validate_kong_mcr_routes.py
python scripts/generate_kong_postman.py --check
python -m pytest -q tests/test_kong_mcr_routes.py tests/test_kong_postman_generation.py
```

Exact local cross-repo source validation uses the local exact Middleware, Caddy, and Keycloak worktrees listed above.

## Final integration gate

After Lane A is integrated, PAS-149 is complete only when:

```text
KONG_CROSS_REPO_PARITY=PASS
KONG_FINAL_CONTRACT_REPIN=PASS
CADDY_KONG_MIDDLEWARE_DIGEST_CHAIN=PASS
KONG_WEBHOOK_REGISTRY=PASS
CRM_AUTOMATION_ROUTE_PARITY=PASS
KONG_POSTMAN_GENERATION=PASS
DIRECT_PROVIDER_ROUTES=0
DIRECT_ODOO_ROUTES=0
DIRECT_N8N_EXECUTION_ROUTES=0
RUNTIME_APPLY_AUTHORIZED=NO
```

No staging or production deployment is authorized by this lane.
