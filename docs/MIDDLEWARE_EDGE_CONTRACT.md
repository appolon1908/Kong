# Middleware edge contract — canonical campaign routes

Kong is the authorization edge for the four Middleware integration routes that
the Keycloak → Caddy → Kong → Middleware certification (issue #58) exercises.
This document records what the source declares, what it pins, and how the
certification runner reads it. Nothing here authorizes a runtime apply.

## Pinned contract

| Item | Value |
| --- | --- |
| Source of truth | `appolon1908/Middleware-` `deploy/public-api-route-contract.json` |
| Vendored copy | `config/middleware-public-api-route-contract.v1.json` (byte-identical) |
| Pin | `config/kong-canonical-middleware-routes.json` → `middlewareEdgeContract.sha256` |
| Hash rule | `sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode())` |
| Validator | `scripts/validate_middleware_edge_contract.py` (runs in `validate.yml` and `kong-config.yml`) |

Caddy pins the same digest in `config/caddy-kong-contract.v1.json`; Keycloak in
`config/desired-state/edge-integration-certification/contract.json`. When
Middleware changes the contract, update the vendored copy and the pin in the
same change, then re-run the validator; a stale pin fails CI.

## Canonical routes

All four bind to service `codestra-campaign-automation-api`
(`codestra-middleware-integration-api-1:8095`), host `api.codestra.co`,
plugins `jwt` (RS256, key claim `azp`) + `post-function` claim guard +
`correlation-id` + `rate-limiting` (redis, fail-closed) + `request-size-limiting`.

| Method | Path template | Kong path | Scope | Route name |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/integrations/n8n/results` | literal | `n8n.results.submit` | `codestra-campaign-result-submit` |
| `GET` | `/api/v1/integrations/n8n/results/{event_id}` | `~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `n8n.results.read` | `codestra-campaign-result-read` |
| `GET` | `/api/v1/integrations/odoo/campaigns/{campaign_id}` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | `odoo.campaigns.read` | `codestra-odoo-campaign-read` |
| `GET` | `/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state` | `~/api/v1/integrations/odoo/campaigns/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/desired-state$` | `odoo.campaigns.read` | `codestra-odoo-campaign-desired-state-read` |

Path-parameter routes are anchored regex paths whose character class equals
Middleware's `PUBLIC_ID`; the reconciler refuses a regex that admits a longer
or shorter path than its template. Any other method or path under these
prefixes gets Kong's `404 no Route matched` — there is no catch-all on
`api.codestra.co`. `odoo.campaign.control.read` is Middleware's outbound scope
to Odoo and never appears on an ingress route; `odoo.campaign.control.write`
is a forbidden scope for every consumer.

## Claim guard order

For every route the `post-function` guard checks, in order: `iss` (401
`invalid_issuer`), `aud` (401 `invalid_audience`), then `azp` ∈ consumers
holding the route scope **and** `environment` == manifest environment (403
`service_identity_denied`), then the route scope (403 `insufficient_scope`).
Middleware re-validates signature, issuer, audience, scope and tenant itself;
Kong never terminates authorization.

## Identities

Production (`config/kong-campaign-automation-routes.json`, issuer
`https://auth.codestra.co/realms/codestra`, audience `codestra-middleware`):

| Consumer / `azp` | Scopes |
| --- | --- |
| `codestra-n8n-campaign-crm-production` | `n8n.policy.check`, `n8n.results.submit`, `n8n.results.read` |
| `codestra-odoo-campaign-reader-production` | `odoo.campaigns.read` |

Staging certification (`config/staging/kong-campaign-automation-routes.json`,
issuer `https://auth-staging.codestra.co/realms/codestra`, environment claim
`staging`, campaign `TEST_SYN`, `safety.reconciliation_apply: false`):

| Consumer / `azp` | Scopes | Role |
| --- | --- | --- |
| `test-syn-n8n-submit` | `n8n.results.submit` | positive |
| `test-syn-n8n-read` | `n8n.results.read` | positive |
| `test-syn-odoo-reader` | `odoo.campaigns.read` | positive |
| `test-syn-wrong-tenant` | `n8n.results.read`, `odoo.campaigns.read` | negative: passes Kong, Middleware proves the cross-tenant 404/403 |
| `test-syn-wrong-audience` | none | negative: guard answers 401 `invalid_audience` |

Each consumer needs one Kong JWT credential keyed by its `azp` with the realm's
current RS256 public key; the reconciler provisions it from the live JWKS
(`--jwks-url`) and nothing in this repository carries key material.

## Validation and rendering

```bash
python3 scripts/validate_middleware_edge_contract.py
python3 scripts/render_kong_campaign_automation_routes.py --environment production | deck file validate /dev/stdin
python3 scripts/render_kong_campaign_automation_routes.py --environment staging    | deck file validate /dev/stdin
pytest -q tests/test_kong_campaign_edge_certification.py tests/test_kong_canonical_route_contract.py tests/test_kong_route_authority_hardening.py
```

The cross-repository Phase 1 gate lives in the Middleware repository:

```bash
CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN \
CERTIFY_KEYCLOAK_ISSUER=https://auth-staging.codestra.co/realms/codestra \
CERTIFY_KONG_REPO=../Kong CERTIFY_CADDY_REPO=../Caddy CERTIFY_KEYCLOAK_REPO=../Keycloak \
python -m scripts.certify_edge_integration --static-only --report static.json
```

It reads `contractRoutes[].pathTemplate` to match this repository's regex
paths against the Middleware templates and fails closed on any hash, method,
path, scope or plugin drift.

## Activation boundary

`config/staging/kong-campaign-automation-routes.json` is prepared source; the
reconciler refuses `--apply` for it. Applying the staging routes, minting
`test-syn-*` tokens, and the live certification matrix are separate operations
under the change-authority process in `operations/runbooks/`. The production
route inventory (`config/kong-production-route-inventory.v2.json`) records
what is deployed today and is intentionally unchanged by this source change.
