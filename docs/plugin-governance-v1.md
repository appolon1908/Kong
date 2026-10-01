# Kong Plugin Governance V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Machine-readable authority: `config/kong-gateway-foundation.v1.json` (`plugins[]`,
`pluginGovernance`). Validator: `python3 scripts/validate_kong_foundation.py`.

## Rules

1. Every plugin name that appears in any reviewed source (declarative
   candidate, contract, renderer, readback, standby design, integration policy
   template) must be registered with `plugin`, `kind`, `allowedScopes`,
   `owner`, `purpose`, `configurationSources`, `securityImpact`,
   `orderingDependency`, `environments` and `priority`. A source that uses a
   plugin without being listed as one of its configuration sources fails.
2. Scope is explicit: `GLOBAL`, `SERVICE`, `ROUTE`, `CONSUMER`. Only
   `prometheus` may be global; every other plugin is scoped to the service or
   route whose contract it enforces. Authentication plugins can never be global
   because their audience differs per service (`codestra-control-plane`,
   `codestra-callback-api`, `codestra-middleware`, `middleware-api`,
   `moneybee-api`, `sdk-intake`, `codestra-api`).
3. `kong/plugins/oidc/keycloak.yml` is literally a top-level `plugins:` list —
   a global `openid-connect` if ever loaded as a declarative document. It is
   registered as a `PLUGIN_TEMPLATE` with activation `TEMPLATE_NOT_LOADABLE`;
   reconcilers copy its bearer settings onto services.
4. Authentication must be explicit per route class. A route whose plugin set
   contains no authentication plugin is `PUBLIC` with a reason, `BLOCKED`, or a
   non-activatable design with a declared gap — never an authenticated route by
   omission.
5. Claim guards (`post-function`, `codestra-authz`) run only after a token
   authentication plugin on the same route/service; the validator checks the
   priority relation on every desired source. `pre-function` is reserved for
   raw request-metadata guards (`deploy/kong/correlation-required.lua` on the
   calling contract) and is never a claim guard.
6. Plugin configuration values are never trusted from a name-only listing.
   The production readback records names only; the reconcilers verify exact
   configuration (`require_config_subset`, exact drift errors) against the
   contracts before any apply.

## Ordering

Kong executes access-phase plugins by descending priority. The invariants the
configuration relies on:

| Order | Plugin(s) | Why the order matters |
| --- | --- | --- |
| 1 | `pre-function` (1000000), `codestra-request-context` (100002), `correlation-id` (100001) | request identity and correlation are fixed before any decision; caller-supplied identity headers are stripped before authentication |
| 2 | `ip-restriction` (3000), `bot-detection` (2500), `cors` (2000) | source and preflight controls run before credentials; a denied source never reaches a credential check, and `OPTIONS` preflights are answered without credentials |
| 3 | `jwt` (1450), `key-auth` (1250), `openid-connect` (1050), `mtls-auth` (1006), `codestra-webhook-verifier` (1000) | authentication; the signature/issuer/expiry/audience decision |
| 4 | `request-size-limiting` (951), `rate-limiting` (910) | after authentication so an anonymous oversized or noisy request is rejected 401 first; counters are keyed by consumer where a credential exists |
| 5 | `codestra-authz` (900), `request-transformer` (801), `response-transformer` (800) | prerequisites and header shaping on an authenticated request; transformers never add identity headers a guard did not mint |
| 6 | `request-termination` (2) | explicit deny for quarantined or disabled variants |
| 7 | `post-function` (-1000) | claim guards: the only serverless phase that observes the result of authentication |
| log | `prometheus` (13) | metrics; independent |

Priorities are the Kong Gateway 3.x bundled values; custom plugins declare
`PRIORITY` in their handler. The comment in `deploy/kong/control-plane.yml`
quotes older 2.x values for `openid-connect`/`jwt`; the invariant it protects
(post-function after every authentication plugin) holds on 3.x as well.

The one live deviation is recorded as drift: the 2026-09-06 readback shows the
two callback routes running their claim guard as `pre-function`. Because `jwt`
still gates the signature on the same route, the composed decision is
unchanged, but the guard runs on unverified claims and the ordering is wrong;
the callback reconciler moves it to `post-function` on apply.

## Rate-limit, request-size and CORS authority

Rate limiting uses the `redis` policy with `fault_tolerant: false` on every
canonical route so that N nodes share one counter and an unreachable Redis
fails closed; only the private standby node uses `policy: local`. Per-route
profiles live in `profiles.rateLimit` (see the route registry). Request-size
profiles bound bodies per traffic class; Kong never validates application
schemas. CORS is a Kong concern only on legacy browser routes
(`cors` + `key-auth`, finding `CORS_WITH_SHARED_KEY`); canonical service routes
have no browser origin and no `cors` plugin, and
`corsCredentialsWithWildcardOriginAllowed` is `false` — the integration
compiler rejects wildcard origins outright.

## Registry

Generated by `scripts/validate_kong_foundation.py --write-docs`; CI fails if stale.

<!-- BEGIN GENERATED: plugins -->
| Plugin | Kind | Auth | Priority | Allowed scopes | Owner | Purpose | Security impact | Ordering dependency | Environments | Configuration sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pre-function` | bundled | no | 1000000 | ROUTE | gateway-platform | Raw request metadata guards and client-supplied identity-header stripping before authentication; never reads claims or credentials. | HIGH | Runs before every authentication plugin; must not read credentials or claims. | staging, production | `config/kong-calling-routes.v1.json`, `config/kong-production-route-inventory.v2.json`, `config/kong-platform-api-read-routes.v1.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-canonical-middleware-routes.json` |
| `codestra-private-surface` | custom | no | 100004 | GLOBAL, ROUTE | gateway-platform | Reject management/private paths and encoded bypasses before authentication; private overrides require governed source restrictions. | HIGH | Before all authentication | staging, production | `scripts/gateway_integrations.py`, `scripts/generate_middleware_routes.py`, `config/kong-canonical-middleware-routes.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `deploy/kong/plugins/codestra-private-surface/handler.lua` |
| `codestra-request-context` | custom | no | 100002 | SERVICE, ROUTE | gateway-platform | Strip caller identity headers, validate/mint correlation, request id and traceparent, add response security headers. | HIGH | Runs before correlation-id and before authentication so spoofed identity never reaches a plugin. | staging, production | `deploy/kong/plugins/codestra-request-context/handler.lua`, `scripts/gateway_integrations.py`, `scripts/generate_middleware_routes.py`, `config/kong-canonical-middleware-routes.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml` |
| `correlation-id` | bundled | no | 100001 | SERVICE, ROUTE | gateway-platform | Generate X-Correlation-ID (uuid) and echo it downstream. | LOW | Runs before authentication and logging so every decision carries the id. | staging, production | `deploy/kong/control-plane.yml`, `config/kong-production-route-inventory.v2.json`, `config/kong-canonical-middleware-routes.json`, `config/kong-callback-routes.json`, `config/kong-campaign-automation-routes.json`, `config/staging/kong-campaign-automation-routes.json`, `config/kong-intake-routes.json`, `config/kong-n8n-control-plane-routes.json`, `config/staging/kong-n8n-control-plane-routes.json`, `config/kong-moneybee-identity-routes.json`, `config/kong-calling-routes.v1.json`, `config/kong-community-n8n-egress.v1.json`, `config/marketing-stage4-routes.yaml`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-platform-api-read-routes.v1.json` |
| `ip-restriction` | bundled | yes | 3000 | ROUTE | gateway-standby | Source allowlist for the private standby routes and private integration policies. | HIGH | Runs before token authentication; a denied source never reaches a credential check. | production | `config/kong-production-route-inventory.v2.json`, `deploy/kong-production-standby/kong/standby.json`, `config/integrations/policies/internal-service-jwt.json`, `config/integrations/policies/private-mtls-api.json` |
| `bot-detection` | bundled | no | 2500 | ROUTE | website | User-agent based abuse control on legacy public website forms. | LOW | Runs before cors and key-auth. | production | `config/kong-production-route-inventory.v2.json` |
| `cors` | bundled | no | 2000 | ROUTE | website | Browser preflight for legacy website routes; credentials with a wildcard origin are forbidden. | MEDIUM | Runs before key-auth so OPTIONS preflights are answered without credentials. | production | `config/kong-production-route-inventory.v2.json` |
| `jwt` | bundled | yes | 1450 | ROUTE | gateway-identity | RS256 signature and exp verification keyed by azp against the realm JWKS credential. | CRITICAL | Must complete before post-function claim guards (priority -1000). | staging, production | `config/kong-production-route-inventory.v2.json`, `config/kong-canonical-middleware-routes.json`, `config/kong-callback-routes.json`, `config/kong-campaign-automation-routes.json`, `config/staging/kong-campaign-automation-routes.json`, `config/kong-intake-routes.json`, `config/kong-n8n-control-plane-routes.json`, `config/staging/kong-n8n-control-plane-routes.json` |
| `key-auth` | bundled | yes | 1250 | ROUTE | legacy-shared-key-consumers | Legacy shared API keys; not permitted for new production routes (config/integrations/policies/legacy-api-key.json). | HIGH | Runs after cors; the only credential check on legacy routes. | production | `config/kong-production-route-inventory.v2.json`, `config/integrations/policies/legacy-api-key.json` |
| `openid-connect` | bundled-enterprise | yes | 1050 | SERVICE, ROUTE | gateway-identity | Bearer validation against the Keycloak realm: signature via discovery/JWKS, issuer, expiry, audience, scopes_required, consumer mapping by azp. | CRITICAL | Must complete before post-function and codestra-authz; never global because the audience differs per service. | staging, production | `deploy/kong/control-plane.yml`, `config/kong-canonical-middleware-routes.json`, `config/kong-intake-routes.json`, `config/kong-moneybee-identity-routes.json`, `config/kong-calling-routes.v1.json`, `kong/plugins/oidc/keycloak.yml`, `config/integrations/examples/moneybee-account-bootstrap.json`, `scripts/gateway_integrations.py`, `scripts/render_kong_calling_routes.py`, `scripts/render_kong_moneybee_identity.py`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-platform-api-read-routes.v1.json` |
| `mtls-auth` | bundled-enterprise | yes | 1006 | ROUTE | gateway-identity | Client-certificate authentication for the private mTLS integration policy. | CRITICAL | Runs with openid-connect before codestra-authz. | staging, production | `config/integrations/policies/private-mtls-api.json` |
| `codestra-webhook-verifier` | custom | yes | 1000 | ROUTE | gateway-platform | Versioned HMAC verification of signed webhook bytes with per-integration vault keys; replay denial stays in Middleware. | CRITICAL | Sole authentication on signed-webhook routes; runs before request-size-limiting so it bounds its own body read. | staging, production | `deploy/kong/plugins/codestra-webhook-verifier/handler.lua`, `config/integrations/policies/signed-webhook.json` |
| `request-size-limiting` | bundled | no | 951 | SERVICE, ROUTE | gateway-platform | Bound request bodies per request-size profile; require Content-Length on command routes. | MEDIUM | Runs after authentication so an anonymous oversized body is rejected as 401 first. | staging, production | `deploy/kong/control-plane.yml`, `config/kong-production-route-inventory.v2.json`, `config/kong-canonical-middleware-routes.json`, `config/kong-callback-routes.json`, `config/kong-campaign-automation-routes.json`, `config/staging/kong-campaign-automation-routes.json`, `config/kong-intake-routes.json`, `config/kong-n8n-control-plane-routes.json`, `config/staging/kong-n8n-control-plane-routes.json`, `config/kong-moneybee-identity-routes.json`, `config/kong-calling-routes.v1.json`, `config/kong-community-n8n-egress.v1.json`, `deploy/kong-production-standby/kong/standby.json`, `config/marketing-stage4-routes.yaml`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-platform-api-read-routes.v1.json` |
| `rate-limiting` | bundled | no | 910 | SERVICE, ROUTE | gateway-platform | Per-profile request rate; redis policy with fault_tolerant false on canonical routes, local policy only on the private standby node. | MEDIUM | Runs after authentication and request-size-limiting; counters are keyed by consumer where a credential exists. | staging, production | `deploy/kong/control-plane.yml`, `config/kong-production-route-inventory.v2.json`, `config/kong-canonical-middleware-routes.json`, `config/kong-callback-routes.json`, `config/kong-campaign-automation-routes.json`, `config/staging/kong-campaign-automation-routes.json`, `config/kong-intake-routes.json`, `config/kong-n8n-control-plane-routes.json`, `config/staging/kong-n8n-control-plane-routes.json`, `config/kong-moneybee-identity-routes.json`, `config/kong-calling-routes.v1.json`, `config/kong-community-n8n-egress.v1.json`, `deploy/kong-production-standby/kong/standby.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-platform-api-read-routes.v1.json` |
| `codestra-authz` | custom | yes | 900 | ROUTE | gateway-platform | Route authorization prerequisites after openid-connect: issuer, audience, authorized party, time claims, scopes, realm roles, tenant. | CRITICAL | Requires openid-connect (1050) to have accepted the request; never verifies signatures itself. | staging, production | `deploy/kong/plugins/codestra-authz/handler.lua`, `config/integrations/examples/moneybee-account-bootstrap.json`, `config/integrations/policies/public-oidc-api.json`, `config/integrations/policies/internal-service-jwt.json`, `config/integrations/policies/private-mtls-api.json`, `config/integrations/policies/websocket-api.json` |
| `request-transformer` | bundled | no | 801 | ROUTE | gateway-platform | Strip trusted identity headers before the upstream (standby, legacy communication routes, egress proposal). | MEDIUM | Runs after authentication; must never add identity headers a guard did not mint. | production | `config/kong-production-route-inventory.v2.json`, `deploy/kong-production-standby/kong/standby.json`, `config/kong-community-n8n-egress.v1.json` |
| `response-transformer` | bundled | no | 800 | ROUTE | moneybee-platform | Response header shaping on the MoneyBee bootstrap route. | LOW | Header-filter phase only; must not remove correlation or security headers. | production | `config/kong-moneybee-identity-routes.json`, `scripts/render_kong_moneybee_identity.py` |
| `codestra-resource-guard` | custom | no | 800 | ROUTE | gateway-platform | Bound in-flight requests per route per worker, global verified-tenant Redis quotas, and gateway error responses. | HIGH | After codestra-authz; tenant quota reads only verified shared context | staging, production | `scripts/gateway_integrations.py`, `scripts/generate_middleware_routes.py`, `config/kong-canonical-middleware-routes.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `deploy/kong/plugins/codestra-resource-guard/handler.lua` |
| `prometheus` | bundled | no | 13 | GLOBAL | observability | Node, request, latency, bandwidth and upstream-health metrics on the private status listener; per-consumer and AI metrics disabled. | LOW | Log phase; independent of other plugins. | staging, production | `deploy/kong/control-plane.yml` |
| `request-termination` | bundled | no | 2 | ROUTE | gateway-platform | Explicit deny for quarantined or disabled route variants (legacy host termination on intake, callback quarantine); the generated Middleware manifests use it to answer 404 on the retired /v1/integrations/n8n and campaign-action aliases. | MEDIUM | Runs last in access; only reached when every earlier plugin admitted the request. | production | `config/kong-canonical-middleware-routes.json`, `config/kong-intake-routes.json`, `scripts/reconcile_kong_callback_routes.py`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml` |
| `post-function` | bundled | no | -1000 | SERVICE, ROUTE | gateway-identity | Claim guards that consume verified authentication state: scope, tenant, campaign, authorized party, minted identity headers. | CRITICAL | Priority -1000: the only serverless phase that observes the result of jwt/openid-connect; never attach a claim guard as pre-function. | staging, production | `deploy/kong/control-plane.yml`, `config/kong-production-route-inventory.v2.json`, `config/kong-canonical-middleware-routes.json`, `config/kong-callback-routes.json`, `config/kong-campaign-automation-routes.json`, `config/staging/kong-campaign-automation-routes.json`, `config/kong-intake-routes.json`, `config/kong-n8n-control-plane-routes.json`, `config/staging/kong-n8n-control-plane-routes.json`, `config/kong-moneybee-identity-routes.json`, `config/kong-calling-routes.v1.json`, `config/kong-middleware-routes.production.yml`, `config/staging/kong-middleware-routes.staging.yml`, `config/kong-platform-api-read-routes.v1.json` |
<!-- END GENERATED: plugins -->
