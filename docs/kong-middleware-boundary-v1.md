# Kong → Middleware Boundary V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Companion to `docs/MIDDLEWARE_EDGE_CONTRACT.md` (the pinned issue #58 contract).

```text
Kong                                   Middleware (appolon1908/Middleware-)
  route identity                         re-validates signature, issuer, audience, scope, tenant
  authentication prerequisite   ──▶      MAY this identity execute this command on this resource
  audience / scope / tenant guard        in this environment?  (business authorization)
  rate, body, correlation                command idempotency ledger
  approved upstream alias                provider / Odoo / n8n business integrations
```

Kong routes; Middleware decides. Kong never terminates authorization, never
executes a command, never talks to a provider on behalf of a governed
operation, and never becomes the idempotency ledger.

## What Kong may do before Middleware

| Prerequisite | Where |
| --- | --- |
| signature, issuer, expiry (and audience/scopes on OIDC services) | `openid-connect` / `jwt` |
| route audience, required scope, authorized party, tenant claim, campaign membership | `post-function` claim guards (`deploy/kong/scope-policy.lua`, `deploy/kong/calling-policy.lua`, the callback/campaign/n8n reconciler guards) or `codestra-authz` |
| strip caller identity headers, mint gateway identity headers (`X-Authenticated-Client/-Subject/-Tenant/-Campaign/-Role`, `X-Codestra-Gateway-Secret`) only after authentication | claim guards; `codestra-request-context` |
| bound rate, body size, require `Content-Length`, require `X-Correlation-ID` / `Idempotency-Key` on declared command routes | `rate-limiting`, `request-size-limiting`, guards |
| reject the forwarded scheme when it is not `https` from the trusted edge | guards (`426`) |

Middleware must still revalidate the token and make the resource-level
decision; `X-Codestra-Gateway-Secret` only proves the request traversed Kong.

## Governed routes and their Middleware listener

| Route family | Kong service | Middleware alias | Status |
| --- | --- | --- | --- |
| callbacks (`/api/v1/callbacks`, `/api/v1/control/callbacks`) | `codestra-callback-api` | `codestra-middleware-integration-api-1:8095` | canonical, runtime observed |
| campaign automation (`/api/v1/automation/policy-check`, `/api/v1/integrations/n8n/results[/{event_id}]`, `/api/v1/integrations/odoo/campaigns/…`) | `codestra-campaign-automation-api` | `…-1:8095` | canonical; two routes observed, three source candidates; pinned to Middleware's public API route contract by sha256 |
| intake (`/v1/intake/leads`, `/v1/intake/surveys/responses`) | `codestra-middleware-intake` | `…-1:8095` | canonical source candidate |
| telephony (`/v1/telephony/*`, `/api/v1/realtime/sessions` on the private host) | `codestra-calling-api` | `…-1:8095` | canonical source candidate |
| n8n control plane (`/v1/integrations/n8n/commands`, `/operations`) | `codestra-middleware-n8n-control-plane` | `appolon-middleware-integration-api:8080` | canonical, runtime observed, **transitional listener** |
| provider control (`/api/v1/control/{ai,communications,marketing,social}/…`, `/api/v1/odoo/events`) | `provider-control-middleware` | `…:8080` | prepared, disabled |
| communication control plane (`/api/v1/control`, `/events`, `/results`, `/reconciliation`, `/messages`, `/health`, `/v1/admin/system`) | `codestra-control-plane` | `codestra-control-plane:8096` | canonical declarative candidate (OIDC), supersedes the key-auth `codestra-communication-control-plane` routes on `codestra-integration-control-plane-api-1:8096` |
| legacy webhooks (`/v1/webhooks`) | `codestra-webhooks` | `codestra-middleware-event-gateway-1:8095` | legacy shared key |

The listener split (8080 / 8095 / 8096) is declared in
`boundaryRules.middlewareListenerSplit`; every governed service must target a
declared alias and every *new* governed route targets 8095. Consolidating the
n8n and provider-control routes onto 8095 is a coordinated change with the
Middleware repository (its validators pin the 8080 alias today).

## Direct provider and application bypass audit

| Target | Route(s) | Classification | Disposition |
| --- | --- | --- | --- |
| `scraper.internal.codestra.agency:8443` (readback) | `breero-production-api-route` | SECURITY_RISK — public catch-all straight to a scraper runtime | already fail-closed to `…-1:8095` in the inventory candidate; route `BLOCKED` until it has a contract |
| `10.40.0.3:8443` (readback) | `codestra-website-api-route` | SECURITY_RISK — hard-coded private IP | fail-closed to `…-1:8095`; legacy, `MOVE` |
| `codestra-kong-service-auth-adapter-1:8080` | `crm-route`, `sms-route` | LEGACY | `DEPRECATE`; retirement blocked pending consumer migration |
| `codestra-email-reseller-api-1:8080` | `email-route` | LEGACY provider adapter | `DEPRECATE` |
| `codestra-sms-api-api-1:8080` | `sms-dlr-telnexa-route` (Telnexa delivery receipts) | LEGACY provider adapter | `DEPRECATE`; successor is a signed-webhook policy into a Middleware inbox |
| `codestra-mail-api:8098` | `codestra-mail-api` | SECURITY_RISK — no authentication, admin path | `BLOCKED` (inventory `activationBlockedRoutes`) |
| `codestra-n8n-main:5678` | `codestra-n8n-editor-ui` | INTENTIONAL — browser UI of an application, not a command API | `PROPOSED`, `enabled: false`; reason recorded |
| `moneybee-api:8000` | `moneybee-account-bootstrap` | INTENTIONAL — product identity bootstrap; backend revalidates the JWT | source candidate; the gateway-platform example routes the same operation through Middleware and is the target model |
| `codestra-marketing/ai/communication/social:8000` | stage-4 fragment | TRANSITIONAL design, no auth, no host, no methods | `DESIGN_ONLY`, `REFACTOR` |
| `kong-test-upstream:8080` | `gateway-test-route` | REMOVE | `RETIRE_CANDIDATE`, `BLOCKED` |
| `identity-certification:8080` | `codestra-token-validation-certification` | TRANSITIONAL certification tooling | `DEPRECATE` |
| Odoo, n8n execution, Twilio/SendGrid/Telnexa APIs | none in any reviewed source | — | `directProviderRoutesAllowed: false`; the validator blocks provider markers and IP literals |

No reviewed source routes Kong → Odoo or Kong → n8n execution directly; both
are reached only through Middleware (`/api/v1/integrations/odoo/...`,
`/v1/integrations/n8n/...`).

## Idempotency boundary

`Idempotency-Key` is propagated unchanged. The intake, n8n command and calling
contracts require it on command routes (`400 missing_idempotency`); the
callback control route does not yet, which is recorded as a follow-up in the
audit. Middleware owns deduplication, conflict detection on a changed body and
retention; Kong keeps no ledger and never answers a replay itself. Kong retries
are `NONE` on every command service so a re-attempt can only originate from
the caller with the same key ([retry policy](retry-policy-v1.md)).

## Failure behaviour

An unreachable or failing Middleware listener yields the route's `502`/`503`/
`504`. There is no fallback to `8080` from `8095`, to the key-auth control
plane from the OIDC one, or to any provider. Upstream health is
`DNS_TARGET_PASSIVE` today (single target per service); active health checks
become mandatory before any multi-target upstream ([service registry](service-registry-v1.md)).
