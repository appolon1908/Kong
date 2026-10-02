# Kong Mission 3 — Staging Apply Plan (source only, not executed)

This plan defines how the staging Kong runtime would be brought to the
Mission-2/Mission-3 candidate. **Nothing in this document is executed by
Mission 3.** No `deck sync`, no Admin API call, no container start, no
provider activation. `runtimeApplyAuthorized: false` and
`providerEffectsEnabled: false` remain true in every artifact until a
separately reviewed runtime change authorizes staging certification.

## 1. Candidate identity

| Item | Value / source |
| --- | --- |
| candidate `main` SHA | the protected `main` commit whose `release.yml` run produced `kong-release-<sha>` with `RELEASE_EVIDENCE=PASS`; recorded as `KONG_CERTIFIED_SOURCE_SHA` |
| candidate image | `ghcr.io/appolon1908/kong-standby-auth@<standby_auth_image_digest>` from that release manifest (never a tag) |
| Kong image | `kong/kong-gateway:3.14.0.1-ubuntu@<kong_image_digest>` from the same manifest (`KONG_IMAGE_DIGEST`) |
| release run | `KONG_CANDIDATE_RUN_ID`; `tools/verify_release_candidate.py` re-authenticates run, artifact digest, manifest sha256 and image digests before any promotion |
| evidence | `release-manifest.json` verified by `tools/verify_release_evidence.py`; `standby-sbom.spdx.json` and `standby-provenance.json` bound by sha256 |

## 2. Configuration to apply (staging environment only)

| Component | Source | Notes |
| --- | --- | --- |
| Kong node | `deploy/kong/compose.kong.yaml` | proxy `0.0.0.0:8000` reached only from Caddy (`KONG_TRUSTED_IPS` = exact Caddy source CIDR); Admin `127.0.0.1:8001`, Admin GUI off; status `0.0.0.0:8100` on the private network; Postgres over TLS with verification |
| Canonical Middleware edge | `config/staging/kong-middleware-routes.staging.yml` | generated from `config/kong-middleware-authority.v2.json`; 80 openid-connect routes on `api.codestra.co` → `middleware-integration-api:8095`, 10 denied aliases (404); staging issuer |
| Campaign overlay | `config/staging/kong-campaign-automation-routes.json` | jwt reconciler routes for campaign `TEST_SYN` only (transitional, superseded by the v2 routes; must not be co-applied with them — precedence declared in the foundation registry) |
| n8n control plane | `config/staging/kong-n8n-control-plane-routes.json` | `RETIRED_DENY_ONLY_STAGING`: not applied; the denied aliases answer 404 |
| Control plane | `deploy/kong/control-plane.yml` | `codestra-control-plane` service and routes (audience `codestra-control-plane`, `scope-policy.lua`) |
| Standby fixture | `deploy/kong-production-standby/compose.standby.yaml` | only with `KONG_STANDBY_AUTH_IMAGE_DIGEST` = the candidate digest; no build, no retag |
| Registry contract | `config/kong-release-registry-contract.v1.json` | image namespace and digest policy |

## 3. Identity and upstream prerequisites

| Prerequisite | Requirement |
| --- | --- |
| Keycloak issuer | `https://auth-staging.codestra.co/realms/codestra` (discovery + JWKS reachable from the Kong node); RS256 only; never the production realm |
| Certification identities | staging realm `test-syn-*` client-credentials clients only, one client per scope; no production client secret is present on the node |
| Middleware | `middleware-integration-api:8095` resolvable inside the staging stack (canonical alias); `appolon-middleware-integration-api:8080` must not resolve to any reachable service |
| Caddy → Kong | Caddy terminates TLS for `api.codestra.co` (staging edge) and forwards to Kong `:8000` with `X-Forwarded-*`; Kong trusts only `KONG_TRUSTED_IPS` |
| Admin API isolation | `127.0.0.1:8001` inside the container network namespace only; never published; changes go through `scripts/kong_admin_channel.py` under change authority |
| Redis | dedicated staging Redis for rate limiting (`{vault://env/kong-rate-limit-redis-password}`) |
| Database | dedicated staging Postgres, TLS verified, `kong_runtime` role with the least privilege in `operations/kong-database/roles.sql` |

## 4. Secrets required (names only; values never in Git)

`KONG_OIDC_CACHE_TOKENS_SALT`, `KONG_RATE_LIMIT_REDIS_PASSWORD`,
`KONG_CONTROL_PLANE_GATEWAY_SECRET`, `KONG_DB_STABLE_ENDPOINT`,
`KONG_TRUSTED_IPS`, `KONG_IMAGE_DIGEST`, `KONG_STANDBY_AUTH_IMAGE_DIGEST`,
`/run/secrets/kong_database_runtime_password`,
`/run/secrets/identity_registry_database_url`,
`/run/secrets/kong_standby_webhook_hmac`. All are provisioned on the staging
host through the environment/vault references in `deploy/kong/runtime.env.example`;
the repository holds only the names.

## 5. Health checks

- Kong status listener `:8100` (`/status`) on the private network — node readiness.
- Edge probes `/healthz`, `/readyz`, `/version` are Caddy-owned; no Kong route serves them.
- Authenticated `control-plane-health` (`/api/v1/health`, audience `codestra-control-plane`) — application health behind identity.
- Every upstream is a single DNS target (`DNS_TARGET_PASSIVE`): failure surfaces as the route's 502/503/504, never as a fallback.

## 6. Rollback artifact

- previous candidate: `rollback_source_sha` + `rollback_image_digest` + `rollback_configuration_sha256` from the release manifest / staging certification receipt;
- rollback procedure: `operations/runbooks/kong-production-rollback.md` (staging variant identical in mechanism), `scripts/rollback_kong_standby.py` for the standby fixture;
- a rollback is itself an apply under change authority; it never re-resolves a mutable tag.

## 7. Evidence capture

1. `tools/capture_kong_server_baseline.py` / `server-drift.yml` — read-only route readback before and after the apply (expected route count and inventory as pinned in `docs/evidence/`).
2. `runtime-certification.yml` on the `staging` branch — `tools/verify_release_candidate.py` (exact candidate), `tools/package_staging_certification.py` (observations → `certification.json`), published as `kong-staging-certification-<sha>-<attempt>`.
3. `release.yml` on `staging` — `staging-certified` release manifest bound to the candidate and the certification receipt (`PASS:<sha>:<identity>`), verified by `tools/verify_release_evidence.py`.

## 8. TEST_SYN restrictions

- Only campaign `TEST_SYN` and the staging `test-syn-*` identities may be exercised.
- `provider_effects_enabled: false`: no SMS, email, PSTN, social or Odoo side effect; standby delivery stays disabled.
- No production data, secrets or hostnames are present on the staging node.
- The policy-check route is production-only; no certification identity holds `n8n.policy.check`.

## 9. Staging negative certification plan (to be executed with the apply, not now)

| Case | Request | Expected | Enforced by |
| --- | --- | --- | --- |
| wrong issuer | bearer minted by the production realm (or any other issuer) on a v2 route | 401, constant body | openid-connect discovery issuer (staging realm only) |
| wrong audience | staging token with `aud` ≠ `middleware-api` on a `middleware-*` route | 401 | openid-connect `audience` |
| missing scope | staging token without the route's `scopes_required` | 403 | openid-connect `scopes_required` |
| wrong azp | token whose `azp` maps to no registered consumer / not the contracted client | 401/403 at Kong (consumer mapping) and 403 at Middleware (`X-Codestra-Expected-Azp`) | `consumer_claim: [azp]` + Middleware re-authorization |
| client-supplied identity header | valid token plus `X-Authenticated-Tenant`, `X-User-ID`, `X-Codestra-Scopes`, … | headers absent upstream; only gateway-minted `X-Consumer-*` and `X-Codestra-*` arrive | generated post-function `clear_header` strip |
| retired alias | `POST /v1/integrations/n8n/commands`, `GET /v1/integrations/n8n/operations`, campaign-action aliases | 404 `not found`, no upstream contact | `request-termination` denied routes |
| legacy Middleware :8080 | any route attempting `appolon-middleware-integration-api:8080` | no such canonical route exists; alias must not resolve | registry `RETIRED_DENIED_PR105`; `TRANSITIONAL_8080_ALIASES=0` |
| direct provider route | any path targeting a provider host | no route (404 from Kong) | `DIRECT_PROVIDER_ROUTES=0` |
| Admin API from the public edge | `https://api.codestra.co/…` to `:8001` paths, `/admin` on the proxy | unreachable (Admin bound to loopback; no proxy route) | `KONG_ADMIN_LISTEN 127.0.0.1:8001` |
| Middleware unavailable | stop `middleware-integration-api` in staging | 502/503 from the route, no fallback, no cached response | `DNS_TARGET_PASSIVE`, retries 0 |
| Keycloak / JWKS unavailable | block `auth-staging.codestra.co` from the node | protected routes fail closed (5xx/401 from openid-connect), never allow | openid-connect discovery/JWKS, no `anonymous` |

Every case records request, response status, response body hash (bodies are
constant), and the readback route matched, into the staging certification
observation set consumed by `tools/package_staging_certification.py`.

## 10. Exit criteria for staging certification (future mission)

`KONG_CANDIDATE_ARTIFACT=PASS` → apply under change authority → all negative
cases as expected → positive `TEST_SYN` flows as expected →
`kong-staging-certification-<sha>` published → `release.yml` on `staging`
produces `staging-certified` evidence → independent review. Only then does a
production promotion become a discussable change; it is not authorized by any
Mission-3 artifact.
