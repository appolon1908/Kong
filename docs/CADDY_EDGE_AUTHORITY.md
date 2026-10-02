# Caddy-to-Kong Authority Boundary

## Decision

`appolon1908/Caddy` is the principal source repository for shared Codestra Caddy edge configuration.

`appolon1908/Kong` is the principal source repository for Kong gateway services, routes, plugins, OIDC/JWT policy, rate/body/route enforcement, gateway reconciliation and the compatibility contract Caddy must satisfy when forwarding governed API ingress.

Kong does **not** own Caddy source merely because Caddy forwards traffic to Kong.

## Architecture

```text
Internet / private ingress
        |
        v
Caddy   -- principal repo: appolon1908/Caddy
        |  TLS, host, network edge, reverse proxy, log redaction
        v
Kong    -- principal repo: appolon1908/Kong
        |  OIDC/JWT, ACL/scope, rate/body/route policy
        v
Middleware
           tenant/actor revalidation, durable command/write authority
```

Keycloak is the identity authority. Caddy must not manufacture trusted service identity. Kong validates the reviewed Keycloak token/policy for the gateway route, and Middleware independently revalidates the identity/tenant authorization needed for privileged commands.

## Historical reference

`appolon1908/codestra-production-platform` is historical runtime/deployment/reconciliation/rollback evidence only.

The reviewed historical baseline:

```text
release/production-activation:operations/caddy/api.codestra.co.caddy
```

has been imported into `appolon1908/Caddy` with provenance recorded. The old copy remains historical evidence and is not the place for new Caddy feature development.

## Kong responsibilities for the boundary

Kong source may and should validate the assumptions it requires from Caddy, including:

- the intended upstream listener/route boundary;
- preservation of the bearer token required for Kong/ Middleware validation;
- request-size and transport expectations;
- no caller-controlled trusted identity-header bypass;
- no public exposure of Kong Admin;
- health/readiness route compatibility;
- failure behavior when gateway policy rejects a request.

Those compatibility tests do not turn Kong into the Caddy source repository.

## Change rule

If a change is primarily a Caddy concern (TLS site block, reverse proxy target, Caddy request policy, Caddy log redaction, Caddy modules or Caddy release/reload behavior), change `appolon1908/Caddy`.

If a change is a Kong concern (service/route/plugin/OIDC/scope/rate-limit/gateway reconciliation), change `appolon1908/Kong`.

If both change, use coordinated PRs and versioned compatibility evidence; do not duplicate either implementation in the other repository.

## Runtime migration

No live traffic or Caddy file is changed by this document. Before the Caddy repository becomes runtime-authoritative for a host, perform read-only inventory, checksum reconciliation, complete config validation, staging Caddy→Kong/Middleware tests, rollback rehearsal, controlled reload and post-change read-back.
