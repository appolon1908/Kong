# Communications Platform Gateway Authority

`appolon1908/Kong` is the principal API gateway and security-policy authority for the Codestra communications platform.

## Kong owns

- public/private API route definitions;
- JWT/OIDC validation policy;
- audience, scope and route authorization policy;
- consumer/service authentication policy;
- rate limits, quotas and traffic protection at the gateway layer;
- request-size and protocol policy where gateway-owned;
- upstream routing to Middleware/private services;
- gateway observability, reconciliation and rollback;
- exact gateway compatibility tests.

Kong does not own communications business logic, provider credentials, provider delivery state or provider runtime source.

## Required path

```text
Client/SDK
  -> Caddy
  -> Kong
  -> Middleware
  -> Klyrow/Telnexa/VICIdial provider boundary
```

Kong must not expose direct public routes that allow an SDK/browser to bypass Middleware for privileged communications mutations.

## Principal related repositories

- `Middleware-` — cross-system write/control authority
- `SDK-repository` — developer-facing contracts and clients
- `communication-platform-` — architecture/coordination authority
- `Keycloak` — identity authority
- `Caddy` — public TLS edge authority
- `klyrow.com` — email runtime
- `telnexa` — SMS runtime
- `Vicidialer-Codestra` — voice runtime
- `Infustruction-repo` — shared infrastructure/deployment topology

## Communications route policy

Public communications APIs should terminate at governed Middleware endpoints. Provider-local administration APIs remain private and must not be republished through Kong as general customer APIs.

Expected route families may include provider-neutral communications paths such as:

```text
/v1/communications/messages
/v1/communications/templates
/v1/communications/channels
/v1/communications/suppressions
/v1/communications/preferences
/v1/communications/reputation
/v1/communications/providers/health
```

Exact paths are contract-owned by `SDK-repository`/Middleware and must be added to Kong only after contract review.

## Identity contract

Before production cutover, Keycloak, Kong and Middleware must agree on one caller-token model. Kong must validate the intended issuer, audience and scopes without transforming caller identity into a token shape Middleware rejects.

Required proof:

- valid service token succeeds on only allowed routes;
- invalid issuer/audience/signature fails;
- missing required scope fails;
- tenant spoofing fails;
- expired token fails;
- browser/user and machine-client flows remain distinct where required;
- Middleware receives enough original identity context to revalidate authorization consistently.

## Traffic controls

Communications endpoints should have route-specific controls for:

- request/body size;
- send rate and burst rate;
- tenant/client quotas where enforceable at gateway;
- abuse-sensitive bulk endpoints;
- webhook ingress restrictions;
- private/mTLS-only provider callback paths when applicable;
- deterministic correlation headers;
- safe logging that excludes secrets and message bodies where sensitive.

## Release rule

A route merge is not production activation. Live Admin API reconciliation, traffic cutover or policy activation requires separate exact-head approval and rollback evidence.
