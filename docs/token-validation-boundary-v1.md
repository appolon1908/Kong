# Token Validation Boundary V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).

Keycloak (`appolon1908/Keycloak`) is the identity authority: it issues
tokens, owns users, passwords, MFA and clients. Kong is the gateway validation
point: it verifies a presented token against the realm and enforces the
route's audience and scope prerequisites. Middleware makes the business
decision. Kong implements no custom JWT cryptography — every signature check is
the bundled `openid-connect` (discovery + JWKS) or `jwt` (RS256 credential
provisioned from the realm's live JWKS by the reconcilers) plugin; the Lua claim
guards only read claims from a token a plugin has already verified.

## Realms per environment

| Environment | Issuer | Discovery |
| --- | --- | --- |
| production | `https://auth.codestra.co/realms/codestra` | `…/.well-known/openid-configuration` |
| staging | `https://auth-staging.codestra.co/realms/codestra` | `…/.well-known/openid-configuration` |
| development | none checked in; a local realm chosen at render time | — |

The validator refuses a staging source that binds the production issuer (and
vice versa), refuses a shared issuer between the two, and the integration
compiler enforces the same coupling per integration
(`issuer_environment_mismatch`). The gateway-platform example previously
declared `environment: staging` with the production issuer because the
integration schema pinned that issuer as a constant; both are fixed.

## Validation stages on a protected route

| Stage | Enforced by | Failure |
| --- | --- | --- |
| signature | `openid-connect` (JWKS from discovery) or `jwt` (RS256 public key per `azp` credential) | `401` |
| issuer | `openid-connect` discovery binding; claim guards compare `iss` exactly | `401 invalid_issuer` |
| expiration / time claims | `openid-connect`; `jwt` `claims_to_verify: [exp]`; `codestra-authz` also checks `nbf`, `iat` and rejects non-finite values | `401` |
| audience | `openid-connect` `audience: [...]`; claim guards check `aud` (string or array) for the route audience | `401 invalid_audience` |
| authorized party (`azp`) | `openid-connect` `consumer_claim: [azp]` maps to a registered consumer; guards check `azp` ∈ the parties holding the route scope | `403 service_identity_denied` / `unauthorized_identity` |
| required scope | guards check the route scope in the space-separated `scope` claim (`openid-connect` `scopes_required` where used) | `403 insufficient_scope` |
| tenant / campaign / role | guards check `tenant` / `tenant_id`, `campaign_ids`, `realm_access.roles`, `environment` claim on staging identities | `403` |
| transport | guards require the forwarded scheme `https` from the trusted edge | `426 https_required` |

A missing, malformed, expired, wrong-issuer or wrong-audience credential is
`401`; a valid credential lacking the scope, party, tenant or role is `403`.
There is no anonymous consumer, no `config.anonymous`, no downgrade to public
access, and the guards deny (`403 route_scope_undefined`) any path they do not
recognize before minting identity headers.

## Audience boundary

A token minted for one audience is not valid for another Kong service. The
registry records the audience per route and the validator requires one on
every token-authenticated route:

| Audience | Routes | Mechanism |
| --- | --- | --- |
| `codestra-control-plane` | control-plane candidate (7 routes) | `openid-connect` service plugin + `scope-policy.lua` |
| `codestra-callback-api` | callback read/control | `jwt` + claim guard |
| `codestra-middleware` | campaign automation (5 routes; staging overlay uses the same audience on the staging realm) | `jwt` + claim guard |
| `middleware-api` | n8n control plane, calling contract, prepared provider-control routes, community-n8n egress proposal, cell design | `jwt`/`openid-connect` + guard |
| `sdk-intake` | intake leads / survey responses | `openid-connect` + `jwt` + guard — **audience equals the client id**; this is contractually defined by `requiredClientId` in `config/kong-intake-routes.json` and verified exactly by the reconciler, and is recorded as the accepted finding `AUDIENCE_IS_CLIENT_ID` rather than assumed |
| `moneybee-api` | MoneyBee bootstrap (`azp` must be `moneybee-borrower`, `email_verified` required) | `openid-connect` + `moneybee-identity-policy.lua` |
| `codestra-api` | private standby routes (validated by the standby auth middleware behind `ip-restriction`) | RS256 in the auth middleware |

`client_id == audience` is never assumed elsewhere: n8n (`n8n-automation` →
`middleware-api`), provider control (`codestra-ai` etc. → `middleware-api`) and
MoneyBee (`moneybee-borrower` → `moneybee-api`) all separate the two.
`kong/plugins/oidc/keycloak.yml` (`middleware-api`) is a template, never a
global plugin, precisely so that it cannot make every route accept
`middleware-api` tokens.

## Scope boundary

Scopes are gateway *prerequisites*, not permissions. Reaching
`POST /v1/telephony/commands` requires `telephony:command`; whether a specific
command on a specific campaign is allowed is Middleware's decision. The
registry lists `requiredScopes` per route (or `scopeAuthority` for the
path-family policy in `scope-policy.lua`), the source contract's scope must be
registered, and forbidden scopes (`odoo.campaign.control.write`) are refused for
every consumer by the campaign contract.

## Consumers and credentials

Consumers exist only as the target of `consumer_claim: [azp]` /
`key_claim_name: azp`; no credential material is in Git. The reconcilers
provision each consumer's RS256 credential from the realm's live JWKS
(`--jwks-url`) under change authority. Legacy `key-auth` consumers are
`LEGACY` and cannot be promoted.

## What remains runtime certification

Live token matrices (valid, expired, wrong issuer, wrong audience, wrong party,
missing scope, wrong tenant) are exercised by `tools/kong_certification.py`
plans and the Middleware repository's `certify_edge_integration` gate; this
document defines the contract they test, not evidence that they passed.
