# Kong V3 Identity & API Security — PAS-148

## Purpose

PAS-148 defines Kong's final authentication/authorization policy for the frozen Middleware V3 contract without becoming a second route authority.

The route/upstream authority remains Lane A. Lane B owns the security projection only.

## Frozen authorities

- Middleware: `ingtrader21-spec/Middleware-@bd406a6508c8095a3f23b35149a2eebcb94c94c6`
- Middleware route digest: `9c32daecd4a15104c6f9ff60ce19c8f7e78707fb31d9fd9fcb55b1b8dfa3512b`
- Routes: **117 = 105 shared_edge + 10 denied + 2 private_only**
- Keycloak: `ingtrader21-spec/Keycloak@45a487d71a516ae3039b00c250752897469ffe7a`
- Canonical Middleware audience: `middleware-api`
- Runtime apply: **disabled**

Machine-readable authority:

- `config/kong-authentication-profiles.v1.json -> v3CallerAuthority`
- `config/kong-access-policy.v1.json -> v3MiddlewareSecurityAuthority`

## Caller authority

Kong recognizes exactly the 18 final Middleware caller selectors. No selector is treated as a wildcard AZP grant.

The catalogue distinguishes:

- concrete service clients;
- concrete human clients;
- reviewed client families;
- symbolic runtime selectors.

Service callers use short-lived `client_credentials` tokens. Human callers use Authorization Code + PKCE. Tokens are bounded to 300 seconds by the final authority.

For `CLIENT_FAMILY` and symbolic selectors, the selector name is policy metadata. A concrete token AZP must resolve to a reviewed member; the selector text itself is never accepted as a wildcard identity.

## service-or-user-jwt

The final Middleware contract contains 84 `service-or-user-jwt` operations.

Kong policy requires:

- service actor -> `client_credentials`;
- user actor -> `authorization_code` + PKCE;
- exact environment issuer;
- contracted audience;
- reviewed AZP / caller-family membership;
- exact route scope;
- token tenant claim as authority;
- expiry and <=300 second lifetime;
- role/MFA evidence when the operation is privileged.

Business/resource authorization remains revalidated by Middleware.

## Platform command scopes

The final privileged V3 scopes are:

- `platform.command`
- `platform.command.read`
- `platform.command.replay`

They may not become realm defaults, Kong wildcard grants, or implicit route defaults.

## Replay boundary

`POST /platform/v1/operations/{operation_id}/replay` is stricter than the general platform-command family.

It requires all of:

- caller family: `platform-command-client`;
- actor: **user only**;
- grant: Authorization Code;
- PKCE;
- scope: `platform.command.replay`;
- realm role: `platform-operator`;
- MFA evidence;
- service replay: **forbidden**.

Removing any one of these requirements must fail validation.

## Header spoofing prevention

Client-supplied identity and Kong-consumer headers are not authority.

Before trusted propagation, the V3 policy requires stripping or overwriting headers including:

- `X-Authenticated-*`;
- `X-Consumer-*`;
- `X-Credential-Identifier`;
- `X-Anonymous-Consumer`;
- `X-Codestra-Tenant`;
- `X-Codestra-Scopes`;
- `X-Codestra-Contract-Operation`;
- `X-Codestra-Expected-Azp`;
- `X-Codestra-Required-Scope`;
- legacy user/role/admin identity headers.

`X-Tenant-ID` remains a selector only and must be compared with the token tenant claim. It is never identity authority.

## Negative matrix

PAS-148 fails closed on:

- wrong issuer;
- wrong/wildcard audience;
- unknown AZP or unreviewed caller-family member;
- missing/wrong/wildcard scope;
- missing required role;
- tenant mismatch;
- missing MFA;
- wrong actor grant type;
- expired or overlong token;
- replay boundary downgrade;
- spoofed identity headers.

Authentication failures never downgrade the request to public access.

## Validation

Standalone policy validation:

```text
python scripts/validate_kong_v3_identity_security.py
```

Cross-repository exact-source validation:

```text
python scripts/validate_kong_v3_identity_security.py \
  --middleware-contract <Middleware>/deploy/public-api-route-contract.json \
  --keycloak-callers <Keycloak>/config/contracts/middleware-caller-classification.v1.json \
  --keycloak-access <Keycloak>/config/contracts/middleware-api-access.v3.json
```

Required success markers:

```text
KONG_V3_IDENTITY_SECURITY=PASS
ROUTES=117
SHARED_EDGE=105
DENIED=10
PRIVATE_ONLY=2
CALLER_SELECTORS=18
UNKNOWN_CALLER_IDENTITIES=0
SERVICE_OR_USER_ROUTES=84
ISSUER_AUDIENCE_AZP_SCOPE_NEGATIVE_MATRIX=PASS
SERVICE_OR_USER_JWT_MATRIX=PASS
REPLAY_NEGATIVE_PATH=PASS
HEADER_SPOOFING_PREVENTION=PASS
PRIVILEGED_DEFAULT_GRANTS=0
RUNTIME_APPLY_AUTHORIZED=false
```

## Lane boundary

PAS-148 does not edit:

- generated Middleware route YAML;
- the vendored Middleware route contract;
- canonical route/upstream authority;
- gateway foundation;
- workflows;
- migration manifests;
- runtime/provider activation.

If the eventual Lane A generated runtime does not satisfy this security authority, that is an integration dependency for the ordered A -> B convergence, not permission for Lane B to modify Lane A files.
