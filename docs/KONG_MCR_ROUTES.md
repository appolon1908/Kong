# Kong MCR-J route contract

`config/kong-mcr-routes.v1.json` is the source authority for the 8 MCR
`/platform/v1` routes. It is source-only: `runtimeApplyAuthorized` and
`productionEffectsAuthorized` are both `false`.

## Routing

- Every route is on `api.codestra.co` and goes to the existing
  `middleware-integration-api:8095` service. Settings: `strip_path: false`,
  `preserve_host: true`, `path_handling: v0`. Kong retries on that service
  stay at `0`.
- `scripts/render_kong_mcr_routes.py --write` renders
  `config/kong-mcr-routes.production.yml` and
  `config/staging/kong-mcr-routes.staging.yml`. These are top-level route
  fragments that reference the service by name. They never declare a service,
  so they cannot add a second upstream or a direct provider route. `--apply`
  is refused.
- Every `pathRegex` must be anchored and must not be double-escaped. It must
  route the route's `probePath`. A literal template must equal the canonical
  `generate_middleware_routes.route_regex()` output.
- No MCR route may overlap any route in the pinned Middleware contract
  (`9c32daec…`, all classifications), in either direction. None may match
  `/internal/*`, `/metrics*`, the `private_only` Odoo surfaces, the denied
  routes, or a non-`klyrow:`/`whatsapp:` campaign namespace.

## Header normalization

Plugin chain: `pre-function` → `openid-connect` → `post-function` →
`correlation-id` → `rate-limiting` → `request-size-limiting`.

| Concern | Gateway behaviour |
| --- | --- |
| Authorization | Preserved. OIDC bearer checks audience `middleware-api`, the per-route scope and `consumer_claim: azp`. Middleware owns the azp and tenant decisions. |
| Required context | The `pre-function` guard rejects a missing required header with `400 {"error": "<code>_required"}` before `correlation-id` can mint a replacement. Middleware re-enforces the same headers. |
| Correlation | `X-Correlation-ID` must come from the caller and is echoed downstream. |
| Idempotency | `Idempotency-Key` is preserved, never retried by the gateway, and replayed only by Middleware. |
| Identity spoofing | The generated `post-function` clears the untrusted identity headers before it sets `X-Codestra-Contract-Operation` and `X-Codestra-Required-Scope`. |
| Body size | 1 MB. |

## Activation boundary

The three MCR files are excluded from foundation source discovery with a
recorded reason. They must be registered as foundation sources, with routes,
access classes and profiles, before any activation. No deploy, Admin API
mutation or provider effect is authorized by this contract.

## Validation

```text
python scripts/validate_kong_mcr_routes.py
python scripts/render_kong_mcr_routes.py --check
python -m pytest -q tests/test_kong_mcr_routes.py
```
