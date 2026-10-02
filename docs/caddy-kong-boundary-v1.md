# Caddy → Kong Boundary V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Companion to `docs/CADDY_EDGE_AUTHORITY.md` (repository ownership). This document
formalizes the edge contract Kong relies on; it does not redesign Caddy, and it
authorizes no runtime change.

```text
Internet
  │  public TLS, hostnames, certificates, HTTP→HTTPS, edge logging   (Caddy, appolon1908/Caddy)
  ▼
Caddy (host process)  ──plain HTTP──▶  127.0.0.1:8000  (published Kong proxy listener, host loopback only)
                                            │
                                            ▼
                                   Kong proxy 0.0.0.0:8000 inside the container
                                   trusted_ips = exact Caddy source CIDR (KONG_TRUSTED_IPS, no default)
                                            │
                                            ▼
                                   route → prerequisites → approved upstream
```

## Listener and network

| Item | Contract | Enforced by |
| --- | --- | --- |
| Proxy listener | `KONG_PROXY_LISTEN=0.0.0.0:8000` inside the container, published only as `127.0.0.1:8000` on the host for Caddy | `validate_node`: every published port binds host loopback |
| Admin / Manager / Status | never reachable from Caddy or the Internet: Admin `127.0.0.1:8001` container loopback, Manager off, Status 8100 unpublished on the private observability network ([admin boundary](admin-boundary-v1.md)) | `validate_node` |
| Networks | `codestra_edge` (Caddy-facing alias `codestra-kong`), `codestra_backend` (upstreams, Redis, database), `codestra-observability` (alias `kong`); all external, none created by the gateway compose | `validate_node`: every network is external |
| Public ports | 80/443 are owned by Caddy; Kong opens none | `config/codestra-kong-cells.v1.json` public_edge, compose ports |

## Trusted proxy and forwarded headers

Kong must not treat every caller as Caddy. `KONG_TRUSTED_IPS` is required from
the deployment with no default (`${KONG_TRUSTED_IPS:?...}`) and must be the
exact source address Caddy connects from — the Docker bridge gateway of the
edge network, or `127.0.0.1` when Kong listens on the host loopback. Never
`0.0.0.0/0`: that would let any client assert `X-Forwarded-Proto: https`.

| Header | From a trusted source (Caddy) | From any other source |
| --- | --- | --- |
| `X-Forwarded-For` | consumed recursively (`real_ip_header`, `real_ip_recursive=on`) to identify the client for rate limits keyed by IP and for logs | ignored; the TCP peer is the client |
| `X-Forwarded-Proto` | honoured by `kong.request.get_forwarded_scheme()`; the control-plane and calling claim guards reject anything but `https` with `426` | ignored; the real scheme (`http`) is reported and every guarded route answers `426` |
| `X-Forwarded-Host` | honoured for forwarded-host readback only; routing uses the `Host` header Caddy preserves | ignored |
| `Forwarded` (RFC 7239) | not used by any reviewed policy | ignored |
| Client identity headers (`X-Authenticated-*`, `X-Tenant-ID` as identity, `X-Consumer-*`, `X-Codestra-*`) | stripped by the claim guards / `codestra-request-context` before any upstream sees them; only the gateway mints them after successful authentication | same — never trusted from any source |

Because `KONG_HEADERS=off`, Kong never advertises itself or its version to
the public client.

## Correlation propagation

| Header | Behaviour |
| --- | --- |
| `X-Correlation-ID` | canonical routes carry `correlation-id` (uuid generator, `echo_downstream`): a caller value that passes validation is preserved, otherwise one is generated; the calling contract additionally *requires* a caller value via the `pre-function` guard (`400 correlation_id_required`) |
| `X-Request-ID`, `traceparent` | `codestra-request-context` (gateway-platform topology) validates the W3C format strictly (version `00`, lowercase hex, non-zero ids, flags `00`/`01`) and generates a trace context when absent; malformed values are rejected with `400`, so arbitrary client values never poison logs |
| `tracestate` | passed through untouched where present; not emitted by Kong |
| `Idempotency-Key` | propagated unchanged; required on declared command routes; Middleware owns the ledger ([Kong → Middleware](kong-middleware-boundary-v1.md)) |

Caddy's own request logging redacts identity material (Caddy repository
responsibility); Kong logs the correlation id, route, service, method, path,
status and latency on the proxy access log.

## TLS expectation between edge and gateway

The Caddy → Kong hop is plain HTTP on the host loopback / edge bridge; TLS
terminates at Caddy. This is acceptable only because both endpoints are on the
same host and the hop never leaves the private edge network; Kong compensates
by trusting the forwarded scheme solely from `KONG_TRUSTED_IPS` and by failing
closed (`426`) on guarded routes when the forwarded scheme is not `https`. If
Caddy and Kong are ever split across hosts, the private balancer contract in
`deploy/gateway-platform/network-boundaries.yaml` applies (TLS proxy listeners
on 8443 with `tls_verify: true`).

## Health behaviour

| Probe | Owner |
| --- | --- |
| `/healthz`, `/readyz`, `/version` on `api.codestra.co` | edge-owned: Caddy answers from the websocket gateway; there is no Kong route (`config/kong-public-readonly-canary.v1.json`, `edgeOwnedPaths`) and the validator rejects any Kong route that claims these paths on the canonical host |
| Kong node health | container healthcheck `kong health`; Status API `/status` on the private 8100 listener for observability |
| Application health | `GET /api/v1/health` on the control plane is an authenticated application health route, not an edge probe |

When Kong is unhealthy Caddy receives a connection error or 502 and returns
its own controlled error; Caddy must never fall back to a non-Kong upstream
for a governed API host.

## Failure behaviour at the boundary

| Condition | Kong response | Caddy behaviour |
| --- | --- | --- |
| no route matches | `404 {"message":"no Route matched with those values"}` | pass through |
| route prerequisites fail | `401`/`403`/`413`/`426`/`429` from the failing plugin | pass through |
| upstream unreachable / timeout | `502`/`503`/`504` | pass through; no retry to another upstream |
| rate-limit Redis unreachable | `500` (fault_tolerant false: fail closed) | pass through |

## Runtime certification still required

This repository proves the configuration above statically. The live
Caddy→Kong hop (exact `KONG_TRUSTED_IPS`, `426` on forged scheme, header
stripping, network isolation, peer-network Admin denial) is certification
evidence gathered under `docs/KONG_RUNTIME_CERTIFICATION.md`; nothing here
claims it was observed.
