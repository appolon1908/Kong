# Repository Profile — `Kong`

## Identity

- **Repository:** `appolon1908/Kong`
- **Category:** Platform edge — API gateway
- **Visibility:** `private`
- **Default branch:** `main`
- **Authority:** Primary API gateway, route, service, plugin, and traffic-policy authority
- **Status:** Active gateway GitOps repository with route-drift and protected-apply controls.

## Purpose

Routes and protects platform APIs through authentication integration, authorization boundaries, rate limits, request validation, mTLS, observability, upstream policy, and declarative migrations.

## Owns

- Kong services, routes, plugins, consumers, upstreams, and migration manifests
- Gateway rate limits, request/response policy, mTLS, routing, and ingress observability
- Gateway configuration validation, drift review, apply evidence, and rollback source

## Does not own

- Application business logic or data
- Keycloak realm, client, role, or authentication-flow state
- Caddy public TLS/hostname configuration

## Key integrations

- Caddy
- Keycloak
- Middleware
- Product, provider, and internal APIs

## Current priorities

1. Keep routes synchronized with exact deployed Middleware and application APIs
2. Add OpenAPI/upstream contract tests and prevent authenticated routes from reaching 404s
3. Require immutable declarative configuration and exact-head drift review
4. Prove staging apply, read-back, rollback, rate-limit, auth, and mTLS behavior before production

## Governance and safety

- Promotion model: `feature/*` or `fix/*` -> reviewed `main` -> `staging` -> `production`, as defined in `docs/branch-governance.md`.
- Every apply must use the exact accepted configuration SHA and an independently reviewed drift plan.
- Never commit credentials, private keys, database dumps, provider secrets, or live token material.
- Merge is gateway source acceptance only; production apply remains separately approved.
- This document does not change routes, reload Kong, enable traffic, alter Keycloak, or deploy the gateway.

## Account-wide catalog

See `appolon1908/documentaions/REPOSITORY_CATALOG.md`.
