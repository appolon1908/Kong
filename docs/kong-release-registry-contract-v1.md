# Kong Release Registry Contract V1

Machine-readable: `config/kong-release-registry-contract.v1.json`, loaded by
`tools/release_contract.py`; enforced statically by
`scripts/validate_release_supply_chain.py` (CI: `validate.yml`) and at run time
by the contract-binding step of `.github/workflows/release.yml` and
`.github/workflows/release-preflight.yml`.

## Registry, namespace, package

| Field | Value | Rule |
| --- | --- | --- |
| registry | `ghcr.io` | GitHub Container Registry only |
| namespace | `appolon1908` | `lower(GITHUB_REPOSITORY_OWNER)` of the repository that runs the workflow; a literal owner never appears in a workflow or tool |
| package | `kong-standby-auth` | the standby auth image built from `deploy/kong-production-standby/auth-middleware/Dockerfile` |
| image | `ghcr.io/appolon1908/kong-standby-auth` | `registry/namespace/package` |
| repository | `appolon1908/Kong` (id `1347790742`) | former names `appolon1908-hue/Kong` and `ingtrader21-spec/Kong` are HTTP 301 redirects; the package namespace follows the current owner |

Why derived, not hard-coded: a repository-scoped `GITHUB_TOKEN` can publish only
into its owner's namespace. The pre-transfer literal produced
`permission_denied: The requested installation does not exist` on every push
to `main`. The workflows now prove `GITHUB_REPOSITORY == repository.fullName`
and `lower(GITHUB_REPOSITORY_OWNER) == registry.namespace` *before*
`docker login`; a future transfer stops the release instead of publishing to
a stale namespace.

## Identities

| Role | Identity | Notes |
| --- | --- | --- |
| writer | `GITHUB_TOKEN` of `release.yml` on push to `main` (authoritative candidate) and of `release-preflight.yml` on same-repository pull requests (preflight only) | `permissions: contents: read, packages: write`; `docker login ghcr.io --username "${GITHUB_ACTOR}"` with `github.token` |
| reader | `GITHUB_TOKEN` of the promotion (`release.yml` on `staging`/`production`), certification (`runtime-certification.yml`) and drift workflows; the staging/production deploy identity | readers consume `image@sha256:<digest>` only; the deploy credential is provisioned outside Git |
| forbidden | personal access tokens, shared/universal registry credentials, fork pull requests | `secrets.` never appears in a release workflow; `release-preflight` refuses head repositories other than the contract repository |

## Tag policy and digest authority

| Tag | Producer | Promotable | Meaning |
| --- | --- | --- | --- |
| `sha-<40 hex>` | `release.yml` on protected `main` | yes | the authoritative candidate; staging and production reuse its digest byte for byte |
| `preflight-sha-<40 hex>` | `release-preflight.yml` on a pull-request head | never | proof of build/publish/digest/SBOM/provenance capability before merge; `tools/verify_release_candidate.py` refuses it |
| `latest`, `main`, `staging`, `production`, `stable`, any other mutable tag | — | forbidden | `mutableTagsAllowed: false`; the static gate fails on their presence |

The digest authority is the OCI image index digest reported by buildx
(`containerimage.digest`), re-read from the registry with
`docker buildx imagetools inspect` and required to be identical
(`LOCAL_DIGEST == REMOTE_DIGEST`). Every consumer — the release manifest,
`compose.standby.yaml`, promotion — references `image@sha256:<digest>`.

## Attestations

- Provenance: BuildKit SLSA provenance (`--provenance=mode=max`) attached to the
  published index; extracted to `standby-provenance.json`; `buildType` must be
  BuildKit and, when VCS metadata is present, `revision` must equal the source SHA.
- SBOM: BuildKit SPDX attestation (`--sbom=true`); the SPDX document is extracted to
  `standby-sbom.spdx.json` and its sha256 is bound in the release manifest.
- GitHub artifact attestations are not used: they would require `id-token: write`
  and `attestations: write`, and the BuildKit attestations already bind builder,
  source revision and digest.

## Retention, promotion, rollback

- Release evidence artifacts: 90 days (`kong-release-<sha>`), preflight evidence 30 days.
- Authoritative image versions are never deleted or retagged by automation; preflight
  versions may be pruned by a repository administrator, never by a workflow token.
- Promotion: `tools/verify_release_candidate.py` binds the certified main run id,
  artifact digest, manifest sha256 and image digests; no rebuild, re-resolve or retag.
- Rollback reference: `rollback_source_sha` in the release manifest plus the previous
  candidate's image digest and configuration sha256 recorded by the staging certification.

## Production authorization boundary

No release evidence authorizes a runtime apply. `runtimeApplyAuthorized: false`
and `providerEffectsEnabled: false` are asserted by the contract loader, the
evidence verifier and the static gate; deployment remains a separately reviewed
change with its own runtime certification.
