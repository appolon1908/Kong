# Kong Admin isolation and immutable promotion

Source repair for issues #6, #49, #52 and #58, following the two unresolved
reviews on merged PR #64. This document authorizes no runtime change.

## Private management path

The data plane keeps its existing host-loopback `127.0.0.1:8000` binding for
Caddy and its designated edge, backend and observability networks. The Admin
listener is **container-loopback** `127.0.0.1:8001`; there is no published Admin
port. Manager is explicitly disabled. A loopback *host* port mapping alone
would not prevent a peer on a shared Docker bridge reaching a wildcard
container listener.

`tools/capture_kong_server_baseline.sh` delegates to the Python capture tool.
An already authorized local operator can run it through the existing Docker
operator boundary. It selects only the Compose service, runtime identity,
port bindings and two Admin listener settings, then executes bounded `curl`
GETs inside that exact running `kong-gateway` container. The local Unix daemon
is explicit; caller Docker contexts/DOCKER_HOST cannot redirect the capture.
No shell, arbitrary Admin URL, credential endpoint, mutation verb, privilege
change, extra container, or TCP management exposure is introduced. The selected
runtime must already contain curl; missing tooling is a failure, not permission
to install anything. This repository does not grant Docker/socket/sudo access.

Only status, routes, services and each route's plugin names are read. Plugin
configuration is never written to the output; raw Admin replies are not saved.
Collections exceeding the bound or requiring pagination, duplicate routes,
missing services, non-200 replies, and changed container identity fail closed.
A successful result is atomically written as a private file. The default route
contract is the committed v2 successor with 27 routes; `--expected-route-count
29` permits an explicit historical-baseline capture, not v2 certification.

Readback v2 labels Admin as `CONTAINER_LOOPBACK_CONFIGURED` and explicitly reports
`peerNetworkDenialVerified=false`. This is configuration and bounded GET evidence,
not a live peer-network denial test, an atomic multi-resource snapshot, complete
plugin-value parity, or deployment authorization. Existing dated v1 evidence is
preserved unchanged; it is not a new runtime observation. The production-read-only
workflow runs only reviewed protected branches on the designated Kong runner and
still requires its environment gate.

## Operational clients use the same private channel

Removing the published Admin port also removes it from the host-side operators
that used to dial `http://127.0.0.1:8001`. `scripts/kong_admin_channel.py` is the
single private path they now share. It verifies the running `kong-gateway`
container exactly as the read-only capture does: runtime identity, Compose
service, no host or shared network namespace, container-loopback Admin listener,
disabled Manager and no published Admin port binding. It then runs one bounded
`curl` inside that existing namespace over the pinned local Docker socket.

Only `GET`, `POST`, `PATCH` and `DELETE` are offered, against checked Admin
paths. There is no shell, redirect following, arbitrary URL or credential
endpoint. Write bodies travel on stdin, so service, route and plugin payloads
never reach argv or the host process table. Replies are bounded, non-2xx
statuses fail closed with the method, endpoint path and status only, and `confirm_unchanged()` re-verifies
the container before a client reports PASS, so a replaced runtime fails instead
of being silently adopted.

`scripts/apply_kong_standby.py` and `scripts/rollback_kong_standby.py` route every
Admin call through that channel and keep their existing ownership, tagging,
read-back and rollback contracts unchanged. The monthly root restore rehearsal
reads the live services, routes and plugins inventory inside the verified gateway
container and keeps its pagination-safety checks; the isolated restore gateway it
creates still uses its own private-network endpoint, which was never published on
the host. The standby applier's data-plane synchronization probe continues to use
the retained `127.0.0.1:8000` proxy publication.

This is a source change to management paths only. It grants no Docker, socket or
sudo access, and authorizes no runtime mutation.

### Direct transport and collection validation

The explicitly selected HTTP(S) Admin transport used by isolated runners shares
the private channel's method, payload encoding, status and JSON-object checks.
It binds every request and pagination reference to the selected origin, rejects
userinfo and non-root Admin base URLs, refuses redirects, and disables inherited
HTTP proxies. HTTPS certificate verification remains enabled. These choices use
the standard-library [urllib handler interfaces](https://docs.python.org/3.12/library/urllib.request.html).
Response reads are limited to 2 MiB plus one overflow-detection byte. Request
bodies retain canonical form booleans or explicit JSON encoding as selected by
the client. A failed GET or an empty/non-object GET response cannot become an
empty successful inventory.

Neither raw Admin error bodies, query parameters, untrusted HTTP reason text nor
actual/expected plugin configuration values belong in diagnostic messages.
Drift errors identify the mismatched field and support set-valued comparisons.

Canonical, callback, n8n and export inventory pagination validates every page and
entity, detects repeated normalized references and duplicate entity IDs, and
stops after 100 pages or 10,000 rows. A malformed page or exceeded bound fails the
operation; it is never accepted as an empty or complete inventory. This remains
bounded read-back, not an atomic snapshot or proof of staging certification.

## Build on main, promote the same bytes

The canonical `.github/workflows/release.yml` builds the standby image and resolves
the upstream Kong digest **only on protected main**. The image namespace is not a
literal: `tools/release_contract.py` derives `ghcr.io/<repository owner>/kong-standby-auth`
from `config/kong-release-registry-contract.v1.json` and the workflow proves the
running repository matches it before `docker login` (the repository was transferred
from `appolon1908` and the stale namespace made every publication fail). The
build is verified (`tools/verify_standby_image.py`) before it is published with
BuildKit provenance and SBOM attestations, the registry digest is re-read and must
equal the built digest, the attestations are extracted, and the release manifest is
verified against `config/kong-release-evidence-contract.v1.json`
(`tools/verify_release_evidence.py`). Pull requests exercise the same path through
`.github/workflows/release-preflight.yml`, publishing only the non-promotable
`preflight-sha-<sha>` version. Staging/production may not rebuild, re-resolve a
mutable tag, or retag the candidate. Their protected environment must supply all of:

- `KONG_CERTIFIED_SOURCE_SHA`: the original accepted main commit actually certified;
- `KONG_CANDIDATE_RUN_ID`: the successful canonical main release run for that commit;
- `STAGING_CERTIFICATION`: `PASS:<same-source-sha>:<evidence-identity>` from completed
  isolated staging, not a fabricated placeholder.

The candidate fetcher verifies the canonical workflow path, same repository/head
repository, main branch, source SHA, allowed event, completed successful run, and
GitHub's verified source commit. It requires one unexpired artifact with the exact
candidate name and a SHA-256 digest; verifies the ZIP bytes against that digest;
reads only the bounded manifest without extracting or executing contents; and
rejects unsafe members, unresolved digests, wrong repositories/images and stages.
The authenticated API/Actions artifact is the trust source, not a self-declared
local file. Missing/expired evidence requires a separately reviewed release step;
there is no automatic rebuild fallback in promotion.

A destination merge/squash/rebase commit normally has a different SHA. The release
manifest preserves `source_sha` and the original image/configuration/rollback tuple,
records `promotion_sha` separately, and requires **exact Git-tree equality**, current
manifest/config hashes, and original candidate-manifest hash/run/artifact identity.
A changed merge result, including an extra file, is rejected. Staging PR admission
also compares its synthetic merge tree with the tested current-main tree rather
than incorrectly requiring identical commit history. These checks do not bypass
independent review or current-head/merge-result CI.

The images must remain registry-readable at their original digests. A protected
certification identifier is an operator-owned evidence reference, **not a
cryptographic proof that staging tests ran**; emitted evidence labels this
`PROTECTED_ENVIRONMENT_REFERENCE_ONLY`. Live route/authentication/tenant/mTLS
negative tests, peer-network denials, recovery/rollback rehearsal, and one-percent
read-only canary acceptance remain separate requirements. Runtime integration
still requires healthy Caddy/Kong/Middleware/Redis on their designated networks.

Both `runtime_apply_authorized` and `external_effects_enabled` remain false in
release manifests. None of these scripts enables email, SMS, telephony, provider
traffic, Odoo writes, n8n delivery or production activation. Never populate protected
variables until their actual immutable candidate and staging evidence exist.

## Validation boundary

Repository tests use synthetic Git histories, Actions metadata and Admin replies.
They exercise normal/squash/rebase promotion, changed tree/digest/config/rollback,
wrong/failed/forked releases, missing/ambiguous/expired artifacts, checksum mismatch,
unsafe archive members, private listener configuration, response limits and route
inventory failures. Passing these tests is source correctness evidence, not a
live deployment or completed production certification.
