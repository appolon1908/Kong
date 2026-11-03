# Governance Git hooks

These hooks run the shared control-plane verifier before a push. Setup is an
explicit opt-in for each clone. Check out the approved development worktree and
branch, preserve existing work, and satisfy the repository's own entry rules
before enabling hooks. The setup script does not create a worktree or change
canonical-worktree authority.

The prerequisites are Git, Bash, Python 3, the Python `psycopg2` package, access
to the control-plane PostgreSQL database, and an assigned workstation with an
active lease owned by your agent. Install dependencies through your approved
environment setup. The hook does not install packages or provision access.

Ensure these reviewed files are present and executable, then opt in:

```sh
chmod +x .githooks/pre-push .githooks/codestra-pre-push \
  .githooks/codestra-push-check.py scripts/setup-governance-hooks.sh
./scripts/setup-governance-hooks.sh
```

Setup refuses a different effective `core.hooksPath` and any executable,
non-sample hook in Git's default hooks directory. Reconcile and preserve those
hooks before trying again. It runs executable `scripts/agent_preflight.sh`
without arguments before changing Git configuration. A failing preflight leaves
hook configuration untouched. Enabling `.githooks` also enables any other hooks
already present there; review them, including `pre-commit`, before opting in.

Linked worktrees normally share `--local` configuration. Setup refuses multiple
worktrees unless `extensions.worktreeConfig` is already enabled. When that
extension is enabled, setup uses `git config --worktree`; otherwise it uses
`--local`. Have the repository owner review any migration to per-worktree
configuration, including existing `core.worktree` and `core.bare` settings.
Setup never enables that extension or updates another worktree's configuration.

Set identities in the terminal that will run Git, using the values assigned to
you. Replace the placeholders; no workstation or agent is supplied by default:

```sh
export CODESTRA_WORKSTATION_ID='<assigned-workstation-id>'
export CODESTRA_AGENT_ID='<lease-owning-agent-id>'
```

`CODESTRA_CONTROL_DSN` defaults to the existing `codestra-devctl` local database:

```text
host=127.0.0.1 port=5432 dbname=codestra_dev_control user=codestra
```

Use your approved environment to configure a different DSN if necessary. Do
not commit credentials to the repository or paste them into logs.

Lease management remains an explicit control-plane operation. From an authorized
control-plane checkout, claim your assigned workstation and maintain its lease
with the real commands, supplying the assigned atomic task description:

```sh
./bin/codestra-devctl claim "$CODESTRA_WORKSTATION_ID" \
  --agent "$CODESTRA_AGENT_ID" --task '<assigned-atomic-task>'
./bin/codestra-devctl heartbeat "$CODESTRA_WORKSTATION_ID" \
  --agent "$CODESTRA_AGENT_ID"
```

The push hook does not claim or renew leases, modify evidence, sign files, or
authorize publication. Keep any repository-specific publication and remote-SHA
compare-and-swap requirements in place. A passing local check does not guarantee
CI success, protected merge approval, orchestrator trust, or release acceptance.
No local signing key or invented `codestra-cli` command is required by this
integration.

The verifier queries the existing registry in a read-only transaction. It checks
lease ownership and expiration, active task status, the registered worktree and
branch, a clean working tree, and the repository identity configured as `origin`.
Every ref and commit supplied by Git must match the leased branch and its current
HEAD. The push destination must match its configured remote. GitHub destinations
must identify the registered repository; the portfolio's explicitly configured
`codestra-local` remote retains its self-hosted publication route.

Normal fast-forward pushes and creation of the leased branch are supported.
Protected branch pushes, branch deletion, tags, renamed destination branches,
other branches in a multi-ref push, and non-fast-forward updates are blocked.
Use the existing approved release/promotion process for those operations. The
hook permits new, unpublished commits; CI evidence is evaluated after the push
against that exact commit. It neither fetches nor signs local build output.

Run the isolated hook and installer regression tests from the repository root:

```sh
python3 -B -m unittest discover -s .githooks/tests -p 'test_*.py' -q
```
