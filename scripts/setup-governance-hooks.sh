#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

if current_hooks=$(git config --get core.hooksPath); then
  if [[ "$current_hooks" != .githooks ]]; then
    echo 'CODESTRA_HOOK_SETUP_BLOCKED: existing core.hooksPath must be reconciled before enabling .githooks.' >&2
    exit 65
  fi
fi

common_dir=$(git rev-parse --git-common-dir)
for hook in "$common_dir/hooks/"*; do
  if [[ -f "$hook" && -x "$hook" && "$hook" != *.sample ]]; then
    echo "CODESTRA_HOOK_SETUP_BLOCKED: preserve and reconcile the existing executable default hook: $hook" >&2
    exit 65
  fi
done

for hook in .githooks/pre-push .githooks/codestra-pre-push .githooks/codestra-push-check.py; do
  if [[ ! -f "$hook" || ! -x "$hook" ]]; then
    echo "CODESTRA_HOOK_SETUP_BLOCKED: required hook asset must exist and be executable: $hook" >&2
    exit 65
  fi
done

worktree_config=$(git config --bool --get extensions.worktreeConfig || true)
worktree_count=$(git worktree list --porcelain | awk '/^worktree / {count++} END {print count+0}')
if [[ "$worktree_count" -gt 1 && "$worktree_config" != true ]]; then
  echo 'CODESTRA_HOOK_SETUP_BLOCKED: linked worktrees share local Git config. Reconcile their hooks and explicitly enable extensions.worktreeConfig before opting in.' >&2
  exit 65
fi

if [[ -x scripts/agent_preflight.sh ]]; then
  scripts/agent_preflight.sh
fi

if [[ "$worktree_config" == true ]]; then
  git config --worktree core.hooksPath .githooks
else
  git config --local core.hooksPath .githooks
fi
echo 'CODESTRA_HOOK_SETUP_PASS: governance hooks enabled for this checkout.'
