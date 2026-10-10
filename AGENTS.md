# Codestra Agent Governance Standard

<!-- CODESTRA_AGENT_GOVERNANCE_V1 -->

This root contract is authoritative for agent-driven development. Repository-specific rules may add constraints but may not weaken these rules.

1. Every task is Product -> Section -> Subsection -> Atomic Task. Implement only in the assigned subsection worktree. Promotion is only: subsection/* -> section/* -> development -> testing -> staging -> production.
2. One implementation owner per subsection. Review/test agents may inspect but do not modify the lane unless reassigned. Claim a lease before editing.
3. Pre-work: fetch/prune, verify branch/parent, record SHA, require clean tree, know ahead/behind, safely sync parent, run preflight, require dependencies CERTIFIED, validate environment, keep production effects off. Unknown local work or divergence means BLOCKED.
4. Atomic tasks include implementation, tests, error handling, contract/docs/migration/observability/security changes when applicable. Do not mix unrelated changes.
5. No placeholders, TODO-as-implementation, dead/duplicate code, bypasses, broad exception swallowing, hard-coded credentials, production secrets, unexplained suppressions, disabled tests/security checks or temporary production flags.
6. Before push run applicable format/lint/type/unit/integration/contract/migration/security/secret checks and git diff --check. Do not knowingly push broken code.
7. After each valid atomic checkpoint commit, push, verify remote SHA and record evidence. Do not leave completed work only on a workstation.
8. Commits are one understandable unit with descriptive messages such as feat(area), fix(area), test(area), refactor(area).
9. Before merge fetch parent, integrate current parent safely, resolve intentionally, rerun gates, push exact branch and require CI on the new SHA. Old CI never certifies a changed SHA.
10. Do not directly develop on main, development, testing, staging or production. Force pushes to protected branches are prohibited.
11. Defaults: PRODUCTION_GO=NO, LIVE_CAPABILITIES_ENABLED=NO, EXTERNAL_EFFECTS=false. Implementation must not silently enable external/production effects.
12. COMPLETE requires final branch/SHA, parent SHA, changed files, tests, security, migration/API evidence where applicable, dependency changes, limitations/TODOs, CI and reviewer state.
13. COMPLETE requires implementation, applicable tests/contracts/security/docs/migrations, pushed clean tree, local/remote SHA match and no blockers.
14. CERTIFIED additionally requires exact-SHA CI, independent review, parent integration/regression/security/performance evidence as applicable, no unresolved critical/high defects, and stored completion evidence. Only CERTIFIED promotes.
15. After integration archive evidence and safely clean stale worktrees/locks/refs; never delete unmerged work.
16. Fail closed. If safety cannot be proven, stop and mark BLOCKED. Never guess around secrets, migrations, authorization, ancestry, production effects, destructive operations or incomplete CI evidence.


## Repository-specific additions
<!-- CODESTRA_AGENT_PROTOCOL_V1 -->
## Codestra continuation contract

Canonical protocol:
https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md

Quick start:
https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-QUICKSTART.md

Before changing code:
1. Read `.codestra-mission/*` when present.
2. Read the active Linear issue and linked Notion architecture.
3. Inspect exact Git branch/HEAD/dirty/worktree/upstream/PR/CI state.
4. Preserve all existing local work.
5. If acting as Builder, verify exclusive issue ownership and use a dedicated worktree.
6. Do not invent or self-assign the next task.
7. Update GitHub + Linear + Notion + the mission checkpoint before handoff.
8. Do not cross the live-production approval boundary.

The canonical protocol's no-loss, one-writer, protected-merge, checkpoint, and production-boundary rules are mandatory.
