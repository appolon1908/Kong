"""Exercise opt-in hook templates against isolated, local Git repositories."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TEMPLATES = Path(__file__).resolve().parents[2]
ASSETS = (
    ".githooks/pre-push",
    ".githooks/codestra-pre-push",
    "scripts/setup-governance-hooks.sh",
)


class HookTemplateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="codestra hook templates ")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "source repo"
        self.root.mkdir()
        self.env = os.environ.copy()
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        for key in ("CODESTRA_WORKSTATION_ID", "CODESTRA_AGENT_ID", "GIT_DIR", "GIT_WORK_TREE"):
            self.env.pop(key, None)
        self.git("init", "-q")
        for relative in ASSETS:
            source = TEMPLATES / relative
            self.assertTrue(source.is_file(), f"missing hook template: {relative}")
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        checker = self.root / ".githooks/codestra-push-check.py"
        checker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'stdin': sys.stdin.read()}))\n"
            "sys.exit(7)\n"
        )
        checker.chmod(0o755)

    def run_command(self, args, *, input=None, env=None, cwd=None):
        return subprocess.run(
            args, cwd=cwd or self.root, env=env or self.env,
            input=input, text=True, capture_output=True, check=False,
        )

    def git(self, *args, cwd=None, check=True):
        result = self.run_command(["git", *args], cwd=cwd)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def setup_hooks(self):
        return self.run_command([str(self.root / "scripts/setup-governance-hooks.sh")])

    def assert_hooks_unset(self):
        self.assertEqual(self.git("config", "--get", "core.hooksPath", check=False).returncode, 1)

    def add_linked_worktree(self):
        self.git("-c", "user.name=Template Test", "-c", "user.email=test@example.invalid",
                 "commit", "--allow-empty", "-qm", "fixture")
        linked = Path(self.scratch.name) / "linked repo"
        self.git("worktree", "add", "-qb", "linked", str(linked))
        return linked

    def test_setup_is_opt_in_and_idempotent(self):
        self.assert_hooks_unset()
        for _ in range(2):
            result = self.setup_hooks()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.git("config", "--local", "--get", "core.hooksPath").stdout.strip(), ".githooks")

    def test_setup_preserves_a_different_effective_hook_path(self):
        self.git("config", "core.hooksPath", "custom hooks")
        result = self.setup_hooks()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.hooksPath", result.stderr)
        self.assertEqual(self.git("config", "--get", "core.hooksPath").stdout.strip(), "custom hooks")

    def test_setup_preserves_an_explicitly_empty_hook_path(self):
        self.git("config", "core.hooksPath", "")
        result = self.setup_hooks()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.hooksPath", result.stderr)
        self.assertEqual(self.git("config", "--get", "core.hooksPath").stdout, "\n")

    def test_setup_refuses_to_displace_any_executable_default_hook(self):
        hook = self.root / ".git/hooks/pre-commit"
        contents = "#!/usr/bin/env bash\nexit 0\n"
        hook.write_text(contents)
        hook.chmod(0o755)
        result = self.setup_hooks()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pre-commit", result.stderr)
        self.assertEqual(hook.read_text(), contents)
        self.assert_hooks_unset()

    def test_setup_allows_samples_and_nonexecutable_default_hooks(self):
        (self.root / ".git/hooks/pre-commit").write_text("inactive hook\n")
        result = self.setup_hooks()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_refuses_missing_or_nonexecutable_required_assets(self):
        for relative in (".githooks/pre-push", ".githooks/codestra-pre-push", ".githooks/codestra-push-check.py"):
            with self.subTest(asset=relative):
                asset = self.root / relative
                original_mode = asset.stat().st_mode
                asset.chmod(0o644)
                result = self.setup_hooks()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(relative, result.stderr)
                self.assert_hooks_unset()
                asset.chmod(original_mode)

    def test_setup_refuses_shared_config_for_multiple_worktrees(self):
        self.add_linked_worktree()
        result = self.setup_hooks()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("worktree", result.stderr.lower())
        self.assert_hooks_unset()
        self.assertEqual(self.git("config", "--get", "extensions.worktreeConfig", check=False).returncode, 1)

    def test_setup_uses_existing_per_worktree_config_without_changing_other_worktrees(self):
        linked = self.add_linked_worktree()
        self.git("config", "extensions.worktreeConfig", "true")
        result = self.setup_hooks()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("config", "--worktree", "--get", "core.hooksPath").stdout.strip(), ".githooks")
        self.assertEqual(self.git("config", "--local", "--get", "core.hooksPath", check=False).returncode, 1)
        self.assertEqual(self.git("config", "--get", "core.hooksPath", cwd=linked, check=False).returncode, 1)

    def test_failed_preflight_leaves_hook_configuration_unset(self):
        preflight = self.root / "scripts/agent_preflight.sh"
        preflight.write_text("#!/usr/bin/env bash\ntest \"$#\" -eq 0 || exit 99\nexit 9\n")
        preflight.chmod(0o755)
        result = self.setup_hooks()
        self.assertEqual(result.returncode, 9)
        self.assert_hooks_unset()

    def test_successful_preflight_runs_without_arguments_before_configuration(self):
        preflight = self.root / "scripts/agent_preflight.sh"
        preflight.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            "test \"$#\" -eq 0\n"
            "if git config --get core.hooksPath; then exit 88; fi\n"
            "printf 'ran\\n' > preflight-marker\n"
        )
        preflight.chmod(0o755)
        result = self.setup_hooks()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "preflight-marker").read_text(), "ran\n")

    def test_hook_forwards_quoted_arguments_stdin_and_checker_exit_status(self):
        hook_env = self.env | {"CODESTRA_WORKSTATION_ID": "assigned workstation", "CODESTRA_AGENT_ID": "agent one"}
        remote_url = "ssh://git@example.invalid/team/repo name.git"
        updates = "refs/heads/topic aaaa refs/heads/topic bbbb\nrefs/heads/second cccc refs/heads/second dddd\n"
        result = self.run_command(
            [str(self.root / ".githooks/pre-push"), "remote name", remote_url],
            input=updates, env=hook_env,
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["args"], [
            "--workstation", "assigned workstation", "--agent", "agent one",
            "--repo-path", str(self.root), "--remote-name", "remote name", "--remote-url", remote_url,
        ])
        self.assertEqual(report["stdin"], updates)

    def test_hook_missing_identity_explains_required_environment_variable(self):
        for missing, present in (("CODESTRA_WORKSTATION_ID", "CODESTRA_AGENT_ID"),
                                 ("CODESTRA_AGENT_ID", "CODESTRA_WORKSTATION_ID")):
            with self.subTest(missing=missing):
                hook_env = self.env | {present: "assigned"}
                result = self.run_command([str(self.root / ".githooks/pre-push"), "origin", "unused"], env=hook_env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(missing, result.stderr)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
