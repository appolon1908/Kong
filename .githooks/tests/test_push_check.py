import argparse
import importlib.machinery
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch


CHECKER = Path(__file__).resolve().parents[1] / 'codestra-push-check.py'


class PushCheckTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CHECKER.is_file(), 'read-only push checker is missing')
        loader = importlib.machinery.SourceFileLoader('push_checker', str(CHECKER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.checker = importlib.util.module_from_spec(spec)
        loader.exec_module(self.checker)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'checkout with spaces'
        self.root.mkdir()
        self.git('init', '-q', '-b', 'subsection/hooks')
        self.git('config', 'user.name', 'Hook test')
        self.git('config', 'user.email', 'hook-test@example.invalid')
        self.git('remote', 'add', 'origin', 'https://github.com/appolon1908/Caddy.git')
        (self.root / 'file').write_text('base\n')
        self.git('add', 'file')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD')
        (self.root / 'file').write_text('next\n')
        self.git('commit', '-qam', 'next')
        self.head = self.git('rev-parse', 'HEAD')
        self.args = argparse.Namespace(workstation='caddy-hooks', agent='test-builder',
            repo_path=str(self.root), remote_name='origin',
            remote_url='https://github.com/appolon1908/Caddy.git')
        self.lease = dict(workstation_id='caddy-hooks', repository='appolon1908/Caddy',
            worktree=str(self.root), branch='subsection/hooks', test_branch='test',
            status='IN_PROGRESS', agent='test-builder', lease_state='ACTIVE',
            current_atomic_task='shared pre-push hooks',
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args],
            check=True, capture_output=True, text=True).stdout.strip()

    def updates(self, local_ref='refs/heads/subsection/hooks', remote_ref=None,
                local_sha=None, remote_sha=None):
        text = f'{local_ref} {local_sha or self.head} {remote_ref or local_ref} {remote_sha or self.base}\n'
        return self.checker.read_updates(io.StringIO(text))

    def validate(self, updates=None):
        return self.checker.validate_push(self.args,
            self.updates() if updates is None else updates, self.lease)

    def test_normal_push_and_new_branch_allow_unpublished_commit(self):
        self.validate()
        self.validate(self.updates(remote_sha='0' * 40))

    def test_head_and_full_sha_refspecs_bind_to_the_leased_branch(self):
        for ref in ['HEAD', self.head]:
            with self.subTest(ref=ref):
                self.validate(self.updates(local_ref=ref, remote_ref='refs/heads/subsection/hooks'))

    def test_expired_or_missing_expiration_is_rejected(self):
        for expiry in [datetime.now(timezone.utc) - timedelta(seconds=1), None]:
            with self.subTest(expiry=expiry):
                self.lease['lease_expires_at'] = expiry
                with self.assertRaisesRegex(self.checker.CheckError, 'LEASE_EXPIRED'):
                    self.validate()

    def test_wrong_owner_inactive_lease_and_blocked_task_are_rejected(self):
        for field, value, reason in [('agent', 'other-builder', 'LEASE_NOT_OWNED'),
                ('lease_state', 'FROZEN', 'LEASE_NOT_ACTIVE'),
                ('status', 'BLOCKED', 'TASK_NOT_ACTIVE'),
                ('current_atomic_task', '', 'TASK_NOT_BOUND')]:
            previous = self.lease[field]
            with self.subTest(field=field):
                self.lease[field] = value
                with self.assertRaisesRegex(self.checker.CheckError, reason):
                    self.validate()
            self.lease[field] = previous

    def test_wrong_workstation_worktree_and_repository_are_rejected(self):
        for field, value, reason in [('workstation_id', 'other', 'WORKSTATION_MISMATCH'),
                ('worktree', str(self.root.parent), 'WORKTREE_MISMATCH'),
                ('repository', 'appolon1908/Kong', 'REPOSITORY_MISMATCH')]:
            previous = self.lease[field]
            with self.subTest(field=field):
                self.lease[field] = value
                with self.assertRaisesRegex(self.checker.CheckError, reason):
                    self.validate()
            self.lease[field] = previous

    def test_pushed_commit_must_match_the_registered_branch_and_head(self):
        with self.assertRaisesRegex(self.checker.CheckError, 'COMMIT_MISMATCH'):
            self.validate(self.updates(local_sha=self.base))
        self.git('branch', 'other')
        with self.assertRaisesRegex(self.checker.CheckError, 'REF_NOT_BOUND'):
            self.validate(self.updates(local_ref='refs/heads/other'))

    def test_all_updates_are_checked_before_push(self):
        self.git('branch', 'other')
        updates = self.updates() + self.updates(local_ref='refs/heads/other')
        with self.assertRaisesRegex(self.checker.CheckError, 'REF_NOT_BOUND'):
            self.validate(updates)

    def test_protected_ref_and_renamed_destination_are_rejected(self):
        for ref, reason in [('refs/heads/main', 'PROTECTED_REF'),
                            ('refs/heads/other', 'REF_NOT_BOUND')]:
            with self.subTest(ref=ref), self.assertRaisesRegex(self.checker.CheckError, reason):
                self.validate(self.updates(remote_ref=ref))

    def test_deletions_tags_and_malformed_input_are_rejected(self):
        for text in [f'(delete) {"0" * 40} refs/heads/subsection/hooks {self.head}\n',
                     f'refs/tags/v1 {self.head} refs/tags/v1 {"0" * 40}\n',
                     'malformed\n',
                     f'refs/heads/x not-a-sha refs/heads/x {self.base}\n']:
            with self.subTest(text=text), self.assertRaises(self.checker.CheckError):
                self.checker.read_updates(io.StringIO(text))

    def test_duplicate_destination_is_rejected(self):
        line = f'refs/heads/subsection/hooks {self.head} refs/heads/subsection/hooks {self.base}\n'
        with self.assertRaisesRegex(self.checker.CheckError, 'DUPLICATE_REF'):
            self.checker.read_updates(io.StringIO(line + line))

    def test_dirty_worktree_is_rejected(self):
        (self.root / 'untracked').write_text('not committed')
        with self.assertRaisesRegex(self.checker.CheckError, 'DIRTY_WORKTREE'):
            self.validate()

    def test_hidden_untracked_files_are_still_rejected(self):
        self.git('config', 'status.showUntrackedFiles', 'no')
        (self.root / 'hidden-untracked').write_text('not committed')
        with self.assertRaisesRegex(self.checker.CheckError, 'DIRTY_WORKTREE'):
            self.validate()

    def test_git_commands_disable_optional_index_writes(self):
        index = self.root / '.git/index'
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        tracked = self.root / 'file'
        stat = tracked.stat()
        os.utime(tracked, (stat.st_atime, stat.st_mtime + 30))
        self.validate()
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before)

    def test_wrong_destination_or_unconfigured_remote_is_rejected(self):
        self.args.remote_url = 'https://github.com/appolon1908/Kong.git'
        with self.assertRaisesRegex(self.checker.CheckError, 'REMOTE_MISMATCH'):
            self.validate()
        self.args.remote_name = 'missing'
        with self.assertRaises(self.checker.CheckError):
            self.validate()

    def test_repointed_github_push_remote_is_rejected(self):
        self.git('remote', 'set-url', '--push', 'origin', 'https://github.com/appolon1908/Kong.git')
        self.args.remote_url = 'https://github.com/appolon1908/Kong.git'
        with self.assertRaisesRegex(self.checker.CheckError, 'REPOSITORY_MISMATCH'):
            self.validate()

    def test_configured_self_hosted_publisher_is_supported(self):
        self.git('remote', 'add', 'codestra-local', '/tmp/codestra-local/Caddy.git')
        self.args.remote_name = 'codestra-local'
        self.args.remote_url = '/tmp/codestra-local/Caddy.git'
        self.validate()

    def test_non_fast_forward_and_unknown_remote_commit_are_rejected(self):
        self.git('checkout', '-qb', 'other', self.base)
        (self.root / 'file').write_text('other\n')
        self.git('commit', '-qam', 'other')
        other = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', 'subsection/hooks')
        for remote_sha in [other, 'f' * 40]:
            with self.subTest(remote_sha=remote_sha), self.assertRaisesRegex(self.checker.CheckError, 'NON_FAST_FORWARD'):
                self.validate(self.updates(remote_sha=remote_sha))

    def test_lease_is_checked_again_after_git_validation(self):
        actual_git = self.checker.git
        def expire_during_git(*args, **kwargs):
            self.lease['lease_expires_at'] = datetime.now(timezone.utc) - timedelta(seconds=1)
            return actual_git(*args, **kwargs)
        with patch.object(self.checker, 'git', side_effect=expire_during_git):
            with self.assertRaisesRegex(self.checker.CheckError, 'LEASE_EXPIRED'):
                self.validate()

    def test_database_reads_use_readonly_transaction_and_close(self):
        driver = MagicMock()
        connection = driver.connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = None
        with patch.dict('sys.modules', {'psycopg2': driver}):
            with self.assertRaisesRegex(self.checker.CheckError, 'UNKNOWN_WORKSTATION'):
                self.checker.load_lease('missing')
        connection.set_session.assert_called_once_with(readonly=True, autocommit=False)
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()
        statements = [call.args[0].strip().upper() for call in cursor.execute.call_args_list]
        self.assertTrue(all(sql.startswith(('SELECT ', 'SET LOCAL ')) for sql in statements))

    def test_credentials_are_not_in_connection_failure_output(self):
        driver = MagicMock()
        driver.connect.side_effect = RuntimeError('password=never-print-this')
        with patch.dict('sys.modules', {'psycopg2': driver}):
            with self.assertRaises(self.checker.CheckError) as caught:
                self.checker.load_lease('missing')
        self.assertNotIn('never-print-this', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
