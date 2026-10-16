#!/usr/bin/env python3
"""Read-only local push readiness; CI remains the certification authority."""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_DSN = 'host=127.0.0.1 port=5432 dbname=codestra_dev_control user=codestra'
LEASE_COLUMNS = (
    'workstation_id', 'repository', 'worktree', 'branch', 'test_branch',
    'status', 'agent', 'lease_state', 'lease_expires_at', 'current_atomic_task',
)


class CheckError(Exception):
    pass


def git(root, *arguments):
    try:
        result = subprocess.run(
            ['git', '-C', str(root), *arguments],
            capture_output=True, text=True, timeout=10, check=False,
            env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckError('GIT_UNAVAILABLE: verify Git and the assigned worktree') from error
    if result.returncode:
        # Git errors can contain credential-bearing remote URLs.
        raise CheckError('GIT_VALIDATION_FAILED: reconcile the assigned worktree')
    return result.stdout.strip()


def read_updates(stream):
    updates = []
    destinations = set()
    for line in stream:
        fields = line.split()
        if len(fields) != 4:
            raise CheckError('MALFORMED_PUSH_INPUT')
        local_ref, local_sha, remote_ref, remote_sha = fields
        if not all(re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', sha)
                   for sha in (local_sha, remote_sha)) or len(local_sha) != len(remote_sha):
            raise CheckError('MALFORMED_PUSH_SHA')
        if set(local_sha) == {'0'} or local_ref == '(delete)':
            raise CheckError('REF_DELETION: use the separately approved publication workflow')
        commit_ref = local_ref == 'HEAD' or re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', local_ref)
        if not (local_ref.startswith('refs/heads/') or commit_ref) or not remote_ref.startswith('refs/heads/'):
            raise CheckError('BRANCH_REFS_REQUIRED: releases use their existing CI workflow')
        if remote_ref in destinations:
            raise CheckError('DUPLICATE_REF')
        destinations.add(remote_ref)
        updates.append(tuple(fields))
    return updates


def repository_identity(url):
    if url.startswith('git@github.com:'):
        path = url[len('git@github.com:'):]
    else:
        parsed = urlsplit(url)
        if parsed.scheme not in {'https', 'ssh'} or parsed.hostname != 'github.com':
            raise CheckError('REPOSITORY_MISMATCH: origin must identify the registered GitHub repository')
        path = parsed.path.lstrip('/')
    path = path.removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', path):
        raise CheckError('REPOSITORY_MISMATCH')
    return path.casefold()


def load_lease(workstation):
    try:
        import psycopg2
    except ImportError as error:
        raise CheckError('REGISTRY_DRIVER_MISSING: Python 3 with psycopg2 is required') from error
    try:
        connection = psycopg2.connect(
            os.environ.get('CODESTRA_CONTROL_DSN', DEFAULT_DSN), connect_timeout=5,
        )
        try:
            connection.set_session(readonly=True, autocommit=False)
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout = '5s'")
                cursor.execute(
                    'SELECT w.workstation_id,p.repository,w.worktree,w.branch,p.test_branch,'
                    'w.status,w.agent,w.lease_state,w.lease_expires_at,w.current_atomic_task '
                    'FROM workstations w JOIN products p ON p.product=w.product '
                    'WHERE w.workstation_id=%s', (workstation,),
                )
                row = cursor.fetchone()
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()
    except Exception as error:
        # Never expose DSNs, passwords, server errors, or authentication details.
        raise CheckError('REGISTRY_UNAVAILABLE: check approved registry access') from error
    if row is None:
        raise CheckError('UNKNOWN_WORKSTATION: request a registered task/worktree binding')
    return dict(zip(LEASE_COLUMNS, row))


def require_unexpired(lease):
    expiry = lease.get('lease_expires_at')
    if (not isinstance(expiry, datetime) or expiry.tzinfo is None
            or expiry <= datetime.now(timezone.utc)):
        raise CheckError('LEASE_EXPIRED: refresh the owned lease explicitly before pushing')


def validate_push(args, updates, lease):
    if lease.get('workstation_id') != args.workstation:
        raise CheckError('WORKSTATION_MISMATCH')
    if lease.get('agent') != args.agent:
        raise CheckError('LEASE_NOT_OWNED: use the assigned Builder identity')
    if lease.get('lease_state') != 'ACTIVE':
        raise CheckError('LEASE_NOT_ACTIVE: resolve the task lease through its owner')
    require_unexpired(lease)
    if lease.get('status') not in {'CLAIMED', 'IN_PROGRESS', 'REVIEW'}:
        raise CheckError('TASK_NOT_ACTIVE')
    if not lease.get('current_atomic_task'):
        raise CheckError('TASK_NOT_BOUND')
    root = Path(args.repo_path).resolve()
    registered_root = lease.get('worktree')
    if not registered_root or root != Path(registered_root).resolve():
        raise CheckError('WORKTREE_MISMATCH: use the assigned worktree')
    if Path(git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise CheckError('WORKTREE_MISMATCH')
    branch = lease.get('branch')
    protected = {'main', 'master', 'development', 'test', 'testing', 'staging', 'production',
                 lease.get('test_branch')}
    if branch in protected:
        raise CheckError('PROTECTED_REF: use the existing reviewed promotion workflow')
    if git(root, 'branch', '--show-current') != branch:
        raise CheckError('REF_NOT_BOUND: checkout the assigned branch')
    expected_ref = f'refs/heads/{branch}'
    head = git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    if git(root, 'status', '--porcelain', '--untracked-files=all', '--ignore-submodules=none'):
        raise CheckError('DIRTY_WORKTREE: commit or reconcile work in the owning lane')
    expected_repository = str(lease.get('repository', '')).casefold()
    if repository_identity(git(root, 'remote', 'get-url', 'origin')) != expected_repository:
        raise CheckError('REPOSITORY_MISMATCH')
    if not args.remote_name or args.remote_name.startswith('-'):
        raise CheckError('REMOTE_MISMATCH: use a configured publication remote')
    destinations = git(root, 'remote', 'get-url', '--push', '--all', args.remote_name).splitlines()
    if args.remote_url not in destinations:
        raise CheckError('REMOTE_MISMATCH: destination differs from the configured push remote')
    # Preserve the portfolio's configured self-hosted publication route.
    if args.remote_name != 'codestra-local':
        if repository_identity(args.remote_url) != expected_repository:
            raise CheckError('REPOSITORY_MISMATCH')
    for local_ref, local_sha, remote_ref, remote_sha in updates:
        if remote_ref.removeprefix('refs/heads/') in protected:
            raise CheckError('PROTECTED_REF: use the existing reviewed promotion workflow')
        if local_ref not in {expected_ref, 'HEAD', local_sha} or remote_ref != expected_ref:
            raise CheckError('REF_NOT_BOUND: every pushed ref must match the leased branch')
        if local_sha != head or git(root, 'rev-parse', '--verify', f'{local_ref}^{{commit}}') != local_sha:
            raise CheckError('COMMIT_MISMATCH: pushed commit differs from the assigned branch HEAD')
        if set(remote_sha) != {'0'}:
            try:
                git(root, 'merge-base', '--is-ancestor', remote_sha, local_sha)
            except CheckError as error:
                raise CheckError('NON_FAST_FORWARD: fetch and reconcile through the owning lane') from error
    require_unexpired(lease)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workstation', required=True)
    parser.add_argument('--agent', required=True)
    parser.add_argument('--repo-path', required=True)
    parser.add_argument('--remote-name', required=True)
    parser.add_argument('--remote-url', required=True)
    args = parser.parse_args()
    try:
        updates = read_updates(sys.stdin)
        if not updates:
            print('CODESTRA_PUSH_READY no ref updates')
            return 0
        if not args.workstation.strip() or not args.agent.strip():
            raise CheckError('IDENTITY_REQUIRED: set the assigned workstation and Builder identity')
        validate_push(args, updates, load_lease(args.workstation))
    except (CheckError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, CheckError) else 'LOCAL_VALIDATION_FAILED'
        print(f'CODESTRA_PUSH_BLOCKED {message}', file=sys.stderr)
        return 1
    print('CODESTRA_PUSH_READY lease and pushed refs validated; CI certification is still required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
