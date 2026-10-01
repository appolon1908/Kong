#!/usr/bin/env python3
"""Single source of the release registry authority.

Every release tool and workflow derives the repository, registry namespace and
image reference from ``config/kong-release-registry-contract.v1.json`` and
proves that the process is running inside that repository. A historical owner
literal never appears in a tool or workflow again: the repository was
transferred (``appolon1908-hue`` -> ``ingtrader21-spec`` -> ``appolon1908``) and the release
workflow kept publishing to the stale namespace, which a repository-scoped
GITHUB_TOKEN cannot write.

Command line::

    python3 tools/release_contract.py --assert-repository "$GITHUB_REPOSITORY" \
        --assert-owner "$GITHUB_REPOSITORY_OWNER" --print image

exits 0 and prints the requested field, or exits 2 with ``RELEASE_CONTRACT=FAIL``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/kong-release-registry-contract.v1.json"
EVIDENCE_CONTRACT_PATH = ROOT / "config/kong-release-evidence-contract.v1.json"
SCHEMA = "codestra.kong.release-registry-contract.v1"
EVIDENCE_SCHEMA = "codestra.kong.release-evidence-contract.v1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
NAMESPACE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
FORBIDDEN_TAGS = ("latest", "main", "staging", "production", "stable")


class ContractError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ContractError(reason)


def load_contract(path: Path = CONTRACT_PATH) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    require(contract.get("schema") == SCHEMA, "registry_contract_schema")
    require(contract.get("runtimeApplyAuthorized") is False, "registry_contract_authorizes_runtime_apply")
    require(contract.get("providerEffectsEnabled") is False, "registry_contract_enables_provider_effects")
    repository = contract["repository"]
    registry = contract["registry"]
    require(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repository["fullName"]) is not None, "repository_name")
    require(type(repository["id"]) is int and repository["id"] > 0, "repository_id")
    owner = repository["fullName"].split("/", 1)[0]
    require(repository["owner"] == owner, "repository_owner_mismatch")
    require(registry["host"] == "ghcr.io", "registry_host")
    require(NAMESPACE.fullmatch(registry["namespace"]) is not None, "registry_namespace_format")
    require(registry["namespace"] == owner.lower(), "registry_namespace_not_repository_owner")
    require(PACKAGE.fullmatch(registry["package"]) is not None, "registry_package_format")
    require(registry["image"] == f"{registry['host']}/{registry['namespace']}/{registry['package']}", "registry_image_inconsistent")
    policy = contract["tagPolicy"]
    require(policy["mutableTagsAllowed"] is False, "mutable_tags_allowed")
    require(set(FORBIDDEN_TAGS) <= set(policy["forbiddenTags"]), "forbidden_tags_incomplete")
    for former in repository.get("formerNames", []):
        require(former["fullName"] != repository["fullName"], "former_name_is_current")
    return contract


def load_evidence_contract(path: Path = EVIDENCE_CONTRACT_PATH) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    require(contract.get("schema") == EVIDENCE_SCHEMA, "evidence_contract_schema")
    require(contract.get("runtimeApplyAuthorized") is False, "evidence_contract_authorizes_runtime_apply")
    require(contract.get("providerEffectsEnabled") is False, "evidence_contract_enables_provider_effects")
    require(contract.get("registryContract") == CONTRACT_PATH.relative_to(ROOT).as_posix(), "evidence_contract_registry_reference")
    return contract


def contract_sha256(path: Path = CONTRACT_PATH) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_repository(contract: dict, repository: str | None, owner: str | None) -> None:
    """Fail closed unless the process runs inside the contracted repository."""
    require(repository == contract["repository"]["fullName"], f"repository_mismatch:{repository}")
    if owner is not None:
        require(owner.lower() == contract["registry"]["namespace"], f"owner_namespace_mismatch:{owner}")


def authoritative_tag(source_sha: str) -> str:
    require(SHA.fullmatch(source_sha or "") is not None, "source_sha_format")
    return f"sha-{source_sha}"


def preflight_tag(source_sha: str) -> str:
    require(SHA.fullmatch(source_sha or "") is not None, "source_sha_format")
    return f"preflight-sha-{source_sha}"


_CONTRACT = load_contract()
REPOSITORY: str = _CONTRACT["repository"]["fullName"]
REPOSITORY_ID: int = _CONTRACT["repository"]["id"]
REGISTRY_HOST: str = _CONTRACT["registry"]["host"]
REGISTRY_NAMESPACE: str = _CONTRACT["registry"]["namespace"]
STANDBY_IMAGE: str = _CONTRACT["registry"]["image"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--assert-repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--assert-owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER"))
    parser.add_argument("--print", choices=["image", "repository", "namespace", "package", "contract-sha256"], default=None)
    args = parser.parse_args()
    try:
        contract = load_contract()
        load_evidence_contract()
        if args.assert_repository is not None or args.assert_owner is not None:
            assert_repository(contract, args.assert_repository, args.assert_owner)
    except (ContractError, KeyError, OSError, ValueError) as error:
        print(f"RELEASE_CONTRACT=FAIL {error}", file=sys.stderr)
        return 2
    if args.print == "image":
        print(contract["registry"]["image"])
    elif args.print == "repository":
        print(contract["repository"]["fullName"])
    elif args.print == "namespace":
        print(contract["registry"]["namespace"])
    elif args.print == "package":
        print(contract["registry"]["package"])
    elif args.print == "contract-sha256":
        print(contract_sha256())
    else:
        print("RELEASE_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
