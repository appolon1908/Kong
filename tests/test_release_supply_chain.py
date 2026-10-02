"""Mission 3 — release supply chain, immutable evidence and registry authority.

Positive tests prove the committed release/preflight workflows, release tools,
compose file and contracts agree. Negative tests mutate isolated copies of the
repository or synthetic evidence and prove the gates fail closed on a stale
registry owner, missing packages: write, a mutable tag, a source SHA mismatch,
a missing or mismatched digest, a missing SBOM, evidence without exact source,
runtime/provider flags set to true and a release step that continues on error.
Nothing here builds, pushes, pulls or applies anything.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import extract_image_attestations as attest  # noqa: E402
from tools import release_contract as contract  # noqa: E402
from tools import verify_release_evidence as evidence  # noqa: E402
from tools import verify_standby_image as image  # noqa: E402

RELEASE = ".github/workflows/release.yml"
PREFLIGHT = ".github/workflows/release-preflight.yml"
REGISTRY_CONTRACT = "config/kong-release-registry-contract.v1.json"
EVIDENCE_CONTRACT = "config/kong-release-evidence-contract.v1.json"
COMPOSE = "deploy/kong-production-standby/compose.standby.yaml"
COPIED = ("config", "deploy", "scripts", "tools", ".github")
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def load_validator(root: Path):
    spec = importlib.util.spec_from_file_location("validate_release_supply_chain_" + root.name,
                                                  root / "scripts/validate_release_supply_chain.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    for name in COPIED:
        shutil.copytree(ROOT / name, root / name, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return root


def expect_failure(root: Path, match: str) -> None:
    module = load_validator(root)
    with pytest.raises(module.SupplyChainError, match=match):
        module.validate(root)


def read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def write(root: Path, rel: str, text: str) -> None:
    (root / rel).write_text(text, encoding="utf-8")


def good_manifest(stage: str = "protected-main-source-candidate", source: str = SHA) -> dict:
    tag = contract.preflight_tag(source) if stage == "pull-request-preflight" else contract.authoritative_tag(source)
    return {
        "release_stage": stage, "repository": contract.REPOSITORY, "repository_id": contract.REPOSITORY_ID,
        "source_sha": source, "source_tree": "c" * 40, "commit_verification_status": "VERIFIED",
        "kong_version": "3.14.0.1", "kong_image": "kong/kong-gateway:3.14.0.1-ubuntu", "kong_image_digest": "sha256:" + "a" * 64,
        "standby_auth_image": contract.STANDBY_IMAGE, "standby_auth_image_tag": tag, "standby_auth_image_digest": DIGEST,
        "standby_auth_sbom_sha256": "5" * 64, "standby_auth_provenance_sha256": "6" * 64,
        "manifest_generation_id": "1" * 64, "migration_manifest_json_sha256": "2" * 64,
        "migration_manifest_yaml_sha256": "3" * 64, "kong_declarative_config_sha256": "4" * 64,
        "middleware_contract_sha256": "7" * 64, "release_registry_contract_sha256": contract.contract_sha256(),
        "workflow_run_id": 123, "workflow_run_attempt": 1,
        "workflow_ref": contract.REPOSITORY + "/.github/workflows/release.yml@refs/heads/main",
        "rollback_source_sha": "d" * 40, "staging_certification": "NOT_RUN_SOURCE_CANDIDATE",
        "runtime_apply_authorized": False, "external_effects_enabled": False, "provider_effects_enabled": False,
    }


# --------------------------------------------------------------------------- positive


def test_registry_contract_is_derived_from_the_current_repository_owner():
    document = json.loads(read(ROOT, REGISTRY_CONTRACT))
    assert document["repository"]["fullName"] == "appolon1908/Kong"
    assert document["registry"]["namespace"] == document["repository"]["owner"].lower()
    assert document["registry"]["image"] == "ghcr.io/appolon1908/kong-standby-auth"
    assert document["tagPolicy"]["mutableTagsAllowed"] is False
    assert "latest" in document["tagPolicy"]["forbiddenTags"]
    assert document["runtimeApplyAuthorized"] is False and document["providerEffectsEnabled"] is False
    former = {item["fullName"] for item in document["repository"]["formerNames"]}
    assert former == {"appolon1908/Kong"}
    contract.assert_repository(document, "appolon1908/Kong", "appolon1908")
    with pytest.raises(contract.ContractError):
        contract.assert_repository(document, "appolon1908/Kong", "appolon1908")


def test_supply_chain_validator_accepts_the_committed_tree():
    module = load_validator(ROOT)
    result = module.validate(ROOT)
    assert result["release"]["permissions"] == {"actions": "read", "contents": "read", "packages": "write"}
    assert result["preflight"]["permissions"] == {"contents": "read", "packages": "write"}


def test_release_workflows_bind_contract_before_login_and_verify_digest_sbom_provenance():
    for path in (RELEASE, PREFLIGHT):
        text = read(ROOT, path)
        assert "appolon1908" not in text
        assert text.index("tools/release_contract.py") < text.index("docker login ghcr.io")
        assert "--provenance=mode=max" in text and "--sbom=true" in text and "--load" in text and "--push" in text
        assert text.index("--load") < text.index("--push")
        assert "tools/verify_standby_image.py" in text and "tools/extract_image_attestations.py" in text
        assert "tools/verify_release_evidence.py" in text
        assert "continue-on-error" not in text and "latest" not in text and "secrets." not in text
    release = yaml.safe_load(read(ROOT, RELEASE))
    for step in release["jobs"]["release-evidence"]["steps"]:
        if "docker buildx build" in step.get("run", ""):
            assert step["if"] == "github.ref_name == 'main'"
    preflight = yaml.safe_load(read(ROOT, PREFLIGHT))
    assert preflight["jobs"]["release-preflight"]["if"] == "github.event.pull_request.head.repo.full_name == github.repository"


def test_release_tools_and_compose_use_the_contract_image():
    for tool in ("tools/generate_release_manifest.py", "tools/verify_release_candidate.py", "tools/verify_release_evidence.py"):
        text = read(ROOT, tool)
        assert "ghcr.io/" not in text and "appolon1908" not in text
    compose = read(ROOT, COMPOSE)
    assert contract.STANDBY_IMAGE + "@${KONG_STANDBY_AUTH_IMAGE_DIGEST:?" in compose


def test_good_evidence_verifies_for_every_build_stage(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}), encoding="utf-8")
    provenance = tmp_path / "provenance.json"
    provenance.write_text("{}", encoding="utf-8")
    for stage in ("protected-main-source-candidate", "pull-request-preflight"):
        manifest = good_manifest(stage)
        manifest["standby_auth_sbom_sha256"] = evidence.sha256_file(sbom)
        manifest["standby_auth_provenance_sha256"] = evidence.sha256_file(provenance)
        summary = evidence.verify(manifest, expected_source_sha=SHA, expected_stage=stage, sbom=sbom,
                                  provenance=provenance, registry_digest=DIGEST)
        assert summary["image"] == contract.STANDBY_IMAGE + "@" + DIGEST
        assert summary["promotable"] is (stage == "protected-main-source-candidate")
    preflight = good_manifest("pull-request-preflight")
    preflight["commit_verification_status"] = "UNVERIFIED_PREFLIGHT_HEAD"
    evidence.verify(preflight, expected_stage="pull-request-preflight")


def test_generated_manifest_carries_every_binding_and_verifies(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("generate_release_manifest_m3", ROOT / "tools/generate_release_manifest.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    monkeypatch.setenv("GITHUB_RUN_ID", "4242")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", contract.REPOSITORY + "/.github/workflows/release.yml@refs/heads/main")
    head = generator.git("rev-parse", "HEAD")
    # CI checks out a shallow head, so the rollback source is synthetic here; the
    # generator only validates its shape and the workflow supplies the real parent.
    parent = "d" * 40
    output = tmp_path / "release-manifest.json"
    monkeypatch.setattr(sys, "argv", ["generate", "--output", str(output), "--release-stage", "protected-main-source-candidate",
                                      "--commit-verification-status", "VERIFIED", "--kong-image-digest", "sha256:" + "a" * 64,
                                      "--standby-auth-image-digest", DIGEST, "--rollback-source-sha", parent,
                                      "--standby-auth-sbom-sha256", "5" * 64, "--standby-auth-provenance-sha256", "6" * 64,
                                      "--staging-certification", "NOT_RUN_SOURCE_CANDIDATE"])
    assert generator.main() == 0
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["standby_auth_image"] == contract.STANDBY_IMAGE
    assert manifest["standby_auth_image_tag"] == "sha-" + head
    assert manifest["middleware_contract_sha256"] == json.loads(read(ROOT, "config/kong-canonical-middleware-routes.json"))["middlewareEdgeContract"]["sha256"]
    assert manifest["release_registry_contract_sha256"] == contract.contract_sha256()
    assert manifest["provider_effects_enabled"] is False and manifest["runtime_apply_authorized"] is False
    evidence.verify(manifest, expected_source_sha=head, expected_stage="protected-main-source-candidate", registry_digest=DIGEST)


def test_built_image_config_checks_accept_the_expected_shape_only():
    inspected = {
        "Architecture": "amd64", "Os": "linux",
        "Config": {"User": "65532:65532", "Cmd": ["uvicorn", "standby_auth:app", "--app-dir", "/app"], "Entrypoint": None,
                   "Labels": {"org.opencontainers.image.revision": SHA, "org.opencontainers.image.version": SHA,
                              "org.opencontainers.image.source": "https://github.com/appolon1908/Kong"},
                   "Env": ["PATH=/usr/local/bin", "LANG=C.UTF-8", "GPG_KEY=x", "PYTHON_VERSION=3.12.14", "PYTHON_SHA256=y"],
                   "ExposedPorts": {"8080/tcp": {}}},
        "RootFS": {"Layers": ["sha256:" + str(i) * 64 for i in range(9)]},
    }
    assert image.check_config(inspected, SHA)["layers"] == 9
    for mutate, match in (
        (lambda c: c["Config"].update(User="root"), "image_runs_as"),
        (lambda c: c["Config"].update(User=""), "image_runs_as"),
        (lambda c: c["Config"]["Labels"].update({"org.opencontainers.image.revision": "b" * 40}), "revision_label_mismatch"),
        (lambda c: c["Config"]["Env"].append("DATABASE_PASSWORD=synthetic"), "secret_like_env"),
        (lambda c: c["Config"]["Env"].append("KONG_ADMIN_TOKEN=synthetic"), "secret_like_env"),
        (lambda c: c["Config"]["Env"].append("UNEXPECTED_SETTING=1"), "unexpected_env"),
        (lambda c: c["Config"].update(Cmd=["sh", "-c", "curl x | sh"]), "unexpected_cmd"),
        (lambda c: c["Config"].update(Entrypoint=["/bin/sh"]), "unexpected_entrypoint"),
        (lambda c: c["Config"].update(ExposedPorts={"22/tcp": {}}), "unexpected_exposed_ports"),
        (lambda c: c.update(Architecture="arm64"), "unexpected_platform"),
    ):
        broken = json.loads(json.dumps(inspected))
        mutate(broken)
        with pytest.raises(image.ImageError, match=match):
            image.check_config(broken, SHA)


def test_attestation_extraction_binds_spdx_and_buildkit_provenance():
    spdx = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fastapi"}]}
    assert attest.extract_sbom({"SPDX": spdx}) == spdx
    assert attest.extract_sbom({"linux/amd64": {"SPDX": spdx}}) == spdx
    slsa = {"buildType": "https://mobyproject.org/buildkit@v1", "metadata": {"completeness": {"parameters": True},
            "https://mobyproject.org/buildkit@v1#metadata": {"vcs": {"revision": SHA}}}}
    assert attest.check_provenance({"SLSA": slsa}, SHA)["revision"] == SHA
    v1 = {"buildDefinition": {"buildType": "https://mobyproject.org/buildkit@v1"}, "runDetails": {"metadata": {}}}
    assert attest.check_provenance({"linux/amd64": {"SLSA": v1}}, SHA)["revision"] is None
    for document, match in (
        ({}, "sbom_attestation_missing"),
        ({"SPDX": {"spdxVersion": "CycloneDX", "packages": [1]}}, "sbom_not_spdx"),
        ({"SPDX": {"spdxVersion": "SPDX-2.3", "packages": []}}, "sbom_without_packages"),
        ({"linux/amd64": {"SPDX": spdx}, "linux/arm64": {"SPDX": spdx}}, "attestation_platforms"),
    ):
        with pytest.raises(attest.AttestationError, match=match):
            attest.extract_sbom(document)
    wrong = json.loads(json.dumps(slsa))
    wrong["metadata"]["https://mobyproject.org/buildkit@v1#metadata"]["vcs"]["revision"] = "b" * 40
    with pytest.raises(attest.AttestationError, match="provenance_revision"):
        attest.check_provenance({"SLSA": wrong}, SHA)
    with pytest.raises(attest.AttestationError, match="provenance_build_type"):
        attest.check_provenance({"SLSA": {"buildType": "https://example.invalid/other", "metadata": {}}}, SHA)


# --------------------------------------------------------------------------- negative: static supply chain


def test_stale_registry_owner_fails(repo):
    for path in (RELEASE, PREFLIGHT):
        write(repo, path, read(repo, path).replace(
            'test "${image}" = "ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/kong-standby-auth"',
            'test "${image}" = "ghcr.io/appolon1908/kong-standby-auth"'))
    expect_failure(repo, "stale former owner literal")
    write(repo, PREFLIGHT, read(ROOT, PREFLIGHT))
    write(repo, RELEASE, read(ROOT, RELEASE).replace("${GITHUB_REPOSITORY_OWNER,,}", "some-other-org"))
    expect_failure(repo, "namespace literal 'some-other-org'|re-derived from the running repository owner")


def test_stale_owner_in_compose_or_tools_fails(repo):
    write(repo, COMPOSE, read(repo, COMPOSE).replace("ghcr.io/appolon1908/", "ghcr.io/appolon1908/"))
    expect_failure(repo, "compose.standby.yaml")
    write(repo, COMPOSE, read(ROOT, COMPOSE))
    tool = "tools/generate_release_manifest.py"
    write(repo, tool, read(repo, tool).replace('"standby_auth_image": STANDBY_IMAGE,',
                                               '"standby_auth_image": "ghcr.io/appolon1908/kong-standby-auth",'))
    expect_failure(repo, "image authority must come from tools/release_contract.py")


@pytest.mark.parametrize(("path", "old", "new", "match"), [
    (RELEASE, "  packages: write\n", "  packages: read\n", "packages"),
    (RELEASE, "  packages: write\n", "", "packages"),
    (PREFLIGHT, "  packages: write\n", "  packages: write\n  id-token: write\n", "not the least-privilege set|forbidden permission"),
    (RELEASE, "  contents: read\n", "  contents: write\n", "not the least-privilege set|forbidden permission"),
    (RELEASE, 'tag="${STANDBY_IMAGE_REPOSITORY}:sha-${EXPECTED_SHA}"', 'tag="${STANDBY_IMAGE_REPOSITORY}:latest"', "mutable tag|immutable"),
    (RELEASE, 'tag="${STANDBY_IMAGE_REPOSITORY}:sha-${EXPECTED_SHA}"', 'tag="${STANDBY_IMAGE_REPOSITORY}:main"', "immutable"),
    (PREFLIGHT, 'tag="${STANDBY_IMAGE_REPOSITORY}:preflight-sha-${EXPECTED_SHA}"', 'tag="${STANDBY_IMAGE_REPOSITORY}:sha-${EXPECTED_SHA}"', "immutable preflight sha tag"),
    (RELEASE, 'test "$(git rev-parse HEAD)" = "${EXPECTED_SHA}"', 'true', "exact source identity"),
    (RELEASE, 'test -z "$(git status --porcelain)"', 'true', "dirty tree"),
    (RELEASE, '[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]', 'true', "validated as sha256"),
    (RELEASE, "containerimage.digest", "containerimage.size", "captured from the build metadata"),
    (RELEASE, 'test "${remote}" = "${LOCAL_DIGEST}"', 'true', "registry digest must equal"),
    (RELEASE, "--sbom=true", "--sbom=false", "provenance and SBOM"),
    (RELEASE, "--provenance=mode=max", "--provenance=false", "provenance and SBOM"),
    (RELEASE, "tools/verify_release_evidence.py", "tools/verify_release_evidence_skipped.py", "generated and verified"),
    (RELEASE, "tools/verify_standby_image.py", "tools/verify_standby_image_skipped.py", "verified before publication"),
    (RELEASE, "tools/extract_image_attestations.py", "tools/extract_image_attestations_skipped.py", "attestations must be extracted"),
    (RELEASE, "        id: standby\n", "        id: standby\n        continue-on-error: true\n", "continue-on-error"),
    (PREFLIGHT, "        id: standby\n", "        id: standby\n        continue-on-error: true\n", "continue-on-error"),
    (RELEASE, "GHCR_TOKEN: ${{ github.token }}", "GHCR_TOKEN: ${{ secrets.GHCR_PAT }}", "github.token|stored credential"),
    (PREFLIGHT, "if: github.event.pull_request.head.repo.full_name == github.repository", "if: true", "refuse fork"),
])
def test_release_workflow_downgrades_fail(repo, path, old, new, match):
    text = read(repo, path)
    assert old in text, old
    write(repo, path, text.replace(old, new))
    expect_failure(repo, match)


def test_contract_binding_must_precede_registry_login(repo):
    # Removing the binding step entirely leaves docker login unguarded by the contract.
    write(repo, RELEASE, read(repo, RELEASE).replace("tools/release_contract.py", "tools/release_contract_absent.py"))
    expect_failure(repo, "bound before docker login")


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda c: c.update(runtimeApplyAuthorized=True), "registry_contract_authorizes_runtime_apply"),
    (lambda c: c.update(providerEffectsEnabled=True), "registry_contract_enables_provider_effects"),
    (lambda c: c["registry"].update(namespace="appolon1908", image="ghcr.io/appolon1908/kong-standby-auth"), "registry_namespace_not_repository_owner"),
    (lambda c: c["registry"].update(image="ghcr.io/appolon1908/other"), "registry_image_inconsistent"),
    (lambda c: c["tagPolicy"].update(mutableTagsAllowed=True), "mutable_tags_allowed"),
    (lambda c: c["tagPolicy"].update(forbiddenTags=["stable"]), "forbidden_tags_incomplete"),
])
def test_registry_contract_mutations_fail(repo, mutate, match):
    document = json.loads(read(repo, REGISTRY_CONTRACT))
    mutate(document)
    write(repo, REGISTRY_CONTRACT, json.dumps(document, indent=2))
    expect_failure(repo, match)


def test_dockerfile_and_requirements_downgrades_fail(repo):
    dockerfile = "deploy/kong-production-standby/auth-middleware/Dockerfile"
    text = read(repo, dockerfile)
    write(repo, dockerfile, text.replace("USER 65532:65532", "USER root"))
    expect_failure(repo, "non-root")
    write(repo, dockerfile, text.split("@sha256:")[0] + "\n" + "\n".join(text.splitlines()[1:]))
    expect_failure(repo, "pinned by digest")
    write(repo, dockerfile, text)
    requirements = "deploy/kong-production-standby/auth-middleware/requirements.txt"
    write(repo, requirements, read(repo, requirements).replace("fastapi==0.141.1", "fastapi>=0.141"))
    expect_failure(repo, "unpinned requirement")


# --------------------------------------------------------------------------- negative: release evidence


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda m: m.update(source_sha="b" * 40), "source_sha_mismatch"),
    (lambda m: m.pop("source_sha"), "unbound:source_sha"),
    (lambda m: m.update(source_sha="UNRESOLVED"), "unbound:source_sha"),
    (lambda m: m.pop("standby_auth_image_digest"), "unbound:standby_auth_image_digest"),
    (lambda m: m.update(standby_auth_image_digest="sha256:abc"), "standby_image_digest_format"),
    (lambda m: m.update(standby_auth_image_digest="sha256:" + "e" * 64), "registry_digest_mismatch"),
    (lambda m: m.update(standby_auth_image="ghcr.io/appolon1908/kong-standby-auth"), "standby_image_authority"),
    (lambda m: m.update(standby_auth_image_tag="latest"), "tag_policy"),
    (lambda m: m.update(standby_auth_image_tag="preflight-sha-" + SHA), "tag_policy"),
    (lambda m: m.pop("standby_auth_sbom_sha256"), "unbound:standby_auth_sbom_sha256"),
    (lambda m: m.update(standby_auth_sbom_sha256="UNRESOLVED"), "unbound:standby_auth_sbom_sha256"),
    (lambda m: m.update(standby_auth_provenance_sha256="not-a-digest"), "digest_format:standby_auth_provenance_sha256"),
    (lambda m: m.update(release_registry_contract_sha256="9" * 64), "registry_contract_drift"),
    (lambda m: m.update(commit_verification_status="N"), "commit_not_verified"),
    (lambda m: m.update(commit_verification_status="UNVERIFIED_PREFLIGHT_HEAD"), "commit_not_verified"),
    (lambda m: m.update(repository="appolon1908/Kong"), "repository_mismatch"),
    (lambda m: m.update(workflow_ref="appolon1908/Kong/.github/workflows/release.yml@refs/heads/main"), "workflow_ref_foreign"),
    (lambda m: m.update(workflow_run_id=None), "unbound:workflow_run_id"),
    (lambda m: m.update(runtime_apply_authorized=True), "runtime_apply_authorized_not_false"),
    (lambda m: m.update(provider_effects_enabled=True), "provider_effects_enabled_not_false"),
    (lambda m: m.update(external_effects_enabled=True), "external_effects_enabled_not_false"),
    (lambda m: m.update(staging_certification="PASS:" + SHA + ":fixture"), "staging_certification_stage"),
    (lambda m: m.update(release_stage="nightly"), "unknown_stage"),
])
def test_release_evidence_mutations_fail(mutate, match):
    manifest = good_manifest()
    mutate(manifest)
    with pytest.raises(evidence.EvidenceError, match=match):
        evidence.verify(manifest, expected_source_sha=SHA, registry_digest=DIGEST)


def test_release_evidence_sbom_file_must_match_its_digest(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}), encoding="utf-8")
    manifest = good_manifest()
    with pytest.raises(evidence.EvidenceError, match="sbom_digest_mismatch"):
        evidence.verify(manifest, sbom=sbom)
    manifest["standby_auth_sbom_sha256"] = evidence.sha256_file(sbom)
    evidence.verify(manifest, sbom=sbom)
    with pytest.raises(evidence.EvidenceError, match="sbom_digest_mismatch"):
        evidence.verify(manifest, sbom=tmp_path / "missing.json")


def test_preflight_evidence_is_never_promotable():
    spec = importlib.util.spec_from_file_location("verify_release_candidate_m3", ROOT / "tools/verify_release_candidate.py")
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    import hashlib
    import io
    import zipfile

    def archive(manifest: dict) -> tuple[bytes, dict]:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as bundle:
            bundle.writestr("release-manifest.json", json.dumps(manifest))
        raw = out.getvalue()
        return raw, {"id": 42, "name": "kong-release-" + SHA, "expired": False,
                     "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}

    manifest = {"release_stage": "protected-main-source-candidate", "source_sha": SHA, "source_tree": "c" * 40,
                "commit_verification_status": "VERIFIED", "staging_certification": "NOT_RUN_SOURCE_CANDIDATE",
                "rollback_source_sha": "d" * 40, "kong_image": "kong/kong-gateway:3.14.0.1-ubuntu",
                "standby_auth_image": contract.STANDBY_IMAGE, "standby_auth_image_tag": "sha-" + SHA,
                "kong_image_digest": "sha256:" + "a" * 64, "standby_auth_image_digest": DIGEST}
    raw, artifact = archive(manifest)
    candidate.verified_manifest(raw, artifact, SHA)
    for tag in ("preflight-sha-" + SHA, "latest", "sha-" + "b" * 40):
        broken = dict(manifest, standby_auth_image_tag=tag)
        raw, artifact = archive(broken)
        with pytest.raises(ValueError, match="non_authoritative_image_tag"):
            candidate.verified_manifest(raw, artifact, SHA)
    broken = dict(manifest, release_stage="pull-request-preflight", standby_auth_image_tag="preflight-sha-" + SHA)
    raw, artifact = archive(broken)
    with pytest.raises(ValueError, match="not_source_candidate"):
        candidate.verified_manifest(raw, artifact, SHA)
    broken = dict(manifest, standby_auth_image="ghcr.io/appolon1908/kong-standby-auth")
    raw, artifact = archive(broken)
    with pytest.raises(ValueError, match="wrong_image_authority"):
        candidate.verified_manifest(raw, artifact, SHA)
