import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GENERATOR = ROOT / "tools/generate_release_manifest.py"


def module():
    spec = importlib.util.spec_from_file_location("generate_release_manifest", GENERATOR)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_release_images_require_immutable_sha256_digests():
    pattern = module().IMAGE_DIGEST
    assert pattern.fullmatch("sha256:" + "a" * 64)
    assert not pattern.fullmatch("latest")
    assert not pattern.fullmatch("sha256:abc")
    assert not pattern.fullmatch("sha256:" + "A" * 64)


def test_release_signature_must_be_verified():
    verified = module().VERIFIED_SIGNATURES
    assert {"G", "U", "VERIFIED"} <= verified
    assert "N" not in verified
    assert "UNVERIFIED" not in verified


def test_release_stage_is_explicit_and_fail_closed():
    release = module()
    assert release.RELEASE_STAGES == {
        "pull-request-preflight",
        "protected-main-source-candidate",
        "staging-certified",
        "production",
    }
    assert release.BUILD_STAGES == {"pull-request-preflight", "protected-main-source-candidate"}
    sha = "a" * 40
    assert release.CERTIFICATION_ID.fullmatch(f"PASS:{sha}:staging-run-123")
    assert not release.CERTIFICATION_ID.fullmatch("PASS:staging-run-123")
    assert not release.CERTIFICATION_ID.fullmatch("PENDING")


def test_staging_promotion_requires_exact_main_tree():
    workflow = (ROOT / ".github/workflows/staging-certification.yml").read_text()
    assert 'git/ref/heads/main' in workflow
    assert 'test "$HEAD_SHA" = "$main_sha"' in workflow
    assert 'release/staging-main-${main_sha:0:12}' in workflow
    assert '.commit.verification.verified' in workflow
    assert 'test "$head_verified" = true' in workflow
    assert 'test "$head_tree" = "$main_tree"' in workflow
    assert 'git/commits/${MERGE_SHA}' in workflow
    assert 'test \"$merge_tree\" = \"$main_tree\"' in workflow


def test_release_evidence_builds_exact_immutable_standby_image():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "packages: write" in workflow
    assert "--provenance=mode=max" in workflow
    assert "--sbom=true" in workflow
    assert 'org.opencontainers.image.revision=${EXPECTED_SHA}' in workflow
    assert 'name: release-evidence' in workflow
    assert "latest" not in workflow


def test_staging_and_production_release_require_live_topology_gate():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "runs-on: [self-hosted, linux, kong-runtime]" in workflow
    assert "python3 scripts/verify_runtime_integration.py" in workflow
    assert "needs: [runtime-topology]" in workflow
    assert "needs.runtime-topology.result == 'success'" in workflow
    assert 'PASS:${CERTIFIED_SOURCE_SHA}:' in workflow
    assert '--candidate-manifest' in workflow


def test_standby_compose_forbids_deploy_time_build_and_floating_tag():
    compose = (ROOT / "deploy/kong-production-standby/compose.standby.yaml").read_text()
    assert "build:" not in compose
    assert "codestra/kong-standby-auth:20260820" not in compose
    from tools.release_contract import STANDBY_IMAGE

    assert STANDBY_IMAGE + "@${KONG_STANDBY_AUTH_IMAGE_DIGEST:?" in compose
    image_line = compose.split("image:")[1].splitlines()[0]
    assert "appolon1908" not in image_line
