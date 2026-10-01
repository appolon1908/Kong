from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_admin_is_not_reachable_from_peer_container_networks():
    service = yaml.safe_load((ROOT / 'deploy/kong/compose.kong.yaml').read_text())['services']['kong-gateway']
    assert service['environment']['KONG_ADMIN_LISTEN'] == 'off'
    assert service['environment'].get('KONG_ADMIN_GUI_LISTEN') == 'off'
    assert not any(':8001' in port for port in service.get('ports', []))


def test_promotions_reuse_original_candidate_without_rebuild():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    assert 'CERTIFIED_SOURCE_SHA' in workflow
    assert 'KONG_CANDIDATE_RUN_ID' in workflow
    assert 'if: github.ref_name == \'main\'' in workflow
    assert '--candidate-manifest' in workflow
    assert 'PASS:${EXPECTED_SHA}:' not in workflow
