import copy
import json
from pathlib import Path

import pytest

from scripts.gateway_integrations import ContractError, compile_integrations, validate
from scripts.generate_middleware_routes import build_manifest, route_plugins

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def contract():
    return json.loads((ROOT / 'config/integrations/examples/moneybee-account-bootstrap.json').read_text())


def plugins(document):
    result = compile_integrations([document], environment='staging')
    return {p['name']: p['config'] for p in result['kong']['services'][0]['routes'][0]['plugins']}


def test_default_route_has_bounded_burst_concurrency_and_body(contract):
    configured = plugins(contract)
    assert configured['rate-limiting']['second'] == 10
    assert configured['rate-limiting']['minute'] == 10
    assert configured['rate-limiting']['error_code'] == 429
    assert configured['codestra-resource-guard']['concurrency_limit_per_worker'] == 32
    assert configured['codestra-resource-guard']['tenant_quota_per_minute'] == 0
    assert configured['request-size-limiting']['allowed_payload_size'] == 65536


def test_route_policy_can_select_verified_tenant_quota(contract):
    contract['spec']['routes'][0]['trafficPolicy'] = {
        'burstPerSecond': 2, 'maxConcurrentPerWorker': 4, 'tenantQuotaPerMinute': 20,
    }
    configured = plugins(contract)
    assert configured['rate-limiting']['second'] == 2
    guard = configured['codestra-resource-guard']
    assert guard['concurrency_limit_per_worker'] == 4
    assert guard['tenant_quota_per_minute'] == 20
    assert guard['redis']['host'] == 'codestra-redis'
    assert guard['redis']['password'].startswith('{vault://')


def test_non_idempotent_retry_needs_explicit_route_authorization(contract):
    contract['spec']['upstream']['retries'] = 1
    with pytest.raises(ContractError, match='unsafe_write_retry'):
        validate(contract)
    contract['spec']['routes'][0]['retrySafe'] = True
    validate(contract)


def test_webhook_cannot_claim_authenticated_tenant_quota(contract):
    contract['spec']['authentication'] = {
        'template': 'signed-webhook', 'keyId': 'webhook-v1',
        'secretRef': '{vault://env/kong-webhook-moneybee-account-bootstrap}',
    }
    contract['spec']['routes'][0]['scopes'] = []
    contract['spec']['policies']['corsOrigins'] = []
    contract['spec']['routes'][0]['trafficPolicy'] = {'tenantQuotaPerMinute': 20}
    with pytest.raises(ContractError, match='tenant_quota_requires_verified_identity'):
        validate(contract)


def test_circuit_opens_on_passive_connection_and_timeout_failures(contract):
    output = compile_integrations([contract], environment='staging')
    passive = output['kong']['upstreams'][0]['healthchecks']['passive']
    assert passive['unhealthy']['tcp_failures'] == 2
    assert passive['unhealthy']['timeouts'] == 2
    assert passive['unhealthy']['http_statuses'] == [500, 502, 503, 504]


def test_canonical_middleware_routes_use_same_traffic_boundaries():
    rows = json.loads((ROOT / 'config/middleware-public-api-route-contract.v1.json').read_text())['routes']
    row = next(r for r in rows if r['classification'] == 'shared_edge')
    configured = {p['name']: p['config'] for p in route_plugins(row, 'https://auth.codestra.co/realms/codestra')}
    assert configured['rate-limiting']['second'] == 10
    assert configured['codestra-resource-guard']['concurrency_limit_per_worker'] == 32
    assert configured['codestra-private-surface']['allow_private'] is False


def test_traffic_policy_is_bound_into_deterministic_digest(contract):
    before = compile_integrations([contract], environment='staging')
    contract['spec']['routes'][0]['trafficPolicy'] = {'maxConcurrentPerWorker': 2}
    after = compile_integrations([contract], environment='staging')
    assert before['config_sha256'] != after['config_sha256']
    assert after == compile_integrations([copy.deepcopy(contract)], environment='staging')


def test_canonical_runtime_has_upstream_circuit_and_preserves_middleware_target():
    manifest = build_manifest([], [], 'https://auth.codestra.co/realms/codestra', 'production')
    upstream = manifest['upstreams'][0]
    assert upstream['name'] == manifest['services'][0]['host']
    assert upstream['targets'] == [{'target': 'middleware-integration-api:8095', 'weight': 100}]
    assert upstream['healthchecks']['passive']['unhealthy']['timeouts'] == 2
    assert upstream['healthchecks']['active']['http_path'] == '/readyz'


def test_maximum_route_name_still_produces_valid_guard_namespace(contract):
    contract['metadata']['id'] = 'a' * 63
    contract['spec']['routes'][0]['id'] = 'b' * 63
    assert len(plugins(contract)['codestra-resource-guard']['route_key']) <= 128
