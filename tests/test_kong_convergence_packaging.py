from pathlib import Path
import json
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_plugin_order_matches_governed_trust_boundary():
    registry = json.loads((ROOT / 'config/kong-gateway-foundation.v1.json').read_text())['plugins']
    priorities = {}
    for handler in (ROOT / 'deploy/kong/plugins').glob('*/handler.lua'):
        name = handler.parent.name
        priority = int(re.search(r'PRIORITY\s*=\s*(\d+)', handler.read_text()).group(1))
        entry = next(item for item in registry if item['plugin'] == name)
        assert entry['priority'] == priority
        priorities[name] = priority
    assert priorities['codestra-private-surface'] > priorities['codestra-request-context']
    assert priorities['codestra-authz'] > priorities['codestra-resource-guard']


@pytest.mark.parametrize('profile', ['deploy/gateway-platform/compose.hybrid.yaml',
    'deploy/gateway-platform/compose.traditional.yaml', 'deploy/kong/compose.kong.yaml'])
def test_every_runtime_profile_loads_reviewed_custom_plugin_sources(profile):
    path = ROOT / profile
    doc = yaml.safe_load(path.read_text())
    required = {'codestra-authz', 'codestra-request-context', 'codestra-webhook-verifier',
                'codestra-private-surface', 'codestra-resource-guard'}
    for service in doc['services'].values():
        assert required <= set(service['environment']['KONG_PLUGINS'].split(','))
        mounts = {v['target']: v for v in service['volumes'] if isinstance(v, dict)}
        for plugin in required:
            mount = mounts['/usr/local/share/lua/5.1/kong/plugins/' + plugin]
            assert mount['read_only'] is True
            source = (path.parent / mount['source']).resolve()
            assert source == ROOT / 'deploy/kong/plugins' / plugin
            assert (source / 'handler.lua').is_file()
            assert (source / 'schema.lua').is_file()
