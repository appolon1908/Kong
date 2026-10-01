import json
from pathlib import Path
def test_k1_runtime_authority_is_fail_closed():
 x=json.loads(Path('config/kong-runtime-config-mode.v1.json').read_text())
 assert x['production_mode']=='hybrid'
 assert x['standalone_dbless_production'] is False
 assert x['admin_api']['public'] is False
 assert x['hybrid_cluster']['mtls'] is True
 assert x['runtime_apply_authorized'] is False
