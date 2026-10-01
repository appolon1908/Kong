from __future__ import annotations
import copy,importlib.util,json
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("mcr",ROOT/"scripts/validate_kong_mcr_routes.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
BASE=json.loads((ROOT/"config/kong-mcr-routes.v1.json").read_text())

def test_contract_passes(): mod.validate(copy.deepcopy(BASE))
def test_execute_activation_fails():
 d=copy.deepcopy(BASE);d["productionEffectsAuthorized"]=True
 with pytest.raises(ValueError,match="production effects"): mod.validate(d)
def test_direct_provider_upstream_fails():
 d=copy.deepcopy(BASE);d["routes"][0]["serviceHost"]="klyrow"
 with pytest.raises(ValueError,match="direct provider"): mod.validate(d)
def test_delivery_signature_header_removal_fails():
 d=copy.deepcopy(BASE);r=next(x for x in d["routes"] if x["pathTemplate"]=="/platform/v1/delivery-events");r["requiredHeaders"].remove("X-Codestra-Signature")
 with pytest.raises(ValueError,match="headers"): mod.validate(d)
def test_authorization_strip_fails():
 d=copy.deepcopy(BASE);d["headerPolicy"]["authorization"]="strip"
 with pytest.raises(ValueError,match="Authorization"): mod.validate(d)
def test_route_loss_fails():
 d=copy.deepcopy(BASE);d["routes"]=d["routes"][:-1]
 with pytest.raises(ValueError,match="route set"): mod.validate(d)
def route(d,name): return next(x for x in d["routes"] if x["name"]==name)
def test_double_escaped_regex_fails():
 d=copy.deepcopy(BASE);r=route(d,"mcr-plan");r["pathRegex"]=r["pathRegex"].replace("\\-","\\\\-")
 with pytest.raises(ValueError,match="double-escaped"): mod.validate(d)
def test_every_regex_routes_its_probe_and_hyphenated_paths_match():
 import re
 for r in BASE["routes"]:
  assert re.fullmatch(r["pathRegex"][1:],r["probePath"]),r["name"]
 assert re.fullmatch(route(BASE,"mcr-next-action")["pathRegex"][1:],"/platform/v1/leads/L1/next-action")
def test_probe_outside_template_fails():
 d=copy.deepcopy(BASE);route(d,"mcr-journey")["probePath"]="/platform/v1/leads/L1/next-action"
 with pytest.raises(ValueError,match="does not route its probe"): mod.validate(d)
def test_overlap_with_middleware_contract_fails():
 d=copy.deepcopy(BASE);route(d,"mcr-journey")["pathRegex"]="~/platform/v1/(?:leads/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/journey|contacts)$"
 with pytest.raises(ValueError,match="overlaps Middleware contract"): mod.validate(d)
def test_private_odoo_surface_reachable_fails():
 d=copy.deepcopy(BASE);r=route(d,"mcr-eligible-leads");r["pathRegex"]="~/platform/v1/campaigns/[^/]+/eligible\\-leads$"
 with pytest.raises(ValueError,match="private surface"): mod.validate(d)
def test_private_surfaces_must_be_declared_denied():
 d=copy.deepcopy(BASE);d["privateSurfacesDenied"].remove("/api/v1/integration/campaigns/actual-state")
 with pytest.raises(ValueError,match="private DB/internal"): mod.validate(d)
def test_header_both_preserved_and_cleared_fails():
 d=copy.deepcopy(BASE);d["headerPolicy"]["clearUntrustedIdentityHeaders"].append("X-Tenant-ID")
 with pytest.raises(ValueError,match="both preserved and cleared"): mod.validate(d)
def test_untrusted_identity_clearing_weakened_fails():
 d=copy.deepcopy(BASE);d["headerPolicy"]["clearUntrustedIdentityHeaders"].remove("X-Admin")
 with pytest.raises(ValueError,match="untrusted identity"): mod.validate(d)
def test_generated_correlation_masking_fails():
 d=copy.deepcopy(BASE);d["headerPolicy"]["correlation"]["callerSupplied"]="generated"
 with pytest.raises(ValueError,match="correlation"): mod.validate(d)
def test_gateway_idempotency_retries_fail():
 d=copy.deepcopy(BASE);d["headerPolicy"]["idempotency"]["gatewayRetries"]=1
 with pytest.raises(ValueError,match="idempotency"): mod.validate(d)
def test_required_header_without_error_code_fails():
 d=copy.deepcopy(BASE);del d["headerPolicy"]["gatewayErrors"]["missingHeaderCodes"]["X-Tenant-ID"]
 with pytest.raises(ValueError,match="gateway error code"): mod.validate(d)
def test_plugin_chain_without_header_guard_fails():
 d=copy.deepcopy(BASE);route(d,"mcr-plan")["requiredPlugins"].remove("pre-function")
 with pytest.raises(ValueError,match="plugin chain"): mod.validate(d)
def test_rendered_fragments_are_fresh_and_bound_to_middleware_service():
 import yaml
 rspec=importlib.util.spec_from_file_location("mcr_render",ROOT/"scripts/render_kong_mcr_routes.py")
 render=importlib.util.module_from_spec(rspec);rspec.loader.exec_module(render)
 assert render.main(["--check"])==0
 for env,path in render.OUTPUTS.items():
  doc=yaml.safe_load(path.read_text())
  assert "services" not in doc and len(doc["routes"])==8
  issuer=BASE["identity"]["issuers"][env]
  for kr in doc["routes"]:
   assert kr["service"]=="middleware-integration-api" and kr["strip_path"] is False and kr["preserve_host"] is True
   plugins={p["name"]:p["config"] for p in kr["plugins"]}
   assert plugins["openid-connect"]["issuer"].startswith(issuer+"/")
   assert plugins["openid-connect"]["audience"]==["middleware-api"]
   guard=plugins["pre-function"]["access"][0]
   for h in route(BASE,kr["name"])["requiredHeaders"]:
    assert f'"{h}"' in guard
   assert "clear_header" in plugins["post-function"]["access"][0]
   assert plugins["request-size-limiting"]=={"allowed_payload_size":1,"size_unit":"megabytes"}
def test_renderer_refuses_apply():
 rspec=importlib.util.spec_from_file_location("mcr_render2",ROOT/"scripts/render_kong_mcr_routes.py")
 render=importlib.util.module_from_spec(rspec);rspec.loader.exec_module(render)
 with pytest.raises(SystemExit): render.main(["--apply"])
def test_non_kong_regex_path_form_fails():
 d=copy.deepcopy(BASE);r=route(d,"mcr-plan");r["pathRegex"]="~^"+r["pathRegex"][1:]
 with pytest.raises(ValueError,match="Kong ~/ form"): mod.validate(d)
def _run_guard(headers):
 import yaml
 from lupa import LuaRuntime
 doc=yaml.safe_load((ROOT/"config/kong-mcr-routes.production.yml").read_text())
 kr=next(r for r in doc["routes"] if r["name"]=="mcr-plan")
 guard=next(p for p in kr["plugins"] if p["name"]=="pre-function")["config"]["access"][0]
 lua=LuaRuntime(unpack_returned_tuples=True)
 exits=[]
 lua.globals().py_header=lambda name: headers.get(name)
 lua.globals().py_exit=lambda status,body,hdrs: exits.append((status,dict(body),dict(hdrs))) or "exited"
 lua.execute("kong={request={get_header=function(n) return py_header(n) end},response={exit=function(s,b,h) return py_exit(s,b,h) end}}")
 lua.execute(guard)
 return exits
def test_header_guard_echoes_safe_correlation_id_on_rejection():
 exits=_run_guard({"X-Correlation-ID":"TEST_SYN-corr.1:a"})
 assert exits and exits[0][0]==400 and exits[0][1]["error"]=="tenant_id_required"
 assert exits[0][2]["X-Correlation-ID"]=="TEST_SYN-corr.1:a" and exits[0][2]["Content-Type"]=="application/json"
def test_header_guard_never_reflects_unsafe_correlation_id():
 for bad in ("x\r\nSet-Cookie: a=b","-leading-dash","a"*129,"has space"):
  exits=_run_guard({"X-Correlation-ID":bad})
  assert exits and "X-Correlation-ID" not in exits[0][2]
def test_header_guard_passes_complete_caller_context():
 assert _run_guard({"X-Correlation-ID":"TEST_SYN-1","X-Tenant-ID":"tenant-1"})==[]
