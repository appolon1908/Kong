#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from generate_middleware_routes import UNTRUSTED_IDENTITY_HEADERS,route_regex  # noqa: E402
import render_kong_mcr_routes as renderer  # noqa: E402
PATH=ROOT/"config/kong-mcr-routes.v1.json"
MIDDLEWARE_CONTRACT=ROOT/"config/middleware-public-api-route-contract.v1.json"
MIDDLEWARE_MANIFEST=ROOT/"config/kong-middleware-routes.production.yml"
EXPECTED={
 ("POST","/platform/v1/campaign-engine/plan"):"campaign.engine.plan",
 ("POST","/platform/v1/campaign-engine/execute"):"campaign.engine.execute",
 ("GET","/platform/v1/leads/{lead_id}/journey"):"leads.journey.read",
 ("GET","/platform/v1/leads/{lead_id}/next-action"):"campaign.engine.read",
 ("GET","/platform/v1/campaigns/{campaign_id}/eligible-leads"):"campaign.engine.read",
 ("POST","/platform/v1/delivery-events"):"campaign.delivery_events.publish",
 ("POST","/platform/v1/suppressions"):"campaign.suppressions.write",
 ("GET","/platform/v1/campaign-engine/status"):"campaign.engine.read",
}
WRITE_HEADERS={
 "/platform/v1/campaign-engine/execute":{"Idempotency-Key"},
 "/platform/v1/delivery-events":{"Idempotency-Key","X-Codestra-Event-ID","X-Codestra-Timestamp","X-Codestra-Signature"},
 "/platform/v1/suppressions":{"Idempotency-Key"},
}
PLUGIN_CHAIN=["pre-function","openid-connect","post-function","correlation-id","rate-limiting","request-size-limiting"]
PARAM=re.compile(r"\{[^{}]+\}")
# Private DB/internal surfaces that must never be reachable through an MCR route.
PRIVATE_PROBES=(
 "/internal/health","/internal/platform/v1/campaign-engine/plan","/metrics","/metrics/platform",
 "/platform/v1/internal/journey","/platform/v1/leads/../internal/journey",
 "/platform/v1/leads/%2e%2e/journey","/platform/v1/campaigns/odoo:CAMP/eligible-leads",
 "/platform/v1/campaign-engine/plan/","/platform/v1/campaign-engine/plan/extra",
)

def kong_regex(path:str)->re.Pattern[str]:
    if not (path.startswith("~/") and path.endswith("$")): raise ValueError(f"MCR path regex must use the Kong ~/ form and end with $: {path}")
    if "\\\\" in path: raise ValueError(f"double-escaped MCR path regex: {path}")
    try: return re.compile(path[1:])
    except re.error as exc: raise ValueError(f"invalid MCR path regex {path}: {exc}") from exc

def template_probe(template:str)->str:
    return PARAM.sub("TEST-SYN",template)

def probe_fits_template(probe:str,template:str)->bool:
    a,b=probe.strip("/").split("/"),template.strip("/").split("/")
    return len(a)==len(b) and all(PARAM.fullmatch(t) or t==p for p,t in zip(a,b))

def validate_header_policy(data):
    hp=data["headerPolicy"]
    if hp.get("authorization")!="preserve": raise ValueError("Authorization must be preserved")
    if hp.get("requiredHeadersEnforcedAtGateway") is not True or hp.get("requiredHeadersEnforcedUpstream") is not True:
        raise ValueError("required headers must be enforced at gateway and upstream")
    corr=hp.get("correlation",{})
    if corr!={"header":"X-Correlation-ID","callerSupplied":"required","echoDownstream":True}:
        raise ValueError("correlation header policy drift")
    idem=hp.get("idempotency",{})
    if idem.get("header")!="Idempotency-Key" or idem.get("preserve") is not True or idem.get("gatewayRetries")!=0:
        raise ValueError("idempotency header policy drift")
    errors=hp.get("gatewayErrors",{})
    if errors.get("contentType")!="application/json" or errors.get("missingHeaderStatus")!=400 or errors.get("unmatchedStatus")!=404:
        raise ValueError("gateway error header policy drift")
    codes=errors.get("missingHeaderCodes",{})
    if not all(isinstance(v,str) and re.fullmatch(r"[a-z_]+_required",v) for v in codes.values()):
        raise ValueError("gateway error codes must be snake_case *_required")
    keep=set(hp.get("doNotStrip",[])); cleared=set(hp.get("clearUntrustedIdentityHeaders",[]))
    if "Authorization" not in keep: raise ValueError("Authorization must be preserved")
    if not set(UNTRUSTED_IDENTITY_HEADERS)<=cleared: raise ValueError("untrusted identity header clearing weakened")
    if keep&cleared: raise ValueError(f"header both preserved and cleared: {sorted(keep&cleared)}")
    return keep,codes

def validate_isolation(data,compiled):
    contract=json.loads(MIDDLEWARE_CONTRACT.read_text(encoding="utf-8"))
    mw=[(r["method"],r["path"],re.compile(route_regex(r["path"])[1:])) for r in contract["routes"]]
    for method,path,_ in mw:
        for route,rx in compiled:
            if rx.fullmatch(template_probe(path)):
                raise ValueError(f"MCR route {route['name']} overlaps Middleware contract {method} {path}")
    for route,_ in compiled:
        for method,path,rx in mw:
            if method==route["method"] and rx.fullmatch(route["probePath"]):
                raise ValueError(f"MCR route {route['name']} shadowed by Middleware contract {path}")
    private={r["path"] for r in contract["routes"] if r["classification"]=="private_only"}
    denied=set(data.get("privateSurfacesDenied",[]))
    if not private<=denied or not {"/internal/","/metrics"}<=denied:
        raise ValueError("private DB/internal surfaces must be declared denied")
    for probe in (*PRIVATE_PROBES,*private,*(template_probe(r["path"]) for r in contract["routes"] if r["classification"]!="shared_edge")):
        for route,rx in compiled:
            if rx.fullmatch(probe): raise ValueError(f"private surface {probe} reachable via {route['name']}")
    manifest=yaml.safe_load(MIDDLEWARE_MANIFEST.read_text(encoding="utf-8"))
    service=next((s for s in manifest["services"] if s["name"]==renderer.SERVICE_NAME),None)
    if not service or (service["host"],service["port"],service["retries"])!=("middleware-integration-api",8095,0):
        raise ValueError("canonical Middleware :8095 service missing or retries enabled")

def validate_rendered(data):
    for environment in renderer.OUTPUTS:
        doc=renderer.render(data,environment)
        if "services" in doc: raise ValueError("MCR fragment must not declare services")
        for kr in doc["routes"]:
            if kr["service"]!=renderer.SERVICE_NAME: raise ValueError("MCR fragment upstream drift")
            if [p["name"] for p in kr["plugins"]]!=PLUGIN_CHAIN: raise ValueError("rendered plugin chain drift")

def validate(data):
    if data.get("schema")!="codestra.kong.mcr-routes.v1": raise ValueError("schema drift")
    if data.get("runtimeApplyAuthorized") is not False: raise ValueError("runtime apply must remain disabled")
    if data.get("productionEffectsAuthorized") is not False: raise ValueError("production effects must remain disabled")
    svc=data.get("service",{})
    if (svc.get("host"),svc.get("port")) != ("middleware-integration-api",8095):
        raise ValueError("MCR must route only to canonical Middleware :8095")
    boundary=data["routingBoundary"]
    if not all(boundary[k] is True for k in ("directProviderRoutingForbidden","directPublicMiddlewareExposureForbidden","internalAndMetricsPublicForbidden")):
        raise ValueError("routing boundary weakened")
    identity=data.get("identity",{})
    if identity.get("audience")!="middleware-api" or identity.get("consumerClaim")!="azp" or identity.get("authMethods")!=["bearer"]:
        raise ValueError("identity policy drift")
    if set(identity.get("issuers",{}))!=set(renderer.OUTPUTS) or not all(i.startswith("https://") for i in identity["issuers"].values()):
        raise ValueError("identity issuer drift")
    keep,codes=validate_header_policy(data)
    got={}; compiled=[]
    for route in data.get("routes",[]):
        key=(route["method"],route["pathTemplate"])
        if key in got: raise ValueError("duplicate MCR route")
        got[key]=route["requiredScope"]
        if (route["serviceHost"],route["servicePort"]) != ("middleware-integration-api",8095):
            raise ValueError("direct provider/noncanonical upstream")
        if route["host"]!=data["canonicalHost"]: raise ValueError("noncanonical MCR host")
        if route["stripPath"] is not False or route["preserveHost"] is not True:
            raise ValueError("path/host forwarding drift")
        if route["requiredPlugins"]!=PLUGIN_CHAIN:
            raise ValueError("plugin chain drift")
        headers=set(route["requiredHeaders"])
        if not {"X-Tenant-ID","X-Correlation-ID"} <= headers:
            raise ValueError("required MCR request context missing")
        if not WRITE_HEADERS.get(route["pathTemplate"],set()) <= headers:
            raise ValueError("write/signature headers missing")
        if not headers<=keep or not headers<=set(codes):
            raise ValueError("required headers must be preserved and carry a gateway error code")
        if "/internal" in route["pathTemplate"] or "/metrics" in route["pathTemplate"]:
            raise ValueError("internal route exposure")
        rx=kong_regex(route["pathRegex"])
        if not PARAM.search(route["pathTemplate"]):
            expected_regex = route_regex(route["pathTemplate"])
            if route["pathRegex"] != expected_regex:
                raise ValueError(f"path regex drift for {route['pathTemplate']}")
        if not probe_fits_template(route["probePath"],route["pathTemplate"]) or not rx.fullmatch(route["probePath"]):
            raise ValueError(f"path regex does not route its probe: {route['name']}")
        compiled.append((route,rx))
    if got != EXPECTED: raise ValueError(f"MCR route set drift: {got}")
    execute=next(r for r in data["routes"] if r["pathTemplate"]=="/platform/v1/campaign-engine/execute")
    if execute["effects"]!="hard_denied_by_middleware":
        raise ValueError("execute boundary must remain hard denied")
    validate_isolation(data,compiled)
    validate_rendered(data)

def main():
    data=json.loads(PATH.read_text())
    try: validate(data)
    except ValueError as exc:
        print("KONG_MCR_ROUTE_CONTRACT=FAIL"); print(f"ERROR={exc}"); return 1
    if renderer.main(["--check"])!=0: return 1
    print("KONG_MCR_ROUTE_CONTRACT=PASS")
    print(f"MCR_ROUTE_COUNT={len(data['routes'])}")
    print("MCR_UPSTREAM=middleware-integration-api:8095")
    print("MCR_PRIVATE_SURFACES_REACHABLE=0")
    print("MCR_PRODUCTION_EFFECTS_AUTHORIZED=false")
    return 0
if __name__=="__main__": raise SystemExit(main())
