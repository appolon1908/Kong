#!/usr/bin/env python3
import ipaddress
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
contract_path = root / "config/kong-community-n8n-egress.v1.json"
route_authority_path = root / "config/kong-n8n-control-plane-routes.json"
contract = json.loads(contract_path.read_text())
route_authority = json.loads(route_authority_path.read_text())
service = contract["service"]
route = contract["route"]
current = contract["current_runtime_authority"]
promotion = contract["promotion_gates"]

assert contract["schema_version"] == "1.1"
# The /v1/integrations/n8n aliases are denied by the canonical Middleware edge
# contract, so this HTTPS egress proposal is superseded and can never be applied.
assert contract["status"] == "SUPERSEDED_NOT_APPLIED"
superseded = contract["superseded_by"]
assert superseded["decision"] == "R6-2026-09-16-canonical-middleware-upstream"
assert (root / superseded["contract"]).is_file()
assert (root / superseded["contract_sha256_pin"]).is_file()
for manifest in superseded["canonical_manifests"]:
    assert (root / manifest).is_file(), manifest
    assert "8080" not in (root / manifest).read_text(encoding="utf-8"), manifest
assert contract["public_endpoint"] == "https://api.codestra.co/v1/integrations/n8n"
assert service["protocol"] == "https" and service["port"] == 443 and service["tls_verify"] is True
assert service["host_source"] == "MIDDLEWARE_TLS_HOST"
assert service["ip_literal_allowed"] is False
assert route["protocols"] == ["https"] and route["methods"] == ["GET", "POST"]
assert route["http_redirect_status"] in (301, 308)
assert set(contract["plugins"]["names"]) == {
    "correlation-id", "request-transformer", "request-size-limiting", "rate-limiting"
}
assert contract["identity"]["client_id"] == "n8n-automation"
assert contract["identity"]["middleware_revalidates_token"] is True
assert contract["safety"]["external_effects_enabled"] is False
assert contract["safety"]["current_route_mutation_authorized"] is False

# The route authority is retired deny-only and bound to the single canonical
# Middleware upstream. The legacy runtime verified in PR #30 stays recorded as
# retired so no source-only change can route the denied aliases back to it.
assert current["status"] == "RETIRED_DENY_ONLY"
assert current["authority_path"] == "config/kong-n8n-control-plane-routes.json"
assert current["service_host"] == "middleware-integration-api"
assert current["service_port"] == 8095
assert current["service_protocol"] == "http"
assert current["service_enabled"] is False
assert current["mutation_authorized"] is False
assert current["evidence_url"] == "https://github.com/appolon1908/Kong/pull/30"
denied_aliases = set(current["ambiguous_aliases_denied"])
assert denied_aliases == {"appolon-middleware-integration-api"}
legacy = current["retired_legacy_runtime"]
assert legacy["host"] == "appolon-middleware-integration-api"
assert legacy["port"] == 8080
assert legacy["evidence_url"] == current["evidence_url"]

production_service = route_authority["service"]
assert route_authority["status"] == "RETIRED_DENY_ONLY"
assert route_authority["runtime_apply_authorized"] is False
assert production_service["enabled"] is False
assert production_service["host"] == current["service_host"]
assert production_service["port"] == current["service_port"]
assert production_service["protocol"] == current["service_protocol"]
assert production_service["host"] not in denied_aliases
assert production_service["host"] != legacy["host"]
assert production_service["port"] != legacy["port"]
assert {item["classification"] for item in route_authority["routes"]} == {"denied"}
assert route_authority["client_id"] == contract["identity"]["client_id"]
assert route_authority["audience"] == contract["identity"]["audience"]

required_results = {
    "source_sha_verified",
    "current_runtime_unique",
    "ambiguous_alias_not_current_runtime",
    "tls_candidate_resolves",
    "tls_candidate_same_runtime",
    "tls_certificate_verified",
    "tls_hostname_verified",
    "readiness_response_fail_closed",
    "no_runtime_mutations_performed",
}
assert set(promotion["required_results"]) == required_results
assert promotion["promotion_authorized"] is False
assert promotion["exact_head_ci_required"] is True
assert promotion["independent_review_required"] is True
assert promotion["rollback_rehearsal_required"] is True

collector_path = root / promotion["topology_collector"]
schema_path = root / promotion["topology_evidence_schema"]
assert collector_path.is_file() and schema_path.is_file()
schema = json.loads(schema_path.read_text())
assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
assert schema["properties"]["runtime_mutations_performed"]["const"] is False
assert schema["properties"]["secrets_captured"]["const"] is False
assert schema["properties"]["gates"]["properties"]["source_sha_verified"]["const"] is True

collector_source = collector_path.read_text()
for required_token in (
    "git",
    "rev-parse",
    "--show-toplevel",
    "HEAD^{commit}",
    "--porcelain=v1",
    "--untracked-files=all",
    "ls-files",
    "docker",
    "inspect",
    "getent",
    "openssl",
    "curl",
    "verified_source_sha",
    "metadata_identifies_kong",
    'EXPECTED_KONG_SERVICE_LABEL = "kong-gateway"',
    "service_label == EXPECTED_KONG_SERVICE_LABEL",
    "tls_targets_exclusively_match_current_runtime",
    "tls_resolved.issubset",
    "CANDIDATE_BLOCKED",
    "runtime_mutations_performed",
    "secrets_captured",
):
    assert required_token in collector_source
for forbidden_token in (
    "docker network connect",
    "docker network disconnect",
    "docker restart",
    "docker stop",
    "docker rm",
    "iptables",
    "nft ",
    'return "kong" in',
    "NON_KONG_IDENTITY_TOKENS",
):
    assert forbidden_token not in collector_source

host = os.environ.get("MIDDLEWARE_TLS_HOST")
if host:
    assert not host.startswith("http://") and not host.startswith("https://")
    assert host not in denied_aliases
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise AssertionError("MIDDLEWARE_TLS_HOST must be a DNS name, not an IP literal")

print("KONG_COMMUNITY_N8N_EGRESS=PASS")
print("CURRENT_N8N_RUNTIME_AUTHORITY=RETIRED_DENY_ONLY")
print("CANONICAL_MIDDLEWARE_UPSTREAM=middleware-integration-api:8095")
print("COMMUNITY_HTTPS_PROMOTION=NOT_AUTHORIZED")
