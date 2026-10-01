"""Every Kong-bound route path must satisfy Kong's own router path schema.

Kong 3.x `typedefs.router_path` accepts only paths that start with `/` (fixed)
or `~/` (regex) and contain no empty segment; anything else is rejected when the
declarative configuration is loaded. `deck file validate` does not enforce this
offline, so the rule is pinned here against every rendered and committed source.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.gateway_integrations import compile_integrations


ROOT = Path(__file__).resolve().parents[1]
KONG_ROUTER_PATH = re.compile(r"(?:/|~/)")

DECLARATIVE_FILES = (
    "deploy/kong/control-plane.yml",
    "config/kong-middleware-routes.production.yml",
    "config/staging/kong-middleware-routes.staging.yml",
    "config/kong-mcr-routes.production.yml",
    "config/staging/kong-mcr-routes.staging.yml",
    "config/marketing-stage4-routes.yaml",
)
RENDERERS = (
    ("scripts/render_kong_calling_routes.py",),
    ("scripts/render_kong_moneybee_identity.py",),
    ("scripts/render_kong_campaign_automation_routes.py", "--environment", "production"),
    ("scripts/render_kong_campaign_automation_routes.py", "--environment", "staging"),
)
SOURCE_AUTHORITIES = (
    ("config/kong-mcr-routes.v1.json", "pathRegex"),
    ("config/kong-calling-routes.v1.json", "path"),
    ("config/kong-platform-api-read-routes.v1.json", "path"),
)


def route_paths(document):
    for service in document.get("services") or ():
        for route in service.get("routes") or ():
            yield route.get("name"), route.get("paths") or ()
    for route in document.get("routes") or ():
        yield route.get("name"), route.get("paths") or ()


def field_values(value, field):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == field and isinstance(item, str):
                yield item
            else:
                yield from field_values(item, field)
    elif isinstance(value, list):
        for item in value:
            yield from field_values(item, field)


def assert_router_path(path, where):
    assert KONG_ROUTER_PATH.match(path), f"{where}: {path!r} should start with / or ~/"
    assert "//" not in path, f"{where}: {path!r} has an empty segment"
    if path.startswith("~"):
        re.compile(path[1:])


def assert_document(document, where):
    checked = 0
    for name, paths in route_paths(document):
        for path in paths:
            assert_router_path(path, f"{where}:{name}")
            checked += 1
    return checked


@pytest.mark.parametrize("path", DECLARATIVE_FILES)
def test_committed_declarative_routes_load_under_kong_path_schema(path):
    document = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    assert assert_document(document, path) > 0


@pytest.mark.parametrize("argv", RENDERERS, ids=lambda argv: " ".join(argv))
def test_rendered_routes_load_under_kong_path_schema(argv):
    result = subprocess.run([sys.executable, *argv], cwd=ROOT, capture_output=True, text=True, check=True)
    assert assert_document(yaml.safe_load(result.stdout), argv[0]) > 0


def test_compiled_integration_routes_load_under_kong_path_schema():
    documents = [json.loads(path.read_text(encoding="utf-8"))
                 for path in sorted((ROOT / "config/integrations/examples").glob("*.json"))]
    environments = {document["metadata"]["environment"] for document in documents}
    checked = sum(assert_document(compile_integrations(documents, environment=env)["kong"], f"integrations:{env}")
                  for env in sorted(environments))
    assert checked > 0


@pytest.mark.parametrize("path,field", SOURCE_AUTHORITIES)
def test_route_authorities_use_kong_path_schema(path, field):
    values = list(field_values(json.loads((ROOT / path).read_text(encoding="utf-8")), field))
    assert values
    for value in values:
        assert_router_path(value, path)


@pytest.mark.parametrize("path", ["~^/platform/v1/x$", "platform/v1/x", "^/x$", "~x", "/a//b"])
def test_kong_path_schema_rejects_non_kong_forms(path):
    with pytest.raises(AssertionError):
        assert_router_path(path, "negative-control")
