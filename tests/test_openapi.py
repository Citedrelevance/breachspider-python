"""The shipped OpenAPI document is valid and covers every correlate endpoint the client wraps."""

import json
from pathlib import Path

import pytest

SPEC = Path(__file__).parent.parent / "openapi" / "breachspider-openapi.json"


def test_spec_is_valid_openapi():
    validator = pytest.importorskip("openapi_spec_validator")
    validator.validate(json.loads(SPEC.read_text()))


def test_spec_covers_client_endpoints():
    paths = json.loads(SPEC.read_text())["paths"]
    for p, m in (("/api/v1/assets/correlate-cves", "post"), ("/api/v1/assets/correlate-cves/check", "post"),
                 ("/api/v2/assets/correlate", "post"), ("/api/v2/assets/correlate-csv", "post"),
                 ("/api/v2/assets/results", "get")):
        assert m in paths[p]
    sort = json.loads(SPEC.read_text())["components"]["schemas"]["CorrelateOptions"]["properties"]["sort"]
    assert sort["enum"] == ["priority", "score", "exploit", "newest"]
