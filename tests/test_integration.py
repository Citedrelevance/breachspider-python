"""Integration tests against the live API using a read-only demo token.

Skipped automatically when the network / API is unreachable, or when
BREACHSPIDER_SKIP_INTEGRATION is set, so the suite stays green offline.

These use real, stable fixtures from the Schneider-Electric catalog:
vendor id 11529 / slug schneider-electric, product Modicon M340 id 25001.
"""

import os
import itertools

import pytest

import breachspider
from breachspider import exceptions as exc

pytestmark = pytest.mark.integration

if os.environ.get("BREACHSPIDER_SKIP_INTEGRATION"):
    pytest.skip("integration disabled via env", allow_module_level=True)


@pytest.fixture(scope="module")
def bs():
    try:
        client = breachspider.Client.demo()
    except (exc.APIConnectionError, exc.APIError) as e:
        pytest.skip(f"live API unreachable: {e}")
    return client


def test_vendor_lookup_reads_slug(bs):
    v = bs.catalog.vendor("schneider electric")
    assert v.id == 11529
    assert v.name == "Schneider-Electric"
    assert v.slug == "schneider-electric"  # read from response, not derived


def test_products_have_cve_counts(bs):
    products = bs.catalog.products(vendor_id=11529)
    m340 = next((p for p in products if p.id == 25001), None)
    assert m340 is not None
    assert m340.name == "Modicon M340"
    assert m340.cve_count == 41


def test_by_vendor_filters_critical_kev(bs):
    got = list(itertools.islice(
        bs.cves.by_vendor("schneider-electric", severity="CRITICAL", kev=True), 5))
    assert got, "expected at least one CRITICAL KEV CVE"
    for cve in got:
        assert cve.severity == "CRITICAL"
        assert cve.kev_flagged is True
        assert cve.cve_id.startswith("CVE-")


def test_get_single_cve_parses_nested(bs):
    cve = bs.cves.get("CVE-2025-32433")
    assert cve.cve_id == "CVE-2025-32433"
    assert cve.severity == "CRITICAL"
    assert cve.cvss_score == 10.0
    assert cve.html_url and cve.html_url.startswith("https://")


def test_per_page_over_100_is_validation_error(bs):
    # Bypass the client-side cap to confirm the server still enforces le=100.
    with pytest.raises(exc.ValidationError):
        bs.request("GET", "/cves", params={"per_page": 101})


def test_unknown_param_lists_accepted(bs):
    with pytest.raises(exc.UnknownParameterError) as ei:
        bs.request("GET", "/cves", params={"bogusparam": 1})
    assert "per_page" in ei.value.accepted_parameters


def test_demo_is_not_metered(bs):
    list(itertools.islice(bs.cves.search(vendor="schneider-electric", per_page=3), 3))
    # Demo tokens carry no X-RateLimit headers.
    assert bs.quota is None
