"""API v1 correlate: client behaviour against recorded responses (no live calls).

Fixtures in tests/fixtures/ were recorded from the live API on 2026-09-26 with the public example device
(Moxa EDS-518A, firmware V3.5).
"""

import json
from pathlib import Path

import pytest
import responses

import breachspider
from breachspider import exceptions as exc

FIX = Path(__file__).parent / "fixtures"
URL = "https://breachspider.com/api/v1/assets/correlate-cves"
MOXA = {"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}


def rec(name):
    return json.loads((FIX / f"{name}.json").read_text())


@responses.activate
def test_correlate_default_parses_priority_fields(client):
    r = rec("v1_correlate_default")
    responses.add(responses.POST, URL, json=r["response"], status=r["status"])
    resp = client.correlate.correlate([MOXA])
    sent = json.loads(responses.calls[0].request.body)
    assert sent == {"assets": [MOXA]}                        # no options sent: the API's defaults apply
    assert resp.meta["sort"] == "priority"
    res = resp.results[0]
    assert res.status == "resolved" and res.confidence_band == "HIGH"
    assert [c.priority_rank for c in res.cves] == list(range(1, len(res.cves) + 1))
    assert all(c.confirmed and c.match_tier == "RANGE" for c in res.cves)
    assert res.cves[0].priority_reason.startswith("confirmed (affected 1.0 to 3.11)")
    assert res.cves[0].fix.derived and res.cves[0].fix.action == "upgrade beyond 3.11"
    assert res.fix_groups[0].fix == "upgrade beyond 3.11" and res.fix_groups[0].counts["total"] == len(res.cves)
    step = res.fix_plan.to_clear_all_fixable
    assert step.derived and "vendor's advisory" in step.note
    assert res.cves_page.total == 3 and res.cves_page.has_more is False
    assert resp.fix_summary[0].fix == "upgrade beyond 3.11" and resp.fix_summary[0].asset_ids == ["EXAMPLE-SWITCH-01"]
    assert res.result_hash.startswith("sha256:")


@responses.activate
def test_options_are_sent_and_validated(client):
    r = rec("v1_correlate_sort_exploit")
    responses.add(responses.POST, URL, json=r["response"], status=200)
    client.correlate.correlate([MOXA], sort="exploit", confirmed_only=True, known_exploited_only=False,
                               include_capec=False, cve_page_size=1000)
    opts = json.loads(responses.calls[0].request.body)["options"]
    assert opts == {"sort": "exploit", "confirmed_only": True, "known_exploited_only": False,
                    "include_capec": False, "cve_page_size": 1000}
    with pytest.raises(ValueError, match="sort must be one of: priority, score, exploit, newest"):
        client.correlate.correlate([MOXA], sort="cvss")
    with pytest.raises(ValueError, match="cve_page_size"):
        client.correlate.correlate([MOXA], cve_page_size=1001)
    with pytest.raises(ValueError, match="At most 200 assets"):
        client.correlate.correlate([MOXA] * 201)
    assert len(responses.calls) == 1                         # invalid calls never reached the network


@responses.activate
def test_result_hash_is_order_independent(client):
    a, b = rec("v1_correlate_default"), rec("v1_correlate_sort_exploit")
    responses.add(responses.POST, URL, json=a["response"], status=200)
    responses.add(responses.POST, URL, json=b["response"], status=200)
    h1 = client.correlate.correlate([MOXA]).results[0].result_hash
    h2 = client.correlate.correlate([MOXA], sort="exploit", confirmed_only=True).results[0].result_hash
    assert h1 == h2


@responses.activate
def test_server_side_invalid_sort_is_validation_error(client):
    r = rec("v1_error_invalid_sort")
    responses.add(responses.POST, URL, json=r["response"], status=r["status"])
    with pytest.raises(exc.ValidationError) as ei:
        client.request("POST", URL, json=r["request"])       # bypass the client-side check
    assert "sort must be one of" in json.dumps(ei.value.detail)


@responses.activate
def test_iter_asset_cves_fetches_every_page(client):
    p1, p2 = rec("v1_correlate_page1"), rec("v1_correlate_page2")
    responses.add(responses.POST, URL, json=p1["response"], status=200)
    responses.add(responses.POST, URL, json=p2["response"], status=200)
    cves = client.correlate.all_cves(MOXA, cve_page_size=2)
    assert [c.priority_rank for c in cves] == [1, 2, 3]
    assert [json.loads(c.request.body)["options"]["cve_page"] for c in responses.calls] == [1, 2]
    full = rec("v1_correlate_default")["response"]["data"]["results"][0]["cves"]
    assert [c.cve_id for c in cves] == [c["cve_id"] for c in full]       # pages concatenate to the full ranked list


@responses.activate
def test_check(client):
    r = rec("v1_check")
    responses.add(responses.POST, URL + "/check", json=r["response"], status=200)
    out = client.correlate.check(r["request"]["assets"])
    assert [(x.asset_id, x.changed) for x in out] == [("EXAMPLE-SWITCH-01", False), ("EXAMPLE-SWITCH-02", True)]


@responses.activate
def test_rate_limit_retry_uses_body_retry_after(client, monkeypatch):
    r, ok = rec("v1_error_rate_limited"), rec("v1_correlate_default")
    responses.add(responses.POST, URL, json=r["response"], status=429)
    responses.add(responses.POST, URL, json=ok["response"], status=200)
    slept = []
    monkeypatch.setattr("breachspider.client.time.sleep", lambda s: slept.append(s))
    resp = client.correlate.correlate([MOXA])
    assert resp.results and slept == [float(r["response"]["error"]["detail"]["retry_after"])]


@responses.activate
def test_rate_limit_error_after_retries(client, monkeypatch):
    r = rec("v1_error_rate_limited")
    for _ in range(3):
        responses.add(responses.POST, URL, json=r["response"], status=429)
    monkeypatch.setattr("breachspider.client.time.sleep", lambda s: None)
    with pytest.raises(exc.RateLimitError) as ei:
        client.correlate.correlate([MOXA])
    assert ei.value.retry_after == float(r["response"]["error"]["detail"]["retry_after"])


def test_firmware_version_is_passed_through(client):
    with responses.RequestsMock() as rsps:
        rsps.add(responses.POST, URL, json=rec("v1_correlate_default")["response"], status=200)
        client.correlate.correlate([{"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A",
                                     "firmware_version": "V3.5"}])
        assert json.loads(rsps.calls[0].request.body)["assets"][0]["firmware_version"] == "V3.5"
