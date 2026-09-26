"""API v2 Windows patch level: client behaviour against recorded responses (no live calls).

Fixtures were recorded from the live API on 2026-09-26 with illustrative test hosts only (WIN-EXAMPLE-01 Server 2019
about a year behind, WIN-EXAMPLE-02 Server 2012 R2 without ESU, WIN-EXAMPLE-03 refused for a hostname field).
"""

import copy
import json
from pathlib import Path

import pytest
import responses

from breachspider import exceptions as exc
from breachspider.resources.windows import RECOMMENDED_HOSTS_PER_CALL

FIX = Path(__file__).parent / "fixtures"
BASE = "https://breachspider.com/api/v2/assets"


def rec(name):
    return json.loads((FIX / f"{name}.json").read_text())


@responses.activate
def test_correlate_json_with_a_refused_host(client):
    r = rec("v2_correlate")
    responses.add(responses.POST, f"{BASE}/correlate", json=r["response"], status=200)
    resp = client.windows.correlate(12, r["request"]["windows_hosts"], include_cleared=False, cve_page_size=3)
    sent = json.loads(responses.calls[0].request.body)
    assert sent["environment_id"] == 12 and sent["options"] == {"include_cleared": False, "cve_page_size": 3}
    assert resp.status_code == 200 and not resp.all_refused
    assert [a.asset_id for a in resp.assets] == ["WIN-EXAMPLE-01", "WIN-EXAMPLE-02"]
    assert resp.rejected[0].asset_id == "WIN-EXAMPLE-03" and resp.rejected[0].error_codes == ["forbidden_field"]
    srv = resp.assets[0]
    assert srv.microsoft_product == "Windows Server 2019" and srv.patch_resolved
    assert srv.cves[0].status == "confirmed open" and srv.cves[0].priority_rank == 1
    assert srv.cves_page.page_size == 3 and srv.cves_page.has_more
    assert srv.fix_groups[0].fix.startswith("install KB") and srv.fix_groups[0].fix_type == "kb"
    assert srv.fix_groups[0].counts["total"] == srv.counts["confirmed_open"]     # one cumulative update clears all
    eol = resp.assets[1]
    assert eol.end_of_life and "end of life" in eol.labels
    assert eol.fix_groups[0].fix == "ESU required (or upgrade the OS)" and eol.fix_groups[0].fix_type == "esu"
    assert resp.fix_summary and resp.fix_summary[0].rank == 1
    assert resp.meta["sort"] == "priority"


@responses.activate
def test_all_hosts_refused_returns_result_not_exception(client):
    r = rec("v2_error_all_refused")
    responses.add(responses.POST, f"{BASE}/correlate", json=r["response"], status=r["status"])
    resp = client.windows.correlate(12, r["request"]["windows_hosts"])
    assert r["status"] == 422 and resp.status_code == 422 and resp.all_refused
    assert resp.rejected[0].errors[0]["field"] == "hostname"


@responses.activate
def test_invalid_sort(client):
    r = rec("v2_error_invalid_sort")
    responses.add(responses.POST, f"{BASE}/correlate", json=r["response"], status=r["status"])
    with pytest.raises(ValueError, match="sort must be one of"):
        client.windows.correlate(12, r["request"]["windows_hosts"], sort="bogus")      # caught client-side
    with pytest.raises(exc.ValidationError):
        client.request("POST", f"{BASE}/correlate", json=r["request"], accept_statuses=(422,))   # server-side envelope


@responses.activate
def test_correlate_csv_sends_multipart(client, tmp_path):
    r = rec("v2_correlate_csv")
    responses.add(responses.POST, f"{BASE}/correlate-csv", json=r["response"], status=200)
    csv = (Path(__file__).parent.parent / "examples" / "hosts.csv").read_text()
    resp = client.windows.correlate_csv(12, csv, include_cleared=False, cve_page_size=3)
    body = responses.calls[0].request.body
    body = body.decode() if isinstance(body, bytes) else body
    assert 'name="hosts"' in body and "WIN-EXAMPLE-01" in body
    assert 'name="include_cleared"' in body and "false" in body and 'name="cve_page_size"' in body
    assert [a.asset_id for a in resp.assets] == ["WIN-EXAMPLE-01", "WIN-EXAMPLE-02"]
    p = tmp_path / "hosts.csv"
    p.write_text(csv)
    responses.add(responses.POST, f"{BASE}/correlate-csv", json=r["response"], status=200)
    client.windows.correlate_csv(12, p)                         # a file path works too


@responses.activate
def test_results_and_host_paging(client):
    p1 = rec("v2_results")["response"]
    p2 = copy.deepcopy(rec("v2_results_page2")["response"])
    p2["data"]["assets"][0]["cves_page"]["has_more"] = False     # end the loop after two recorded pages
    first = copy.deepcopy(p1)
    first["data"]["assets"] = [a for a in first["data"]["assets"] if a["asset_id"] == "WIN-EXAMPLE-01"]
    responses.add(responses.GET, f"{BASE}/results", json=first, status=200)
    responses.add(responses.GET, f"{BASE}/results", json=p2, status=200)
    cves = client.windows.all_host_cves(12, "WIN-EXAMPLE-01", cve_page_size=3, include_cleared=False)
    assert [c.priority_rank for c in cves] == [1, 2, 3, 4, 5, 6]
    q = [c.request.url for c in responses.calls]
    assert "cve_page=1" in q[0] and "cve_page=2" in q[1] and "asset_id=WIN-EXAMPLE-01" in q[0]
    assert "include_cleared=false" in q[0]


@responses.activate
def test_batching_helper_splits_into_calls_of_100(client):
    r = rec("v2_correlate")["response"]
    calls = []

    def cb(req):
        body = json.loads(req.body)
        calls.append((len(body["windows_hosts"]), len(body.get("installed_software") or [])))
        return (200, {}, json.dumps(r))
    responses.add_callback(responses.POST, f"{BASE}/correlate", callback=cb, content_type="application/json")
    hosts = [{"asset_id": f"WIN-EXAMPLE-{i:03d}"} for i in range(250)]
    software = [{"asset_id": "WIN-EXAMPLE-150", "name": "Example App", "publisher": "Example", "version": "1.0"}]
    out = list(client.windows.correlate_batched(12, hosts, software=software))
    assert RECOMMENDED_HOSTS_PER_CALL == 100
    assert [c[0] for c in calls] == [100, 100, 50] and len(out) == 3
    assert [c[1] for c in calls] == [0, 1, 0]                   # software rides with its host's batch
    with pytest.raises(ValueError):
        list(client.windows.correlate_batched(12, hosts, batch_size=201))
    with pytest.raises(ValueError, match="At most 200 hosts"):
        client.windows.correlate(12, hosts)
