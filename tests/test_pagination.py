"""Pagination across the API's several envelope shapes."""

import responses

from conftest import envelope

BASE = "https://breachspider.com/api/v1"


@responses.activate
def test_links_style_follows_next(client):
    """/cves style: follow _links.next until it is null."""
    responses.add(responses.GET, f"{BASE}/cves",
                  json={"data": [{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}],
                        "_links": {"self": "/api/v1/cves?page=1&per_page=2",
                                   "next": "/api/v1/cves?page=2&per_page=2"}},
                  status=200)
    # Page 2 (matched by the full next URL).
    responses.add(responses.GET, f"{BASE}/cves",
                  json={"data": [{"cve_id": "CVE-3"}],
                        "_links": {"self": "/api/v1/cves?page=2&per_page=2", "next": None}},
                  status=200)
    ids = [c.cve_id for c in client.cves.search(per_page=2)]
    assert ids == ["CVE-1", "CVE-2", "CVE-3"]
    assert len(responses.calls) == 2


@responses.activate
def test_page_number_style(client):
    """{page,pages} style with no _links (e.g. a vendor listing)."""
    responses.add(responses.GET, f"{BASE}/reports",  # any path; we drive via style
                  json={"data": [{"id": 1}, {"id": 2}], "page": 1, "pages": 2},
                  status=200)
    responses.add(responses.GET, f"{BASE}/reports",
                  json={"data": [{"id": 3}], "page": 2, "pages": 2},
                  status=200)
    got = list(client.paginate("/reports", params={"per_page": 2}, style="page"))
    assert [g["id"] for g in got] == [1, 2, 3]
    assert len(responses.calls) == 2


@responses.activate
def test_offset_limit_style_assets(client):
    """assets style: advance offset until a short page arrives."""
    page1 = [{"id": i, "asset_name": f"a{i}"} for i in range(3)]
    page2 = [{"id": 3, "asset_name": "a3"}]  # short page -> stop
    responses.add(responses.GET, f"{BASE}/environments/6/assets",
                  json={"assets": page1, "limit": 3, "offset": 0}, status=200)
    responses.add(responses.GET, f"{BASE}/environments/6/assets",
                  json={"assets": page2, "limit": 3, "offset": 3}, status=200)
    names = [a.name for a in client.environments.assets(6, limit=3)]
    assert names == ["a0", "a1", "a2", "a3"]
    assert len(responses.calls) == 2
    # Second call must carry offset=3.
    assert "offset=3" in responses.calls[1].request.url


@responses.activate
def test_single_page_stops(client):
    responses.add(responses.GET, f"{BASE}/cves",
                  json={"data": [{"cve_id": "CVE-1"}], "_links": {"next": None}}, status=200)
    assert [c.cve_id for c in client.cves.search()] == ["CVE-1"]
    assert len(responses.calls) == 1


@responses.activate
def test_per_page_capped_at_100(client):
    responses.add(responses.GET, f"{BASE}/cves",
                  json={"data": [], "_links": {"next": None}}, status=200)
    list(client.cves.search(per_page=5000))
    assert "per_page=100" in responses.calls[0].request.url
