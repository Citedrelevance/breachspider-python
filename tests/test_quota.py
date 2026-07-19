"""X-RateLimit-* header parsing, including the 'unlimited' string."""

import responses

from breachspider.client import Quota

CVES = "https://breachspider.com/api/v1/cves"


def test_quota_parses_ints():
    q = Quota.from_headers({"X-RateLimit-Limit": "25000",
                            "X-RateLimit-Used": "6",
                            "X-RateLimit-Remaining": "24994"})
    assert (q.limit, q.used, q.remaining) == (25000, 6, 24994)
    assert q.is_unlimited is False


def test_quota_parses_unlimited():
    q = Quota.from_headers({"X-RateLimit-Limit": "unlimited",
                            "X-RateLimit-Used": "3",
                            "X-RateLimit-Remaining": "unlimited"})
    assert q.limit == "unlimited"
    assert q.remaining == "unlimited"
    assert q.used == 3
    assert q.is_unlimited is True


def test_quota_absent_returns_none():
    assert Quota.from_headers({}) is None


@responses.activate
def test_client_exposes_quota_after_call(client):
    responses.add(
        responses.GET, CVES,
        json={"data": [], "_links": {"next": None}},
        status=200,
        headers={"X-RateLimit-Limit": "25000", "X-RateLimit-Used": "1",
                 "X-RateLimit-Remaining": "24999"},
    )
    assert client.quota is None  # nothing called yet
    list(client.cves.search())
    assert client.quota is not None
    assert client.quota.limit == 25000
    assert client.quota.remaining == 24999


@responses.activate
def test_demo_call_leaves_quota_none(client):
    # No X-RateLimit headers (demo tokens are not metered).
    responses.add(responses.GET, CVES, json={"data": [], "_links": {"next": None}}, status=200)
    list(client.cves.search())
    assert client.quota is None
