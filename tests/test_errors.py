"""Error-envelope -> typed-exception mapping."""

import pytest
import responses

import breachspider
from breachspider import exceptions as exc
from conftest import error_body

CVES = "https://breachspider.com/api/v1/cves"


@responses.activate
def test_unknown_parameter_surfaces_accepted_list(client):
    accepted = ["q", "vendor", "severity", "kev", "page", "per_page"]
    responses.add(
        responses.GET, CVES,
        json=error_body(
            "UNKNOWN_PARAMETER",
            "Unrecognized query parameter(s): bogus.",
            {"unknown_parameters": ["bogus"], "accepted_parameters": accepted},
        ),
        status=400,
    )
    with pytest.raises(exc.UnknownParameterError) as ei:
        list(client.cves.search(vendor="x"))
    err = ei.value
    assert err.accepted_parameters == accepted
    assert err.unknown_parameters == ["bogus"]
    # The accepted list is the whole value of the error -> must be in the message.
    assert "per_page" in str(err)
    assert err.request_id == "bs-req-err"


@responses.activate
def test_401_authentication(client):
    responses.add(responses.GET, CVES,
                  json=error_body("AUTH_REQUIRED", "Authentication required"), status=401)
    with pytest.raises(exc.AuthenticationError):
        list(client.cves.search())


@responses.activate
def test_403_insufficient_scope(client):
    responses.add(
        responses.GET, "https://breachspider.com/api/v1/watchlist",
        json=error_body("FORBIDDEN", "This API key is read-only.",
                        {"error": "insufficient_scope", "required_scope": "write",
                         "current_scopes": ["read"]}),
        status=403,
    )
    with pytest.raises(exc.InsufficientScopeError) as ei:
        client.watchlist.list()
    assert ei.value.required_scope == "write"
    assert "write" in str(ei.value)


@responses.activate
def test_403_cap_exceeded(client):
    responses.add(
        responses.POST, "https://breachspider.com/api/v1/environments",
        json=error_body("FORBIDDEN", "You have reached your plan limit of 10 environments.",
                        {"error": "cap_exceeded", "resource": "environments",
                         "limit": 10, "current": 10, "tier": "professional"}),
        status=403,
    )
    with pytest.raises(exc.CapExceededError) as ei:
        client.environments.create("New Plant")
    e = ei.value
    assert (e.resource, e.limit, e.current, e.tier) == ("environments", 10, 10, "professional")


@responses.activate
def test_404_not_found(client):
    responses.add(responses.GET, "https://breachspider.com/api/v1/cves/CVE-0000-0",
                  json=error_body("NOT_FOUND", "CVE not found.",
                                  {"resource": "CVE", "identifier": "CVE-0000-0"}), status=404)
    with pytest.raises(exc.NotFoundError):
        client.cves.get("CVE-0000-0")


@responses.activate
def test_422_validation_surfaces_field(client):
    responses.add(
        responses.GET, CVES,
        json=error_body("VALIDATION_ERROR", "Request validation failed.",
                        [{"field": "query.per_page",
                          "message": "Input should be less than or equal to 100",
                          "type": "less_than_equal"}]),
        status=422,
    )
    with pytest.raises(exc.ValidationError) as ei:
        list(client.cves.search(per_page=100))  # server-side rejection is what we mock
    assert "per_page" in str(ei.value)
    assert ei.value.fields and ei.value.fields[0]["field"] == "query.per_page"


@responses.activate
def test_429_retries_then_succeeds(client):
    responses.add(responses.GET, CVES,
                  json=error_body("RATE_LIMITED", "Too many requests"), status=429)
    responses.add(responses.GET, CVES,
                  json={"data": [], "_links": {"next": None}}, status=200)
    # Should not raise: the first 429 is retried and the second call succeeds.
    assert list(client.cves.search()) == []
    assert len(responses.calls) == 2


@responses.activate
def test_429_exhausts_retries_then_raises(client):
    for _ in range(5):
        responses.add(responses.GET, CVES,
                      json=error_body("RATE_LIMITED", "Too many requests"), status=429)
    with pytest.raises(exc.RateLimitError):
        list(client.cves.search())
