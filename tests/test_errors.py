"""Error-envelope -> typed-exception mapping."""

import pytest
import responses

import breachspider
from breachspider import exceptions as exc
from conftest import error_body


def guide(retryable, action, after=None, **extra):
    return {"retryable": retryable, "retry_after_seconds": after, "action": action, **extra}


def guided(code, message, retryable, action, after=None, detail=None):
    body = error_body(code, message, detail)
    body["error"].update(guide(retryable, action, after))
    return body

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


@responses.activate
@pytest.mark.parametrize("code", ["PARTNER_SCOPE", "TRIAL_SCOPE"])
def test_403_scope_codes_raise_scope_error(client, code):
    responses.add(responses.GET, CVES, json=error_body(code, "This key can call ... only."), status=403)
    with pytest.raises(exc.ScopeError) as ei:
        list(client.cves.search())
    assert isinstance(ei.value, exc.ForbiddenError)      # existing except ForbiddenError still catches it
    assert ei.value.code == code


@responses.activate
def test_403_trial_ended(client):
    responses.add(responses.GET, CVES, status=403, json=error_body(
        "TRIAL_ENDED", "Your 14 day BreachSpider API trial has ended.",
        {"code": "TRIAL_ENDED", "reason": "expired", "ended_at": "2026-09-30T00:00:00+00:00",
         "contact_url": "https://breachspider.com/developers"}))
    with pytest.raises(exc.TrialEndedError) as ei:
        list(client.cves.search())
    assert isinstance(ei.value, exc.ForbiddenError)
    assert ei.value.reason == "expired" and ei.value.ended_at.startswith("2026-09-30")


@responses.activate
@pytest.mark.parametrize("code,action", [("PARTNER_LIMIT", "wait_until_reset"), ("TRIAL_ENDED", "contact_us")])
def test_429_usage_limit_is_not_retried(client, code, action):
    body = error_body(code, "This request needs 25 asset checks.",
                      {"code": code, "reason": "limit", "used": 740, "limit": 750, "remaining": 10, "requested": 25,
                       "resets_at": "2026-11-01"})
    body["error"].update(guide(False, action, reset_at="2026-11-01"))
    responses.add(responses.GET, CVES, status=429, json=body)
    with pytest.raises(exc.UsageLimitError) as ei:
        list(client.cves.search())
    assert len(responses.calls) == 1                    # non-retryable: raised at once, never retried
    assert isinstance(ei.value, exc.RateLimitError)
    assert (ei.value.remaining, ei.value.limit, ei.value.requested) == (10, 750, 25)
    assert ei.value.retryable is False and ei.value.action == action and ei.value.reset_at == "2026-11-01"


@responses.activate
@pytest.mark.parametrize("code,mx", [("BATCH_TOO_LARGE", 25), ("TRIAL_BATCH_LIMIT", 25)])
def test_413_batch_too_large(client, code, mx):
    responses.add(responses.GET, CVES, status=413, json=error_body(
        code, "At most 25 hosts per call.", {"code": code, "max": mx, "received": 30}))
    with pytest.raises(exc.BatchTooLargeError) as ei:
        list(client.cves.search())
    assert ei.value.max == mx and ei.value.received == 30 and ei.value.status_code == 413


# -- retry guidance (0.3.2) ---------------------------------------------------

@pytest.fixture
def slept(monkeypatch):
    calls = []
    monkeypatch.setattr(breachspider.client.time, "sleep", lambda s: calls.append(s))
    return calls


@responses.activate
def test_rate_limit_waits_retry_after_seconds_then_succeeds(client, slept):
    responses.add(responses.GET, CVES, status=429, headers={"Retry-After": "17"},
                  json=guided("RATE_LIMITED", "Per-key limit.", True, "retry_later", 17, {"retry_after": 17}))
    responses.add(responses.GET, CVES, json={"data": [], "_links": {"next": None}}, status=200)
    assert list(client.cves.search()) == []
    assert slept == [17] and len(responses.calls) == 2


@responses.activate
def test_retryable_error_exposes_guidance_after_retries_run_out(client, slept):
    for _ in range(3):
        responses.add(responses.GET, CVES, status=503, json=guided("ERROR", "Database unavailable", True, "retry_later", 30))
    with pytest.raises(exc.ServerError) as ei:
        list(client.cves.search())
    assert len(responses.calls) == 3 and slept == [30, 30]          # max_retries=2 in the fixture
    e = ei.value
    assert (e.retryable, e.retry_after_seconds, e.action) == (True, 30, "retry_later")


@responses.activate
@pytest.mark.parametrize("status,code,action", [
    (400, "UNKNOWN_PARAMETER", "fix_input"),
    (401, "AUTH_REQUIRED", "use_different_key"),
    (403, "PARTNER_SCOPE", "contact_us"),
    (403, "TRIAL_ENDED", "contact_us"),
    (404, "NOT_FOUND", "fix_input"),
    (413, "BATCH_TOO_LARGE", "reduce_batch"),
    (422, "VALIDATION_ERROR", "fix_input"),
    (503, "ERROR", "contact_us"),                   # demo account unavailable: retrying will not help
])
def test_non_retryable_errors_are_never_retried(client, slept, status, code, action):
    responses.add(responses.GET, CVES, status=status, json=guided(code, "no", False, action))
    with pytest.raises(exc.APIError) as ei:
        list(client.cves.search())
    assert len(responses.calls) == 1 and slept == []
    assert ei.value.retryable is False and ei.value.action == action and ei.value.retry_after_seconds is None


@responses.activate
def test_no_guidance_falls_back_to_status(client, slept):
    # An edge page (Cloudflare 524) or an older server: 5xx and 429 are retryable, honoring Retry-After.
    responses.add(responses.GET, CVES, status=524, body="<html>timeout</html>", headers={"Retry-After": "5"})
    responses.add(responses.GET, CVES, json={"data": [], "_links": {"next": None}}, status=200)
    assert list(client.cves.search()) == []
    assert slept == [5]
    responses.add(responses.GET, CVES + "/CVE-2024-0001", status=404, json=error_body("NOT_FOUND", "nope"))
    with pytest.raises(exc.NotFoundError) as ei:
        client.cves.get("CVE-2024-0001")
    assert ei.value.retryable is False and ei.value.action is None


def test_every_exception_class_exposes_guidance():
    for name in dir(exc):
        cls = getattr(exc, name)
        if isinstance(cls, type) and issubclass(cls, exc.BreachSpiderError):
            for attr in ("retryable", "retry_after_seconds", "action"):
                assert hasattr(cls, attr), f"{name}.{attr}"
    assert exc.APIConnectionError("x").retryable is True


@responses.activate
def test_gateway_timeout_on_post_is_not_repeated(client, slept):
    url = "https://breachspider.com/api/v1/assets/correlate-cves"
    responses.add(responses.POST, url, status=504, json=guided("GATEWAY_TIMEOUT", "timed out", True, "retry_later", 30))
    with pytest.raises(exc.ServerError) as ei:
        client.request("POST", "/assets/correlate-cves", json={"assets": []})
    assert len(responses.calls) == 1 and slept == []
    assert ei.value.retryable is True and ei.value.retry_after_seconds == 30     # the caller may still decide
