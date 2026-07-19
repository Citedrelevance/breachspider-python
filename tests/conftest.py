"""Shared test fixtures."""

import pytest

import breachspider

# A syntactically-valid but fake key used across unit tests. Never a real key.
FAKE_KEY = "bs_live_" + "0123456789abcdef" * 4  # 64 hex chars


@pytest.fixture
def client():
    # page_delay=0 keeps unit tests fast; max_retries small so 429 tests are quick.
    return breachspider.Client(
        FAKE_KEY,
        base_url="https://breachspider.com",
        page_delay=0,
        max_retries=2,
        backoff_factor=0,
    )


def envelope(data=None, **extra):
    """Build a success envelope like the API returns."""
    body = {"api": {"version": "1.0.0", "request_id": "bs-req-test"}}
    if data is not None:
        body["data"] = data
    body.update(extra)
    return body


def error_body(code, message, detail=None):
    return {
        "api": {"version": "1.0.0", "request_id": "bs-req-err"},
        "error": {"code": code, "message": message, "detail": detail},
    }
