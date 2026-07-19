"""The API key must never appear in repr/str/logs/exceptions."""

import logging

import pytest
import requests
import responses

import breachspider
from breachspider import exceptions as exc
from conftest import FAKE_KEY, error_body

CVES = "https://breachspider.com/api/v1/cves"


def test_key_not_in_repr_or_str():
    c = breachspider.Client(FAKE_KEY)
    assert FAKE_KEY not in repr(c)
    assert FAKE_KEY not in str(c)
    assert "redacted" in repr(c)


def test_key_not_in_vars_dump_values():
    # Even a naive vars() dump should not print the raw key as a nice attribute
    # name; it lives under a single underscore-prefixed attr and repr is guarded.
    c = breachspider.Client(FAKE_KEY)
    # The attribute exists (we need it to auth) but the public surface hides it.
    assert c._api_key == FAKE_KEY  # internal
    assert FAKE_KEY not in f"{c}"


@responses.activate
def test_key_not_in_http_error_message(client):
    responses.add(responses.GET, CVES,
                  json=error_body("AUTH_REQUIRED", "Authentication required"), status=401)
    with pytest.raises(exc.APIError) as ei:
        list(client.cves.search())
    assert FAKE_KEY not in str(ei.value)
    assert FAKE_KEY not in repr(ei.value)


@responses.activate
def test_key_not_in_connection_error(client):
    # Simulate a network failure; the raised APIConnectionError must not carry
    # the PreparedRequest (which holds the Authorization header).
    responses.add(responses.GET, CVES, body=requests.exceptions.ConnectionError("boom"))
    with pytest.raises(exc.APIConnectionError) as ei:
        list(client.cves.search())
    assert FAKE_KEY not in str(ei.value)


@responses.activate
def test_key_not_logged_at_debug(client, caplog):
    responses.add(responses.GET, CVES, json={"data": [], "_links": {"next": None}}, status=200)
    with caplog.at_level(logging.DEBUG):
        list(client.cves.search())
    assert FAKE_KEY not in caplog.text


def test_redact_helper_scrubs_key():
    c = breachspider.Client(FAKE_KEY)
    leaked = f"the key is {FAKE_KEY} oops"
    assert FAKE_KEY not in c._redact(leaked)
    assert "***redacted***" in c._redact(leaked)
