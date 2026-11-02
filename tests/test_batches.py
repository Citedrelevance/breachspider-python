"""Async batch jobs: submit (Idempotency-Key, body, local caps), status, results across pages, cancel, wait with
backoff, the v2 Windows path, and a key without batches (404). Recorded-shape responses, no live calls."""

import json

import pytest
import responses

import breachspider
from breachspider import exceptions as exc
from conftest import envelope, error_body

V1 = "https://breachspider.com/api/v1/batches"
V2 = "https://breachspider.com/api/v2/batches"
JID = "7393adc8-e440-41d3-8256-2bbd604328ac"
DEV = [{"asset_id": "sw-1", "vendor": "Moxa", "product": "EDS-518A", "version": "3.5"}]


def status(st, done=0, total=1, summary=None):
    return envelope({"job_id": JID, "status": st, "progress": {"done": done, "failed": 0, "total": total}, "summary": summary})


@responses.activate
def test_submit_sends_body_and_idempotency_key(client):
    responses.add(responses.POST, V1, json=envelope({"job_id": JID, "status": "queued"}), status=202)
    job = client.batches.submit(DEV, options={"sort": "score"}, callback_url="https://hooks.example.com/bs", idempotency_key="my-key-0001")
    req = responses.calls[0].request
    assert req.headers["Idempotency-Key"] == "my-key-0001" and req.headers["Authorization"].startswith("Bearer bs_live_")
    assert json.loads(req.body) == {"assets": DEV, "options": {"sort": "score"}, "callback_url": "https://hooks.example.com/bs"}
    assert isinstance(job, breachspider.BatchJob) and (job.job_id, job.kind, job.status, job.done) == (JID, "devices", "queued", False)
    client.batches.submit(DEV)
    assert responses.calls[1].request.headers["Idempotency-Key"].startswith("sdk-")      # a fresh key when none is given


def test_local_checks(client):
    with pytest.raises(ValueError):
        client.batches.submit([])
    with pytest.raises(ValueError):
        client.batches.submit(DEV * 5001)
    with pytest.raises(ValueError):
        client.batches.submit(DEV, kind="routers")
    with pytest.raises(ValueError):
        client.batches.submit(DEV, idempotency_key="short")


@responses.activate
def test_windows_path(client):
    responses.add(responses.POST, V2, json=envelope({"job_id": JID, "status": "queued"}), status=202)
    job = client.batches.submit([{"asset_id": "h1", "os_build": "10.0.19045.4894"}], kind="windows_hosts")
    assert json.loads(responses.calls[0].request.body) == {"windows_hosts": [{"asset_id": "h1", "os_build": "10.0.19045.4894"}]}
    responses.add(responses.GET, f"{V2}/{JID}", json=status("succeeded", 1))
    assert client.batches.get(job).status == "succeeded"


@responses.activate
def test_results_follow_the_cursor(client):
    responses.add(responses.GET, f"{V1}/{JID}/results", json={**envelope({"items": [{"idx": 0, "state": "done", "result": {"asset_id": "a"}},
                                                                                 {"idx": 1, "state": "failed", "error_code": "CHECK_FAILED"}]}),
                                                               "meta": {"next_cursor": 1, "limit": 2}})
    responses.add(responses.GET, f"{V1}/{JID}/results", json={**envelope({"items": [{"idx": 2, "state": "done", "result": {"asset_id": "c"}}]}),
                                                               "meta": {"next_cursor": None, "limit": 2}})
    items = list(client.batches.results(JID, page_size=2))
    assert [i["idx"] for i in items] == [0, 1, 2] and items[1]["error_code"] == "CHECK_FAILED"
    assert "cursor=1" in responses.calls[1].request.url and "limit=2" in responses.calls[1].request.url


@responses.activate
def test_cancel_and_wait(client, monkeypatch):
    responses.add(responses.DELETE, f"{V1}/{JID}", json=status("running"), status=202)
    assert client.batches.cancel(JID).status == "running"
    for st in ("queued", "running", "succeeded"):
        responses.add(responses.GET, f"{V1}/{JID}", json=status(st, 1 if st == "succeeded" else 0, summary={"summary": {"total": 1}} if st == "succeeded" else None))
    sleeps = []
    monkeypatch.setattr("breachspider.resources.batches.time.sleep", lambda s: sleeps.append(s))
    done = client.batches.wait(JID, poll_interval=1)
    assert done.status == "succeeded" and done.summary == {"summary": {"total": 1}} and len(sleeps) == 2 and sleeps[1] > sleeps[0] * 1.1


@responses.activate
def test_wait_times_out(client, monkeypatch):
    responses.add(responses.GET, f"{V1}/{JID}", json=status("running"))
    monkeypatch.setattr("breachspider.resources.batches.time.sleep", lambda s: None)
    with pytest.raises(TimeoutError):
        client.batches.wait(JID, timeout=0)


@responses.activate
def test_key_without_batches_is_not_found(client):
    responses.add(responses.POST, V1, json=error_body("NOT_FOUND", "Not found."), status=404)
    with pytest.raises(exc.NotFoundError):
        client.batches.submit(DEV)
