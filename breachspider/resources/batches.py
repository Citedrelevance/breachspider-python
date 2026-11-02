"""Asynchronous batch jobs: ``/api/v1/batches`` (devices) and ``/api/v2/batches`` (stateless Windows hosts).

Submit up to 5,000 devices or 1,000 Windows hosts as one job, then poll its status (or receive a signed
``batch.completed`` webhook) and read the results page by page. Each result is exactly the object the sync endpoint
returns for that device or host. Batches are enabled per API key; for a key without them every route answers 404.

    job = client.batches.submit(assets)                     # devices; returns at once (202)
    job = client.batches.wait(job)                          # polls with backoff until it finishes
    for item in client.batches.results(job):                # every result, in submission order
        ...
"""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, Optional

from . import _Resource

PATHS = {"devices": "/api/v1/batches", "windows_hosts": "/api/v2/batches"}
#: Job size limits (413 above them).
MAX_DEVICES = 5000
MAX_WINDOWS_HOSTS = 1000
FINAL = ("succeeded", "partial", "failed", "cancelled")


@dataclass
class BatchJob:
    """A batch job's status as the API returns it."""

    job_id: str
    kind: str
    status: str
    progress: Dict[str, int] = field(default_factory=dict)
    summary: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def done(self) -> bool:
        """True once the job has finished (succeeded, partial, failed or cancelled)."""
        return self.status in FINAL

    @classmethod
    def from_body(cls, data: Dict[str, Any], kind: str) -> "BatchJob":
        return cls(job_id=data["job_id"], kind=kind, status=data.get("status", "queued"),
                   progress=data.get("progress") or {}, summary=data.get("summary"), raw=data)


def _kind(kind: str) -> str:
    if kind not in PATHS:
        raise ValueError(f"kind must be one of: {', '.join(PATHS)} (got {kind!r})")
    return kind


def _ref(job: Any, kind: Optional[str]) -> tuple:
    if isinstance(job, BatchJob):
        return job.job_id, job.kind
    return str(job), _kind(kind or "devices")


class Batches(_Resource):
    """``client.batches``"""

    def submit(
        self,
        items: Iterable[Dict[str, Any]],
        *,
        kind: str = "devices",
        options: Optional[Dict[str, Any]] = None,
        callback_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> BatchJob:
        """Queue a batch job and return at once.

        ``kind="devices"`` takes the assets of ``client.correlate.correlate`` (up to 5,000); ``kind="windows_hosts"``
        takes the hosts of ``client.windows.check`` (up to 1,000). ``options`` are the same options as the sync call.
        ``callback_url`` (https, public) gets a signed ``batch.completed`` webhook; the key needs a batch webhook
        secret first. ``idempotency_key`` (8 to 80 characters) defaults to a new random key; send the same one to
        retry a submit safely: within 24 hours the same body returns the original job, a different body is refused.
        """
        kind = _kind(kind)
        rows = list(items)
        cap = MAX_DEVICES if kind == "devices" else MAX_WINDOWS_HOSTS
        if not rows:
            raise ValueError("a batch needs at least one item")
        if len(rows) > cap:
            raise ValueError(f"at most {cap} items per job (got {len(rows)}); split it into several jobs")
        key = idempotency_key or f"sdk-{uuid.uuid4().hex}"
        if not 8 <= len(key) <= 80:
            raise ValueError("idempotency_key must be 8 to 80 characters")
        body: Dict[str, Any] = {"assets" if kind == "devices" else "windows_hosts": rows}
        if options:
            body["options"] = options
        if callback_url:
            body["callback_url"] = callback_url
        resp = self._client.request("POST", PATHS[kind], json=body, headers={"Idempotency-Key": key})
        return BatchJob.from_body(resp["data"], kind)

    def get(self, job: Any, *, kind: Optional[str] = None) -> BatchJob:
        """The job's current status, progress and, once finished, its summary."""
        jid, kind = _ref(job, kind)
        return BatchJob.from_body(self._client.request("GET", f"{PATHS[kind]}/{jid}")["data"], kind)

    def results(self, job: Any, *, kind: Optional[str] = None, page_size: int = 200) -> Iterator[Dict[str, Any]]:
        """Every finished item in submission order: ``{"idx", "state": "done", "result"}`` or
        ``{"idx", "state": "failed", "error_code"}``. Items still pending are not returned yet."""
        jid, kind = _ref(job, kind)
        if not 1 <= page_size <= 200:
            raise ValueError("page_size must be between 1 and 200")
        cursor = -1
        while True:
            resp = self._client.request("GET", f"{PATHS[kind]}/{jid}/results", params={"cursor": cursor, "limit": page_size})
            for item in resp["data"]["items"]:
                yield item
            cursor = (resp.get("meta") or {}).get("next_cursor")
            if cursor is None:
                return

    def cancel(self, job: Any, *, kind: Optional[str] = None) -> BatchJob:
        """Ask the job to stop after its current chunk; unprocessed items are refunded. Only the key that submitted the
        job, or an admin key, may cancel it."""
        jid, kind = _ref(job, kind)
        return BatchJob.from_body(self._client.request("DELETE", f"{PATHS[kind]}/{jid}")["data"], kind)

    def wait(self, job: Any, *, kind: Optional[str] = None, timeout: float = 1800, poll_interval: float = 3,
             max_interval: float = 30) -> BatchJob:
        """Poll until the job finishes, with exponential backoff and jitter between polls. Raises ``TimeoutError``
        after ``timeout`` seconds (the job keeps running; call ``wait`` again or ``get`` later)."""
        jid, kind = _ref(job, kind)
        deadline = time.monotonic() + timeout
        interval = poll_interval
        while True:
            current = self.get(jid, kind=kind)
            if current.done:
                return current
            if time.monotonic() >= deadline:
                raise TimeoutError(f"batch {jid} still {current.status} after {timeout} s")
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())) * random.uniform(0.8, 1.2))
            interval = min(interval * 1.5, max_interval)
