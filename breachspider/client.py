"""The BreachSpider API client.

Design notes
------------
* The API key is held privately and is **never** rendered. ``__repr__`` shows
  only the auth *kind* (live/demo), and every exception message is passed
  through :meth:`_redact` before it leaves the client.
* Network failures are re-raised as :class:`APIConnectionError` so a
  ``requests`` ``PreparedRequest`` (which holds the Authorization header) can
  never escape.
* Errors the API marks ``retryable`` (rate limits, 5xx) are retried up to
  ``max_retries`` times, waiting the server's ``retry_after_seconds`` (or the
  ``Retry-After`` header) when given, else exponential backoff. A
  non-retryable error (a used-up quota, a refused key, bad input) is raised at
  once, never retried. A gateway timeout (504/524) on a POST is not repeated
  either, since the API may already have processed it. Responses without guidance (an older server, the
  Cloudflare edge limit that trips around 37 rapid requests from one IP)
  fall back to retrying 429 and 5xx. Paginated iteration also sleeps ``page_delay`` between
  pages so a naive loop over thousands of CVEs stays under the edge limit.
* ``X-RateLimit-*`` headers are parsed after every call and exposed via
  :attr:`quota`, the only way to see usage while metering is observe-only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional, Tuple, Union
from urllib.parse import urlsplit, parse_qs

import requests

from ._version import __version__
from . import exceptions as exc

DEFAULT_BASE_URL = "https://breachspider.com"
API_PREFIX = "/api/v1"

#: Max page size the API accepts on /cves (Pydantic le=100), used as the
#: pagination default because fewer pages == fewer edge-limit risks.
MAX_PER_PAGE = 100
#: Max limit the assets endpoint accepts (silently clamped above this).
MAX_ASSET_LIMIT = 500
#: Default per-request timeout in seconds (every request always sets a timeout).
DEFAULT_TIMEOUT = 30.0


@dataclass
class Quota:
    """Snapshot of the ``X-RateLimit-*`` headers from the most recent call.

    ``limit`` and ``remaining`` are ints, or the string ``"unlimited"`` on
    unlimited tiers. ``None`` means the header was absent (e.g. the call was
    made with a demo token, which is not metered).
    """

    limit: Optional[Union[int, str]] = None
    used: Optional[int] = None
    remaining: Optional[Union[int, str]] = None

    @property
    def is_unlimited(self) -> bool:
        return self.limit == "unlimited"

    @staticmethod
    def _num(value: Optional[str]) -> Optional[Union[int, str]]:
        if value is None:
            return None
        if value.strip().lower() == "unlimited":
            return "unlimited"
        try:
            return int(value)
        except (TypeError, ValueError):
            return value

    @classmethod
    def from_headers(cls, headers: Any) -> Optional["Quota"]:
        limit = headers.get("X-RateLimit-Limit")
        used = headers.get("X-RateLimit-Used")
        remaining = headers.get("X-RateLimit-Remaining")
        if limit is None and used is None and remaining is None:
            return None
        used_int: Optional[int]
        try:
            used_int = int(used) if used is not None else None
        except (TypeError, ValueError):
            used_int = None
        return cls(limit=cls._num(limit), used=used_int, remaining=cls._num(remaining))


class Client:
    """Entry point. ``Client(api_key="bs_live_...")`` or ``Client.demo()``.

    Parameters
    ----------
    api_key:
        A ``bs_live_`` key or a ``bs_demo_`` token.
    base_url:
        Defaults to production.
    timeout:
        Per-request timeout in seconds.
    page_delay:
        Seconds to sleep between pages during iteration (edge-limit safety).
        Set to ``0`` to disable.
    max_retries:
        Attempts on ``429``/connection errors before giving up.
    backoff_factor:
        Base for exponential backoff: sleep = ``backoff_factor * 2**attempt``.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        page_delay: float = 0.25,
        max_retries: int = 5,
        backoff_factor: float = 0.5,
        session: Optional[requests.Session] = None,
        user_agent: Optional[str] = None,
        _is_demo: bool = False,
    ) -> None:
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._is_demo = _is_demo or api_key.startswith("bs_demo_")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_delay = max(0.0, page_delay)
        self.max_retries = max(0, max_retries)
        self.backoff_factor = backoff_factor
        self.user_agent = user_agent or f"breachspider-python/{__version__}"
        self._session = session or requests.Session()
        self._quota: Optional[Quota] = None

        # Lazy import to avoid a package-level import cycle.
        from .resources.cves import CVEs
        from .resources.catalog import Catalog
        from .resources.environments import Environments
        from .resources.watchlist import Watchlist
        from .resources.reports import Reports
        from .resources.correlate import Correlate
        from .resources.windows import Windows

        self.cves = CVEs(self)
        self.catalog = Catalog(self)
        self.environments = Environments(self)
        self.watchlist = Watchlist(self)
        self.reports = Reports(self)
        self.correlate = Correlate(self)      # API v1: stateless asset -> CVE correlation
        self.windows = Windows(self)          # API v2: Windows patch-level results

    # -- constructors -------------------------------------------------------

    @classmethod
    def demo(cls, *, base_url: str = DEFAULT_BASE_URL, **kwargs: Any) -> "Client":
        """Mint a fresh read-only demo token (24h) and return a client using it.

        No signup required. The demo token is scoped to the public demo org
        and is not metered.
        """
        base = base_url.rstrip("/")
        timeout = float(kwargs.get("timeout") or DEFAULT_TIMEOUT)
        try:
            resp = requests.post(
                f"{base}{API_PREFIX}/auth/demo-token",
                headers={
                    # The endpoint requires an Origin header.
                    "Origin": base,
                    "User-Agent": f"breachspider-python/{__version__}",
                },
                timeout=timeout,
            )
        except requests.RequestException as e:
            raise exc.APIConnectionError(
                f"Could not reach the demo-token endpoint: {type(e).__name__}"
            ) from None
        if resp.status_code >= 400:
            raise exc.APIError(
                "Failed to mint a demo token.",
                status_code=resp.status_code,
                code="DEMO_TOKEN_FAILED",
            )
        token = (resp.json() or {}).get("token")
        if not token:
            raise exc.APIError("Demo token endpoint returned no token.", status_code=502)
        return cls(token, base_url=base_url, _is_demo=True, **kwargs)

    # -- introspection (key-safe) ------------------------------------------

    @property
    def is_demo(self) -> bool:
        return self._is_demo

    @property
    def quota(self) -> Optional[Quota]:
        """Quota snapshot from the most recent metered call, or ``None``."""
        return self._quota

    def _redact(self, text: str) -> str:
        """Defensive: strip the key from any string before it leaves the SDK."""
        if self._api_key and self._api_key in text:
            text = text.replace(self._api_key, "***redacted***")
        return text

    def __repr__(self) -> str:
        kind = "demo" if self._is_demo else "live"
        return f"<breachspider.Client base_url={self.base_url!r} auth={kind} key=***redacted***>"

    __str__ = __repr__

    # -- request plumbing ---------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/api/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}{API_PREFIX}/{path.lstrip('/')}"

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        accept_statuses: Tuple[int, ...] = (),
    ) -> Dict[str, Any]:
        """Perform one request, map errors, update quota, return parsed JSON.

        ``data``/``files`` send a multipart form (used by the v2 CSV upload).
        ``accept_statuses`` lists error statuses whose body is a normal result
        rather than an error envelope (API v2 returns 422 with ``data.rejected``
        when every host in a call is refused).
        """
        url = self._url(path)
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        # requests drops params whose value is None, which is exactly what we want.
        clean_params = None if params is None else {k: v for k, v in params.items() if v is not None}

        attempt = 0
        while True:
            try:
                resp = self._session.request(
                    method,
                    url,
                    params=clean_params,
                    json=json,
                    data=data,
                    files=files,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                # Retry transient network errors; never surface the request object.
                if attempt < self.max_retries:
                    time.sleep(self._backoff(attempt))
                    attempt += 1
                    continue
                raise exc.APIConnectionError(
                    self._redact(f"Request to {url} failed: {type(e).__name__}")
                ) from None

            q = Quota.from_headers(resp.headers)
            if q is not None:
                self._quota = q

            if resp.status_code >= 400:
                if resp.status_code in accept_statuses:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    if isinstance(body, dict) and isinstance(body.get("data"), dict):
                        return body
                error = self._to_exception(resp)
                # A gateway timeout on a POST may come after the API already processed (and metered) the call, so
                # it is not repeated automatically; the error still says retryable for the caller to decide.
                timed_out_post = resp.status_code in (504, 524) and method.upper() not in ("GET", "HEAD")
                if error.retryable and not timed_out_post and attempt < self.max_retries:
                    wait = error.retry_after_seconds
                    time.sleep(wait if wait is not None else self._backoff(attempt))
                    attempt += 1
                    continue
                raise error

            if resp.status_code == 204 or not resp.content:
                return {}
            try:
                return resp.json()
            except ValueError:
                raise exc.APIError(
                    "Response was not valid JSON.",
                    status_code=resp.status_code,
                    code="BAD_RESPONSE",
                )

    def _backoff(self, attempt: int) -> float:
        return min(self.backoff_factor * (2 ** attempt), 30.0)

    def _to_exception(self, resp: "requests.Response") -> exc.APIError:
        status = resp.status_code
        code: Optional[str] = None
        message = f"HTTP {status}"
        detail: Any = None
        request_id: Optional[str] = None
        try:
            body = resp.json()
        except ValueError:
            body = None
        guide: Dict[str, Any] = {}
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                code = err.get("code")
                message = err.get("message") or message
                detail = err.get("detail")
                if isinstance(err.get("retryable"), bool):
                    guide = {"retryable": err["retryable"], "action": err.get("action"),
                             "retry_after_seconds": err.get("retry_after_seconds"), "reset_at": err.get("reset_at")}
            request_id = (body.get("api") or {}).get("request_id")
        message = self._redact(message)
        if not guide or (guide["retryable"] and guide["retry_after_seconds"] is None):
            after = _retry_after_seconds(resp.headers, resp)    # Retry-After header / detail.retry_after
            if after is not None:
                guide["retry_after_seconds"] = max(1, int(after))

        kw = dict(status_code=status, code=code, detail=detail, request_id=request_id, **guide)

        if status == 400:
            if code == "UNKNOWN_PARAMETER" or (isinstance(detail, dict) and detail.get("accepted_parameters")):
                return exc.UnknownParameterError(message, **kw)
            return exc.BadRequestError(message, **kw)
        if status == 401:
            return exc.AuthenticationError(message, **kw)
        if status == 403:
            if code in ("PARTNER_SCOPE", "TRIAL_SCOPE"):
                return exc.ScopeError(message, **kw)
            if code == "TRIAL_ENDED":
                return exc.TrialEndedError(message, **kw)
            marker = detail.get("error") if isinstance(detail, dict) else None
            if marker == "insufficient_scope" or code == "insufficient_scope":
                return exc.InsufficientScopeError(message, **kw)
            if marker == "cap_exceeded" or code == "cap_exceeded":
                return exc.CapExceededError(message, **kw)
            return exc.ForbiddenError(message, **kw)
        if status == 404:
            return exc.NotFoundError(message, **kw)
        if status == 413 and code in ("BATCH_TOO_LARGE", "TRIAL_BATCH_LIMIT"):
            return exc.BatchTooLargeError(message, **kw)
        if status == 422:
            return exc.ValidationError(message, **kw)
        if status == 429:
            if code in ("PARTNER_LIMIT", "TRIAL_ENDED"):
                return exc.UsageLimitError(message, retry_after=_retry_after_seconds(resp.headers, resp), **kw)
            return exc.RateLimitError(message, retry_after=_retry_after_seconds(resp.headers, resp), **kw)
        if status >= 500:
            return exc.ServerError(message, **kw)
        return exc.APIError(message, **kw)

    # -- pagination engine --------------------------------------------------

    def paginate(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        container: Optional[str] = None,
        style: str = "auto",
        page_size_param: str = "per_page",
        page_size: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield every item across all pages, absorbing the API's shape zoo.

        ``style``:
          * ``"links"``   -- follow ``_links.next`` (used by /cves).
          * ``"page"``    -- increment ``page`` until ``page >= pages``.
          * ``"offset"``  -- advance ``offset`` by ``limit`` (assets/audit).
          * ``"auto"``    -- detect per response.

        ``container`` is the key holding the list; auto-detected among
        ``data``/``items``/``environments``/``assets``/``tickets`` when omitted.
        """
        params = dict(params or {})
        if page_size is not None:
            params[page_size_param] = page_size

        first = True
        offset = int(params.get("offset", 0) or 0)
        while True:
            if not first and self.page_delay:
                time.sleep(self.page_delay)
            body = self.request("GET", path, params=params)
            items, meta = _extract(body, container)
            for item in items:
                yield item
            first = False

            nxt = _next_request(body, meta, style, params, offset, len(items), page_size_param, path)
            if nxt is None:
                return
            path, params, offset = nxt


# -- module helpers (no key involved) --------------------------------------

_CONTAINERS = ("data", "items", "environments", "assets", "tickets", "results")


def _extract(body: Any, container: Optional[str]) -> Tuple[list, Dict[str, Any]]:
    """Return (list_of_items, pagination_meta) from a response body."""
    if isinstance(body, list):
        return body, {}
    if not isinstance(body, dict):
        return [], {}
    key = container
    if key is None:
        for candidate in _CONTAINERS:
            if isinstance(body.get(candidate), list):
                key = candidate
                break
    items = body.get(key) if key else None
    if not isinstance(items, list):
        items = []
    return items, body


def _next_request(
    body: Dict[str, Any],
    meta: Dict[str, Any],
    style: str,
    params: Dict[str, Any],
    offset: int,
    got: int,
    page_size_param: str,
    current_path: str,
) -> Optional[Tuple[str, Dict[str, Any], int]]:
    """Compute the next (path, params, offset) or None when exhausted.

    Only the ``_links.next`` style changes the path; every other style keeps
    ``current_path`` and advances the params.
    """
    links = meta.get("_links") if isinstance(meta, dict) else None
    pagination = meta.get("pagination") if isinstance(meta, dict) else None

    if style in ("auto", "links") and isinstance(links, dict):
        if links.get("next"):
            # _links.next is a site-absolute path with query already encoded.
            return links["next"], {}, offset
        if "next" in links:  # next explicitly null -> last page
            return None
    if style in ("auto", "links") and isinstance(pagination, dict) and "has_next" in pagination:
        if not pagination.get("has_next"):
            return None
        nxt = dict(params)
        nxt["page"] = int(pagination.get("page", 1)) + 1
        return current_path, nxt, offset

    # page-number style: {page, pages} at top level (e.g. /cves/vendor/{slug})
    page = meta.get("page")
    pages = meta.get("pages")
    if style in ("auto", "page") and isinstance(page, int) and isinstance(pages, int):
        if got == 0 or page >= pages:
            return None
        nxt = dict(params)
        nxt["page"] = page + 1
        return current_path, nxt, offset

    # offset/limit style (assets): advance until fewer than limit returned.
    if style in ("auto", "offset") and ("limit" in params or page_size_param == "limit"):
        limit = int(params.get("limit", got) or got or 1)
        if got < limit or got == 0:
            return None
        nxt = dict(params)
        nxt["offset"] = offset + got
        return current_path, nxt, offset + got

    return None


def _retry_after_seconds(headers: Any, resp: Any = None) -> Optional[float]:
    """Seconds to wait before retrying: the ``Retry-After`` header, else the
    per-key limiter's ``error.detail.retry_after`` in the response body."""
    val = headers.get("Retry-After")
    if val is None and resp is not None:
        try:
            body = resp.json()
            detail = (body.get("error") or {}).get("detail") if isinstance(body, dict) else None
            if isinstance(detail, dict):
                val = detail.get("retry_after")
        except (ValueError, AttributeError):
            val = None
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _query_of(url: str) -> Dict[str, Any]:  # pragma: no cover - helper
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
