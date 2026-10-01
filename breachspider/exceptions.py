"""Typed exceptions mapped from the BreachSpider error envelope.

Every error response looks like::

    {"api": {...}, "error": {"code": "...", "message": "...", "detail": ...}}

These classes surface the server's ``code``, ``message`` and structured
``detail`` so the caller never loses the API's own (often very helpful)
explanation -- e.g. the ``accepted_parameters`` list on a 400.

Every exception also carries the API's retry guidance:

* :attr:`~BreachSpiderError.retryable` -- True only when repeating the exact
  same request later may succeed. The client's built-in retries follow it and
  never retry a non-retryable error.
* :attr:`~BreachSpiderError.retry_after_seconds` -- how long to wait, when the
  server knows (rate limits), else ``None``.
* :attr:`~BreachSpiderError.action` -- what to do instead: ``retry_later``,
  ``wait_until_reset``, ``reduce_batch``, ``fix_input``, ``use_different_key``
  or ``contact_us``.

When a response carries no guidance (an older server, or an edge page such as
Cloudflare's 524), it is derived from the status: 429 and 5xx are retryable
(``retry_later``, honoring ``Retry-After``); everything else is not.

Nothing in this module ever stores or renders the API key.
"""

from __future__ import annotations

from typing import Any, Optional


class BreachSpiderError(Exception):
    """Base class for every error raised by this SDK."""

    #: True only when repeating the exact same request later may succeed.
    retryable: bool = False
    #: Seconds to wait before retrying, when the server knows; else None.
    retry_after_seconds: Optional[int] = None
    #: What to do instead: retry_later, wait_until_reset, reduce_batch, fix_input, use_different_key, contact_us.
    action: Optional[str] = None


class APIConnectionError(BreachSpiderError):
    """A network-level failure (DNS, TLS, timeout, connection reset).

    Raised instead of letting ``requests`` exceptions propagate, so the
    underlying ``PreparedRequest`` (which carries the Authorization header)
    can never escape and leak the key.
    """

    retryable = True
    action = "retry_later"


class APIError(BreachSpiderError):
    """Base class for a structured HTTP error returned by the API."""

    #: Default HTTP status; subclasses override for readability.
    status_code: int = 0

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        detail: Any = None,
        request_id: Optional[str] = None,
        retryable: Optional[bool] = None,
        retry_after_seconds: Optional[int] = None,
        action: Optional[str] = None,
        reset_at: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.code = code
        self.detail = detail
        self.request_id = request_id
        if retryable is None:                       # no guidance in the response: derive it from the status
            retryable = self.status_code == 429 or self.status_code >= 500
            action = action or ("retry_later" if retryable else None)
        self.retryable = bool(retryable)
        self.retry_after_seconds = retry_after_seconds
        self.action = action
        #: When a usage limit resets (ISO 8601), where the API says so.
        self.reset_at = reset_at

    def __str__(self) -> str:  # pragma: no cover - trivial
        bits = [f"[{self.status_code}]"]
        if self.code:
            bits.append(self.code)
        bits.append(self.message)
        if self.action:
            bits.append(f"(action={self.action}, retryable={str(self.retryable).lower()}"
                        + (f", retry_after_seconds={self.retry_after_seconds}" if self.retry_after_seconds else "") + ")")
        if self.request_id:
            bits.append(f"(request_id={self.request_id})")
        return " ".join(bits)


class BadRequestError(APIError):
    """Generic 400."""

    status_code = 400


class UnknownParameterError(BadRequestError):
    """400 UNKNOWN_PARAMETER.

    The accepted-parameter list is the whole value of this error, so it is
    surfaced both as :attr:`accepted_parameters` and inside the message.
    """

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.accepted_parameters = list(detail.get("accepted_parameters") or [])
        self.unknown_parameters = list(detail.get("unknown_parameters") or [])
        if self.accepted_parameters and "Accepted:" not in message:
            message = f"{message} Accepted: {', '.join(self.accepted_parameters)}."
        super().__init__(message, **kw)


class AuthenticationError(APIError):
    """401 -- missing or invalid credential."""

    status_code = 401


class ForbiddenError(APIError):
    """403 -- authenticated but not allowed."""

    status_code = 403


class InsufficientScopeError(ForbiddenError):
    """403 insufficient_scope -- the API key lacks a required scope."""

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.required_scope = detail.get("required_scope")
        self.current_scopes = detail.get("current_scopes")
        if self.required_scope and "scope" not in message.lower():
            message = f"{message} Required scope: '{self.required_scope}'."
        super().__init__(message, **kw)


class ScopeError(ForbiddenError):
    """403 PARTNER_SCOPE or TRIAL_SCOPE -- this key cannot call this endpoint.

    Retrying will not help; a key with a wider scope is needed. :attr:`code`
    says which kind of key refused the call.
    """


class TrialEndedError(ForbiddenError):
    """403 TRIAL_ENDED -- the trial is over (expired after 14 days, or ended early).

    :attr:`reason` is ``"expired"`` or ``"ended"``. The key is genuine but no
    longer accepted. A trial whose asset checks are used up raises
    :class:`UsageLimitError` instead.
    """

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.reason = detail.get("reason")
        self.ended_at = detail.get("ended_at")
        self.contact_url = detail.get("contact_url")
        super().__init__(message, **kw)


class CapExceededError(ForbiddenError):
    """403 cap_exceeded -- a plan/tier resource cap was hit."""

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.resource = detail.get("resource")
        self.limit = detail.get("limit")
        self.current = detail.get("current")
        self.tier = detail.get("tier")
        super().__init__(message, **kw)


class NotFoundError(APIError):
    """404 -- resource does not exist."""

    status_code = 404


class ValidationError(APIError):
    """422 -- request parameters failed validation.

    ``per_page`` greater than 100 lands here. :attr:`fields` holds the
    per-field messages the server returned.
    """

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail")
        self.fields = detail if isinstance(detail, list) else []
        if self.fields:
            joined = "; ".join(
                f"{f.get('field', '?')}: {f.get('message', '')}" for f in self.fields
            )
            message = f"{message} ({joined})"
        super().__init__(message, **kw)


class RateLimitError(APIError):
    """429 -- rate limited (origin or Cloudflare edge).

    :attr:`retry_after` carries the ``Retry-After`` seconds when present.
    The client retries these automatically with backoff before giving up.
    """

    status_code = 429

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kw: Any) -> None:
        self.retry_after = retry_after
        if kw.get("retry_after_seconds") is None and retry_after is not None:
            kw["retry_after_seconds"] = int(retry_after)
        super().__init__(message, **kw)


class UsageLimitError(RateLimitError):
    """429 PARTNER_LIMIT or TRIAL_ENDED (reason ``limit``) -- the key's asset checks are used up.

    Nothing in the request was processed. Not retried automatically
    (:attr:`retryable` is False): waiting seconds will not help.
    :attr:`used`, :attr:`limit`, :attr:`remaining` and :attr:`requested` are
    in asset checks; :attr:`resets_at` is set for partner keys (start of next
    month, UTC).
    """

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.used = detail.get("used")
        self.limit = detail.get("limit")
        self.remaining = detail.get("remaining")
        self.requested = detail.get("requested")
        self.resets_at = detail.get("resets_at")
        super().__init__(message, **kw)


class BatchTooLargeError(APIError):
    """413 BATCH_TOO_LARGE or TRIAL_BATCH_LIMIT -- too many hosts or assets in one call.

    :attr:`max` is the per-call maximum and :attr:`received` what was sent.
    Split the request into batches of at most :attr:`max`.
    """

    status_code = 413

    def __init__(self, message: str, **kw: Any) -> None:
        detail = kw.get("detail") or {}
        self.max = detail.get("max")
        self.received = detail.get("received")
        super().__init__(message, **kw)


class ServerError(APIError):
    """5xx -- something broke on the server side."""

    status_code = 500
