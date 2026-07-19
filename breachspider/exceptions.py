"""Typed exceptions mapped from the BreachSpider error envelope.

Every error response looks like::

    {"api": {...}, "error": {"code": "...", "message": "...", "detail": ...}}

These classes surface the server's ``code``, ``message`` and structured
``detail`` so the caller never loses the API's own (often very helpful)
explanation -- e.g. the ``accepted_parameters`` list on a 400.

Nothing in this module ever stores or renders the API key.
"""

from __future__ import annotations

from typing import Any, Optional


class BreachSpiderError(Exception):
    """Base class for every error raised by this SDK."""


class APIConnectionError(BreachSpiderError):
    """A network-level failure (DNS, TLS, timeout, connection reset).

    Raised instead of letting ``requests`` exceptions propagate, so the
    underlying ``PreparedRequest`` (which carries the Authorization header)
    can never escape and leak the key.
    """


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
    ) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.code = code
        self.detail = detail
        self.request_id = request_id

    def __str__(self) -> str:  # pragma: no cover - trivial
        bits = [f"[{self.status_code}]"]
        if self.code:
            bits.append(self.code)
        bits.append(self.message)
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
        super().__init__(message, **kw)


class ServerError(APIError):
    """5xx -- something broke on the server side."""

    status_code = 500
