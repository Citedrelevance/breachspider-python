"""BreachSpider -- official Python SDK for the BreachSpider ICS/OT CVE API.

Quick start::

    import breachspider
    bs = breachspider.Client.demo()                 # read-only, no signup
    vendor = bs.catalog.vendor("schneider electric")
    for cve in bs.cves.by_vendor(vendor.slug, severity="CRITICAL", kev=True):
        print(cve.cve_id, cve.title)
"""

from __future__ import annotations

from ._version import __version__
from .client import Client, Quota
from .models import (
    CVE,
    Vendor,
    Product,
    Environment,
    Asset,
    Report,
    WatchlistItem,
    SORT_MODES,
    Fix,
    FixGroup,
    FixPlan,
    FixPlanStep,
    FixSummaryItem,
    CvePage,
    CorrelatedCVE,
    CorrelateResult,
    CorrelateResponse,
    CheckResult,
    WindowsCVE,
    WindowsHostResult,
    RejectedHost,
    WindowsResponse,
    WindowsChange,
    WindowsChangesResponse,
)
from .exceptions import (
    BreachSpiderError,
    APIConnectionError,
    APIError,
    BadRequestError,
    UnknownParameterError,
    AuthenticationError,
    ForbiddenError,
    InsufficientScopeError,
    CapExceededError,
    ScopeError,
    TrialEndedError,
    UsageLimitError,
    BatchTooLargeError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    ServerError,
)

__all__ = [
    "__version__",
    "Client",
    "Quota",
    # models
    "CVE",
    "Vendor",
    "Product",
    "Environment",
    "Asset",
    "Report",
    "WatchlistItem",
    "SORT_MODES",
    "Fix",
    "FixGroup",
    "FixPlan",
    "FixPlanStep",
    "FixSummaryItem",
    "CvePage",
    "CorrelatedCVE",
    "CorrelateResult",
    "CorrelateResponse",
    "CheckResult",
    "WindowsCVE",
    "WindowsHostResult",
    "RejectedHost",
    "WindowsResponse",
    "WindowsChange",
    "WindowsChangesResponse",
    # exceptions
    "BreachSpiderError",
    "APIConnectionError",
    "APIError",
    "BadRequestError",
    "UnknownParameterError",
    "AuthenticationError",
    "ForbiddenError",
    "InsufficientScopeError",
    "CapExceededError",
    "ScopeError",
    "TrialEndedError",
    "UsageLimitError",
    "BatchTooLargeError",
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
]
