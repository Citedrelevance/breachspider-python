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
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
]
