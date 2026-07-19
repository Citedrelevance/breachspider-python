"""Typed, read-only views over API responses.

Each model keeps the full server payload in :attr:`raw`, so anything the
typed fields do not cover is still one attribute away. ``from_dict`` is
tolerant of missing keys and of the two shapes the API uses for CVEs (the
compact list item vs. the detailed single-CVE object).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present key from ``d`` (supports 'a.b' nested paths)."""
    for key in keys:
        cur: Any = d
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return default


@dataclass
class Vendor:
    id: Optional[int]
    name: Optional[str]
    slug: Optional[str]
    cve_product_count: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Vendor":
        return cls(
            id=_get(d, "id"),
            name=_get(d, "name"),
            slug=_get(d, "slug"),
            cve_product_count=_get(d, "cve_product_count", "product_count"),
            raw=d,
        )


@dataclass
class Product:
    id: Optional[int]
    name: Optional[str]
    cve_count: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Product":
        return cls(
            id=_get(d, "id"),
            name=_get(d, "name"),
            cve_count=_get(d, "cve_count"),
            raw=d,
        )


@dataclass
class CVE:
    cve_id: Optional[str]
    bsid: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    bcs_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_flagged: Optional[bool] = None
    patch_status: Optional[str] = None
    has_public_exploit: Optional[bool] = None
    exploit_maturity: Optional[str] = None
    primary_vendor: Optional[str] = None
    primary_product: Optional[str] = None
    published_at: Optional[str] = None
    html_url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CVE":
        # Compact list items are flat; the detailed single-CVE object nests
        # scoring/classification/exploitation/patch -- read from either.
        return cls(
            cve_id=_get(d, "cve_id"),
            bsid=_get(d, "bsid"),
            title=_get(d, "title"),
            severity=_get(d, "severity", "scoring.cvss.severity"),
            cvss_score=_get(d, "cvss_score", "scoring.cvss.score"),
            bcs_score=_get(d, "bcs_score", "scoring.bcs.score", "scoring.bcs_score"),
            epss_score=_get(d, "epss_score", "scoring.epss.score"),
            kev_flagged=_get(d, "kev_flagged", "exploitation.kev_flagged"),
            patch_status=_get(d, "patch_status", "patch.status"),
            has_public_exploit=_get(d, "has_public_exploit", "exploitation.has_public_exploit"),
            exploit_maturity=_get(d, "exploit_maturity", "exploitation.exploit_maturity"),
            primary_vendor=_get(d, "primary_vendor", "affected.primary_vendor"),
            primary_product=_get(d, "primary_product", "affected.primary_product"),
            published_at=_get(d, "published_at", "temporal.published_at"),
            html_url=_get(d, "_links.html"),
            raw=d,
        )


@dataclass
class Environment:
    id: Optional[int]
    name: Optional[str] = None
    slug: Optional[str] = None
    asset_count: Optional[int] = None
    cve_count: Optional[int] = None
    critical_count: Optional[int] = None
    kev_count: Optional[int] = None
    risk_score: Optional[float] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Environment":
        return cls(
            id=_get(d, "id"),
            name=_get(d, "name"),
            slug=_get(d, "slug"),
            asset_count=_get(d, "asset_count"),
            cve_count=_get(d, "cve_count"),
            critical_count=_get(d, "critical_count"),
            kev_count=_get(d, "kev_count"),
            risk_score=_get(d, "risk_score"),
            raw=d,
        )


@dataclass
class Asset:
    id: Optional[int]
    name: Optional[str] = None
    asset_type: Optional[str] = None
    vendor: Optional[str] = None
    vendor_slug: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    criticality: Optional[str] = None
    risk_score: Optional[float] = None
    cve_count: Optional[int] = None
    ip_address: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Asset":
        return cls(
            id=_get(d, "id"),
            name=_get(d, "asset_name", "name"),
            asset_type=_get(d, "asset_type"),
            vendor=_get(d, "vendor_name", "vendor"),
            vendor_slug=_get(d, "vendor_slug"),
            product=_get(d, "product"),
            version=_get(d, "version"),
            criticality=_get(d, "criticality"),
            risk_score=_get(d, "risk_score"),
            cve_count=_get(d, "cve_count"),
            ip_address=_get(d, "ip_address"),
            raw=d,
        )


@dataclass
class Report:
    id: Optional[int]
    report_type: Optional[str] = None
    label: Optional[str] = None
    format: Optional[str] = None
    cve_count: Optional[int] = None
    generated_at: Optional[str] = None
    download_url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Report":
        return cls(
            id=_get(d, "id"),
            report_type=_get(d, "report_type"),
            label=_get(d, "label"),
            format=_get(d, "format"),
            cve_count=_get(d, "cve_count"),
            generated_at=_get(d, "generated_at"),
            download_url=_get(d, "download_url"),
            raw=d,
        )


@dataclass
class WatchlistItem:
    id: Optional[int]
    entity_type: Optional[str] = None
    value: Optional[str] = None
    severity_threshold: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WatchlistItem":
        return cls(
            id=_get(d, "id"),
            entity_type=_get(d, "entity_type", "type"),
            value=_get(d, "value", "name", "entity_value"),
            severity_threshold=_get(d, "severity_threshold", "min_severity"),
            raw=d,
        )


__all__ = [
    "Vendor",
    "Product",
    "CVE",
    "Environment",
    "Asset",
    "Report",
    "WatchlistItem",
]
