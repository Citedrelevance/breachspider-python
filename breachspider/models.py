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


# ---------------------------------------------------------------------------
# Correlation (API v1) and Windows patch level (API v2)
# ---------------------------------------------------------------------------

#: Values accepted by ``options.sort`` on every correlate endpoint.
SORT_MODES = ("priority", "score", "exploit", "newest")


@dataclass
class Fix:
    """The fix for one CVE on one asset (``cves[].fix``)."""

    available: bool = False
    action: Optional[str] = None
    source: Optional[str] = None       # "stored", "derived" or "microsoft"
    derived: bool = False              # taken from the affected version range, not a vendor statement
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "Fix":
        d = d or {}
        return cls(available=bool(d.get("available")), action=d.get("action"), source=d.get("source"),
                   derived=bool(d.get("derived")), raw=d)


@dataclass
class FixGroup:
    """One fix action for an asset and the CVEs it clears (``fix_groups[]``)."""

    fix: str
    fix_type: Optional[str] = None     # "version", "vendor", "kb", "esu" or "none"
    source: Optional[str] = None
    derived: bool = False
    cve_ids: list = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    highest_score: Dict[str, Optional[float]] = field(default_factory=dict)
    group_rank: Optional[int] = None
    kb: Optional[str] = None
    kbs_covered: list = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FixGroup":
        return cls(fix=d.get("fix"), fix_type=d.get("fix_type"), source=d.get("source"),
                   derived=bool(d.get("derived")), cve_ids=list(d.get("cve_ids") or []),
                   counts=dict(d.get("counts") or {}), highest_score=dict(d.get("highest_score") or {}),
                   group_rank=d.get("group_rank"), kb=d.get("kb"), kbs_covered=list(d.get("kbs_covered") or []),
                   raw=d)


@dataclass
class FixPlanStep:
    """One line of a device ``fix_plan``. Derived steps always carry ``note``."""

    fix: Optional[str] = None
    derived: bool = False
    source: Optional[str] = None
    clears: Dict[str, int] = field(default_factory=dict)
    note: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["FixPlanStep"]:
        if not d:
            return None
        return cls(fix=d.get("fix"), derived=bool(d.get("derived")), source=d.get("source"),
                   clears=dict(d.get("clears") or {}), note=d.get("note"), raw=d)


@dataclass
class FixPlan:
    """``fix_plan``: the one upgrade that clears all known-exploited CVEs, and the one that clears all fixable."""

    to_clear_known_exploited: Optional[FixPlanStep] = None
    to_clear_all_fixable: Optional[FixPlanStep] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["FixPlan"]:
        if not d:
            return None
        return cls(to_clear_known_exploited=FixPlanStep.from_dict(d.get("to_clear_known_exploited")),
                   to_clear_all_fixable=FixPlanStep.from_dict(d.get("to_clear_all_fixable")), raw=d)


@dataclass
class FixSummaryItem:
    """One entry of ``data.fix_summary``: a fix action aggregated across the assets in a call."""

    rank: Optional[int] = None
    fix: Optional[str] = None
    product: Optional[str] = None
    fix_type: Optional[str] = None
    source: Optional[str] = None
    derived: bool = False
    asset_ids: list = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    highest_score: Dict[str, Optional[float]] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FixSummaryItem":
        return cls(rank=d.get("rank"), fix=d.get("fix"), product=d.get("product"), fix_type=d.get("fix_type"),
                   source=d.get("source"), derived=bool(d.get("derived")), asset_ids=list(d.get("asset_ids") or []),
                   counts=dict(d.get("counts") or {}), highest_score=dict(d.get("highest_score") or {}), raw=d)


@dataclass
class CvePage:
    """``cves_page``: which page of an asset's CVE list this is."""

    page: int = 1
    page_size: Optional[int] = None
    total: Optional[int] = None             # after filters
    total_unfiltered: Optional[int] = None
    has_more: bool = False

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["CvePage"]:
        if not d:
            return None
        return cls(page=int(d.get("page") or 1), page_size=d.get("page_size"), total=d.get("total"),
                   total_unfiltered=d.get("total_unfiltered"), has_more=bool(d.get("has_more")))


@dataclass
class VendorAdvisory:
    """A vendor's own advisory for a CVE, from ``references.vendor_advisories``."""

    url: str
    title: Optional[str] = None
    source: Optional[str] = None            # "nvd_vendor_advisory", "vendor_cna" or "cisa_csaf_vendor_reference"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VendorAdvisory":
        return cls(url=d.get("url") or "", title=d.get("title"), source=d.get("source"))


@dataclass
class OtherReference:
    """Any other NVD reference for a CVE, from ``references.other_references``. Not vendor-verified."""

    url: str
    tags: list = field(default_factory=list)
    provided_by: Optional[str] = None       # NVD submitter, e.g. "cve@mitre.org"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OtherReference":
        return cls(url=d.get("url") or "", tags=list(d.get("tags") or []), provided_by=d.get("provided_by"))


@dataclass
class CisaIcsAdvisory:
    """A CISA ICS advisory that lists a CVE, from ``references.cisa_ics_advisories``."""

    advisory_id: str
    url: str
    title: Optional[str] = None
    published: Optional[str] = None         # YYYY-MM-DD

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CisaIcsAdvisory":
        return cls(advisory_id=d.get("advisory_id") or "", url=d.get("url") or "", title=d.get("title"),
                   published=d.get("published"))


@dataclass
class CorrelatedCVE:
    """One CVE in a v1 correlate result: the full CVE object plus match and priority fields."""

    cve_id: Optional[str]
    match_tier: Optional[str] = None        # "EXACT", "RANGE" or "PRODUCT_WIDE"
    priority_rank: Optional[int] = None
    priority_reason: Optional[str] = None
    fix: Fix = field(default_factory=Fix)
    affected_range: Dict[str, Any] = field(default_factory=dict)
    cvss_score: Optional[float] = None
    bcs_score: Optional[float] = None
    kev_flagged: Optional[bool] = None
    vendor_advisories: list = field(default_factory=list)   # list[VendorAdvisory]
    cve_org_url: Optional[str] = None
    other_references: list = field(default_factory=list)    # list[OtherReference], at most 25
    other_references_total: int = 0
    cisa_ics_advisories: list = field(default_factory=list)  # list[CisaIcsAdvisory]
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CorrelatedCVE":
        return cls(cve_id=d.get("cve_id"), match_tier=d.get("match_tier"), priority_rank=d.get("priority_rank"),
                   priority_reason=d.get("priority_reason"), fix=Fix.from_dict(d.get("fix")),
                   affected_range=dict(d.get("affected_range") or {}),
                   cvss_score=_get(d, "scoring.cvss.score"), bcs_score=_get(d, "scoring.bcs.score"),
                   kev_flagged=_get(d, "exploitation.kev_flagged"),
                   vendor_advisories=[VendorAdvisory.from_dict(v) for v in (_get(d, "references.vendor_advisories") or [])],
                   cve_org_url=_get(d, "references.cve_org_url"),
                   other_references=[OtherReference.from_dict(o) for o in (_get(d, "references.other_references") or [])],
                   other_references_total=int(_get(d, "references.other_references_total") or 0),
                   cisa_ics_advisories=[CisaIcsAdvisory.from_dict(x) for x in (_get(d, "references.cisa_ics_advisories") or [])],
                   raw=d)

    @property
    def confirmed(self) -> bool:
        return self.match_tier in ("EXACT", "RANGE")


@dataclass
class CorrelateResult:
    """One asset in a v1 ``correlate-cves`` response."""

    asset_id: Optional[str]
    status: Optional[str] = None            # resolution.status
    confidence: Optional[int] = None
    confidence_band: Optional[str] = None
    coverage: Optional[str] = None
    product: Optional[str] = None
    cves: list = field(default_factory=list)            # list[CorrelatedCVE]
    cves_page: Optional[CvePage] = None
    fix_groups: list = field(default_factory=list)      # list[FixGroup]
    fix_plan: Optional[FixPlan] = None
    needs_review: bool = False
    result_hash: Optional[str] = None
    warnings: list = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CorrelateResult":
        res = d.get("resolution") or {}
        return cls(asset_id=d.get("asset_id"), status=res.get("status"), confidence=res.get("confidence"),
                   confidence_band=res.get("confidence_band"), coverage=res.get("coverage"),
                   product=_get(res, "product.name"),
                   cves=[CorrelatedCVE.from_dict(c) for c in (d.get("cves") or [])],
                   cves_page=CvePage.from_dict(d.get("cves_page")),
                   fix_groups=[FixGroup.from_dict(g) for g in (d.get("fix_groups") or [])],
                   fix_plan=FixPlan.from_dict(d.get("fix_plan")), needs_review=bool(d.get("needs_review")),
                   result_hash=d.get("result_hash"), warnings=list(d.get("warnings") or []), raw=d)

    @property
    def warning_codes(self) -> list:
        return [w.get("code") for w in self.warnings]


@dataclass
class CorrelateResponse:
    """A whole v1 ``correlate-cves`` response."""

    results: list = field(default_factory=list)         # list[CorrelateResult]
    summary: Dict[str, Any] = field(default_factory=dict)
    fix_summary: list = field(default_factory=list)     # list[FixSummaryItem]
    meta: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: Dict[str, Any]) -> "CorrelateResponse":
        data = body.get("data") or {}
        return cls(results=[CorrelateResult.from_dict(r) for r in (data.get("results") or [])],
                   summary=dict(data.get("summary") or {}),
                   fix_summary=[FixSummaryItem.from_dict(x) for x in (data.get("fix_summary") or [])],
                   meta=dict(body.get("meta") or {}), request_id=_get(body, "api.request_id"), raw=body)


@dataclass
class CheckResult:
    """One asset in a ``correlate-cves/check`` response."""

    asset_id: Optional[str]
    changed: bool = False
    current_hash: Optional[str] = None
    reason: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CheckResult":
        return cls(asset_id=d.get("asset_id"), changed=bool(d.get("changed")), current_hash=d.get("current_hash"),
                   reason=d.get("reason"), raw=d)


@dataclass
class WindowsCVE:
    """One CVE for one Windows host (API v2)."""

    cve_id: Optional[str]
    status: Optional[str] = None            # "confirmed open", "cleared (patched)" or "needs review"
    fixed_build: Optional[str] = None
    kb: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    known_exploited: Optional[bool] = None
    note: Optional[str] = None
    priority_rank: Optional[int] = None
    priority_reason: Optional[str] = None
    fix: Fix = field(default_factory=Fix)
    references: Dict[str, Any] = field(default_factory=dict)   # nvd_url, cve_org_url, vendor_advisories, cisa_ics_advisories, ...
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WindowsCVE":
        return cls(cve_id=d.get("cve_id"), status=d.get("status"), fixed_build=d.get("fixed_build"), kb=d.get("kb"),
                   source=d.get("source"), severity=d.get("severity"), known_exploited=d.get("known_exploited"),
                   note=d.get("note"), priority_rank=d.get("priority_rank"), priority_reason=d.get("priority_reason"),
                   fix=Fix.from_dict(d.get("fix")), references=dict(d.get("references") or {}), raw=d)


@dataclass
class WindowsHostResult:
    """One accepted Windows host (API v2 ``data.assets[]``)."""

    asset_id: Optional[str]
    microsoft_product: Optional[str] = None
    candidate_products: Optional[list] = None
    patch_resolved: bool = False
    end_of_life: bool = False
    labels: list = field(default_factory=list)
    map_note: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    cves: list = field(default_factory=list)            # list[WindowsCVE]
    cves_page: Optional[CvePage] = None
    fix_groups: list = field(default_factory=list)      # list[FixGroup]
    warnings: list = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WindowsHostResult":
        return cls(asset_id=d.get("asset_id"), microsoft_product=d.get("microsoft_product"),
                   candidate_products=d.get("candidate_products"), patch_resolved=bool(d.get("patch_resolved")),
                   end_of_life=bool(d.get("end_of_life")), labels=list(d.get("labels") or []),
                   map_note=d.get("map_note"), counts=dict(d.get("counts") or {}),
                   cves=[WindowsCVE.from_dict(c) for c in (d.get("cves") or [])],
                   cves_page=CvePage.from_dict(d.get("cves_page")),
                   fix_groups=[FixGroup.from_dict(g) for g in (d.get("fix_groups") or [])],
                   warnings=list(d.get("warnings") or []), raw=d)


@dataclass
class RejectedHost:
    """A host the API refused; nothing from it was stored. ``asset_id`` is None when its value was refused."""

    asset_id: Optional[str]
    errors: list = field(default_factory=list)          # [{code, field, message}]
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RejectedHost":
        return cls(asset_id=d.get("asset_id"), errors=list(d.get("errors") or []), raw=d)

    @property
    def error_codes(self) -> list:
        return [e.get("code") for e in self.errors]


@dataclass
class WindowsResponse:
    """A whole API v2 response (``correlate``, ``correlate-csv`` or ``results``)."""

    assets: list = field(default_factory=list)          # list[WindowsHostResult]
    rejected: list = field(default_factory=list)        # list[RejectedHost]
    software_stored: int = 0
    software_rejected: list = field(default_factory=list)
    fix_summary: list = field(default_factory=list)     # list[FixSummaryItem]
    meta: Dict[str, Any] = field(default_factory=dict)
    status_code: int = 200                  # 422 when every host in the call was refused
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, body: Dict[str, Any], status_code: int = 200) -> "WindowsResponse":
        data = body.get("data") or {}
        return cls(assets=[WindowsHostResult.from_dict(a) for a in (data.get("assets") or [])],
                   rejected=[RejectedHost.from_dict(r) for r in (data.get("rejected") or [])],
                   software_stored=int(data.get("software_stored") or 0),
                   software_rejected=list(data.get("software_rejected") or []),
                   fix_summary=[FixSummaryItem.from_dict(x) for x in (data.get("fix_summary") or [])],
                   meta=dict(body.get("meta") or {}), status_code=status_code, raw=body)

    @property
    def all_refused(self) -> bool:
        return not self.assets and bool(self.rejected)


__all__ = [
    "Vendor",
    "Product",
    "CVE",
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
]
