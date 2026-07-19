"""CVE search and lookup."""

from __future__ import annotations

from typing import Any, Iterator

from . import _Resource
from ..models import CVE
from ..client import MAX_PER_PAGE

# The exact filter set the /cves endpoint accepts. Anything else would come
# back as a 400 UNKNOWN_PARAMETER; we keep the list here so the SDK's own
# signature stays honest. There is NO product/version/cpe filter today.
_CVE_FILTERS = (
    "q", "vendor", "protocol", "severity", "kev", "unpatched", "has_exploit",
    "patch_status", "cvss_min", "cvss_max", "bcs_min", "bcs_max",
    "date_from", "date_to", "sort_by", "ranked",
)


def _bool(v: Any) -> Any:
    # requests renders Python bools as "True"/"False"; the API wants true/false.
    if isinstance(v, bool):
        return "true" if v else "false"
    return v


class CVEs(_Resource):
    """``client.cves``"""

    def search(self, *, per_page: int = MAX_PER_PAGE, **filters: Any) -> Iterator[CVE]:
        """Iterate CVEs matching filters, transparently following pages.

        Accepted filters: q, vendor, protocol, severity, kev, unpatched,
        has_exploit, patch_status, cvss_min, cvss_max, bcs_min, bcs_max,
        date_from, date_to, sort_by, ranked. ``vendor`` takes a vendor **slug**.
        """
        params = {k: _bool(v) for k, v in filters.items() if v is not None}
        params["per_page"] = min(int(per_page), MAX_PER_PAGE)
        for item in self._client.paginate("/cves", params=params, style="links", container="data"):
            yield CVE.from_dict(item)

    def by_vendor(self, slug: str, *, per_page: int = MAX_PER_PAGE, **filters: Any) -> Iterator[CVE]:
        """Iterate CVEs for a vendor slug, with optional filters.

        Routed through ``/cves?vendor=<slug>`` (not ``/cves/vendor/{slug}``)
        because that dedicated endpoint accepts only page/per_page, whereas the
        main endpoint supports severity/kev/etc. Read the slug from
        :meth:`Catalog.vendor`; do not hand-craft it.
        """
        return self.search(vendor=slug, per_page=per_page, **filters)

    def get(self, cve_id: str) -> CVE:
        """Fetch one CVE by id (e.g. ``"CVE-2025-32433"``)."""
        body = self._client.request("GET", f"/cves/{cve_id}")
        data = body.get("data") if isinstance(body, dict) else None
        return CVE.from_dict(data if isinstance(data, dict) else body)

    def kev(self, *, per_page: int = MAX_PER_PAGE, **filters: Any) -> Iterator[CVE]:
        """Iterate the KEV-flagged CVE feed (``/cves/kev``)."""
        params = {k: _bool(v) for k, v in filters.items() if v is not None}
        params["per_page"] = min(int(per_page), MAX_PER_PAGE)
        for item in self._client.paginate("/cves/kev", params=params, style="auto", container="data"):
            yield CVE.from_dict(item)
