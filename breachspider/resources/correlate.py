"""API v1 stateless correlation: ``POST /api/v1/assets/correlate-cves`` and ``/check``.

Nothing is stored server-side: send assets (vendor, product, version) and get, per asset, the catalog product it
resolved to, the CVEs that affect it (ranked by exposure priority by default), fix actions and a fix plan.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, Iterator, List, Optional

from . import _Resource
from ..models import SORT_MODES, CheckResult, CorrelateResponse, CorrelatedCVE

PATH = "/api/v1/assets/correlate-cves"
#: Hard limit of the endpoint (413 above it).
MAX_ASSETS_PER_CALL = 200
#: Upper bound of ``cve_page_size``.
MAX_CVE_PAGE_SIZE = 1000


def _options(**kw: Any) -> Dict[str, Any]:
    """Build the ``options`` object, sending only what the caller set (the API applies its own defaults: for API keys
    ``include_capec`` is false and ``cve_page_size`` is 250; ``sort`` is ``priority``)."""
    sort = kw.get("sort")
    if sort is not None and sort not in SORT_MODES:
        raise ValueError(f"sort must be one of: {', '.join(SORT_MODES)} (got {sort!r})")
    size = kw.get("cve_page_size")
    if size is not None and not (1 <= int(size) <= MAX_CVE_PAGE_SIZE):
        raise ValueError(f"cve_page_size must be between 1 and {MAX_CVE_PAGE_SIZE}")
    return {k: v for k, v in kw.items() if v is not None}


class Correlate(_Resource):
    """``client.correlate``"""

    def correlate(
        self,
        assets: Iterable[Dict[str, Any]],
        *,
        min_confidence: Optional[str] = None,
        include_capec: Optional[bool] = None,
        sort: Optional[str] = None,
        confirmed_only: Optional[bool] = None,
        known_exploited_only: Optional[bool] = None,
        fix_available_only: Optional[bool] = None,
        cve_page: Optional[int] = None,
        cve_page_size: Optional[int] = None,
    ) -> CorrelateResponse:
        """Correlate up to 200 assets in one call.

        Each asset is a dict with ``asset_id``, ``vendor``, ``product`` and optionally ``version``,
        ``firmware_version`` (used for matching when ``version`` is empty) and ``product_type``.

        ``sort``: ``priority`` (default: confirmed -> known-exploited -> exploit/PoC -> fix available -> BCS -> CVSS ->
        EPSS), ``score`` (the previous BCS-then-CVSS order), ``exploit`` or ``newest``. Filters are off by default and,
        like the sort, apply before paging. ``result_hash`` never depends on sort, filters or page.
        """
        items = list(assets)
        if len(items) > MAX_ASSETS_PER_CALL:
            raise ValueError(f"At most {MAX_ASSETS_PER_CALL} assets per call (got {len(items)}); split the list.")
        body: Dict[str, Any] = {"assets": items}
        opts = _options(min_confidence=min_confidence, include_capec=include_capec, sort=sort,
                        confirmed_only=confirmed_only, known_exploited_only=known_exploited_only,
                        fix_available_only=fix_available_only, cve_page=cve_page, cve_page_size=cve_page_size)
        if opts:
            body["options"] = opts
        return CorrelateResponse.from_dict(self._client.request("POST", PATH, json=body))

    def check(self, assets: Iterable[Dict[str, Any]]) -> List[CheckResult]:
        """Cheap staleness check: send each asset with the ``result_hash`` you stored; only assets that come back
        ``changed`` need a fresh :meth:`correlate` call."""
        items = list(assets)
        if len(items) > MAX_ASSETS_PER_CALL:
            raise ValueError(f"At most {MAX_ASSETS_PER_CALL} assets per call (got {len(items)}); split the list.")
        body = self._client.request("POST", f"{PATH}/check", json={"assets": items})
        return [CheckResult.from_dict(r) for r in ((body.get("data") or {}).get("results") or [])]

    def iter_asset_cves(
        self,
        asset: Dict[str, Any],
        *,
        cve_page_size: int = 250,
        **options: Any,
    ) -> Iterator[CorrelatedCVE]:
        """Yield every CVE for one asset, fetching page after page until ``cves_page.has_more`` is false.

        The order (and any filters) is fixed server-side before paging, so the concatenated pages equal the full
        ranked list. ``options`` takes the same keyword options as :meth:`correlate`.
        """
        page = 1
        while True:
            if page > 1 and self._client.page_delay:
                time.sleep(self._client.page_delay)
            resp = self.correlate([asset], cve_page=page, cve_page_size=cve_page_size, **options)
            if not resp.results:
                return
            result = resp.results[0]
            for cve in result.cves:
                yield cve
            if not (result.cves_page and result.cves_page.has_more):
                return
            page += 1

    def all_cves(self, asset: Dict[str, Any], **kwargs: Any) -> List[CorrelatedCVE]:
        """Convenience: :meth:`iter_asset_cves` as a list."""
        return list(self.iter_asset_cves(asset, **kwargs))
