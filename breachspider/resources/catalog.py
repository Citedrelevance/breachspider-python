"""Vendor and product catalog lookups -- the entry to the primary workflow."""

from __future__ import annotations

from typing import List, Optional

from . import _Resource
from ..models import Vendor, Product
from ..exceptions import NotFoundError


class Catalog(_Resource):
    """``client.catalog``"""

    def vendors(self, q: Optional[str] = None, *, limit: Optional[int] = None) -> List[Vendor]:
        """Search the vendor catalog. Returns typed :class:`Vendor` objects
        whose ``slug`` is read straight from the response (never derived)."""
        params: dict = {}
        if q is not None:
            params["q"] = q
        if limit is not None:
            params["limit"] = limit
        body = self._client.request("GET", "/catalog/vendors", params=params)
        return [Vendor.from_dict(v) for v in (body.get("data") or [])]

    def vendor(self, query: str) -> Vendor:
        """Resolve a single vendor by name (e.g. ``"Schneider Electric"``,
        ``"VMware, Inc."``).

        The catalog ranks results server-side -- multi-word phrases, hyphen/space
        variants, and corporate legal-entity suffixes all resolve to the right
        canonical vendor -- so the first result is the best match. Raises
        :class:`NotFoundError` if nothing matches. The ``slug`` comes straight
        from the response; never derive it.
        """
        candidates = self.vendors(q=query)
        if not candidates:
            raise NotFoundError(
                f"No vendor matched {query!r}.",
                status_code=404,
                code="NOT_FOUND",
                detail={"resource": "Vendor", "identifier": query},
            )
        return candidates[0]

    def products(self, vendor_id: int) -> List[Product]:
        """List products for a vendor id, each with its ``cve_count``."""
        body = self._client.request(
            "GET", "/catalog/products", params={"vendor_id": vendor_id}
        )
        return [Product.from_dict(p) for p in (body.get("data") or [])]
