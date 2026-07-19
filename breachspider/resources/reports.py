"""Report listing, retrieval, and generation (key-usable)."""

from __future__ import annotations

from typing import Any, List

from . import _Resource
from ..models import Report


class Reports(_Resource):
    """``client.reports``"""

    def list(self) -> List[Report]:
        """All generated reports for the org."""
        body = self._client.request("GET", "/reports")
        return [Report.from_dict(r) for r in (body.get("data") or [])]

    def get(self, report_id: int) -> Report:
        """One report by id."""
        body = self._client.request("GET", f"/reports/{report_id}")
        data = body.get("data") if isinstance(body, dict) else None
        return Report.from_dict(data if isinstance(data, dict) else body)

    def generate(self, report_type: str, **fields: Any) -> Report:
        """Generate a report (requires a write-scoped key).

        ``report_type`` is e.g. ``"iec_62443"``, ``"nerc_cip"``, ``"patch_gap"``.
        """
        payload = {"report_type": report_type, **fields}
        body = self._client.request("POST", "/reports/generate", json=payload)
        data = body.get("data") if isinstance(body, dict) else None
        return Report.from_dict(data if isinstance(data, dict) else body)
