"""Watchlist reads and key-usable writes."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import _Resource
from ..models import WatchlistItem


class Watchlist(_Resource):
    """``client.watchlist``"""

    def list(self) -> List[WatchlistItem]:
        """All watchlist entries for the org."""
        body = self._client.request("GET", "/watchlist")
        return [WatchlistItem.from_dict(i) for i in (body.get("items") or [])]

    def usage(self) -> Dict[str, Any]:
        """Watchlist quota: total/limit/used/remaining."""
        body = self._client.request("GET", "/watchlist")
        return {k: body.get(k) for k in ("total", "limit", "used", "remaining")}

    def add(self, entity_type: str, value: str, *, severity_threshold: Optional[str] = None,
            **fields: Any) -> WatchlistItem:
        """Add a watchlist entry (requires a write-scoped key)."""
        payload: Dict[str, Any] = {"entity_type": entity_type, "value": value, **fields}
        if severity_threshold is not None:
            payload["severity_threshold"] = severity_threshold
        body = self._client.request("POST", "/watchlist", json=payload)
        data = body.get("item") if isinstance(body, dict) else None
        return WatchlistItem.from_dict(data if isinstance(data, dict) else body)

    def remove(self, item_id: int) -> Dict[str, Any]:
        """Delete a watchlist entry (requires a write-scoped key)."""
        return self._client.request("DELETE", f"/watchlist/{item_id}")

    def matches(self) -> List[Dict[str, Any]]:
        """CVE matches against the watchlist."""
        body = self._client.request("GET", "/watchlist/matches")
        if isinstance(body, dict):
            return list(body.get("data") or body.get("matches") or [])
        return list(body or [])
