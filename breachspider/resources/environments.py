"""Environments, their assets, and their tickets (reads + key-usable writes)."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional

from . import _Resource
from ..models import Environment, Asset
from ..client import MAX_ASSET_LIMIT


class Environments(_Resource):
    """``client.environments``"""

    def list(self) -> List[Environment]:
        """All environments in the org."""
        body = self._client.request("GET", "/environments")
        return [Environment.from_dict(e) for e in (body.get("environments") or [])]

    def get(self, env_id: int) -> Environment:
        """One environment by id."""
        body = self._client.request("GET", f"/environments/{env_id}")
        data = body.get("environment") if isinstance(body, dict) else None
        return Environment.from_dict(data if isinstance(data, dict) else body)

    def create(self, name: str, **fields: Any) -> Environment:
        """Create an environment (requires a write-scoped key)."""
        payload = {"name": name, **fields}
        body = self._client.request("POST", "/environments", json=payload)
        data = body.get("environment") if isinstance(body, dict) else None
        return Environment.from_dict(data if isinstance(data, dict) else body)

    def assets(self, env_id: int, *, limit: int = MAX_ASSET_LIMIT, **filters: Any) -> Iterator[Asset]:
        """Iterate an environment's assets across pages.

        This endpoint paginates by ``limit``/``offset`` (max limit 500, clamped
        silently), which the SDK handles for you.
        """
        params = {k: v for k, v in filters.items() if v is not None}
        params["limit"] = min(int(limit), MAX_ASSET_LIMIT)
        for item in self._client.paginate(
            f"/environments/{env_id}/assets",
            params=params,
            style="offset",
            page_size_param="limit",
            container="assets",
        ):
            yield Asset.from_dict(item)

    def add_asset(self, env_id: int, **fields: Any) -> Dict[str, Any]:
        """Add a single asset manually (requires a write-scoped key)."""
        return self._client.request(
            "POST", f"/environments/{env_id}/assets/manual", json=fields
        )

    def summary(self, env_id: int, *, layer: Optional[str] = None) -> Dict[str, Any]:
        """Environment risk summary. ``layer`` optionally filters OT/IT/network."""
        params = {"layer": layer} if layer else None
        return self._client.request("GET", f"/environments/{env_id}/summary", params=params)

    def tickets(self, env_id: int) -> List[Dict[str, Any]]:
        """List remediation tickets for an environment."""
        body = self._client.request("GET", f"/environments/{env_id}/tickets")
        return list(body.get("tickets") or [])

    def create_ticket(self, env_id: int, **fields: Any) -> Dict[str, Any]:
        """Open a remediation ticket (requires a write-scoped key)."""
        return self._client.request("POST", f"/environments/{env_id}/tickets", json=fields)
