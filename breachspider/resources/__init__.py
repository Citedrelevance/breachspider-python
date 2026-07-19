"""Resource namespaces exposed on the client (client.cves, client.catalog, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..client import Client


class _Resource:
    """Base for resource namespaces: holds a back-reference to the client."""

    def __init__(self, client: "Client") -> None:
        self._client = client
