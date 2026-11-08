"""Resource namespaces exposed on the client (client.cves, client.catalog, ...)."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..client import Client


class _Resource:
    """Base for resource namespaces: holds a back-reference to the client."""

    def __init__(self, client: "Client") -> None:
        self._client = client


def _not_in_api(what: str) -> None:
    """These calls use web app routes, not the documented API (https://breachspider.com/docs/api/overview/). They
    still answer today; once API keys are limited to the documented API they will be refused (403 NOT_IN_API)."""
    warnings.warn(f"{what} is not part of the BreachSpider API and will stop working with API keys; use the web app "
                  "(see https://breachspider.com/docs/api/overview/).", DeprecationWarning, stacklevel=3)
