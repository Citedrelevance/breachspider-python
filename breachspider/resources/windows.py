"""API v2 Windows patch-level results.

``POST /api/v2/assets/correlate`` (JSON), ``POST /api/v2/assets/correlate-csv`` (multipart CSV) and
``GET /api/v2/assets/results``. Submitting needs a key with the ``write`` scope; reading results needs ``read``.

Hosts are validated one by one: a refused host is listed in ``rejected`` and nothing from it is stored, while the
other hosts in the call are processed. When every host is refused the API answers 422 with the same body shape;
the SDK returns it as a :class:`WindowsResponse` with ``all_refused`` true instead of raising.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union

from . import _Resource
from ..models import SORT_MODES, WindowsCVE, WindowsResponse

BASE = "/api/v2/assets"
#: Hard limit per call (413 above it).
MAX_HOSTS_PER_CALL = 200
#: Recommended batch size: about 0.85 s of processing per host, and responses through breachspider.com must finish
#: within 100 s, so keep calls at 100 hosts or fewer.
RECOMMENDED_HOSTS_PER_CALL = 100


def _options(**kw: Any) -> Dict[str, Any]:
    sort = kw.get("sort")
    if sort is not None and sort not in SORT_MODES:
        raise ValueError(f"sort must be one of: {', '.join(SORT_MODES)} (got {sort!r})")
    size = kw.get("cve_page_size")
    if size is not None and not (1 <= int(size) <= 1000):
        raise ValueError("cve_page_size must be between 1 and 1000")
    return {k: v for k, v in kw.items() if v is not None}


def _form_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _csv_part(csv: Union[str, bytes, Path], name: str):
    """A CSV part for the multipart form: a path, raw CSV text, or bytes."""
    if isinstance(csv, Path) or (isinstance(csv, str) and "\n" not in csv and Path(csv).is_file()):
        p = Path(csv)
        return (p.name, p.read_bytes(), "text/csv")
    data = csv.encode("utf-8") if isinstance(csv, str) else csv
    return (f"{name}.csv", data, "text/csv")


class Windows(_Resource):
    """``client.windows``"""

    def correlate(
        self,
        environment_id: int,
        hosts: Iterable[Dict[str, Any]],
        *,
        software: Optional[Iterable[Dict[str, Any]]] = None,
        include_cleared: Optional[bool] = None,
        sort: Optional[str] = None,
        confirmed_only: Optional[bool] = None,
        known_exploited_only: Optional[bool] = None,
        fix_available_only: Optional[bool] = None,
        cve_page: Optional[int] = None,
        cve_page_size: Optional[int] = None,
    ) -> WindowsResponse:
        """Submit up to 200 Windows hosts (JSON) and get per-CVE status for each.

        Keep calls at :data:`RECOMMENDED_HOSTS_PER_CALL` (100) or fewer; use :meth:`correlate_batched` for more.
        Paging (``cve_page``, ``cve_page_size``) is off by default: every CVE is returned.
        """
        items = list(hosts)
        if len(items) > MAX_HOSTS_PER_CALL:
            raise ValueError(f"At most {MAX_HOSTS_PER_CALL} hosts per call (got {len(items)}); "
                             f"use correlate_batched().")
        body: Dict[str, Any] = {"environment_id": environment_id, "windows_hosts": items}
        if software is not None:
            body["installed_software"] = list(software)
        opts = _options(include_cleared=include_cleared, sort=sort, confirmed_only=confirmed_only,
                        known_exploited_only=known_exploited_only, fix_available_only=fix_available_only,
                        cve_page=cve_page, cve_page_size=cve_page_size)
        if opts:
            body["options"] = opts
        resp_body = self._client.request("POST", f"{BASE}/correlate", json=body, accept_statuses=(422,))
        data = resp_body.get("data") or {}
        return WindowsResponse.from_dict(resp_body, status_code=422 if not data.get("assets") and data.get("rejected") else 200)

    def correlate_csv(
        self,
        environment_id: int,
        hosts_csv: Union[str, bytes, Path],
        *,
        software_csv: Optional[Union[str, bytes, Path]] = None,
        include_cleared: Optional[bool] = None,
        sort: Optional[str] = None,
        confirmed_only: Optional[bool] = None,
        known_exploited_only: Optional[bool] = None,
        fix_available_only: Optional[bool] = None,
        cve_page: Optional[int] = None,
        cve_page_size: Optional[int] = None,
    ) -> WindowsResponse:
        """The CSV equivalent of :meth:`correlate`. ``hosts_csv`` / ``software_csv`` are a file path, CSV text or
        bytes, using the host field names as column headers (``installed_kbs`` semicolon-separated)."""
        form = {"environment_id": str(environment_id)}
        for k, v in _options(include_cleared=include_cleared, sort=sort, confirmed_only=confirmed_only,
                             known_exploited_only=known_exploited_only, fix_available_only=fix_available_only,
                             cve_page=cve_page, cve_page_size=cve_page_size).items():
            form[k] = _form_value(v)
        files = {"hosts": _csv_part(hosts_csv, "hosts")}
        if software_csv is not None:
            files["software"] = _csv_part(software_csv, "software")
        resp_body = self._client.request("POST", f"{BASE}/correlate-csv", data=form, files=files,
                                         accept_statuses=(422,))
        data = resp_body.get("data") or {}
        return WindowsResponse.from_dict(resp_body, status_code=422 if not data.get("assets") and data.get("rejected") else 200)

    def results(
        self,
        environment_id: int,
        *,
        asset_id: Optional[str] = None,
        include_cleared: Optional[bool] = None,
        sort: Optional[str] = None,
        confirmed_only: Optional[bool] = None,
        known_exploited_only: Optional[bool] = None,
        fix_available_only: Optional[bool] = None,
        cve_page: Optional[int] = None,
        cve_page_size: Optional[int] = None,
    ) -> WindowsResponse:
        """Read stored results for an environment, or one ``asset_id``. A read-only key is enough."""
        params: Dict[str, Any] = {"environment_id": environment_id, "asset_id": asset_id}
        for k, v in _options(include_cleared=include_cleared, sort=sort, confirmed_only=confirmed_only,
                             known_exploited_only=known_exploited_only, fix_available_only=fix_available_only,
                             cve_page=cve_page, cve_page_size=cve_page_size).items():
            params[k] = _form_value(v)
        return WindowsResponse.from_dict(self._client.request("GET", f"{BASE}/results", params=params))

    # -- helpers --------------------------------------------------------------

    def correlate_batched(
        self,
        environment_id: int,
        hosts: Iterable[Dict[str, Any]],
        *,
        batch_size: int = RECOMMENDED_HOSTS_PER_CALL,
        software: Optional[Iterable[Dict[str, Any]]] = None,
        **options: Any,
    ) -> Iterator[WindowsResponse]:
        """Split a large host list into calls of ``batch_size`` (default 100, max 200) and yield each response.

        Installed software rows are sent with the batch that contains their host. The per-key rate limit
        (default 60 requests and 5,000 hosts per minute) is handled by the client's automatic 429 backoff.
        """
        if not (1 <= batch_size <= MAX_HOSTS_PER_CALL):
            raise ValueError(f"batch_size must be between 1 and {MAX_HOSTS_PER_CALL}")
        items = list(hosts)
        sw = list(software or [])
        for start in range(0, len(items), batch_size):
            batch = items[start:start + batch_size]
            ids = {h.get("asset_id") for h in batch}
            batch_sw = [s for s in sw if s.get("asset_id") in ids] or None
            if start and self._client.page_delay:
                time.sleep(self._client.page_delay)
            yield self.correlate(environment_id, batch, software=batch_sw, **options)

    def iter_host_cves(
        self,
        environment_id: int,
        asset_id: str,
        *,
        cve_page_size: int = 250,
        **options: Any,
    ) -> Iterator[WindowsCVE]:
        """Yield every stored CVE result for one host, page by page, in the requested order (default priority)."""
        page = 1
        while True:
            if page > 1 and self._client.page_delay:
                time.sleep(self._client.page_delay)
            resp = self.results(environment_id, asset_id=asset_id, cve_page=page, cve_page_size=cve_page_size,
                                **options)
            if not resp.assets:
                return
            host = resp.assets[0]
            for cve in host.cves:
                yield cve
            if not (host.cves_page and host.cves_page.has_more):
                return
            page += 1

    def all_host_cves(self, environment_id: int, asset_id: str, **kwargs: Any) -> List[WindowsCVE]:
        """Convenience: :meth:`iter_host_cves` as a list."""
        return list(self.iter_host_cves(environment_id, asset_id, **kwargs))
