# Changelog

All notable changes to the BreachSpider Python SDK. This project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, a minor release may include behavior changes, and they are listed first.

## 0.2.0 — 2026-09-26

### ⚠ Behavior change (API, affects every correlate caller)
- **The API now returns each asset's CVEs in `priority` order by default** — confirmed for the asset's version,
  then known-exploited, then public exploit or proof-of-concept available, then fix available (directly installable
  before ESU-required), then BCS, CVSS and EPSS. This applies to `POST /api/v1/assets/correlate-cves` and to every
  API v2 Windows endpoint. **To keep the previous order, pass `sort="score"`.** `result_hash` is unchanged and does not
  depend on the order, filters or page.
- For API keys, `include_capec` now defaults to `false` and each asset's CVE list is paged at 250 per page on v1
  (`cves_page.has_more`; use `cve_page_size` up to 1,000, or the new `all_cves()` / `iter_asset_cves()` helpers).

### Added
- `client.correlate` (API v1): `correlate()`, `check()`, `iter_asset_cves()` / `all_cves()` (fetches every CVE page
  for an asset). Options: `sort` (`priority`, `score`, `exploit`, `newest`; validated client-side), filters
  `confirmed_only`, `known_exploited_only`, `fix_available_only`, `min_confidence`, `include_capec`, `cve_page`,
  `cve_page_size`.
- `client.windows` (API v2 Windows patch level): `correlate()` (JSON), `correlate_csv()` (multipart; path, text or
  bytes), `results()`, `correlate_batched()` (splits host lists into calls of 100 or fewer), `iter_host_cves()` /
  `all_host_cves()`; optional paging (off by default) and the same sort and filters.
- Typed models: `CorrelateResponse`, `CorrelateResult`, `CorrelatedCVE`, `CheckResult`, `Fix`, `FixGroup`, `FixPlan`,
  `FixPlanStep`, `FixSummaryItem`, `CvePage`, `WindowsResponse`, `WindowsHostResult`, `WindowsCVE`, `RejectedHost`,
  and `SORT_MODES`.
- New response fields surfaced: `priority_rank`, `priority_reason`, `fix` per CVE; `fix_groups` and `fix_plan` per
  asset (derived plans carry a note to confirm the target release in the vendor's advisory); `data.fix_summary`
  per call; `cves_page.total_unfiltered`; `meta.sort` and `meta.filters`.
- `firmware_version` is documented: the API uses it for matching when `version` is empty (`VERSION_FROM_FIRMWARE`).
- API v2 "every host refused" (HTTP 422 with `data.rejected`) is returned as a `WindowsResponse` with
  `all_refused = True` instead of raising.
- OpenAPI 3.1 document for the correlate and Windows endpoints: `openapi/breachspider-openapi.json`.
- Guides `docs/correlate.md` and `docs/windows-v2.md`; runnable examples for every endpoint in `examples/`.
- Tests against responses recorded from the live API (`tests/fixtures/`), plus an OpenAPI validity test.

### Changed
- API: `meta.matcher` on v1 correlate responses now reads `stateless; same rules as stored matching`; it
  previously named an internal database view. The value is informational; the SDK does not parse it.
- `429` handling now honors the per-key limiter's `error.detail.retry_after` when no `Retry-After` header is sent.
- `Client.request()` accepts `data=`/`files=` (multipart) and `accept_statuses=`.

## 0.1.0 — 2026-07-19

- First release: CVEs, catalog, environments, reports, watchlist; pagination; 429 backoff; typed errors; quota headers.
