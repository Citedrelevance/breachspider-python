# Changelog

All notable changes to the BreachSpider Python SDK. This project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, a minor release may include behavior changes, and they are listed first.

## 0.3.1 (unreleased)

### Added
- **Stateless Windows checks:** `client.windows.check(hosts)` (`POST /api/v2/assets/check-windows`) returns the same
  per-CVE decisions as `correlate()` but stores nothing and needs no environment. Any API key works, read-only
  included. `client.windows.check_batched()` sends calls of 25. Each host carries `result_hash`
  (`WindowsHostResult.result_hash`); `WindowsResponse.stored` is False.
- `client.windows.check_changes(hosts)` (`POST /api/v2/assets/check-windows/changes`): send host facts with their
  `result_hash` and learn which hosts changed, up to 200 per call, without storing anything. New models
  `WindowsChange` and `WindowsChangesResponse`.

### Behavior change
- **Windows (API v2): at most 25 hosts per call** (was 200), matching the API, which now refuses more with
  `413 BATCH_TOO_LARGE`. A full host response takes about 1.8 seconds, and 200 hosts ran past the 100 second limit for
  responses through breachspider.com. `client.windows.correlate()` raises `ValueError` above 25;
  `client.windows.correlate_batched()` now sends batches of 25 by default (maximum 25).

### Changed
- README: API keys no longer say they require the Professional tier. Free trial keys and partner keys are available
  at breachspider.com/developers.
- README: the quota example uses `correlate` (works with every key type) instead of `cves.search`; the CVE search
  section notes that search needs a partner or customer key, not a trial key.
- docs/correlate.md: the example shows the live result (security patch 3.11.2, source `manual_curation`) and reads
  the key from `BREACHSPIDER_API_KEY`.
- Government ICS advisories are described as such in prose. API field names such as `cisa_ics_advisories` are
  unchanged.

## 0.3.0 (2026-09-30)

### Added
- **Vendor advisory links in API v1 correlate.** Each CVE's `references.vendor_advisories` is now filled with the
  vendor's own advisories (`{url, title, source}`) instead of always being empty. A link is included only when it is
  on the matched vendor's own domain and NVD tagged it `Vendor Advisory` (`source: "nvd_vendor_advisory"`) or the
  vendor, as the CVE's CNA, published it (`source: "vendor_cna"`). No link is constructed or guessed; `title` is
  `null` (NVD references have no titles). `patch.patch_url` and `result_hash` are unchanged.
- `CorrelatedCVE.vendor_advisories` (list of the new `VendorAdvisory` model).
- **More references in API v1 correlate.** Each CVE now also has `references.cve_org_url` (the official CVE record)
  and `references.other_references`: every other NVD reference as `{url, tags, provided_by}`, not vendor-verified,
  capped at 25 per CVE, with `references.other_references_total` giving the full count (full list on `nvd_url`).
- `vendor_advisories` also covers 58 vendors' advisory domains that differ from the vendor name (for example android.com for
  Google), each approved on NVD evidence; on those domains only NVD `Vendor Advisory`-tagged links count.
- `vendor_advisories` also includes the vendor advisory that the government ICS advisory's CSAF document states for the CVE (a `self`
  reference), when it is on the matched vendor's own domain (`source: "cisa_csaf_vendor_reference"`, with the advisory's title).
- **Government ICS advisories.** Each CVE's `references.cisa_ics_advisories` lists the government ICS advisories that name it
  (`{advisory_id, url, title, published}`), from the advisories' own CSAF documents; the URL is the page each document states.
- **The same references on every CVE-returning endpoint:** `GET /api/v1/cves/{id}` (vendor context = the CVE's catalog
  vendors) and the v2 Windows results (each CVE gains a `references` object). New SDK model `CisaIcsAdvisory`;
  `CorrelatedCVE.cisa_ics_advisories`; `WindowsCVE.references`.
- `CorrelatedCVE.cve_org_url`, `CorrelatedCVE.other_references` (list of the new `OtherReference` model) and
  `CorrelatedCVE.other_references_total`.

## 0.2.0 (2026-09-26)

### ⚠ Behavior change (API, affects every correlate caller)
- **The API now returns each asset's CVEs in `priority` order by default**: confirmed for the asset's version,
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

## 0.1.0 (2026-07-19)

- First release: CVEs, catalog, environments, reports, watchlist; pagination; 429 backoff; typed errors; quota headers.
