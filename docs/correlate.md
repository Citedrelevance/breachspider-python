# Correlate CVEs (API v1)

`POST /api/v1/assets/correlate-cves` resolves each asset you send (vendor, product, version) to a catalog product and
returns the CVEs that affect it, **ranked by what's exposed and what to fix first**. Nothing is stored.
`POST /api/v1/assets/correlate-cves/check` tells you cheaply whether a result has changed.

Full reference: <https://breachspider.com/docs/api/correlate/>. OpenAPI: [`openapi/breachspider-openapi.json`](../openapi/breachspider-openapi.json).

> **Behavior change (2026-09-26):** `cves[]` is now in **priority** order by default. Pass `sort="score"` for the
> previous order (BCS, then CVSS).

## Python

```python
import os
import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
device = {"asset_id": "asset-1", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}

resp = bs.correlate.correlate([device])
result = resp.results[0]
result.cves[0].cve_id              # 'CVE-2024-9137'
result.cves[0].priority_reason     # 'confirmed (affected 1.0 to 3.11), fix: upgrade to security patch 3.11.2 (from Moxa Technical Support)'
result.cves[0].fix.source          # 'manual_curation'
result.fix_groups[0].fix           # 'upgrade to security patch 3.11.2 (from Moxa Technical Support)'
result.fix_groups[0].cve_ids       # ['CVE-2024-9137', 'CVE-2024-7695', 'CVE-2024-9404']
result.fix_plan.to_clear_all_fixable.clears   # {'cves': 3, 'known_exploited': 0, 'groups': 1}
resp.fix_summary                   # top fix actions across all assets in the call

all_cves = bs.correlate.all_cves(device)                 # every page
changed = bs.correlate.check([{**device, "result_hash": result.result_hash}])
```

## Request

| Field | Required | Meaning |
|---|---|---|
| `assets[].asset_id` | yes | Your identifier, echoed. Use a non-identifying id. |
| `assets[].vendor`, `assets[].product` | yes | Free text as you hold it |
| `assets[].version` | no | Software or firmware version used for matching |
| `assets[].firmware_version` | no | Used for matching **when `version` is empty** (warning `VERSION_FROM_FIRMWARE`) |
| `assets[].product_type` | no | Hint such as `PLC`, `HMI`, `Server` |
| `options.min_confidence` | no | `LOW`, `MEDIUM` (default), `HIGH`: resolutions below it return no CVEs and `needs_review` |
| `options.include_capec` | no | Add MITRE CAPEC to each CVE. Default **false for API keys** |
| `options.cve_page`, `options.cve_page_size` | no | Per-asset CVE paging; page size 1 to 1,000, default **250 for API keys** |
| `options.sort` | no | `priority` (default), `score`, `exploit`, `newest`; anything else → `422` |
| `options.confirmed_only`, `known_exploited_only`, `fix_available_only` | no | Filters, off by default |

At most 200 assets per call (`413`). Sorting and filters are applied **before paging**, so page 1 holds the top
priorities and `cves_page.total` is the filtered count (`total_unfiltered` is the full count).

## Ranking (`sort`)

| Mode | Order |
|---|---|
| `priority` | 1. confirmed for this version (`EXACT`, `RANGE`) before `PRODUCT_WIDE`; 2. known-exploited; 3. public exploit or proof-of-concept; 4. fix available (installable before ESU-required) before no fix known; 5. BCS, CVSS, EPSS (highest first) |
| `score` | The previous order: BCS, then CVSS |
| `exploit` | Known-exploited, exploit/PoC, EPSS, CVSS |
| `newest` | Published date, newest first |

Each CVE carries `priority_rank` (1 = first, across all pages), `priority_reason` (plain language) and
`fix` (`available`, `action`, `source`, `derived`).

## Fix actions

Per CVE, first that applies: a stored fixed version (`upgrade to <v>`); else derived from the affected range:
exclusive end: `upgrade to <end> or later`, inclusive end: `upgrade beyond <end>` (labelled `derived`); else a stored
"patched" status (`vendor fix available (version not recorded)`); else `no fix known`.

**Derived fixes come from affected version ranges, not from a vendor fix statement. Confirm the target release in the
vendor's advisory: it may not exist in the product line.**

- `fix_groups[]`: one per distinct action (all filtered CVEs, all pages), `no fix known` last, ranked by each group's
  highest-priority CVE. Fields: `fix`, `fix_type`, `source`, `derived`, `cve_ids`, `counts` (`total`, `confirmed`,
  `known_exploited`, `exploit_available`), `highest_score`, `group_rank`.
- `fix_plan`: `to_clear_known_exploited` and `to_clear_all_fixable`: the single upgrade that moves past every
  relevant affected range, with what it clears. Derived steps carry the note above. Assumes one release line.
- `data.fix_summary[]`: the top 10 fix actions across all assets in the call.

## Match tiers, resolution, warnings

| `match_tier` | Meaning |
|---|---|
| `EXACT` | The version equals a listed affected version |
| `RANGE` | The version is inside an affected range (`affected_range`) |
| `PRODUCT_WIDE` | No version bound, or no version supplied: not confirmed for this version |

`resolution.status`: `resolved`, `ambiguous` (see `candidates`, no CVEs), `unresolved`. `confidence_band`: `HIGH` ≥ 80,
`MEDIUM` 60 to 79, `LOW` < 60. `coverage`: `covered`, `partial`, `no_cpe_data` (empty list is undetermined, not clean).
Warnings include `NO_VERSION_SUPPLIED`, `VERSION_FROM_FIRMWARE`, `PRODUCT_WIDE_MATCH`, `NO_CPE_DATA`, `NEEDS_REVIEW`,
`FIRMWARE_UNPARSEABLE`, `VERSION_SUFFIX_APPROXIMATE`, `VERSION_SUFFIX_IGNORED`, `AMBIGUOUS_RESOLUTION`; handle unknown
codes gracefully.

## Staleness check and `result_hash`

`result_hash` fingerprints the resolved identity and every (CVE, tier) pair of the **full, unfiltered** result: it does
not change with sort, filters or page. Store it; send it to `/check` later; re-correlate only assets with
`changed: true`.

## Limits and errors

Per API key: 60 requests and 5,000 assets per minute by default (shared with API v2). Over the limit: `429`
`RATE_LIMITED` with `error.retry_after_seconds` (also `error.detail.retry_after` and the `Retry-After` header); the
SDK waits and retries automatically.

| HTTP | Code | When |
|---|---|---|
| 400 | `UNKNOWN_PARAMETER` | Query parameters are not accepted |
| 401 | `AUTH_REQUIRED` | Missing, invalid, expired or revoked key |
| 413 | `batch_too_large` (in `error.detail.error`) | More than 200 assets |
| 422 | `VALIDATION_ERROR` | Missing fields; invalid `min_confidence`, `cve_page`, `cve_page_size` or `sort` |
| 429 | `RATE_LIMITED` | Per-key limit; `error.detail.retry_after` seconds |
