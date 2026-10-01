# BreachSpider Python SDK

Official Python client for the [BreachSpider](https://breachspider.com) ICS/OT
CVE intelligence API. Go from zero to working queries in about ten seconds from
clone to first query (most of it `pip install`) instead of writing your own
HTTP client.

- Typed objects for CVEs, vendors, products, environments, and assets, not raw dicts.
- Transparent pagination that absorbs the API's per-endpoint shapes.
- Automatic retries that follow the API's retry guidance: rate limits and server errors are retried after the
  wait the API asks for; errors marked not retryable are raised at once.
- Typed exceptions that surface the API's own helpful error messages.
- The API key is never printed, logged, or included in an exception.
- **New in 0.3.0:** cited source references on every CVE: vendor advisories, government ICS advisories and the
  CVE.org record. See the [changelog](CHANGELOG.md).
- **New in 0.2.0:** asset correlation (API v1) and Windows patch level (API v2), with the
  exposure-priority ranking, fix groups and fix plans. See the [changelog](CHANGELOG.md): the API's default
  CVE order changed to `priority`.

## Install

```bash
pip install breachspider
```

Requires Python 3.9+. The only dependency is `requests`.

## 60-second quickstart (no signup)

`Client.demo()` mints a read-only demo token (valid 24h, scoped to a public
demo org). No API key or signup required.

```python
import breachspider

bs = breachspider.Client.demo()

# Find a vendor. Read the slug from the response, never hand-craft it.
vendor = bs.catalog.vendor("schneider electric")
print(vendor.id, vendor.name, vendor.slug)   # 11529 Schneider-Electric schneider-electric

# List that vendor's products, each with a CVE count.
for product in bs.catalog.products(vendor_id=vendor.id)[:3]:
    print(f"  {product.id:>6}  {product.name}  ({product.cve_count} CVEs)")

# Critical, known-exploited CVEs for that vendor.
for cve in bs.cves.by_vendor(vendor.slug, severity="CRITICAL", kev=True):
    print(cve.cve_id, "-", cve.title)
    break   # (the loop would page through all of them)
```

## Authentication

Use a real API key (`bs_live_…`) for production. Start a free trial key at
[breachspider.com/developers](https://breachspider.com/developers), or ask about partner keys through "Talk to us" on
the same page. Organizations with dashboard access can also create keys under **Integrations → API Keys**.

```python
import os
import breachspider

# export BREACHSPIDER_API_KEY=bs_live_your_key_here
bs = breachspider.Client(os.environ.get("BREACHSPIDER_API_KEY", "bs_live_YOUR_KEY_HERE"))
print(bs)   # key is redacted: <breachspider.Client base_url='https://breachspider.com' auth=live key=***redacted***>
```

The key is held privately: it never appears in `repr()`, `str()`, logs, or any
exception message.

## The primary workflow: vendor → products → CVEs

```python
import breachspider

bs = breachspider.Client.demo()

vendor = bs.catalog.vendor("schneider electric")
assert (vendor.id, vendor.slug) == (11529, "schneider-electric")

products = bs.catalog.products(vendor_id=vendor.id)
m340 = next(p for p in products if p.id == 25001)
print(m340.name, m340.cve_count)          # Modicon M340 41

# by_vendor takes the slug and supports the full /cves filter set.
criticals = bs.cves.by_vendor(vendor.slug, severity="CRITICAL", kev=True)
first = next(iter(criticals))
print(first.cve_id, first.severity, first.cvss_score, first.kev_flagged)
```

## Searching CVEs

`bs.cves.search(**filters)` returns an iterator that transparently follows
pages. Accepted filters:

`q`, `vendor` (slug), `protocol`, `severity`, `kev`, `unpatched`,
`has_exploit`, `patch_status`, `cvss_min`, `cvss_max`, `bcs_min`, `bcs_max`,
`date_from`, `date_to`, `sort_by`, `ranked`.

> There is **no** `product`, `version`, or `cpe` filter on `/cves` today. To
> narrow to a product, filter by vendor and match on the result fields.

> `cves.search` works with a demo token (as below) or a partner or customer key. A **trial key** cannot call it
> (`TRIAL_SCOPE`); trial keys can correlate devices and look up single CVEs with `bs.cves.get`.

```python
import itertools
import breachspider

bs = breachspider.Client.demo()

# First 5 known-exploited CVEs affecting Siemens, highest CVSS first.
for cve in itertools.islice(bs.cves.search(vendor="siemens", kev=True, sort_by="cvss"), 5):
    print(cve.cve_id, cve.cvss_score, cve.severity)

# One CVE by id (rich detail; nested scoring/exploitation/patch in .raw).
cve = bs.cves.get("CVE-2025-32433")
print(cve.cve_id, cve.severity, cve.cvss_score, cve.html_url)
```

## Pagination

Every `search`/`by_vendor`/`assets` call is a lazy iterator: it fetches the
next page only as you consume it, and stops at the end. Page size defaults to
100 (the maximum). Different endpoints paginate differently (`per_page` vs
`limit`, `_links.next` vs page numbers vs offset); the SDK handles all of them.

```python
import breachspider

bs = breachspider.Client.demo()

count = 0
for _cve in bs.cves.search(vendor="schneider-electric"):
    count += 1
    if count >= 250:      # 250 spans 3 pages of 100; the SDK paged for you
        break
print("iterated", count, "CVEs across multiple pages")
```

### Do not call list() on a search iterator

`list(bs.cves.search(...))` materializes **every page** of the result set.
Siemens alone has over 5,000 CVEs; walking all of them will exhaust every page
and can trigger the rate limit. Use `itertools.islice` when you only need the
first N, or a `for` loop with a `break`.

```python
import itertools
import breachspider

bs = breachspider.Client.demo()

# Safe: fetch exactly 10 results and stop. Never touches page 2 or beyond.
first_ten = list(itertools.islice(
    bs.cves.search(vendor="siemens", kev=True, sort_by="cvss"), 10))
for cve in first_ten:
    print(cve.cve_id, cve.cvss_score)
```

### Rate-limit safety

The API sits behind a Cloudflare edge limit that trips at roughly 37 rapid
requests from one IP. The client sleeps `page_delay` seconds (default `0.25`)
between pages and retries rate limits and server errors the API marks retryable, waiting the time the API asks
for (else exponential backoff). Tune it:

```python
import breachspider

# Faster (riskier) or gentler pagination, and more patient retries.
bs = breachspider.Client.demo(page_delay=0.5, max_retries=8, backoff_factor=1.0)
print("page_delay:", bs.page_delay, "max_retries:", bs.max_retries)
```

## Quota / usage headers

With a demo token (`Client.demo()`), `bs.quota` is always `None`; demo
traffic is not metered.

With a `bs_live_` key, every response carries `X-RateLimit-*` headers that the
client parses into `bs.quota` after any call. Metering is **observe-only** today:
usage is reported but nothing is rejected. Unlimited tiers report the string
`"unlimited"`.

```python
import os
import breachspider
from breachspider import AuthenticationError

# export BREACHSPIDER_API_KEY=bs_live_your_key_here
bs = breachspider.Client(os.environ.get("BREACHSPIDER_API_KEY", "bs_live_YOUR_KEY_HERE"))

try:
    # Correlate works with every key type, including trial keys.
    device = {"asset_id": "asset-1", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}
    bs.correlate.correlate([device])
    q = bs.quota
    print("limit:", q.limit, "used:", q.used, "remaining:", q.remaining)
    # limit is your key's allowance, or 'unlimited'
except AuthenticationError:
    print("Set BREACHSPIDER_API_KEY to a live bs_live_… key to see quota.")
```

## Error handling

Errors map to typed exceptions that keep the server's own message and structured
detail, the most useful part.

```python
import breachspider
from breachspider import UnknownParameterError, ValidationError, NotFoundError

bs = breachspider.Client.demo()

# 400 UNKNOWN_PARAMETER surfaces the accepted-parameter list.
try:
    list(bs.cves.search(color="red"))
except UnknownParameterError as e:
    print("accepted:", e.accepted_parameters)

# 422 for per_page > 100 (the real per-page maximum is 100 on every tier).
try:
    bs.request("GET", "/cves", params={"per_page": 101})
except ValidationError as e:
    print("validation:", e.fields)

# 404 for a CVE that doesn't exist.
try:
    bs.cves.get("CVE-0000-00000")
except NotFoundError as e:
    print("not found:", e.message)
```

| Exception | HTTP | Notable attributes |
|---|---|---|
| `UnknownParameterError` | 400 | `accepted_parameters`, `unknown_parameters` |
| `AuthenticationError` | 401 | |
| `InsufficientScopeError` | 403 | `required_scope`, `current_scopes` |
| `ScopeError` | 403 | `code` is `PARTNER_SCOPE` or `TRIAL_SCOPE` |
| `TrialEndedError` | 403 | `reason` (`expired` or `ended`), `ended_at`, `contact_url` |
| `CapExceededError` | 403 | `resource`, `limit`, `current`, `tier` |
| `NotFoundError` | 404 | `detail` |
| `BatchTooLargeError` | 413 | `max`, `received`; `code` is `BATCH_TOO_LARGE` or `TRIAL_BATCH_LIMIT` (or `detail.error` is `batch_too_large`) |
| `ValidationError` | 422 | `fields` |
| `RateLimitError` | 429 | `retry_after` (auto-retried first when `retryable`) |
| `UsageLimitError` | 429 | `used`, `limit`, `remaining`, `requested`, `resets_at`; `code` is `PARTNER_LIMIT` or `TRIAL_ENDED` |

`ScopeError` and `TrialEndedError` are subclasses of `ForbiddenError`, and `UsageLimitError` of `RateLimitError`,
so existing `except ForbiddenError` and `except RateLimitError` blocks still catch them. Catch the specific class
first:

```python
from breachspider import (BatchTooLargeError, ForbiddenError, ScopeError, TrialEndedError,
                          UsageLimitError)

try:
    result = bs.windows.check(hosts)
except ScopeError as e:          # this key cannot call this endpoint (PARTNER_SCOPE / TRIAL_SCOPE)
    print("needs a different key:", e.message)
except TrialEndedError as e:     # trial expired or ended
    print("trial over:", e.reason, e.contact_url)
except UsageLimitError as e:     # monthly or trial asset checks used up; nothing was processed
    print(f"{e.remaining} of {e.limit} checks left, resets {e.resets_at}")
except BatchTooLargeError as e:  # split into batches of e.max
    print("at most", e.max, "per call")
except ForbiddenError as e:      # any other 403
    print(e)
```

All inherit from `breachspider.BreachSpiderError`. Network failures raise
`APIConnectionError` (never leaking the request or key).

### Retry guidance

Every exception carries the API's retry guidance:

| Attribute | Meaning |
|---|---|
| `retryable` | `True` only when repeating the exact same request later may succeed |
| `retry_after_seconds` | Seconds to wait, when the server knows (rate limits); else `None` |
| `action` | What to do: `retry_later`, `wait_until_reset`, `reduce_batch`, `fix_input`, `use_different_key`, `contact_us` |
| `reset_at` | When a usage limit resets (ISO 8601), where the API says so |

The client already retries errors that are `retryable` (up to `max_retries`, waiting `retry_after_seconds` or the
`Retry-After` header), and never retries one that is not. A gateway timeout (504) on a POST is not repeated
automatically either: the API may already have processed it. A used-up quota, a refused key or bad input is raised at
once. So by the time you catch an error, decide on `action`:

```python
from breachspider import APIError

try:
    result = bs.windows.check(hosts)
except APIError as e:
    if e.action == "reduce_batch":
        ...                                   # split into calls of e.detail["max"] hosts
    elif e.action == "wait_until_reset":
        print("monthly limit used up; resets", e.reset_at)
    elif e.action in ("use_different_key", "contact_us"):
        print("this key cannot do this:", e.message)
    elif e.retryable:
        print(f"still failing after retries; try again in {e.retry_after_seconds or 60}s")
    else:                                     # fix_input
        print("fix the request:", e.message, e.detail)
```

Responses without guidance (Cloudflare's own 429 and 524 pages) fall back to the status: 429 and 5xx are
retryable, everything else is not.

## Correlate assets (API v1)

Send your inventory (vendor, product, version); get each asset's CVEs ranked by what's exposed and what to fix
first, the fix actions, and a fix plan. Nothing is stored server-side.

```python
device = {"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}
resp = bs.correlate.correlate([device])          # sort="priority" by default; also "score", "exploit", "newest"
result = resp.results[0]
for cve in result.cves:
    print(cve.priority_rank, cve.cve_id, cve.priority_reason)
print(result.fix_groups[0].fix, result.fix_plan)
every_page = bs.correlate.all_cves(device)       # follows cves_page.has_more for you
```

Filters: `confirmed_only`, `known_exploited_only`, `fix_available_only`. `result_hash` never depends on sort, filters
or page; use `bs.correlate.check(...)` to re-correlate only what changed. Guide: [docs/correlate.md](docs/correlate.md).

## Windows patch level (API v2)

Send Windows build and KB facts; get confirmed open / cleared / needs review per CVE from Microsoft's own data, with
fix actions such as "install KB5122876 (latest cumulative, build 10.0.17763.9245)". Submitting needs a
**write-scoped** key.

```python
hosts = [{"asset_id": "WIN-EXAMPLE-01", "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard",
          "os_build": "10.0.17763.7792", "architecture": "x64", "installation_type": "Server",
          "collected_at": "2026-09-25T14:02:00Z"}]
resp = bs.windows.correlate(12, hosts, include_cleared=False)
for r in resp.rejected:                          # refused hosts (e.g. an identifying field); nothing stored
    print(r.asset_id, r.error_codes)
for batch in bs.windows.correlate_batched(12, many_hosts):   # calls of 25 hosts (the per-call limit)
    ...
bs.windows.correlate_csv(12, "hosts.csv")        # the same from a CSV file
bs.windows.results(12, asset_id="WIN-EXAMPLE-01", cve_page_size=50)
```

### Check Windows hosts without storing anything

`bs.windows.check()` gives the same per-CVE decisions as `correlate()` (confirmed open, cleared or needs review, with
the fixed build, KB and Microsoft source), but nothing about the hosts is saved and no environment is needed. Any API
key works, read-only included. Trial keys, demo tokens and browser sessions are refused.

```python
hosts = [{"asset_id": "asset-1", "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard",
          "os_build": "10.0.17763.7792", "architecture": "x64", "installation_type": "Server",
          "collected_at": "2026-09-25T14:02:00Z"}]
resp = bs.windows.check(hosts, include_cleared=False)    # at most 25 hosts per call
resp.stored                                              # False: nothing was saved
host = resp.assets[0]
host.counts, host.cves[0].status, host.result_hash
for batch in bs.windows.check_batched(many_hosts):       # calls of 25
    ...
# Later: learn cheaply which hosts changed (up to 200 per call, about a tenth of the cost)
changes = bs.windows.check_changes([{**hosts[0], "result_hash": host.result_hash}])
changes.changed                                          # asset_ids to check again
```

Identifying fields (host name, IP or MAC address, user and similar) are refused, and so is an `asset_id` shaped like
an IP, MAC or email address or a domain name. Your own asset tags, such as `PLC-LINE-2`, are fine.

Guide: [docs/windows-v2.md](docs/windows-v2.md). Examples for every endpoint: [examples/](examples/). OpenAPI
document for these endpoints: [openapi/breachspider-openapi.json](openapi/breachspider-openapi.json).

## Writes

Reads work with any key. Writes (`environments.create`, `environments.add_asset`,
`watchlist.add`, `environments.create_ticket`, `reports.generate`) require a
**write-scoped** `bs_live_` key and are rejected for demo tokens. Session-only
operations (API-key management, webhook delivery, billing, and account
settings) are intentionally **not** part of this SDK; they can never be called
with a key.

## Honest limits

- **Per page:** 100 results maximum on every paid tier (10 on Free). There is no
  pagination depth cap; you can page through the entire result set.
- **No product/version/CPE filter** on `/cves` yet. Filter by `vendor` (slug).
- **Metering is observe-only.** Usage is counted and returned in headers, but no
  request is rejected for exceeding a monthly allowance today.

## Running the tests

Install the dev extras, then run the suite:

```bash
pip install ".[dev]"
pytest
```

The suite includes live integration tests that hit the real API using a demo
token. To skip them when offline (or in CI without network access):

```bash
BREACHSPIDER_SKIP_INTEGRATION=1 pytest
```

The integration tests are marked `@pytest.mark.integration` and are skipped
automatically if the API is unreachable or the env var is set. The correlate and Windows tests run against
responses recorded from the live API (`tests/fixtures/`), so they need no key and no network.

## License

MIT © CITED Relevance LLC
