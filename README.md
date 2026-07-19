# BreachSpider Python SDK

Official Python client for the [BreachSpider](https://breachspider.com) ICS/OT
CVE intelligence API. Go from zero to working queries in about ten seconds from
clone to first query — most of it `pip install` — instead of writing your own
HTTP client.

- Typed objects for CVEs, vendors, products, environments, and assets — not raw dicts.
- Transparent pagination that absorbs the API's per-endpoint shapes.
- Automatic 429 backoff so a naive loop over thousands of CVEs won't trip the edge limit.
- Typed exceptions that surface the API's own helpful error messages.
- The API key is never printed, logged, or included in an exception.

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

# Find a vendor — read the slug from the response, never hand-craft it.
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

Use a real API key (`bs_live_…`) for production. Keys require the Professional
tier or above and are created in the dashboard under **Integrations → API Keys**.

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

```python
import itertools
import breachspider

bs = breachspider.Client.demo()

# First 5 KEV CVEs affecting Siemens, highest CVSS first.
for cve in itertools.islice(bs.cves.search(vendor="siemens", kev=True, sort_by="cvss"), 5):
    print(cve.cve_id, cve.cvss_score, cve.severity)

# One CVE by id (rich detail — nested scoring/exploitation/patch in .raw).
cve = bs.cves.get("CVE-2025-32433")
print(cve.cve_id, cve.severity, cve.cvss_score, cve.html_url)
```

## Pagination

Every `search`/`by_vendor`/`assets` call is a lazy iterator — it fetches the
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
between pages and retries any `429` with exponential backoff. Tune it:

```python
import breachspider

# Faster (riskier) or gentler pagination, and more patient retries.
bs = breachspider.Client.demo(page_delay=0.5, max_retries=8, backoff_factor=1.0)
print("page_delay:", bs.page_delay, "max_retries:", bs.max_retries)
```

## Quota / usage headers

With a demo token (`Client.demo()`), `bs.quota` is always `None` — demo
traffic is not metered.

With a `bs_live_` key, every response carries `X-RateLimit-*` headers that the
client parses into `bs.quota` after any call. Metering is **observe-only** today —
usage is reported but nothing is rejected. Unlimited tiers report the string
`"unlimited"`.

```python
import os
import breachspider
from breachspider import AuthenticationError

# export BREACHSPIDER_API_KEY=bs_live_your_key_here
bs = breachspider.Client(os.environ.get("BREACHSPIDER_API_KEY", "bs_live_YOUR_KEY_HERE"))

try:
    next(iter(bs.cves.search(vendor="siemens", per_page=1)), None)
    q = bs.quota
    print("limit:", q.limit, "used:", q.used, "remaining:", q.remaining)
    # On Professional: limit 25000 ... ; on Enterprise/api: limit 'unlimited'
except AuthenticationError:
    print("Set BREACHSPIDER_API_KEY to a live bs_live_… key to see quota.")
```

## Error handling

Errors map to typed exceptions that keep the server's own message and structured
detail — the most useful part.

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
| `CapExceededError` | 403 | `resource`, `limit`, `current`, `tier` |
| `NotFoundError` | 404 | `detail` |
| `ValidationError` | 422 | `fields` |
| `RateLimitError` | 429 | `retry_after` (auto-retried first) |

All inherit from `breachspider.BreachSpiderError`. Network failures raise
`APIConnectionError` (never leaking the request or key).

## Writes

Reads work with any key. Writes (`environments.create`, `environments.add_asset`,
`watchlist.add`, `environments.create_ticket`, `reports.generate`) require a
**write-scoped** `bs_live_` key and are rejected for demo tokens. Session-only
operations — API-key management, webhook delivery, billing, and account
settings — are intentionally **not** part of this SDK; they can never be called
with a key.

## Honest limits

- **Per page:** 100 results maximum on every paid tier (10 on Free). There is no
  pagination depth cap — you can page through the entire result set.
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
automatically if the API is unreachable or the env var is set.

## License

MIT © CITED Relevance LLC
