# Windows patch-level (API v2)

Send the Windows build and update facts you collect from each host; get back, per CVE, whether the host is
**confirmed open**, **cleared (patched)** or **needs review**, from Microsoft's own fixed builds and KB data — ranked
by what to fix first, with fix actions such as "install KB5122876 (latest cumulative, build 10.0.17763.9245)".

Full reference: <https://breachspider.com/docs/api/windows-patch/>. OpenAPI: [`openapi/breachspider-openapi.json`](../openapi/breachspider-openapi.json).

## 1. Purpose

- **Cumulative Windows** (Windows 10, Windows 11, Server 2016 and later): `os_build` is compared with Microsoft's
  fixed build for each CVE on that product. At or above: cleared. Below: confirmed open.
- **Legacy Windows** (Windows 7, Server 2008 R2, Server 2012 R2): `installed_kbs` is checked against the fix KB; a
  later monthly rollup, or a KB Microsoft lists as replacing the fix, also counts. For CVEs published after end of
  support, `esu_enrolled` decides the outcome.
- **Build and KB list disagree**: needs review. Never guessed.
- **No `os_build`, or a bare "Windows"**: the host is not patch-resolved and stays product-level, as in API v1.

## 2. Authentication and limits

`Authorization: Bearer bs_live_...`. Each key belongs to one organization and sees only its environments.

| Action | Scope |
|---|---|
| Submit hosts (`POST /api/v2/assets/correlate`, `POST /api/v2/assets/correlate-csv`) | **`write`** (a read-only key gets `403 insufficient_scope`) |
| Read stored results (`GET /api/v2/assets/results`) | `read` |

Per key: 60 requests and 5,000 hosts per minute by default; `429` with `error.detail.retry_after` above that (the
SDK retries automatically). At most **200 hosts per call** (`413`). **Send 100 hosts or fewer per call**: processing
takes just under a second per host and responses through breachspider.com must complete within 100 seconds. The SDK's
`client.windows.correlate_batched()` splits large lists into calls of 100.

Request and response bodies are never logged.

## 3. Endpoints

| Method and path | SDK | Purpose |
|---|---|---|
| `POST /api/v2/assets/correlate` | `client.windows.correlate()` | Submit hosts (JSON) and optional installed software |
| `POST /api/v2/assets/correlate-csv` | `client.windows.correlate_csv()` | The same as a multipart CSV upload |
| `GET /api/v2/assets/results` | `client.windows.results()` | Read stored results for an environment, or one `asset_id` |

## 4. Host fields

Same names in JSON and CSV. An empty value means unknown.

| Field | Required | Format and example |
|---|---|---|
| `asset_id` | yes | Your scrubbed identifier, up to 64 characters; must not be a hostname, IP, MAC or serial. `WIN-EXAMPLE-01` |
| `os_product` | yes | Windows ProductName as reported. `Windows Server 2019 Standard`. Windows 11 reports "Windows 10"; it is identified by build 22000 or higher. |
| `edition_id` | yes | EditionID: `ServerStandard`, `ServerDatacenter`, `Enterprise`, `EnterpriseS` (LTSC), `Professional` |
| `display_version` | no | DisplayVersion (ReleaseId on older builds). `1809`, `21H2` |
| `os_build` | yes | Full build `10.0.<CurrentBuild>.<UBR>`, digits and dots. `10.0.17763.7792` |
| `architecture` | yes | `x64`, `x86` or `arm64` |
| `installation_type` | for servers | `Server`, `Server Core` or `Client` |
| `installed_kbs` | see below | JSON: a list (`["KB5031419"]`). CSV: semicolon-separated (`KB5031419;KB5033371`). Duplicates ignored. |
| `kb_source` | when `installed_kbs` is sent | How the list was collected. `WMI QuickFixEngineering`, `DISM packages` |
| `esu_enrolled` | no (legacy Windows) | `yes` or `no` |
| `collected_at` | yes | ISO 8601 with time zone. `2026-09-25T14:02:00Z` |

**The three KB list states:**
1. `installed_kbs` has values → the KB list was collected.
2. `installed_kbs` is empty and `kb_source` is filled → collected, none found.
3. Both empty or both omitted → not collected. (Legacy Windows needs a collected list to be patch-resolved.)

**Installed software** (optional, stored only for now): `installed_software` array (JSON) or a second CSV with
`asset_id, name, publisher, version`. Send the host in `windows_hosts` first.

**Never send identifying data.** These fields are refused (`forbidden_field`) and nothing from that host is stored:
`hostname`, `host_name`, `host`, `computer_name`, `fqdn`, `dns_name`, `domain`, `domain_name`, `workgroup`, `ip`,
`ip_address`, `ipv4`, `ipv6`, `mac`, `mac_address`, `user`, `username`, `user_name`, `owner`, `serial`,
`serial_number`, `license_key`, `product_key`, `install_path`, `path`, `site`, `site_name`, `customer`,
`customer_name`, `location` (and spelling variants). An `asset_id` that looks like an IP, MAC or domain name is
refused with `forbidden_value` and the value is not echoed back.

## 5. Validation (per host)

Each host is validated on its own; a refused host does not stop the others.

| Rule | Code |
|---|---|
| Identifying field (see above) | `forbidden_field` |
| `asset_id` looks like an IP, MAC or domain name, or is over 64 characters | `forbidden_value` |
| Field not in the contract | `unknown_field` |
| Placeholder value (`N/A`, `-`, `unknown`, `none`, `null`, `TBD`, ...): send empty instead | `placeholder_value` |
| Required field missing | `missing_field` |
| `os_product` is only "Windows" with no `os_build` | `bare_windows` |
| `os_build` not digits and dots | `invalid_build` |
| `architecture` not `x64`/`x86`/`arm64` | `invalid_architecture` |
| `installation_type` not `Server`/`Server Core`/`Client` | `invalid_installation_type` |
| Server edition without `installation_type` | `missing_installation_type` |
| KB not "KB" + digits | `invalid_kb` |
| `installed_kbs` without `kb_source` | `missing_kb_source` |
| `esu_enrolled` not yes/no | `invalid_esu` |
| `collected_at` not ISO 8601 with a time zone | `invalid_collected_at` |

Warning (host accepted): `needs_revision` — `os_build` has three parts; the host stays product-level until the full
build is sent.

## 6. Results

Per accepted host (`data.assets[]`, SDK `WindowsHostResult`):

| Field | Meaning |
|---|---|
| `asset_id` | Your identifier |
| `microsoft_product` | e.g. `Windows Server 2019` |
| `candidate_products` | Only when the edition was not supplied and several products fit the build |
| `patch_resolved` | true when based on the build or KB list |
| `end_of_life` | past Microsoft's end of support (and ESU, if enrolled) |
| `labels` | `product-level (no build)`, `needs revision`, `product-level (not mapped)`, `resolved by build; edition not supplied`, `end of life` |
| `map_note` | Why a host could not be matched, or which products fit a build-only host |
| `counts` | `confirmed_open`, `cleared`, `needs_review` (always every CVE) |
| `cves[]` | `cve_id`, `status` (`confirmed open`, `cleared (patched)`, `needs review`), `fixed_build`, `kb`, `source` (Microsoft document), `severity`, `known_exploited` (confirmed open only), `note`, `priority_rank`, `priority_reason`, `fix` |
| `fix_groups[]` | Ranked fix actions (below) |
| `cves_page` | Only when paging is requested |
| `warnings` | e.g. `needs_revision` |

Refused hosts: `data.rejected[]` (`asset_id` — null when its value was refused — and `errors[]` with `code`, `field`,
`message`). `data.fix_summary[]`: top 10 fix actions across the call. `meta.microsoft_data_as_of`: newest Microsoft
document behind the results (refreshed daily). `options.include_cleared: false` leaves cleared CVEs out of `cves[]`
(they stay in `counts`).

## 7. Priority, fix groups, paging

Options (JSON `options`, CSV form fields, `/results` query parameters; all optional):

| Option | Meaning |
|---|---|
| `sort` | `priority` (default): confirmed open → needs review → cleared; known-exploited; exploit/PoC; installable fix, then ESU-required, then none; BCS, CVSS, EPSS. `score`: previous order (confirmed open first, then CVE id). `exploit`, `newest`. Anything else → `422`. |
| `confirmed_only`, `known_exploited_only`, `fix_available_only` | Filters, off by default. ESU-required fixes count as available. |
| `cve_page`, `cve_page_size` | **Optional paging, off by default** (every CVE returned). Page size 1–1,000. |

Fix actions:
- **Cumulative-servicing Windows**: every open CVE with a fixed build is grouped under the product's **latest
  cumulative update** — one install clears them all; the superseded per-CVE KBs are in `kbs_covered`.
- **Legacy servicing**: Monthly Rollup and Security Only fixes are grouped under the newest monthly rollup the host can
  install; servicing-stack and standalone updates keep their own KB; a KB already installed is never recommended.
- **End-of-life hosts not enrolled in ESU**: fixes released after end of support are grouped as
  **`ESU required (or upgrade the OS)`** (the KB is named in each CVE's `priority_reason`); they rank below directly
  installable fixes in the same exploit tier.

## 8. Errors

Standard envelope: `error.code` is general (`RATE_LIMITED`, `VALIDATION_ERROR`, ...); for v2 errors `error.detail`
holds the specific `error`, a `message` and extras such as `retry_after`.

| HTTP | `error` | When |
|---|---|---|
| 401 | | Key missing, invalid, expired or revoked |
| 403 | `insufficient_scope` | Submitting without the `write` scope |
| 404 | `environment_not_found` | `environment_id` is not in your organization |
| 413 | `batch_too_large` | More than 200 hosts |
| 422 | | Malformed body, unknown top-level field, or invalid option (e.g. `sort`) |
| 422 | (per host) | **Every** host was refused: the body is a normal result with `data.rejected` (the SDK returns it with `all_refused = True`) |
| 429 | `rate_limited` | Per-key limit; `retry_after` seconds |
| 400 | `unknown_form_field`, `missing_field` | CSV upload: unexpected form part, or no `environment_id` |

If some hosts are accepted and others refused, the call returns `200` with the refused hosts in `data.rejected`.

## 9. CSV

`POST /api/v2/assets/correlate-csv`, multipart form: `environment_id`, `hosts` (UTF-8 CSV, header row = field names
above), optional `software` (CSV `asset_id,name,publisher,version`), optional `include_cleared` and the options of
section 7. Same validation, processing and response as the JSON call. See [`examples/hosts.csv`](../examples/hosts.csv).
