# Examples

Every example reads the API key from the `BREACHSPIDER_API_KEY` environment variable. Devices use the public
example Moxa EDS-518A at firmware V3.5; Windows examples use illustrative test hosts (`WIN-EXAMPLE-01` ...), and the
environment id `12` is a placeholder: use one of yours (`client.environments.list()`).

| File | Endpoint |
|---|---|
| `v1_correlate.py` | `POST /api/v1/assets/correlate-cves`: ranked CVEs, fix groups, fix plan, batch fix summary |
| `v1_paging_loop.py` | the same endpoint, fetching every CVE page for an asset (manual loop and the helper) |
| `v1_check.py` | `POST /api/v1/assets/correlate-cves/check`: staleness check by `result_hash` |
| `v2_correlate_json.py` | `POST /api/v2/assets/correlate`: Windows hosts as JSON |
| `v2_correlate_csv.py` | `POST /api/v2/assets/correlate-csv`: the same as a CSV upload (`hosts.csv`) |
| `v2_results.py` | `GET /api/v2/assets/results`: read stored results, page by page |
| `v2_refused_host.py` | handling a refused host (identifying field) and an all-refused call |
| `v2_batching.py` | submitting a large host list in calls of 100 |
