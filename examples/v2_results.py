"""GET /api/v2/assets/results: read stored results (a read-only key is enough), page by page."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
ENVIRONMENT_ID = 12   # placeholder

overview = bs.windows.results(ENVIRONMENT_ID, include_cleared=False, cve_page_size=10)
for host in overview.assets:
    print(host.asset_id, host.counts, f"{host.cves_page.total} CVEs listed" if host.cves_page else "")

# Every open CVE for one host, highest priority first, fetched in pages of 250:
for cve in bs.windows.iter_host_cves(ENVIRONMENT_ID, "WIN-EXAMPLE-01", include_cleared=False, confirmed_only=True):
    print(cve.priority_rank, cve.cve_id, cve.fix.action)
