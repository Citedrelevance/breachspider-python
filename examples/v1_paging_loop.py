"""Fetch every CVE for one asset across pages (cve_page / cve_page_size, up to 1,000 per page)."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
device = {"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}

# 1. A manual loop: ask for the next page while cves_page.has_more is true.
page, cves = 1, []
while True:
    result = bs.correlate.correlate([device], cve_page=page, cve_page_size=2).results[0]
    cves.extend(result.cves)
    if not (result.cves_page and result.cves_page.has_more):
        break
    page += 1
print(f"{len(cves)} CVEs over {page} page(s); total reported: {result.cves_page.total}")

# 2. The helper does the same, pausing between pages.
for cve in bs.correlate.iter_asset_cves(device, cve_page_size=1000):
    print(cve.priority_rank, cve.cve_id, cve.priority_reason)
