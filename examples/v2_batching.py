"""Submit a large host list in calls of 100 (the API accepts up to 200, but responses through breachspider.com
must finish within 100 seconds and each host takes under a second)."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
ENVIRONMENT_ID = 12   # placeholder

hosts = [
    {"asset_id": f"WIN-EXAMPLE-{i:03d}", "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard",
     "os_build": "10.0.17763.7792", "architecture": "x64", "installation_type": "Server",
     "collected_at": "2026-09-25T14:02:00Z"}
    for i in range(1, 251)
]
accepted = refused = 0
for resp in bs.windows.correlate_batched(ENVIRONMENT_ID, hosts, batch_size=100, include_cleared=False, cve_page_size=10):
    accepted += len(resp.assets)
    refused += len(resp.rejected)
print(f"{accepted} accepted, {refused} refused")   # 429s are retried automatically after error.detail.retry_after
