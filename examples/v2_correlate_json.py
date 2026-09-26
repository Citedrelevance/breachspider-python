"""POST /api/v2/assets/correlate: Windows patch-level results (needs a write-scoped key)."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
ENVIRONMENT_ID = 12   # placeholder: one of your environments

hosts = [
    {"asset_id": "WIN-EXAMPLE-01", "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard",
     "display_version": "1809", "os_build": "10.0.17763.7792", "architecture": "x64", "installation_type": "Server",
     "collected_at": "2026-09-25T14:02:00Z"},
    {"asset_id": "WIN-EXAMPLE-02", "os_product": "Windows Server 2012 R2 Standard", "edition_id": "ServerStandard",
     "os_build": "6.3.9600.21620", "architecture": "x64", "installation_type": "Server",
     "installed_kbs": ["KB5031419"], "kb_source": "WMI QuickFixEngineering", "esu_enrolled": "no",
     "collected_at": "2026-09-25T14:02:00Z"},
]

resp = bs.windows.correlate(ENVIRONMENT_ID, hosts, include_cleared=False, cve_page_size=25)
for host in resp.assets:
    print(host.asset_id, host.microsoft_product, host.counts, host.labels)
    for group in host.fix_groups[:3]:
        print("   ", group.fix, "clears", group.counts["total"], f"({group.counts['known_exploited']} known-exploited)")
    for cve in host.cves[:5]:
        print("   ", cve.priority_rank, cve.cve_id, cve.status, cve.kb, "-", cve.priority_reason)
for item in resp.fix_summary:
    print(item.rank, item.product, item.fix, item.counts)
