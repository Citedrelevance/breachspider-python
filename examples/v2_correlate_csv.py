"""POST /api/v2/assets/correlate-csv: the same as the JSON call, from a CSV file (see hosts.csv)."""
import os
from pathlib import Path

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
ENVIRONMENT_ID = 12   # placeholder

resp = bs.windows.correlate_csv(ENVIRONMENT_ID, Path(__file__).with_name("hosts.csv"), include_cleared=False)
for host in resp.assets:
    print(host.asset_id, host.counts, host.fix_groups[0].fix if host.fix_groups else "nothing to fix")
