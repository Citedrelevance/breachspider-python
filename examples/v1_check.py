"""POST /api/v1/assets/correlate-cves/check: re-correlate only assets whose result changed."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
device = {"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}

stored_hash = bs.correlate.correlate([device]).results[0].result_hash    # keep this with your asset record

for item in bs.correlate.check([{**device, "result_hash": stored_hash}]):
    print(item.asset_id, "changed" if item.changed else "unchanged", item.reason)
