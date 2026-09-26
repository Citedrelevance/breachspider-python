"""Refused hosts: identifying fields are rejected per host; the rest of the call still runs."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])
ENVIRONMENT_ID = 12   # placeholder

good = {"asset_id": "WIN-EXAMPLE-01", "os_product": "Windows Server 2019 Standard", "edition_id": "ServerStandard",
        "os_build": "10.0.17763.7792", "architecture": "x64", "installation_type": "Server",
        "collected_at": "2026-09-25T14:02:00Z"}
bad = {"asset_id": "WIN-EXAMPLE-03", "hostname": "example-host",            # identifying field: refused, not stored
       "os_product": "Windows 10 Enterprise LTSC 2021", "edition_id": "EnterpriseS", "os_build": "10.0.19044.6332",
       "architecture": "x64", "installation_type": "Client", "collected_at": "2026-09-25T14:02:00Z"}

resp = bs.windows.correlate(ENVIRONMENT_ID, [good, bad])
print("accepted:", [h.asset_id for h in resp.assets])
for r in resp.rejected:
    print("refused:", r.asset_id, [(e["code"], e.get("field")) for e in r.errors])

# When every host is refused the API answers 422 with the same body; the SDK returns it instead of raising:
only_bad = bs.windows.correlate(ENVIRONMENT_ID, [bad])
print("all refused:", only_bad.all_refused, only_bad.status_code)

# A request-level error (for example an invalid option) raises:
try:
    bs.request("POST", "/api/v2/assets/correlate",
               json={"environment_id": ENVIRONMENT_ID, "windows_hosts": [good], "options": {"sort": "cvss"}})
except breachspider.ValidationError as e:
    print("invalid request:", e)
