"""POST /api/v1/assets/correlate-cves: what is exposed and what to fix first."""
import os

import breachspider

bs = breachspider.Client(os.environ["BREACHSPIDER_API_KEY"])

device = {"asset_id": "EXAMPLE-SWITCH-01", "vendor": "Moxa", "product": "EDS-518A", "version": "V3.5"}
# firmware may also be sent as "firmware_version": it is used for matching when "version" is empty.

resp = bs.correlate.correlate([device])            # default: sort="priority", 250 CVEs per page, no CAPEC
result = resp.results[0]
print(result.asset_id, result.status, result.product, result.confidence_band)

for cve in result.cves:                            # already in priority order
    print(f"#{cve.priority_rank} {cve.cve_id} {cve.match_tier}: {cve.priority_reason}")

for group in result.fix_groups:                    # one entry per fix action, ranked
    print(f"fix #{group.group_rank}: {group.fix} clears {group.counts['total']} CVEs"
          f" ({group.counts['known_exploited']} known-exploited){' [derived]' if group.derived else ''}")

if result.fix_plan and result.fix_plan.to_clear_all_fixable:
    step = result.fix_plan.to_clear_all_fixable
    print("plan:", step.fix, step.clears)
    if step.derived:
        print("note:", step.note)                  # confirm the target release in the vendor's advisory

for item in resp.fix_summary:                      # top fix actions across every asset in the call
    print(item.rank, item.product, item.fix, item.counts)

# Other orders and filters (applied before paging; result_hash never changes):
bs.correlate.correlate([device], sort="exploit", known_exploited_only=True)
