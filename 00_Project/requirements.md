# Engagement Requirements

## Detection Coverage Requirements

The following 10 detection categories were identified as priority coverage areas based on the simulated client's risk profile:

| # | Category | Delivered Detection |
|---|---|---|
| 1 | Authentication abuse / brute-force behavior | AUTH-001 |
| 2 | PowerShell execution and suspicious command patterns | PS-001 |
| 3 | LOLBIN / process-abuse behaviors | LOL-001 |
| 4 | Suspicious parent-child process relationships | PPID-001 |
| 5 | Credential-access indicators | CRED-001 |
| 6 | Scheduled task / service / persistence | PERSIST-001 |
| 7 | Lateral-movement indicators | LAT-001 |
| 8 | Suspicious outbound connections | NET-001 |
| 9 | Data staging behavior | STAGE-001 |
| 10 | Defense-evasion indicators | EVASION-001 |

## Required Data Sources

| Data Source | Purpose | Status |
|---|---|---|
| Sysmon (Process Create, Network Connect, FileCreate) | Process-level and network-level visibility on the Windows endpoint | ✅ Validated |
| Windows Security Event Log | Authentication and logon activity | ✅ Validated |
| Windows PowerShell Operational Log (Script Block Logging) | Full-fidelity visibility into PowerShell execution, including decoded obfuscated commands | ✅ Validated (required manual Group Policy configuration; not enabled by default) |
| Windows System Event Log | Log-clearing / defense-evasion evidence | ✅ Validated (required manual addition to Splunk forwarder configuration after an initial coverage gap was identified) |
| Splunk (indexing, search, dashboards) | Central detection and analysis platform | ✅ Operational |

## Quality Requirements

- No detection is considered production-ready without a live attack simulation and validation against real generated telemetry.
- Every detection includes a documented data source dependency and known limitations.
- Every detection was tested against at least one benign/normal activity scenario before being marked validated.
- Any false positive identified during testing was documented along with the tuning decision and trade-off made.
- All MITRE ATT&CK mappings are evidence-based, derived from actual validated detection behavior rather than assumed coverage.
- Identified visibility gaps (e.g., LSASS access monitoring, System log forwarding) are documented transparently rather than omitted.

## Success Criteria

- 10 of 10 planned detections built, tested, and validated. ✅
- At least one false-positive scenario identified and successfully tuned. ✅ (PPID-001, STAGE-001)
- MITRE ATT&CK coverage matrix produced covering all validated detections. ✅
- Consolidated Splunk dashboard delivered. ✅
- Final report summarizing methodology, results, and recommendations. (In progress)

