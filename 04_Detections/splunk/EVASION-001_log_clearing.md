# Detection ID: EVASION-001

## Detection Name
Defense Evasion — Windows Event Log Cleared

## Business/Security Risk
After completing an attack, adversaries commonly attempt to erase evidence of their activity by clearing Windows Event Logs, hindering incident response and forensic investigation. Windows generates a dedicated, self-referential event specifically to flag when this occurs.

## Required Data Sources / Fields
- **Log Source:** Windows System Event Log
- **Sourcetype:** `WinEventLog:System`
- **Event Code:** 104 (Log Clear) — for non-Security logs; Event Code 1102 is the equivalent for the Security log specifically
- **Required Fields:** `Message`, `User`, `ComputerName`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=104
```

## MITRE ATT&CK Mapping
- **Tactic:** Defense Evasion
- **Technique:** T1070.001 — Indicator Removal: Clear Windows Event Logs

## Severity
**Critical** — successful log clearing directly undermines the organization's ability to detect and investigate the full scope of an intrusion, and typically indicates an attacker in a late stage of their operation.

## Expected Alert Evidence
- Event ID 104 in the System log, with a `Message` field identifying which specific log was cleared (e.g., "The Microsoft-Windows-PowerShell/Operational log file was cleared"), and the `User` field identifying the account responsible.

## Known False Positives
- Legitimate log maintenance by IT/SOC administrators occurs occasionally but is rare and should be a documented, change-controlled activity. In this test environment, no non-malicious business justification for this event was identified.

## Tuning Logic and Exclusions
No tuning applied — this event is rare enough by nature that a specific-account allowlist (e.g., only excluding logs cleared by an authorized log-rotation service account) would be the recommended tuning approach in a real production environment, rather than broad exclusions.

## Validation Procedure and Result
1. Simulated attack: cleared the PowerShell Operational log via `wevtutil cl "Microsoft-Windows-PowerShell/Operational"`.
2. Initial detection attempt using Event ID 1102 failed — 1102 is specific to Security log clears only, while this action cleared a different, non-Security log, which Windows logs separately as Event ID 104 in the System log.
3. Discovered during investigation that the System log was not yet included in the Splunk Universal Forwarder's `inputs.conf` — this represented a previously-undetected telemetry gap. Added `[WinEventLog://System]` to the forwarder configuration and restarted the service.
4. Re-ran the SPL query — successfully identified the log-clear event, including which log was cleared and by which user account.
5. **Result:** Detection validated ✅.

## Limitations and Telemetry Dependencies
- This detection critically depends on the System log itself not being cleared or tampered with; a sufficiently sophisticated attacker could attempt to clear the System log immediately after clearing their target log, though this would itself likely generate a detectable Event 104 entry for the System log clear.
- Highlights a broader lesson for this engagement: telemetry gaps are not always visible until a specific detection is actively being built and tested — this reinforces the value of the systematic per-detection Telemetry & Field Validation step in the engineering lifecycle.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready.
