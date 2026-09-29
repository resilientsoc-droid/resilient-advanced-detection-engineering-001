# Detection ID: PERSIST-001

## Detection Name
Persistence via Scheduled Task with SYSTEM Privileges

## Business/Security Risk
Attackers commonly establish persistence by creating scheduled tasks that re-execute their payload on logon, boot, or a recurring interval — often disguised with legitimate-sounding names and configured to run with SYSTEM-level privileges for maximum impact and survivability.

## Required Data Sources / Fields
- **Log Source:** Sysmon
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event Code:** 1 (Process Create)
- **Required Fields:** `Image`, `CommandLine`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=1 Image="*schtasks.exe" CommandLine="*create*" CommandLine="*SYSTEM*"
```

## MITRE ATT&CK Mapping
- **Tactic:** Persistence / Privilege Escalation
- **Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task

## Severity
**High** — a SYSTEM-privileged scheduled task grants the attacker durable, highest-privilege access to the host.

## Expected Alert Evidence
- `schtasks /create` execution with `/ru SYSTEM` in the command line, often paired with a hidden or encoded payload in the `/tr` (task run) argument.

## Known False Positives
- Legitimate scheduled task creation is common in enterprise environments (backup jobs, software update checks), but these rarely run as SYSTEM under a standard user's interactive session — the `/ru SYSTEM` requirement significantly narrows false positive risk.

## Tuning Logic and Exclusions
Query requires both `/create` AND the literal string `SYSTEM` to appear in the command line, deliberately excluding standard user-level scheduled tasks (e.g., daily reminders, personal backup scripts) by design.

## Validation Procedure and Result
1. Simulated attack: `schtasks /create /tn "WindowsUpdateCheck" /tr "powershell.exe -WindowStyle Hidden -Command Write-Host Persistence" /sc onlogon /ru SYSTEM`.
2. SPL query successfully identified the event.
3. Tested benign scheduled task creation (`schtasks /create /tn "MyDailyBackup" /tr "notepad.exe" /sc daily /st 09:00`, no `/ru SYSTEM`) — query correctly returned no new matches.
4. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- Does not cover persistence via Registry Run keys, Startup folder, WMI event subscriptions, or Windows services — these represent separate persistence techniques requiring dedicated detections.
- An attacker could evade this specific rule by omitting `/ru SYSTEM` and instead running the task under the compromised user's own context, trading privilege level for stealth.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready.
