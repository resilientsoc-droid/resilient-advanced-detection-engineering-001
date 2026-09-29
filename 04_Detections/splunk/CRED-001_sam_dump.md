# Detection ID: CRED-001

## Detection Name
Credential Access — SAM Registry Hive Dump

## Business/Security Risk
Attackers with local administrative access commonly dump the SAM (Security Account Manager) registry hive to obtain encrypted local password hashes, which can then be exfiltrated and cracked offline using tools like hashcat or John the Ripper.

## Required Data Sources / Fields
- **Log Source:** Sysmon
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event Code:** 1 (Process Create)
- **Required Fields:** `Image`, `CommandLine`, `IntegrityLevel`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=1 Image="*reg.exe" CommandLine="*save*SAM*"
```

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1003.002 — OS Credential Dumping: Security Account Manager

## Severity
**Critical** — successful exploitation directly exposes all local account password hashes.

## Expected Alert Evidence
- `reg.exe save HKLM\SAM <path>` execution, typically with `IntegrityLevel: High` (requires elevated/administrator privileges).

## Known False Positives
- None observed. `reg.exe save` targeting the SAM hive specifically has essentially no legitimate day-to-day business use case outside of authorized backup/forensic procedures.

## Tuning Logic and Exclusions
No tuning required — the query is narrowly scoped to the SAM hive specifically, which naturally excludes routine registry backup operations on other keys.

## Validation Procedure and Result
1. Simulated attack: `reg.exe save HKLM\SAM C:\Users\SOC\sam_dump.hiv` (executed with elevated/admin privileges).
2. SPL query successfully identified the event.
3. Tested benign registry save on an unrelated key (`HKCU\Software\Microsoft\Windows\CurrentVersion`) — query correctly returned no matches.
4. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- An initial attempt to detect direct LSASS memory access (Sysmon Event ID 10 - ProcessAccess) was unsuccessful: Sysmon applies internal filtering to low-privilege LSASS access attempts even with an inclusive ProcessAccess rule configured, meaning lightweight access attempts are not logged. This is a documented Sysmon behavior and represents a coverage gap for LSASS-targeted credential dumping (e.g., via Mimikatz) that would require a dedicated Sysmon configuration tuned specifically for LSASS access monitoring.
- This detection covers SAM-based credential dumping only; does not cover LSASS memory dumping, NTDS.dit extraction, or DPAPI credential theft.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready. LSASS-based credential access remains an identified coverage gap (see Limitations).
