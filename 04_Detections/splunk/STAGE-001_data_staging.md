# Detection ID: STAGE-001

## Detection Name
Data Staging — Archiving of Sensitive User Directories

## Business/Security Risk
Before exfiltrating stolen data, attackers typically "stage" it by compressing target directories (Desktop, Documents, Downloads) into a single archive file to simplify and speed up transfer. Detecting this staging behavior provides an opportunity to intervene before data actually leaves the network.

## Required Data Sources / Fields
- **Log Source:** Microsoft-Windows-PowerShell/Operational
- **Sourcetype:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`
- **Event Code:** 4104 (Script Block Logging)
- **Required Fields:** `Message`

## SPL Query (Tuned)

```spl
index=* host=DESKTOP-DI2GMCC EventCode=4104 Message="*Compress-Archive*"
| where match(Message, "(?i)(Desktop|Documents|Downloads|AppData)")
```

## MITRE ATT&CK Mapping
- **Tactic:** Collection
- **Technique:** T1560.001 — Archive Collected Data: Archive via Utility

## Severity
**Medium** — indicates preparation for potential data exfiltration; not evidence of exfiltration itself but a strong precursor signal.

## Expected Alert Evidence
- `Compress-Archive` PowerShell cmdlet invocation targeting a well-known sensitive user directory (Desktop, Documents, Downloads, AppData).

## Known False Positives
- **Identified during testing:** the initial (untuned) query flagged any use of `Compress-Archive`, including a completely benign compression of a single small test file — a common, legitimate everyday operation.

## Tuning Logic and Exclusions
- **Trade-off:** Added a requirement that the compressed path reference a known sensitive directory name, rather than matching any Compress-Archive usage.
- **Owner/Date:** Tuned September 9, 2026.
- **Result:** False positive (single-file compression) eliminated while the malicious test case (full Desktop folder compression) remained detected.

## Validation Procedure and Result
1. Simulated attack: `Compress-Archive -Path C:\Users\SOC\Desktop -DestinationPath C:\Users\SOC\staged_data.zip -Force`.
2. Note: Sysmon's default FileCreate rule does not monitor `.zip` file extensions, and `Compress-Archive` (a PowerShell cmdlet, not an external process) does not generate a Process Creation event — PowerShell Script Block Logging (Event 4104) was required to detect this activity, as it captures cmdlet invocations directly.
3. Initial query flagged both the attack AND a benign single-file compression test — false positive identified.
4. Tuned query re-tested — attack still detected, benign case correctly excluded.
5. **Result:** Detection validated ✅ post-tuning.

## Limitations and Telemetry Dependencies
- Fully dependent on PowerShell Script Block Logging; would not detect staging performed via external tools (WinRAR, 7-Zip GUI, or command-line 7z.exe), which would require separate process-based detections.
- Directory keyword list is not exhaustive and should be expanded based on organizational data classification (e.g., shared drives, specific project folders).

---
**Created:** September 9, 2026
**Status:** Validated — production-ready (post-tuning).
