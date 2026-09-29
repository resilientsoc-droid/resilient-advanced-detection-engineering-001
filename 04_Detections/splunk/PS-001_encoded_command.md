# Detection ID: PS-001

## Detection Name
PowerShell Suspicious Execution (Encoded/Obfuscated Command)

## Business/Security Risk
Attackers commonly use PowerShell's `-EncodedCommand` (Base64) option, along with flags like `-NoProfile`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass`, to obfuscate malicious commands and evade signature-based security tools that scan for plaintext suspicious keywords.

## Required Data Sources / Fields
- **Log Source:** Microsoft-Windows-PowerShell/Operational
- **Sourcetype:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`
- **Event Code:** 4104 (Script Block Logging)
- **Required Fields:** `Message` (contains the full script block text, including decoded content)

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=4104
| search Message="*EncodedCommand*" OR Message="*Invoke-Expression*" OR Message="*DownloadString*" OR Message="*-enc*" OR Message="*Bypass*"
```

## MITRE ATT&CK Mapping
- **Tactic:** Execution / Defense Evasion
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Technique:** T1027 — Obfuscated Files or Information

## Severity
**High** — obfuscated execution is a strong indicator of malicious intent and commonly precedes further compromise.

## Expected Alert Evidence
- Event 4104 containing keywords associated with obfuscation or download-execute patterns.
- Script Block Logging captures the decoded plaintext, defeating the Base64 obfuscation.

## Known False Positives
- Legitimate administrative scripts or automation tools that use `Invoke-Expression` for benign purposes.
- Security tools themselves that scan PowerShell activity may generate similar keyword matches.

## Tuning Logic and Exclusions
None required after testing — normal daily-use commands (`Get-Date`, `Get-ChildItem`) did not match the query.

## Validation Procedure and Result
1. Simulated an attacker encoding a command (`Write-Host 'This is a simulated malicious command'`) into Base64 and executing it via `powershell -EncodedCommand`.
2. Ran the SPL query — successfully identified the encoded command event.
3. Ran benign PowerShell commands (`Get-Date`, `Get-ChildItem`) — query correctly returned no matches.
4. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- Fully dependent on PowerShell Script Block Logging being enabled via Group Policy; this had to be manually configured during environment setup as it is not enabled by default.
- Keyword-based detection can be evaded by attackers who avoid the specific flagged terms.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready pending broader keyword list review.
