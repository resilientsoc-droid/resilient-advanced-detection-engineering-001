# Detection ID: PPID-001

## Detection Name
Suspicious Parent-Child Process Relationship (cmd.exe spawning hidden PowerShell)

## Business/Security Risk
Legitimate applications rarely spawn command interpreters in a hidden or obfuscated manner. This pattern is commonly seen in phishing attacks where a macro-enabled document or script spawns cmd.exe/PowerShell to execute a payload while attempting to hide the window from the user.

## Required Data Sources / Fields
- **Log Source:** Sysmon
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event Code:** 1 (Process Create)
- **Required Fields:** `Image`, `ParentImage`, `CommandLine`, `ParentCommandLine`

## SPL Query (Tuned)

```spl
index=* host=DESKTOP-DI2GMCC EventCode=1 ParentImage="*cmd.exe" Image="*powershell.exe"
| where match(ParentCommandLine, "(?i)(hidden|bypass|noprofile|/min|windowstyle)") OR match(CommandLine, "(?i)(hidden|bypass|noprofile|encodedcommand)")
```

## MITRE ATT&CK Mapping
- **Tactic:** Execution / Defense Evasion
- **Technique:** T1059 — Command and Scripting Interpreter
- **Technique:** T1036 — Masquerading

## Severity
**Medium-High** — depends heavily on the presence of obfuscation indicators; without tuning this would be a low-fidelity, high-noise detection.

## Expected Alert Evidence
- `powershell.exe` spawned by `cmd.exe` with the parent or child command line containing hiding/bypass flags (`/min`, `-WindowStyle Hidden`, `-Bypass`, `-NoProfile`, `-EncodedCommand`).

## Known False Positives
- **Identified during testing:** the initial (untuned) query flagged ANY cmd.exe → powershell.exe relationship, including a completely benign `cmd.exe /c "powershell.exe -Command Get-Date"` — a pattern common in legitimate batch scripts.

## Tuning Logic and Exclusions
- **Trade-off:** Added a requirement for at least one obfuscation/hiding indicator in either the parent or child command line.
- **Owner/Date:** Tuned September 9, 2026.
- **Result:** False positive eliminated while the malicious test case (using `/min`) remained detected.

## Validation Procedure and Result
1. Simulated attack: `cmd.exe /c "start /min powershell.exe -Command Start-Sleep -Seconds 2"`.
2. Initial query flagged both the attack AND a benign test (`Get-Date` via cmd/powershell) — false positive identified.
3. Tuned query re-tested — attack still detected, benign case correctly excluded.
4. **Result:** Detection validated ✅ post-tuning.

## Limitations and Telemetry Dependencies
- Keyword-based tuning can be evaded by attackers who avoid the specific flagged terms; a more robust approach for production would combine this with behavioral baselining.
- Only covers cmd.exe → powershell.exe; does not cover Office applications (Word/Excel) spawning shells, which is the classic phishing vector — recommended as a follow-up detection.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready (post-tuning).
