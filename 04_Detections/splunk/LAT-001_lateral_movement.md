# Detection ID: LAT-001

## Detection Name
Lateral Movement via Multiple Network Logons (WMI/Impacket-style)

## Business/Security Risk
After obtaining valid credentials (e.g., via brute-force, as demonstrated in AUTH-001), attackers commonly use tools such as Impacket's `wmiexec` to establish a remote command shell on other hosts in the network without triggering a full interactive RDP session. Each command executed through such tools typically generates a new authenticated network session.

## Required Data Sources / Fields
- **Log Source:** Windows Security Event Log
- **Sourcetype:** `WinEventLog:Security`
- **Event Code:** 4624 (Successful Logon), filtered to Logon Type 3 (Network)
- **Required Fields:** `Account_Name`, `Source_Network_Address`, `Source_Port`, `Logon_Type`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=4624 Logon_Type=3
| stats count as network_logons, values(Source_Port) as ports by Account_Name, Source_Network_Address
| where network_logons >= 3
```

## MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement
- **Technique:** T1021.006 — Remote Services: Windows Remote Management
- **Technique:** T1047 — Windows Management Instrumentation

## Severity
**Critical** — indicates active exploitation of a compromised account across the network with interactive remote code execution capability.

## Expected Alert Evidence
- 3 or more distinct network logons (Logon Type 3) from the same source IP/account within a short window, each typically using a different ephemeral source port — a signature pattern of automated remote execution tooling rather than a single human interactive session.

## Known False Positives
- Legitimate remote administration tools (e.g., PsExec used by IT staff for routine management) would exhibit a similar pattern and require contextual whitelisting of known-good administrative source hosts in a production environment.

## Tuning Logic and Exclusions
Threshold of 3+ logons within the search window distinguishes automated/scripted remote execution from a single legitimate network share access, which was validated to generate only 1 logon event and correctly fall below threshold.

## Validation Procedure and Result
1. Simulated attack: used `impacket-wmiexec` from Kali to establish a remote shell on the Windows host using the compromised `SOC` account, then executed a command (`whoami`) inside the shell.
2. SPL query identified 7 network logon events from the attacker's IP within minutes, across 5 distinct source ports.
3. Tested a single benign local network logon (`net use \\localhost\C$`) — generated only 1 logon event, correctly falling below the threshold and not triggering the query.
4. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- WinRM/WMI remote management had to be manually enabled on the target host (network profile changed from Public to Private, LocalAccountTokenFilterPolicy configured) to complete this simulation — in a real attack, the attacker would typically rely on services already enabled rather than enabling them itself.
- Threshold-based detection may miss slow, low-and-slow lateral movement conducted over a longer time window than the search interval.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready.
