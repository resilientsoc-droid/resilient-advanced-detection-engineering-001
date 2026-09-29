# MITRE ATT&CK Coverage Matrix
## Resilient — Advanced Detection Engineering 001

This matrix maps each validated detection in this engagement to its corresponding MITRE ATT&CK tactic(s) and technique(s), along with validation status and data source dependency.

| Detection ID | Detection Name | ATT&CK Tactic | ATT&CK Technique | Technique ID | Data Source | Status |
|---|---|---|---|---|---|---|
| AUTH-001 | RDP Brute-Force | Credential Access | Brute Force: Password Guessing | T1110.001 | Windows Security Log (4625) | ✅ Validated |
| PS-001 | PowerShell Encoded Command | Execution / Defense Evasion | Command and Scripting Interpreter: PowerShell / Obfuscated Files or Information | T1059.001 / T1027 | PowerShell Operational Log (4104) | ✅ Validated |
| LOL-001 | certutil LOLBIN Abuse | Command and Control / Defense Evasion | Ingress Tool Transfer / System Binary Proxy Execution | T1105 / T1218.001 | Sysmon (Event 1) | ✅ Validated |
| PPID-001 | Suspicious Parent-Child Process | Execution / Defense Evasion | Command and Scripting Interpreter / Masquerading | T1059 / T1036 | Sysmon (Event 1) | ✅ Validated (post-tuning) |
| CRED-001 | SAM Registry Hive Dump | Credential Access | OS Credential Dumping: SAM | T1003.002 | Sysmon (Event 1) | ✅ Validated |
| PERSIST-001 | Scheduled Task (SYSTEM) | Persistence / Privilege Escalation | Scheduled Task/Job: Scheduled Task | T1053.005 | Sysmon (Event 1) | ✅ Validated |
| LAT-001 | Lateral Movement (WMI/Impacket) | Lateral Movement | Remote Services: WinRM / Windows Management Instrumentation | T1021.006 / T1047 | Windows Security Log (4624) | ✅ Validated |
| NET-001 | Suspicious Outbound Connection | Command and Control | Application Layer Protocol / Non-Standard Port | T1071 / T1571 | Sysmon (Event 3) | ✅ Validated |
| STAGE-001 | Data Staging (Archive) | Collection | Archive Collected Data: Archive via Utility | T1560.001 | PowerShell Operational Log (4104) | ✅ Validated (post-tuning) |
| EVASION-001 | Event Log Clearing | Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Windows System Log (104) | ✅ Validated |

---

## Coverage Summary by Tactic

| Tactic | Detections Covering It |
|---|---|
| Credential Access | AUTH-001, CRED-001 |
| Execution | PS-001, PPID-001 |
| Persistence | PERSIST-001 |
| Privilege Escalation | PERSIST-001 |
| Defense Evasion | PS-001, LOL-001, PPID-001, EVASION-001 |
| Lateral Movement | LAT-001 |
| Collection | STAGE-001 |
| Command and Control | LOL-001, NET-001 |
| Exfiltration | *(Not covered — see gap below)* |
| Impact | *(Not covered — see gap below)* |

---

## Identified Visibility / Coverage Gaps

1. **LSASS Memory Access (T1003.001):** Attempted detection of direct LSASS process memory access was unsuccessful during this engagement. Sysmon applies internal filtering to low-privilege access attempts against lsass.exe even with an inclusive ProcessAccess rule configured, meaning tools like Mimikatz performing full memory reads would need a dedicated, more permissive Sysmon ProcessAccess configuration to be reliably detected. **This is a known gap, not a false negative** — it reflects a telemetry limitation rather than a detection logic failure.

2. **Exfiltration (TA0010):** No detection currently covers actual data exfiltration (e.g., large outbound file transfers, DNS tunneling, cloud storage uploads). STAGE-001 detects the staging/preparation step but not the transfer itself.

3. **Impact (TA0040):** No detection covers destructive techniques such as data encryption (ransomware behavior) or data destruction.

4. **Distributed/Multi-Source Attacks:** AUTH-001 and LAT-001 both rely on identifying repeated activity from a *single* source IP. A distributed attack using multiple source IPs (e.g., a botnet-style brute-force or lateral movement staged from multiple compromised hosts) would evade both detections in their current form.

5. **Non-Standard-Port C2:** NET-001 only covers connections to a single hardcoded port (4444). Attackers using standard ports (80/443) for C2 communication, or other well-known offensive tooling ports, would not be caught by this rule as currently scoped.

## Recommendations for Additional Telemetry / Rules

- Add a dedicated Sysmon configuration profile with unrestricted ProcessAccess logging for lsass.exe specifically to close the LSASS visibility gap.
- Add DNS query logging (Sysmon Event 22, already technically enabled per the Sysmon config reviewed during this engagement) as a data source for a future DNS-tunneling / C2-over-DNS detection.
- Expand NET-001 to use a maintained threat-intelligence-informed port/IP list rather than a single hardcoded port.
- Add a detection for large or bulk outbound file transfer volume (Exfiltration, TA0010) using Sysmon network connection byte-count fields if available, or proxy/firewall logs if the organization has them.
- Consider adding a "same technique, multiple source IPs" correlation rule as a follow-up to AUTH-001 and LAT-001 to cover distributed attack patterns.

---
**Prepared:** September 9, 2026
**Coverage basis:** 10 of 10 planned detections validated through live attack simulation and false-positive testing against this lab environment.
