# Detection ID: NET-001

## Detection Name
Suspicious Outbound Connection (Known C2 Port)

## Business/Security Risk
After compromising a host, attackers commonly establish outbound "callback" connections to a Command & Control (C2) server to receive further instructions or exfiltrate data. Certain ports are strongly associated with common offensive tooling — port 4444 being the well-known default listener port for Metasploit.

## Required Data Sources / Fields
- **Log Source:** Sysmon
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Event Code:** 3 (Network Connection)
- **Required Fields:** `Image`, `DestinationIp`, `DestinationPort`, `Initiated`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=3 DestinationPort=4444
```

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control
- **Technique:** T1071 — Application Layer Protocol
- **Technique:** T1571 — Non-Standard Port

## Severity
**High** — an active outbound connection to a known-malicious port indicates likely successful C2 channel establishment.

## Expected Alert Evidence
- Outbound TCP connection with `DestinationPort=4444`, `Initiated=true`, typically originating from an unexpected process (e.g., powershell.exe rather than a browser or legitimate networking application).

## Known False Positives
- None observed — port 4444 has no common legitimate business use. General web browsing traffic (ports 80/443) does not match this port-specific rule.

## Tuning Logic and Exclusions
No tuning required for this simulation; however, documented as a limitation that a single hardcoded port has limited real-world coverage (see Limitations).

## Validation Procedure and Result
1. Set up a netcat listener on Kali (`nc -lvnp 4444`) to simulate an attacker C2 server.
2. From the Windows host, established an outbound TCP connection to the listener via PowerShell (`System.Net.Sockets.TCPClient`).
3. SPL query successfully identified the outbound connection event, confirming `Image: powershell.exe` as the initiating process.
4. Tested benign web browsing activity — query correctly returned no new matches (browser used ports 80/443, not 4444).
5. **Result:** Detection validated ✅, no false positives observed.

## Limitations and Telemetry Dependencies
- Single hardcoded port (4444) provides very limited real-world coverage. A production-ready version of this detection should be expanded to a maintained list of known malicious/C2 ports (e.g., 1337, 8080, 31337, 6666) and ideally supplemented with beaconing/interval-based behavioral detection rather than static port matching alone.
- Sophisticated attackers commonly use standard ports (443, 80) for C2 to blend in with normal traffic, which this detection would not catch.

---
**Created:** September 9, 2026
**Status:** Validated — production-ready for the specific port covered; recommend expansion before considering broader production deployment.
