# Detection ID: AUTH-001

## Detection Name
RDP Authentication Brute-Force (Multiple Failed Logons from Single Source)

## Business/Security Risk
An attacker attempts to guess a valid user account password by rapidly trying a large number of password combinations (brute-force) against an exposed RDP service. If successful, this grants the attacker Initial Access to the host under the compromised account's privileges, which can serve as a foothold for further lateral movement or privilege escalation.

## Required Data Sources / Fields
- **Log Source:** Windows Security Event Log
- **Sourcetype:** `WinEventLog:Security`
- **Event Code:** 4625 (An account failed to log on)
- **Required Fields:**
  - `Account_Name` — targeted account
  - `Source_Network_Address` — source IP of the attack
  - `Logon_Type` — type of logon attempt (3 = Network)
  - `Failure_Reason`

## SPL Query

```spl
index=* host=DESKTOP-DI2GMCC EventCode=4625
| stats count as failed_attempts by Account_Name, Source_Network_Address
| where failed_attempts >= 4
```

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110 — Brute Force
- **Sub-technique:** T1110.001 — Password Guessing

## Severity
**High** — successful exploitation results in direct Initial Access to the host.

## Expected Alert Evidence
- 4 or more Event ID 4625 entries from the same `Source_Network_Address` targeting the same `Account_Name` within a short time window (minutes).
- Timestamps between events are extremely close together (sub-second to a few seconds apart), consistent with automated tooling (e.g., Hydra) rather than manual human entry.

## Known False Positives
- A legitimate user who forgot their password and re-enters it manually multiple times.
- A misconfigured application or service repeatedly attempting to authenticate with stale/incorrect credentials (common in real environments — e.g., scheduled tasks or backup jobs using outdated credentials).

## Tuning Logic and Exclusions
No tuning required. False-positive testing (see `06_Tuning/screenshots/FP_AUTH01_*`) showed that a benign test and a single failed logon attempt both returned no results, because they stay below the threshold of 4 failed attempts. The threshold should still be re-baselined against real production traffic.

## Validation Procedure and Result
1. Simulated a real brute-force attack from Kali Linux using Hydra against the `SOC` account over RDP (port 3389).
2. Executed 6 login attempts (5 failed + 1 successful) using a custom wordlist.
3. Ran the SPL query above over the time window of the attack.
4. **Result:** The query successfully identified 18 failed attempts from source IP `192.168.209.128` against account `SOC` — Detection validated ✅.

## Limitations and Telemetry Dependencies
- This detection fully depends on Windows Security Event Log data reaching Splunk via the Universal Forwarder. If the forwarder fails or `inputs.conf` is misconfigured, the detection will silently fail with no alert on the gap itself.
- The current threshold (4 failed attempts) was set manually and should be reviewed against a real production baseline once benign traffic data is available.
- A distributed brute-force attack (using multiple source IPs instead of one) would evade this detection in its current form and requires a follow-up rule.

---
**Created:** September 8, 2026
**Status:** Validated — false-positive tested; threshold to be re-baselined in production.
