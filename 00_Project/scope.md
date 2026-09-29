# Engagement Scope

## Project Name
Resilient — Advanced Detection Engineering 001

## Client (Simulated)
A simulated mid-sized organization with inconsistent endpoint visibility and a history of noisy, low-fidelity security alerts.

## Objective
Design, build, test, tune, and document a prioritized detection pack covering identity, execution, persistence, credential-access, lateral-movement, and network-based attack behaviors — demonstrating the full detection engineering lifecycle from risk definition through validated, production-candidate detection rules.

## Scope of Work
- Stand up a controlled lab environment (Windows endpoint, Linux/attack host, Splunk) to simulate the client's telemetry environment.
- Validate telemetry visibility and field extraction before building any detection logic.
- Simulate 10 distinct, realistic attack techniques mapped to common real-world threats.
- Develop and validate SPL detection queries for each technique using live attack data.
- Perform false-positive testing against benign/normal activity for every detection.
- Tune detections where false positives were identified, documenting the trade-offs involved.
- Map all validated detections to the MITRE ATT&CK framework.
- Deliver a consolidated Splunk dashboard, MITRE coverage matrix, and final written report.

## Out of Scope
- Production deployment of any detection rule.
- Integration with a live SIEM/SOAR pipeline or ticketing system.
- Coverage of Exfiltration (TA0010) and Impact (TA0040) tactics (documented as identified gaps for future work).
- Any activity against systems outside the isolated lab environment described in this repository.

## Environment
All testing was conducted exclusively within an isolated virtual lab (VMware Workstation) consisting of:
- One Windows 10 endpoint (Sysmon + Windows Security auditing + PowerShell Script Block Logging + Splunk Universal Forwarder)
- One Kali Linux attack host
- One Splunk instance (indexing, search, dashboarding)

No production systems, external networks, or third-party infrastructure were involved at any point in this engagement.

## Authorization
All attack simulations, exploitation techniques, and testing activities described in this repository were conducted solely against self-owned, isolated lab infrastructure for educational and portfolio purposes. No unauthorized system was accessed at any point.

