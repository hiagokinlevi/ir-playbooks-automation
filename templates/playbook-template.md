# Incident Response Playbook Template

## Summary
Brief description of the incident type this playbook addresses, including typical impact and affected systems.

Example:
- What the threat/incident is
- Typical attacker objective
- Environments commonly affected

---

## Triggers
Conditions that should initiate this playbook.

Examples:
- Specific alert types
- Confirmed malicious indicators
- Analyst escalation

---

## Detection Sources
List the tools, telemetry, and logs that may indicate this incident.

Examples:
- EDR alerts
- SIEM detections
- Cloud audit logs
- IDS/IPS alerts
- Email security gateway alerts

---

## Triage Steps
Initial investigation procedures to validate the alert and determine scope.

Typical actions:
- Confirm alert legitimacy
- Identify affected users, hosts, or services
- Review related logs and telemetry
- Determine severity and potential impact

Document:
- Key artifacts
- Indicators of compromise
- Initial timeline

---

## Containment Steps
Actions to stop the attack from spreading or causing further damage.

Examples:
- Isolate affected hosts
- Disable compromised accounts
- Block malicious IPs or domains
- Revoke active sessions
- Apply temporary firewall or network controls

All containment actions should be logged and auditable.

---

## Eradication
Steps required to remove the attacker’s presence and persistence mechanisms.

Examples:
- Remove malware or malicious files
- Delete persistence mechanisms
- Rotate credentials or keys
- Patch exploited vulnerabilities

Ensure no backdoors remain.

---

## Recovery
Procedures to safely restore normal operations.

Examples:
- Restore systems from clean backups
- Re-enable services
- Gradually reconnect isolated systems
- Monitor for reinfection

Recovery should occur only after eradication is verified.

---

## Verification
Steps to confirm the incident has been fully resolved.

Examples:
- Validate systems are clean
- Confirm no malicious traffic remains
- Review monitoring alerts for recurrence
- Conduct post-incident checks

Document final validation evidence.

---

## References
Relevant documentation and supporting resources.

Examples:
- MITRE ATT&CK techniques
- Internal runbooks
- Vendor security advisories
- Detection rule references
- Related incident reports
