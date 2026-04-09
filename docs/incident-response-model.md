# Incident Response Model

## Lifecycle Overview

This tool follows the NIST SP 800-61r2 incident response lifecycle with an additional
Post-Incident Review phase:

```
┌─────────────────────────────────────────────────────────────────────┐
│               NIST SP 800-61r2 Incident Response Lifecycle          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐    ┌──────────┐    ┌─────────────┐    ┌──────────┐   │
│  │  Detect │ ──► │  Triage  │ ──► │  Contain /  │ ──► │ Recover  │  │
│  │  &      │    │  &       │    │  Eradicate  │    │  &       │  │
│  │  Report │    │  Analyze │    │             │    │  Close   │  │
│  └─────────┘    └──────────┘    └─────────────┘    └──────────┘   │
│                                                            │        │
│                                              Post-Incident │        │
│                                              Review        ▼        │
│                                                     ┌──────────┐   │
│                                                     │ Lessons  │   │
│                                                     │ Learned  │   │
│                                                     └──────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Phase Descriptions

### Detection and Reporting

**Goal:** Identify that an incident has occurred and notify the response team.

**Inputs:**
- SIEM alerts
- EDR/XDR detections
- CSPM findings
- User reports
- Threat intelligence feeds
- Third-party notifications

**Outputs:**
- Initial alert data
- Potential incident notification to on-call analyst

**SLA target:** Response within 15 minutes for Critical/High alerts.

---

### Triage and Analysis

**Goal:** Validate the alert, classify the incident, assess scope, and assign severity.

**Playbook:** `playbooks/triage/initial_triage.md`

**Key decisions:**
- Is this a real incident or a false positive?
- What is the incident type?
- What is the severity?
- What is the scope (affected systems, users, data)?

**Outputs:**
- Formal incident record (INC-YYYYMMDD-NNN)
- Severity assignment with justification
- Initial scope assessment
- Response path determination

**SLA targets:**
- Critical: Triage complete within 30 minutes
- High: Triage complete within 2 hours
- Medium: Triage complete within 8 hours
- Low: Triage complete within 24 hours

---

### Containment

**Goal:** Stop the attacker from causing additional harm without destroying forensic evidence.

**Playbooks:**
- `playbooks/containment/compromised_credentials.md`
- `playbooks/containment/cloud_exposure.md`

**Containment strategies:**

| Strategy | When to Use |
|---|---|
| Short-term containment | Immediately limit spread while investigation continues |
| System isolation | Confirmed compromise of a specific system |
| Account lockout | Compromised identity |
| Network segmentation | Lateral movement or network-based threat |
| Long-term containment | Sustained containment while root cause is addressed |

**Key principle:** Prefer reversible containment actions. Document all actions with timestamps and justification.

---

### Eradication

**Goal:** Remove all attacker presence from the environment.

**Playbook:** `playbooks/eradication/remove_persistence.md`

**Activities:**
- Remove malicious files and persistence mechanisms
- Patch or remediate the initial access vulnerability
- Rotate compromised credentials
- Close unauthorized access paths

**Validation:** Eradication is not complete until a clean-state check confirms no residual presence.

---

### Recovery

**Goal:** Restore affected systems and services to normal operation safely.

**Playbook:** `playbooks/recovery/controlled_return.md`

**Activities:**
- Restore from known-good state (backup, IaC rebuild, or validated in-place)
- Validate security and functionality before restoring traffic
- Implement enhanced monitoring during the recovery window
- Communicate restoration status to stakeholders

---

### Post-Incident Review

**Goal:** Extract lessons learned to improve detection, response, and prevention.

**Timing:** Conduct within 5 business days of closure.

**Key outputs:**
- Root cause analysis
- Detection gap identification
- Remediation action items with owners and deadlines
- Playbook improvements
- Metrics update (MTTD, MTTR, dwell time)

---

## Severity Classification

| Severity | Criteria | Response SLA |
|---|---|---|
| **Critical** | Active compromise confirmed; production system; data exposure confirmed; customer impact | Immediate — 24/7 response |
| **High** | Likely compromise; privileged account involved; customer impact possible | Within 2 hours |
| **Medium** | Suspicious activity; limited scope; no confirmed impact | Within 8 hours |
| **Low** | Anomaly; informational; no evidence of harm | Within 24 hours |

## Escalation Matrix

| Severity | Escalation Targets |
|---|---|
| Critical | CISO, IR Lead, Legal, affected service owners |
| High | IR Lead, affected service owners |
| Medium | Assigned analyst, team lead notification |
| Low | Assigned analyst |
