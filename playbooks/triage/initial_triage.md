# Initial Triage Playbook
**Phase:** Triage | **Maturity:** Operational | **Version:** 1.0

## Objective
Rapidly validate an incoming alert, classify the incident, and determine the
appropriate response path within the first 15–30 minutes of notification.

## Prerequisites
- Access to the alerting platform (SIEM, EDR, CSPM)
- Authorization to read logs from affected systems
- Incident Management system access to open a formal ticket

## Step 1 — Validate the Alert (5 min)
1. Review the raw alert details: timestamp, source, detection rule, affected asset
2. Check if this is a known false positive for this rule/asset combination
3. Confirm the alert is reproducible (not a one-time noise event)
4. Look for corroborating signals in the last 24h (same IP, user, or asset)

**Decision gate:**
- If it appears to be a false positive → document findings and close with justification
- If corroborating signals exist → proceed to Step 2
- If uncertain → proceed to Step 2 and maintain an open finding

## Step 2 — Classify the Incident (5 min)
Classify by type:

| Type | Examples |
|------|---------|
| Credential Compromise | Login from unusual location, impossible travel, brute force |
| Malware Suspicion | Unusual process, outbound C2 connection, file hash hit |
| Data Exposure | Public storage, unauthorized export, API data dump |
| API Abuse | Rate anomaly, unusual payload, authentication anomaly |
| Phishing | User report, email gateway alert, clicked link |
| Cloud Exposure | Public resource, misconfigured policy, privilege anomaly |

## Step 3 — Assign Severity (2 min)
Use the severity matrix:

| Severity | Criteria |
|----------|---------|
| Critical | Active compromise, confirmed data exposure, production system |
| High | Likely compromise, privileged account involved, customer impact possible |
| Medium | Suspicious activity, limited scope, no confirmed impact |
| Low | Anomaly, informational, no current evidence of harm |

## Step 4 — Open Formal Incident Record (3 min)
Create the incident ticket with:
- Incident ID (format: INC-YYYYMMDD-NNN)
- Title (descriptive, no jargon)
- Type and severity
- Affected asset(s)
- Detection source
- Initial owner
- Timeline: detected_at, triaged_at

## Step 5 — Determine Response Path
- **Critical/High:** Activate IR team, begin containment playbook immediately
- **Medium:** Assign analyst, begin investigation, revisit in 2h
- **Low:** Assign analyst, investigate within 24h SLA

## Documentation Checkpoint
Before moving to containment, document:
- [ ] Incident ID created
- [ ] Severity assigned with justification
- [ ] Initial owner assigned
- [ ] Stakeholders notified per escalation matrix
