# Slack Security Alerts Response Playbook

## Purpose

Provide a standardized response process for SOC analysts when security alerts are delivered through Slack channels, direct messages, or bot notifications.

## Scope

Use this playbook for:
- Alerts posted by approved security tooling integrations (SIEM, EDR, CSPM, IAM, DLP, etc.) into Slack
- Human-reported suspicious activity in designated security channels (for example: `#soc-alerts`, `#security-help`)
- Mentions of active incidents requiring analyst action

Do **not** use this playbook as the only source of truth for incident status; Slack is a notification layer. The incident/ticketing platform remains authoritative.

## Roles and Ownership

- **Primary Analyst (L1/L2):** Validates alert, performs initial triage, opens/updates ticket
- **Incident Commander / Senior Responder (L2/L3):** Leads high-severity incidents and coordinates response
- **Service Owner / On-call Engineer:** Provides system context and executes approved remediation as needed

## Preconditions

Before acting, confirm:
1. You are viewing messages in an approved security Slack workspace/channel.
2. The alert originates from a trusted integration/app or known internal reporter.
3. You have access to the SIEM/EDR/cloud console and ticketing platform.

---

## Step 1: Alert Intake and Acknowledgement

1. Acknowledge the Slack alert within **5 minutes** during staffed hours:
   - React with the team’s acknowledgement emoji (for example `:eyes:`), or
   - Reply: `Acknowledged — triage in progress.`
2. If alert volume is high, claim ownership in-thread:
   - `@analyst-name handling this alert.`
3. Capture basic metadata immediately:
   - Slack message link (permalink)
   - Channel name
   - Timestamp (UTC)
   - Reporter/integration identity
   - Raw alert text and any attached indicators (user, host, IP, hash, URL, cloud resource)

---

## Step 2: Validate Alert Authenticity

Validate before escalation or containment.

1. **Source validation**
   - Confirm the Slack app/integration is approved.
   - Confirm reporter identity if human-submitted.
   - Check for signs of spoofing/social engineering (new account, unusual urgency, unusual wording, external user flags).

2. **Technical validation**
   - Locate the same event in source system (SIEM/EDR/CSP logs/IAM logs).
   - Verify event timestamp, entity (host/user/workload), and detection rule ID match Slack content.
   - Check whether this is duplicate/noise from known maintenance/testing.

3. **Disposition**
   - **True Positive (TP):** Continue to Step 3.
   - **Benign/Expected Activity:** Create or update ticket as informational and close with rationale.
   - **False Positive (FP):** Document detection gap and tune rule through detection engineering process.
   - **Unverified:** Escalate for secondary review if source cannot be validated within SLA.

---

## Step 3: Initial Triage and Severity Assignment

Classify impact and urgency using existing severity policy.

Minimum triage checklist:
- Affected asset criticality (production, customer-facing, privileged system)
- Identity sensitivity (admin/service accounts, exec accounts)
- Evidence of active compromise (lateral movement, privilege escalation, exfiltration)
- Blast radius (single endpoint vs. multi-system/cloud account)
- Detection confidence and corroborating telemetry

Suggested severity guidance:
- **SEV-1 / Critical:** Active compromise, high-impact asset, confirmed malicious activity
- **SEV-2 / High:** Strong compromise indicators, limited containment window
- **SEV-3 / Medium:** Suspicious behavior requiring investigation, no confirmed impact yet
- **SEV-4 / Low:** Informational or low-risk anomaly

Post triage summary in-thread:
- `Triage update: <severity>, <entity>, <short assessment>, ticket <ID>.`

---

## Step 4: Escalation Procedure

Escalate based on severity and confidence.

1. **SEV-1 / SEV-2**
   - Page on-call incident responder/IC immediately (PagerDuty or defined paging tool).
   - Notify security leadership per communications policy.
   - Engage affected service owner.
   - Start incident bridge/channel if required by policy.

2. **SEV-3**
   - Assign to responder queue and continue investigation.
   - Escalate to senior analyst if no determination within SLA.

3. **SEV-4**
   - Track in backlog/ticket queue.
   - No emergency escalation unless new evidence appears.

Escalation SLA targets (unless stricter policy exists):
- SEV-1: immediate (<15 min)
- SEV-2: <30 min
- SEV-3: <4 hours
- SEV-4: next business day

---

## Step 5: Ticket Creation and Documentation

Create a ticket/case for **every validated alert** and any suspicious unvalidated alert requiring follow-up.

Required ticket fields:
- Title: `Slack Alert - <detection/use case> - <entity> - <UTC date>`
- Source: `Slack`
- Slack permalink and channel
- Alert source system and rule/detector ID
- Severity and current status
- Affected assets/users
- IOCs/IOAs
- Analyst owner
- Timeline entries (first seen, acknowledged, triaged, escalated)
- Immediate actions taken

If a ticket already exists:
- Link Slack alert to existing case.
- Add timeline update rather than creating duplicate incidents.

---

## Step 6: Containment and Response Handoff

If malicious activity is confirmed or highly likely:
1. Follow relevant containment playbook (endpoint isolation, credential revocation, cloud resource isolation, etc.).
2. Record all containment actions in ticket and incident timeline.
3. Keep Slack thread updated with non-sensitive status updates only.

Do not post sensitive evidence in open Slack channels:
- Avoid credentials, customer data, full forensic artifacts.
- Store evidence in approved case/evidence systems and reference by ID.

---

## Step 7: Closure and Post-Incident Notes

Before closure:
1. Ensure ticket includes final disposition (TP/FP/Benign), root cause summary (if known), and impact statement.
2. Confirm all escalations and stakeholder notifications are logged.
3. Add detection improvement tasks for false positives or missed telemetry.
4. Post closure note in Slack thread:
   - `Closed in ticket <ID> — final disposition: <result>.`

---

## Analyst Quick Template (Slack Thread Reply)

```text
Acknowledged. Triage in progress.

Summary:
- Alert: <name>
- Entity: <user/host/resource>
- Validation: <confirmed/unconfirmed>
- Severity: <SEV-X>
- Ticket: <ID>
- Next step: <investigate/escalate/contain>
```

## Quality Checks

- [ ] Alert source verified
- [ ] Event corroborated in source telemetry
- [ ] Severity assigned per policy
- [ ] Escalation completed within SLA
- [ ] Ticket created/updated with Slack permalink
- [ ] Evidence handled in approved systems
- [ ] Final disposition documented
