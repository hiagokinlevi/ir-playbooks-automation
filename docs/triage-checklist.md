# Incident Triage Checklist (First 15 Minutes)

Use this checklist to quickly stabilize incident handling, preserve evidence, and form an initial scope estimate.

> Goal: make a **defensible first assessment** within 15 minutes, not complete the investigation.

---

## 0–3 Minutes: Validate and Start Record

- [ ] Confirm alert is actionable (not duplicate/closed/known test activity).
- [ ] Open or update incident record with:
  - [ ] Detection source (SIEM/EDR/cloud alert/ticket)
  - [ ] Alert ID / case ID
  - [ ] Detection timestamp (UTC)
  - [ ] Analyst owner
- [ ] Capture the **initial hypothesis** (e.g., suspicious login, malware execution, data exposure).
- [ ] Assign provisional severity using current evidence.
- [ ] Start a timeline entry for all actions and findings.

## 3–8 Minutes: Rapid Log Review

Focus on high-signal logs around the alert window (typically ±30–60 minutes).

- [ ] Pull relevant logs by incident type:
  - [ ] Identity/authentication logs (IAM/SSO/IdP)
  - [ ] Endpoint telemetry (EDR process tree, parent-child execution)
  - [ ] Network/security logs (firewall, proxy, DNS, VPN)
  - [ ] Cloud audit logs (CloudTrail/Azure Activity/GCP Audit)
  - [ ] Email logs (if phishing/BEC suspected)
- [ ] Verify key indicators:
  - [ ] Source and destination IPs/domains/hosts
  - [ ] User/service account involved
  - [ ] Process names, hashes, command lines
  - [ ] Access attempts (success/fail anomalies)
- [ ] Identify immediate red flags:
  - [ ] Privilege escalation behavior
  - [ ] Lateral movement signals
  - [ ] Unusual geolocation/impossible travel
  - [ ] Bulk data access/exfiltration patterns
- [ ] Preserve volatile references (query links, event IDs, log export pointers).

## 8–12 Minutes: Asset & Identity Identification

Determine what is affected and who owns it.

- [ ] Identify primary impacted assets:
  - [ ] Hostname(s), IP(s), instance/resource IDs
  - [ ] Environment (prod/stage/dev)
  - [ ] Criticality/business function
- [ ] Identify impacted identities:
  - [ ] User accounts
  - [ ] Service principals/API keys/tokens
  - [ ] Privilege level (standard/admin/root-equivalent)
- [ ] Confirm ownership and contacts:
  - [ ] System owner/team
  - [ ] On-call contact
- [ ] Flag crown-jewel proximity (domain controllers, identity providers, payment/PII systems).

## 12–15 Minutes: Initial Scope Estimation

Produce a bounded “known vs unknown” view.

- [ ] Define **known affected scope**:
  - [ ] Number of confirmed users/assets/resources involved
  - [ ] Earliest known malicious/suspicious timestamp
  - [ ] Observable attacker actions so far
- [ ] Define **potential scope** (blast radius):
  - [ ] Connected systems and trust paths
  - [ ] Shared credentials/tokens/roles
  - [ ] Similar alerts in last 24 hours
- [ ] Classify confidence level:
  - [ ] High / Medium / Low confidence in current scope
- [ ] Decide immediate recommendation:
  - [ ] Continue triage (more data needed)
  - [ ] Escalate incident severity
  - [ ] Initiate containment playbook now

---

## Minimum Output Before Leaving First-15-Minute Triage

- [ ] One-sentence incident summary.
- [ ] List of impacted assets/identities (known).
- [ ] Initial scope statement (known + potential).
- [ ] Evidence references (log queries/event IDs/artifacts).
- [ ] Clear next action and owner (triage, escalate, contain).

### Example Summary Template

`At <time UTC>, alert <id> indicated <activity>. We confirmed involvement of <asset(s)> and <identity(s)>. Current scope is <known scope>; potential spread includes <potential scope>. Recommended next step: <action>.`

---

## Analyst Notes (Quick Guardrails)

- Prefer **evidence-backed statements**; label assumptions explicitly.
- Do not perform destructive actions during triage unless required by active threat policy.
- Keep timestamps in UTC and document every action for chain-of-custody.
- If in doubt on impact or privilege level, escalate early.
