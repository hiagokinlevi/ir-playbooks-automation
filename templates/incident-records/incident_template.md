# Incident Record Template
<!--
  Instructions:
  - Replace all <PLACEHOLDER> values with actual incident data
  - Keep this document in the incident management system
  - Update timestamps in UTC (ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ)
  - Do not include raw credentials, keys, or PII in this document
-->

---

## Identification

| Field | Value |
|---|---|
| **Incident ID** | `INC-<YYYYMMDD>-<NNN>` |
| **Title** | `<Concise, jargon-free title>` |
| **Status** | `DETECTED / TRIAGING / CONFIRMED / CONTAINING / ERADICATING / RECOVERING / CLOSED` |
| **Severity** | `CRITICAL / HIGH / MEDIUM / LOW` |
| **Incident Type** | `credential_compromise / malware / data_exposure / api_abuse / phishing / cloud_exposure / secret_leakage / other` |
| **Created At** | `<UTC timestamp>` |
| **Last Updated** | `<UTC timestamp>` |

---

## Ownership

| Role | Name | Contact |
|---|---|---|
| **Incident Owner** | `<name>` | `<handle or email>` |
| **Assigned Analyst** | `<name>` | `<handle or email>` |
| **Escalation Contact** | `<name>` | `<handle or email>` |
| **Executive Sponsor** | `<name>` | `<handle or email>` |

---

## Affected Assets

| Asset | Type | Environment | Owner |
|---|---|---|---|
| `<hostname or service>` | `EC2 / RDS / S3 / App / Identity / other` | `prod / staging / dev` | `<team>` |

---

## Executive Summary

> _2–4 sentences. What happened, what was the impact, what is the current status. Written for a non-technical audience._

---

## Incident Timeline

| Timestamp (UTC) | Event | Source | Analyst |
|---|---|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | Alert triggered by `<detection rule>` | `<SIEM/EDR/User>` | `<analyst>` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | Incident opened and assigned | Manual | `<analyst>` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | Triage completed; severity confirmed `<SEVERITY>` | Manual | `<analyst>` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | Containment actions initiated | `<script/manual>` | `<analyst>` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | Containment confirmed | Manual | `<analyst>` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | _Add events as they occur_ | | |

---

## Technical Details

### Attack Vector
`<How the attacker gained initial access or how the incident began>`

### Attacker Indicators
| Type | Value | Confidence | Source |
|---|---|---|---|
| IP Address | `<masked or hash>` | High / Medium / Low | `<SIEM log / TI feed>` |
| Domain | `<domain>` | High / Medium / Low | `<source>` |
| File Hash | `sha256:<hash>` | High / Medium / Low | `<EDR/TI>` |
| User Account | `<masked>` | High / Medium / Low | `<IdP logs>` |

### Evidence Items
| Evidence ID | Description | Location | SHA-256 | Collected At |
|---|---|---|---|---|
| `E-001` | `<description>` | `<path in EVIDENCE_DIR>` | `<hash>` | `<UTC timestamp>` |

---

## Impact Assessment

| Category | Impact | Notes |
|---|---|---|
| **Data Exposure** | `Confirmed / Suspected / None` | `<what data, how much>` |
| **Service Disruption** | `Confirmed / Suspected / None` | `<services, duration>` |
| **Customer Impact** | `Confirmed / Suspected / None` | `<number of customers, nature>` |
| **Financial Impact** | `Estimated / Unknown / None` | `<estimated range>` |
| **Regulatory Obligation** | `Yes / No / Under Assessment` | `<GDPR / HIPAA / PCI>` |

---

## Containment Actions Taken

- [ ] `<Action 1 — e.g., "Revoked sessions for compromised account at 2025-01-01T14:22:00Z">`
- [ ] `<Action 2>`
- [ ] `<Action 3>`

---

## Eradication Actions Taken

- [ ] `<Action 1>`
- [ ] `<Action 2>`

---

## Recovery Actions Taken

- [ ] `<Action 1>`
- [ ] `<Action 2>`

---

## Root Cause Analysis

> _Complete after eradication. What was the underlying cause that allowed this incident to occur?_

**Root cause category:** `Technical misconfiguration / Process gap / Human error / External threat actor / Unknown`

**Root cause description:**
`<Detailed explanation>`

---

## Lessons Learned

> _Complete at Post-Incident Review_

**What worked well:**
-

**What could be improved:**
-

**Detection gaps identified:**
-

---

## Follow-Up Actions

| Action | Owner | Due Date | Status |
|---|---|---|---|
| `<Remediation item>` | `<team>` | `<date>` | `Open / In Progress / Done` |
| Post-Incident Review | `<IR Lead>` | `<within 5 business days>` | `Scheduled / Complete` |

---

## Closure

| Field | Value |
|---|---|
| **Closed At** | `<UTC timestamp>` |
| **Closure Reason** | `Resolved / False Positive / Duplicate / Out of Scope` |
| **Closed By** | `<name>` |
| **PIR Completed** | `Yes / No / Scheduled` |
