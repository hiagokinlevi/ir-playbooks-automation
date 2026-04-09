# Technical Incident Report — Template
<!--
  This template is for the technical IR report targeting analyst and engineering audiences.
  For executive communication, use templates/communications/executive_brief.md instead.
  Remove all HTML comment blocks before distributing.
-->

---

**CONFIDENTIAL — For Internal Distribution Only**

| Field | Value |
|---|---|
| **Report Title** | Technical Incident Report: `<Incident Title>` |
| **Incident ID** | `INC-<YYYYMMDD>-<NNN>` |
| **Report Version** | `1.0` |
| **Report Date** | `<YYYY-MM-DD>` |
| **Prepared By** | `<Analyst Name>` |
| **Classification** | `Internal / Confidential / Restricted` |

---

## 1. Executive Summary

> _3–5 sentences. Describe what happened, the scope of impact, current status, and key actions taken. Written so a manager can understand without reading the full report._

---

## 2. Incident Overview

| Attribute | Value |
|---|---|
| **Incident Type** | `<credential_compromise / malware / data_exposure / api_abuse / phishing / cloud_exposure>` |
| **Severity** | `CRITICAL / HIGH / MEDIUM / LOW` |
| **Status at Report Date** | `Closed / In Recovery / Contained` |
| **Initial Detection** | `<UTC timestamp>` |
| **Containment Achieved** | `<UTC timestamp>` |
| **Service Restored** | `<UTC timestamp>` |
| **Total Duration** | `<Xh Ym>` |
| **Affected Assets** | `<list of systems, services, accounts>` |
| **Data Exposure Confirmed** | `Yes / No / Under Assessment` |

---

## 3. Attack Narrative

> _A cohesive, chronological account of what happened — written in plain prose. Include attacker techniques referenced by MITRE ATT&CK tactics and techniques where applicable._

### 3.1 Initial Access
`<How the attacker gained a foothold>`

**ATT&CK Technique:** `T<XXXX> — <Technique Name>` (if applicable)

### 3.2 Execution and Lateral Movement
`<What the attacker did once inside>`

### 3.3 Impact
`<What data, systems, or services were affected>`

---

## 4. Timeline

> _Reference the full timeline document or summarize key events._

| Timestamp (UTC) | Event |
|---|---|
| `<YYYY-MM-DDTHH:MM:SSZ>` | `First attacker action (estimated)` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Alert triggered` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Incident opened` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Containment complete` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Eradication complete` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Service restored` |
| `<YYYY-MM-DDTHH:MM:SSZ>` | `Incident closed` |

Full timeline: `[link to timeline document]`

---

## 5. Indicators of Compromise (IoCs)

> _Include only indicators where sharing is authorized. Mask or omit sensitive internal details._

| Type | Indicator | Confidence | Notes |
|---|---|---|---|
| IP | `<masked or CIDR>` | High | Attacker source IP |
| Domain | `<domain>` | High | C2 / phishing domain |
| File Hash | `sha256:<hash>` | High | Malicious binary |
| Registry Key | `<key path>` | Medium | Persistence mechanism |

> **Distribution note:** IoCs may be shared with threat intelligence platforms (MISP, STIX/TAXII) after legal review.

---

## 6. Root Cause Analysis

### 6.1 Immediate Cause
`<The direct technical cause — e.g., "A valid AWS access key was committed to a public GitHub repository">`

### 6.2 Contributing Factors
- `<Factor 1 — e.g., "No pre-commit secret scanning in CI/CD pipeline">`
- `<Factor 2>`
- `<Factor 3>`

### 6.3 Root Cause Statement
`<The systemic root cause — the process or control gap that allowed the immediate cause to occur>`

---

## 7. Impact Assessment

### 7.1 Data
`<What data may have been accessed, in what volume, at what classification level>`

### 7.2 Systems
`<Which systems were affected, for how long, in what state>`

### 7.3 Customer Impact
`<Number of customers affected, nature of impact, notification status>`

### 7.4 Regulatory Obligations
`<Applicable regulations (GDPR, HIPAA, PCI-DSS), notification deadlines, filing status>`

---

## 8. Remediation Actions

### 8.1 Containment
- `<Action taken — e.g., "Revoked compromised API key at 2025-01-01T14:22:00Z">`

### 8.2 Eradication
- `<Action taken>`

### 8.3 Recovery
- `<Action taken>`

---

## 9. Lessons Learned

| Category | Finding |
|---|---|
| **Detection gap** | `<What we couldn't detect and why>` |
| **Response gap** | `<Where response was slow or incomplete>` |
| **Prevention gap** | `<What control was missing>` |

---

## 10. Follow-Up Recommendations

| Priority | Recommendation | Owner | Target Date |
|---|---|---|---|
| Critical | `<e.g., Implement mandatory secret scanning in all CI/CD pipelines>` | `<team>` | `<YYYY-MM-DD>` |
| High | `<recommendation>` | `<team>` | `<date>` |
| Medium | `<recommendation>` | `<team>` | `<date>` |

---

## 11. References

- Incident record: `[link]`
- Evidence package: `EVIDENCE_DIR/INC-<YYYYMMDD>-<NNN>/`
- MITRE ATT&CK Navigator layer: `[link if created]`
- Related incidents: `[links if applicable]`

---

_Report prepared using ir-playbooks-automation. Classification: Internal._
