# Incident Communication Templates

Use these templates to communicate consistently during an incident. Replace bracketed placeholders with incident-specific details.

---

## 1) Internal Notification Template (SOC / IR Team)

**Subject:** `[SEV-<level>] <incident_type> detected - IR-<incident_id>`

**Channel:** `[Slack/Teams/Email/PagerDuty]`

**Message:**

```text
[ALERT] Incident Declared

Incident ID: IR-<incident_id>
Severity: SEV-<1|2|3|4>
Status: <New|Triage|Containment|Eradication|Recovery|Monitoring>
Detected: <UTC timestamp>
Reported By: <person/system>

Summary:
<1-3 sentence summary of what happened and current impact>

Scope (Current Known):
- Users/Endpoints: <count or list>
- Systems/Services: <list>
- Cloud/On-Prem Assets: <list>
- Data at Risk: <none/unknown/type>

Key Indicators:
- <IP/domain/hash/account/artifact>
- <IP/domain/hash/account/artifact>

Actions Taken:
- <action + timestamp + owner>
- <action + timestamp + owner>

Immediate Requests:
- <e.g., isolate host, disable account, pull logs>
- <e.g., assign comms lead>

Incident Commander: <name>
Comms Lead: <name>
Next Update ETA: <UTC timestamp>
Reference Links: <ticket/case/doc links>
```

---

## 2) Stakeholder Update Template (Leadership / Business / Partners)

**Subject:** `Update #<n> - IR-<incident_id> - <short status>`

**Audience:** `[Executive leadership / Legal / IT Ops / Business owners / External partner]`

**Message:**

```text
Incident Update: IR-<incident_id>
Update #: <n>
Time: <UTC timestamp>
Prepared By: <name>

Current Status:
<one-line status, e.g., Containment in progress>

What We Know:
- <fact 1>
- <fact 2>
- <fact 3>

Business Impact:
- Service Impact: <none/limited/significant + details>
- User Impact: <none/limited/significant + details>
- Data Impact: <none/under investigation/confirmed + details>

What We Are Doing:
- <containment/eradication/recovery action>
- <forensics/investigation action>
- <coordination/compliance action>

Decisions / Support Needed:
- <approval/escalation/resource request>
- <legal/comms/operations decision>

Risks / Unknowns:
- <open question>
- <dependency/blocker>

Next Steps (Next 4-24h):
- <step>
- <step>

Next Update:
<UTC timestamp or trigger condition>
```

---

## 3) Incident Closure Report Template

**Subject:** `Incident Closure - IR-<incident_id> - <incident_type>`

**Message / Report Body:**

```text
Incident Closure Report

Incident ID: IR-<incident_id>
Incident Type: <type>
Severity (Final): SEV-<1|2|3|4>
Owner: <incident commander/primary analyst>
Opened: <UTC timestamp>
Closed: <UTC timestamp>
Duration: <hours/days>

Executive Summary:
<concise summary of event, impact, and resolution>

Timeline (Key Events):
- <timestamp> - <event/action>
- <timestamp> - <event/action>
- <timestamp> - <event/action>

Root Cause:
<confirmed or most likely root cause>

Affected Assets / Scope:
- Systems: <list/count>
- Accounts: <list/count>
- Data: <classification and impact>
- Regions/Business Units: <list>

Containment and Eradication Performed:
- <control/action>
- <control/action>

Recovery Actions:
- <restoration/validation step>
- <monitoring step>

Evidence and Artifacts:
- Case/Ticket: <link/id>
- Evidence Package: <location>
- Hash Manifest: <location>
- Relevant Logs: <location>

Communications Summary:
- Internal Notifications Sent: <yes/no + timestamps>
- Stakeholder Updates Sent: <yes/no + count>
- External/Regulatory Notifications: <required/not required + details>

Lessons Learned:
- What Worked Well: <items>
- What Didn’t: <items>
- Detection Gaps: <items>
- Process Gaps: <items>

Corrective and Preventive Actions (CAPA):
- <action> | Owner: <name> | Due: <date> | Status: <open/closed>
- <action> | Owner: <name> | Due: <date> | Status: <open/closed>

Closure Approval:
- Incident Commander: <name/date>
- Security Leadership: <name/date>
- Compliance/Legal (if required): <name/date>
```

---

## Usage Notes

- Keep updates factual and time-stamped.
- Mark unknowns explicitly; avoid speculation.
- Use UTC for all incident communications.
- Store all sent communications in the incident record for auditability.
