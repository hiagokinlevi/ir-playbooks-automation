# Incident Response — Reference Prompts and Questions

This document contains structured question sets to guide analyst thinking during each phase of an incident response. These are not scripts — they are prompts to ensure critical questions are not overlooked under pressure.

---

## Triage Prompts

### Alert Validation
- What detection rule fired, and how reliable is this rule historically?
- Is this alert correlated with any other alerts in the last 24 hours for the same asset or user?
- What is the base rate for this alert — does it fire frequently as a false positive?
- Can I reproduce the triggering condition, or was it a one-time event?

### Scoping
- What system, account, or data was involved?
- What is the business criticality of the affected asset?
- Is this isolated to one asset, or are there indicators of lateral movement?
- When did this first occur? (Alert time vs. actual event time — look for log gaps)
- Who has access to the affected system or data?

### Classification
- What MITRE ATT&CK tactic does this most closely match?
- Is the actor external, internal, or unknown?
- What is the most likely attacker objective given the evidence?

---

## Containment Prompts

### Before Acting
- What is the exact scope of what I am about to contain?
- Is this action reversible? What is the rollback procedure?
- Which legitimate services will be disrupted by this action?
- Have I notified the service owner and obtained change management approval?
- Have I preserved evidence before making changes?

### During Containment
- Have I confirmed the attacker no longer has the access path I just removed?
- Are there other access paths I haven't addressed yet?
- Is the attacker still active? Did containment alert them?

### After Containment
- Can I verify from an external/unauthenticated perspective that access is blocked?
- Have all affected stakeholders been notified of the impact?

---

## Investigation Prompts

### Attribution and Technique
- What MITRE ATT&CK techniques were used in this attack?
- Is the TTPs consistent with a known threat actor or campaign?
- What tools or malware (if any) were used?
- Where did the attacker initially come from? (IP geolocation, ASN, VPN/Tor)

### Impact Assessment
- What data did the attacker access? How much? At what classification?
- Did the attacker read, copy, modify, or delete data?
- Were any credentials, keys, or secrets exposed?
- Did the attacker establish persistence? How many persistence mechanisms?
- Did the attacker move laterally? How many systems were touched?

### Detection Analysis
- Why did our detection not catch this earlier?
- Were there earlier indicators we missed?
- Were any logs missing, disabled, or tampered with?

---

## Eradication Prompts

- Have I checked ALL common persistence locations for this platform?
- Have I confirmed each persistence mechanism removal was successful?
- Is the original vulnerability patched or mitigated?
- Is there any chance the attacker has a persistence mechanism I haven't found?
- Have I confirmed clean state on ALL affected systems, not just the primary one?

---

## Recovery Prompts

- Is the restored system provably clean, or am I making an assumption?
- Am I restoring from a backup that predates the attacker's initial access?
- What monitoring do I have in place to detect re-compromise on the restored system?
- Who needs to validate functionality before traffic is restored?
- What is the rollback trigger if the restored service shows signs of re-compromise?

---

## Post-Incident Review Prompts

### Root Cause
- What is the specific control or process that failed?
- Was this a one-off human error, or a systemic gap?
- If the same attacker tried again tomorrow, what would stop them now that didn't stop them before?

### Detection
- What was our Mean Time to Detect (MTTD)? Is that acceptable for this incident type?
- What detection rules, if tuned or added, would have caught this earlier?
- Were there logs or telemetry sources that would have been useful but weren't available?

### Response
- What was our Mean Time to Respond (MTTR)? Where did we lose time?
- Were the playbooks accurate and complete? What was missing?
- Did the automation scripts work as expected? Any failures?
- Were stakeholders notified appropriately and on time?

### Prevention
- What controls, if implemented, would have prevented this incident?
- Are there similar assets or configurations that should be reviewed proactively?
- Should this incident trigger a broader security review or assessment?
