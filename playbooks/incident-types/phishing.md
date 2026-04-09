# Phishing — Incident Response Playbook
**Type:** Phishing | **Maturity:** Operational | **Version:** 1.0

## Objective
Respond to a phishing campaign targeting the organization — covering email-based
credential harvesting, malware delivery, and business email compromise (BEC) scenarios.

## Detection Signals

- User report ("I think I clicked a phishing link")
- Email gateway alert (suspicious URL, malicious attachment, sender spoofing)
- SIEM alert: login from new location shortly after suspicious email delivery
- DNS sinhole hit for phishing domain
- Endpoint alert: suspicious process spawned from email client

---

## Phase 1: Triage (10 min)

1. **Obtain the original email** (as attachment or header dump — not forwarded):
   - Sender address and display name
   - Reply-to address (often differs from sender)
   - Links embedded (extract URLs without clicking)
   - Attachments (do not open — get hash only)
   - Delivery time and recipients

2. **Determine scope:**
   - Was this targeted (spear phishing — specific individuals) or bulk?
   - How many mailboxes received the email?
   - How many users clicked the link or opened the attachment?

3. **Classify the phishing type:**

   | Type | Indicator |
   |---|---|
   | Credential harvesting | Link to fake login page |
   | Malware delivery | Malicious attachment (macro-enabled doc, zip with exe) |
   | BEC / CEO fraud | Impersonating executive, requesting wire transfer or gift cards |
   | Spear phishing | Targeted, personalized content referencing internal context |
   | Vishing/Smishing (adjacent) | Voice or SMS-based; follow same escalation path |

4. **Open incident record** with type `phishing`, severity based on whether credentials were entered or malware executed.

---

## Phase 2: Containment (15 min)

### Email Quarantine
```
# Microsoft 365: purge message from all mailboxes
Search-UnifiedAuditLog or Content Search → Purge → Hard Delete
# Or via Security & Compliance Center: Content Search → Purge messages

# Google Workspace: admin.google.com → Reports → Audit → Gmail
# Use Google Vault or Admin SDK to delete messages at scale
```

### Block Phishing Domain and URLs
- Add phishing domain to DNS blocklist / Secure DNS
- Add URLs to web proxy and email gateway blocklist
- Block sender domain at email gateway (if not legitimate)

### Contain Potentially Compromised Accounts
- If credentials were entered: immediately follow `containment/compromised_credentials.md`
- Force password reset for all users who clicked the link
- Revoke sessions for users who entered credentials

### Isolate Endpoints (if malware delivery)
- If attachment was opened: isolate the endpoint immediately
- Escalate to malware incident type
- Collect memory image and disk artifacts before remediation

---

## Phase 3: Investigation (30–60 min)

1. **Analyze the phishing infrastructure:**
   - WHOIS, passive DNS, hosting provider for phishing domain
   - Is the domain a typosquat of a known trusted domain?
   - Check domain age — very new domains are high confidence phishing

2. **Review email authentication:**
   - SPF, DKIM, DMARC headers — did they pass or fail?
   - If DMARC fails on a legitimate-looking sender → misconfiguration or spoofing

3. **Determine who interacted:**
   - Pull email delivery logs for all recipients
   - Pull URL click logs from email gateway / proxy
   - Pull authentication logs for all users who clicked — any successful logins from new IPs?

4. **Credential harvest assessment:**
   - Monitor for login anomalies for 72h for all users who clicked
   - Check credential exposure databases for affected email addresses (HaveIBeenPwned API)

---

## Phase 4: Eradication

1. Ensure all copies of the phishing email are purged from all mailboxes
2. Remove any browser-saved passwords or cookies if endpoint was compromised
3. Submit phishing URL to Google Safe Browsing, Microsoft SmartScreen for takedown
4. Submit phishing domain to registrar abuse contact for takedown
5. If malware was delivered: follow `eradication/remove_persistence.md`

---

## Phase 5: Recovery and Prevention

1. Reset passwords and re-enroll MFA for all users who entered credentials
2. Strengthen email gateway rules (tighten DMARC enforcement, add lookalike domain alerts)
3. Update security awareness training with the specific phishing technique used
4. Review and improve DMARC policy for your own domains (move toward `p=reject`)
5. Add the phishing campaign indicators to SIEM detection rules

---

## Documentation Checkpoint
- [ ] Phishing email preserved as evidence (headers + raw source)
- [ ] Scope of recipients and clickers determined
- [ ] Email quarantined from all mailboxes
- [ ] Phishing infrastructure blocked
- [ ] Compromised accounts contained
- [ ] Endpoint isolation performed if malware delivered
- [ ] Stakeholders notified
- [ ] User notification sent (if credentials potentially harvested)
