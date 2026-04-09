# Compromised Credentials — Containment Playbook
**Phase:** Containment | **Maturity:** Operational | **Version:** 1.0

## Objective
Immediately limit the blast radius of a credential compromise event by revoking
active sessions, disabling or resetting the affected identity, and blocking
further authentication from attacker-controlled positions.

## Prerequisites
- Incident ID opened and severity confirmed as High or Critical
- Identity provider admin access (Okta, Azure AD, Google Workspace, or equivalent)
- Authorization to disable accounts and revoke sessions
- Communication channel established with the account owner

---

## Step 1 — Scope the Compromise (10 min)

1. Identify all accounts associated with the compromised credential set
2. Pull authentication logs for the past 72 hours for each affected account:
   - Source IPs and geolocation
   - Devices and user agents
   - Services accessed
   - Actions taken (especially privileged operations)
3. Determine if the credential was shared, reused, or a service account
4. Check for lateral movement: did the attacker use the credential to authenticate to other systems?
5. Check for persistence: were new credentials, API keys, or SSH keys created during the attacker's session?

**Decision gate:**
- If lateral movement is confirmed → escalate severity, expand scope to all touched systems
- If service account → notify dependent service owners before disabling

---

## Step 2 — Revoke Active Sessions (5 min)

Perform the following in order:

### Azure AD / Entra ID
```
# Revoke all refresh tokens for the user
Revoke-AzureADUserAllRefreshToken -ObjectId <user-object-id>
# Or via automation:
pwsh automations/identity/revoke_azure_sessions.ps1 -UserPrincipalName <upn> -IncidentId <INC-ID>
```

### Okta
1. Navigate to Admin → Users → Select User
2. Click "More Actions" → "Revoke sessions"
3. Confirm revocation applies to all active sessions

### Google Workspace
```
# Via gam (Google Admin SDK CLI)
gam update user <email> revokesessions
```

### AWS IAM (if AWS access keys are compromised)
```
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <username>
```

---

## Step 3 — Disable or Reset the Account (5 min)

Choose the appropriate action based on the account type:

| Account Type | Recommended Action |
|---|---|
| Human user — confirmed compromise | Disable account immediately; coordinate password reset out-of-band |
| Human user — suspected compromise | Force password reset + MFA re-enrollment |
| Service account | Disable; generate new credential; update dependent services |
| API key / token | Revoke immediately; generate replacement; rotate in all consumers |

> **Note:** For human accounts, notify the account owner and their manager before disabling. Use a secure out-of-band channel (phone or in-person) — not email, which the attacker may still have access to.

---

## Step 4 — Block Attacker-Controlled Infrastructure (5 min)

If attacker source IPs or user agents are identified:

1. Add identified attacker IPs to the WAF/network blocklist
2. Create a conditional access policy to block authentication from identified IP ranges (if IdP supports it)
3. Review VPN and remote access logs for attacker IP presence
4. Flag identified IPs in your SIEM for 30-day alerting

---

## Step 5 — Enforce MFA (if not already active) (5 min)

1. Confirm MFA is enforced for the affected account post-reset
2. If MFA was bypassed (e.g., via SIM swap or MFA fatigue): escalate and consider hardware key requirement
3. Review MFA method used — if SMS/TOTP was used, consider enforcing FIDO2/WebAuthn

---

## Step 6 — Preserve Evidence Before Further Changes

Before any account deletion, log purge, or policy change:

- [ ] Export authentication logs (last 72h) to `EVIDENCE_DIR`
- [ ] Capture screenshot of IdP session activity
- [ ] Record original account permissions and group memberships
- [ ] Run evidence packager: `python automations/evidence_packaging/packager.py --incident-id <INC-ID>`

---

## Step 7 — Notify Stakeholders

| Audience | Content | Channel |
|---|---|---|
| Account owner | Compromise confirmed, account locked, next steps | Secure (phone/in-person) |
| Manager | Summary, expected downtime, action required | Email/Slack |
| Security leadership | Scope, severity, containment status | Incident channel |
| Legal/Compliance (if PII involved) | Data access scope, regulatory obligations | Secure email |

---

## Documentation Checkpoint
- [ ] All active sessions revoked
- [ ] Account disabled or reset
- [ ] Attacker IPs blocked
- [ ] MFA status confirmed
- [ ] Evidence preserved and packaged
- [ ] Stakeholders notified
- [ ] Containment timestamp recorded in incident record
- [ ] Proceed to Eradication playbook
