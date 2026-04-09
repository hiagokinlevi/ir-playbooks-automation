# API Abuse — Incident Response Playbook
**Type:** API Abuse | **Maturity:** Operational | **Version:** 1.0

## Objective
Detect, contain, and remediate unauthorized or anomalous API usage — including
credential stuffing against APIs, data scraping, excessive rate consumption,
and authentication bypass attempts.

## Detection Signals

- Rate anomaly: request volume > 3x baseline for a key or IP
- Authentication failures: sustained 401/403 errors from a single source
- Unusual payload patterns: probing for undocumented endpoints, SQL injection patterns, path traversal
- Data volume anomaly: unusually large response bodies or bulk export behavior
- Geographic anomaly: API key used from unexpected region or impossible travel
- Off-hours access: authenticated requests outside expected business hours for a service account

---

## Phase 1: Triage (15 min)

1. **Confirm alert validity:**
   - Pull the API gateway logs for the flagged key/IP for the past 24h
   - Calculate request volume, endpoint spread, and response codes
   - Identify if this is automation (uniform timing, consistent user-agent) or human-driven

2. **Classify the abuse type:**

   | Type | Indicator |
   |---|---|
   | Credential stuffing | High volume of auth failures from rotating IPs |
   | Data scraping | Authenticated, paginated bulk reads across many records |
   | Brute force | High volume of auth failures from single IP |
   | Account takeover (post-auth) | Valid auth, then unusual high-volume reads |
   | Vulnerability probing | Requests to non-existent or admin endpoints |

3. **Assess impact:**
   - What data is exposed by the abused endpoints?
   - How many records may have been accessed?
   - Is this a customer-facing or internal API?

4. **Open incident record** with type `api_abuse`, severity per impact assessment.

---

## Phase 2: Containment (10–20 min)

### Immediate Rate Limiting
- Apply emergency rate limit to the offending API key or IP at the gateway layer
- If key-based: disable the key immediately if confirmed compromised
- If IP-based: add to WAF blocklist; monitor for IP rotation

### Credential Lockout (if credential stuffing)
- Enable CAPTCHA or challenge on the authentication endpoint
- Temporarily increase lockout sensitivity (e.g., lock after 3 failures for 15 min)
- Notify affected users if account lockout is triggered

### Traffic Blocking
```bash
# Example: AWS WAF — add IP to managed rule set (via CLI or console)
aws wafv2 update-ip-set \
  --name AttackerBlocklist \
  --id <ip-set-id> \
  --addresses "203.0.113.0/32" \
  --lock-token <token>
```

### Rotate Compromised API Keys
- Immediately revoke the compromised key
- Issue a replacement key to the legitimate owner out-of-band
- Update key in all consumers

---

## Phase 3: Investigation (30–60 min)

1. **Enumerate accessed resources:**
   - Query API logs for all resources accessed by the attacker's key/IP
   - Estimate total records or bytes returned
   - Identify if any write or delete operations were performed

2. **Attribution (best-effort):**
   - ASN lookup on attacker IPs
   - User-agent analysis
   - Check attacker IPs against threat intelligence feeds

3. **Identify the access vector:**
   - Was the key leaked (e.g., in a public repository, client-side code)?
   - Was the key obtained via phishing or credential theft?
   - Is this an unauthenticated endpoint issue?

---

## Phase 4: Eradication and Recovery

1. Remove or rotate all affected API keys
2. If key was leaked in code: scan all repositories for other leaked keys (`git log`, `truffleHog`, `gitleaks`)
3. If endpoint lacks authentication: add authentication before re-enabling
4. Implement or tune rate limiting at the gateway for the affected endpoint class
5. Review and tighten API scope permissions — apply least-privilege to all keys

---

## Phase 5: Post-Incident Actions

- [ ] Notify affected users if their data was accessed
- [ ] File regulatory notification if PII was exposed (per legal guidance)
- [ ] Document all accessed endpoints and estimated data volume
- [ ] Add detection rule for similar patterns (velocity, endpoint spread)
- [ ] Schedule PIR within 5 business days
