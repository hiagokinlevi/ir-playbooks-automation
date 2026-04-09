# Secret Leakage — Incident Response Playbook
**Type:** Secret Leakage | **Maturity:** Operational | **Version:** 1.0

## Objective
Respond to the accidental or malicious exposure of secrets (API keys, tokens,
passwords, private keys, database credentials) in public or semi-public locations
including code repositories, container images, logs, and public pastes.

## Detection Signals

- GitHub Secret Scanning alert (native or third-party like GitGuardian)
- Developer report ("I accidentally pushed a key")
- CI/CD secret detection hook triggered
- Threat intelligence feed: organization's key observed in paste site or dark web
- AWS GuardDuty: anomalous API activity with a key not expected to be in use

---

## Phase 1: Triage (10 min)

1. **Identify the exposed secret:**
   - Secret type (AWS key, GitHub PAT, database password, JWT secret, OAuth client secret, private key)
   - Where was it exposed? (public GitHub repo, public npm package, container image, log file, paste site)
   - When was it first exposed? (check git blame, commit history, publication timestamp)
   - Is it still exposed right now? (is the commit/file publicly accessible?)

2. **Assess potential usage:**
   - Has the secret been accessed or used since exposure?
   - For AWS keys: check CloudTrail for API calls with that key ID since exposure time
   - For GitHub PATs: check token activity logs (Settings → Security → Token activity)
   - For database credentials: check database access logs for connections from unexpected IPs

3. **Severity classification:**

   | Scenario | Severity |
   |---|---|
   | Production credential, confirmed active use by attacker | Critical |
   | Production credential, no confirmed attacker use, <24h exposure | High |
   | Staging/dev credential, limited blast radius | Medium |
   | Internal-only credential, confirmed restricted access | Low |

4. **Open incident record** with type `secret_leakage`.

---

## Phase 2: Containment (immediate — within 15 min)

> **The single most important action: revoke the secret immediately, regardless of whether attacker use is confirmed. Rotation takes priority over investigation.**

### AWS Access Keys
```bash
# Disable the key immediately (preserves audit trail vs. deletion)
aws iam update-access-key \
  --access-key-id <AKIAIOSFODNN7EXAMPLE> \
  --status Inactive \
  --user-name <username>

# Generate a replacement key for the legitimate owner
aws iam create-access-key --user-name <username>
```

### GitHub Personal Access Token
1. Settings → Developer settings → Personal access tokens
2. Delete the exposed token
3. Create a replacement with minimum required scopes

### Database Credentials
1. Change the database password immediately in the database management console
2. Update the password in all legitimate consumers (application config, secrets manager)
3. Verify no unauthenticated connections remain

### Private Keys (TLS/SSH)
1. For TLS: revoke the certificate with the CA; issue a new certificate
2. For SSH: remove the public key from all `authorized_keys` files; generate a new keypair
3. If a code signing key: notify downstream consumers of the key revocation

### Remove the Secret from Public Locations
- If in a git repository: the commit history must be rewritten (BFG Repo Cleaner or `git filter-repo`)
  - Note: even after rewriting history, forks and cached views may retain the secret
  - GitHub support can assist with clearing cached views for GitHub.com-hosted repos
- If in a container image: pull the image, rebuild without the secret, re-push, delete the vulnerable image tag
- If in a log file: redact or remove the log entry; clear any log aggregation systems

---

## Phase 3: Investigation (30 min)

1. **Root cause analysis:**
   - How did the secret end up in a public location?
   - Was it hardcoded in source code? Missing from `.gitignore`? Logged by accident?
   - Was it a developer mistake or an intentional leak?

2. **Full exposure window:**
   - Determine exact timestamps: committed at → pushed at → first indexed by search engine / scanner at
   - For GitHub: check if the repo was public at any point during the exposure

3. **Audit attacker activity (if any):**
   - Pull all API calls made with the compromised credential during the exposure window
   - Identify: what was accessed, what was created, what was deleted or exfiltrated

4. **Blast radius assessment:**
   - What systems or data could the attacker access with this credential?
   - Were there any privilege escalation paths from this credential?

---

## Phase 4: Eradication

1. Ensure the secret is purged from all storage locations (code, CI/CD env vars, config files, logs)
2. Run a full repository scan with `gitleaks` or `truffleHog` to find any other leaked secrets:
   ```bash
   gitleaks detect --source . --report-format json --report-path gitleaks-report.json
   ```
3. Scan container images for embedded secrets
4. Implement pre-commit hooks to prevent future secret leakage:
   ```bash
   # Install gitleaks as a pre-commit hook
   gitleaks protect --staged -v
   ```

---

## Phase 5: Recovery and Prevention

1. Store all secrets in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
2. Implement mandatory secret scanning in CI/CD pipelines
3. Enable GitHub Secret Scanning and push protection on all repositories
4. Rotate all secrets on a defined schedule (key rotation policy)
5. Train developers on secure secret handling practices

---

## Documentation Checkpoint
- [ ] Secret type and exposure location documented
- [ ] Exposure window determined
- [ ] Secret revoked (timestamp recorded)
- [ ] Replacement credential issued to legitimate owner
- [ ] Attacker activity audited
- [ ] Secret removed from all public locations
- [ ] Repository history cleaned if applicable
- [ ] Root cause documented
- [ ] Prevention controls implemented or scheduled
