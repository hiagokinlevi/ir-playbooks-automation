# Lab 01: Credential Compromise Response

**Difficulty:** Beginner
**Time:** 45–60 minutes
**Prerequisites:** Complete the tutorial in `training/tutorials/running-first-playbook.md`

---

## Scenario

You are an on-call SOC analyst. At 02:17 UTC, your SIEM triggers the following alert:

> **ALERT-2025-0047** — HIGH
> **Rule:** Successful authentication from high-risk country for privileged account
> **User:** svc-deploy@company.com (CI/CD service account)
> **Source IP:** 185.220.101.x (Tor exit node — confirmed by threat intel)
> **Service:** AWS Console + GitHub Enterprise
> **Activity:** 4 successful logins in 90 seconds, followed by repository enumeration

Your task is to respond to this incident following the k1n-ir playbooks.

---

## Lab Setup

No live systems required. Use the simulated data provided in this lab file.

### Simulated Authentication Log (past 24h for svc-deploy@company.com)

```
2025-01-01T01:50:12Z  LOGIN  SUCCESS  svc-deploy@company.com  IP: 10.0.0.50   Service: GitHub  UA: GitHubActions/2.0
2025-01-01T02:17:03Z  LOGIN  SUCCESS  svc-deploy@company.com  IP: 185.220.101.x  Service: GitHub  UA: python-requests/2.28
2025-01-01T02:17:14Z  LOGIN  SUCCESS  svc-deploy@company.com  IP: 185.220.101.x  Service: AWS Console  UA: python-requests/2.28
2025-01-01T02:17:29Z  LOGIN  SUCCESS  svc-deploy@company.com  IP: 185.220.101.x  Service: AWS Console  UA: python-requests/2.28
2025-01-01T02:17:44Z  LOGIN  SUCCESS  svc-deploy@company.com  IP: 185.220.101.x  Service: GitHub  UA: python-requests/2.28
2025-01-01T02:18:01Z  LIST_REPOS  svc-deploy@company.com  IP: 185.220.101.x  Action: list all repositories (47 repos enumerated)
2025-01-01T02:18:15Z  CLONE_REPO  svc-deploy@company.com  IP: 185.220.101.x  Repo: infra-terraform (PRIVATE)
2025-01-01T02:18:22Z  CLONE_REPO  svc-deploy@company.com  IP: 185.220.101.x  Repo: secrets-baseline (PRIVATE)
```

### Simulated AWS CloudTrail (same period)

```
2025-01-01T02:17:14Z  ConsoleLogin  svc-deploy  IP: 185.220.101.x  MFA: false  Result: SUCCESS
2025-01-01T02:17:31Z  ListBuckets   svc-deploy  Region: us-east-1  BucketCount: 23
2025-01-01T02:17:45Z  GetObject     svc-deploy  Bucket: company-backups  Key: db-backup-2024-12-31.sql.gz
2025-01-01T02:17:58Z  GetObject     svc-deploy  Bucket: company-configs   Key: production.env
```

---

## Exercise 1: Triage (10 min)

Using the simulated log data above, answer the following triage questions:

1. Is this a false positive? Why or why not?
2. What is the incident type?
3. What severity would you assign? Justify your answer.
4. What is the scope of affected assets?

**Then run:**
```bash
k1n-ir open-incident \
  --type credential_compromise \
  --severity <your-answer> \
  --title "Compromised CI/CD service account svc-deploy — Tor exit node access" \
  --assets "svc-deploy@company.com,github-enterprise,aws-console,company-backups,company-configs"
```

---

## Exercise 2: Timeline Construction (10 min)

Using the simulated logs, reconstruct the attack timeline. Record each attacker action:

```bash
# Record each event — replace placeholders with your analysis
k1n-ir create-timeline \
  --incident-id INC-<date>-001 \
  --event "Attacker authenticated to GitHub from Tor exit node 185.220.101.x using valid svc-deploy credentials" \
  --actor attacker \
  --phase "Initial Access" \
  --confidence high \
  --technique "T1078.004" \
  --output /tmp/lab01-timeline.json
```

Record at least 4 timeline events based on the log data.

**Questions to answer:**
- What MITRE ATT&CK technique covers the repository clone activity?
- When did the first legitimate login occur, and when did the first suspicious login occur?
- What is the time delta between the last known-good login and the first attacker login?

---

## Exercise 3: Containment Planning (10 min)

Before executing any containment, answer these planning questions:

1. What specific containment actions should you take for this incident?
2. In what order should you perform them? (Think about dependencies)
3. Which legitimate services might be disrupted by each action?
4. What approval do you need before acting?

**Reference:** `playbooks/containment/compromised_credentials.md`

**Then record your containment plan as a timeline event:**
```bash
k1n-ir create-timeline \
  --incident-id INC-<date>-001 \
  --event "Containment plan: 1) Revoke svc-deploy GitHub PAT, 2) Disable AWS access keys, 3) Notify CI/CD team of service disruption" \
  --actor defender \
  --phase "Containment" \
  --confidence high
```

---

## Exercise 4: Evidence Assessment (10 min)

Based on the simulated CloudTrail logs, assess the data exposure:

1. What files were accessed by the attacker?
2. What is the classification level of each file (assume: `db-backup` = confidential, `production.env` = highly sensitive)?
3. What information might `production.env` contain?
4. Does this incident trigger any regulatory notification obligations?

**Then update the severity if warranted:**
```bash
k1n-ir set-severity \
  --incident-id INC-<date>-001 \
  --severity critical \
  --justification "Confirmed download of production.env — likely contains production secrets including database credentials and API keys. All secrets must be rotated."
```

---

## Exercise 5: Generate Lab Report (5 min)

```bash
k1n-ir generate-report \
  --incident-id INC-<date>-001 \
  --format markdown \
  --verbosity verbose \
  --output /tmp/lab01-report.md
```

Review the report. Identify which sections need to be populated with your findings from exercises 1–4.

---

## Answer Key

### Exercise 1 — Suggested Answers

- **False positive?** No. Tor exit node, simultaneous logins across multiple services, and immediate data access are strong indicators of malicious activity. The `python-requests` user agent is inconsistent with legitimate CI/CD automation.
- **Incident type:** `credential_compromise` (specifically: compromised service account credentials)
- **Severity:** Critical — production service account, confirmed download of `production.env` (likely contains secrets), potential database backup exfiltration, customer data possible.
- **Scope:** svc-deploy service account, GitHub Enterprise (47 repos accessible), AWS (23 S3 buckets accessible), specific downloaded files: `db-backup-2024-12-31.sql.gz`, `production.env`

### Exercise 2 — ATT&CK Mappings

- Repository enumeration: `T1213.003` — Code Repositories
- Repository clone: `T1213.003` — Code Repositories
- AWS data access: `T1530` — Data from Cloud Storage Object

---

## Lab Complete

Proceed to `training/labs/` for additional labs covering phishing response, cloud exposure, and secret leakage scenarios.
