# Tutorial: Running Your First Playbook

**Audience:** New SOC analysts or security engineers onboarding to k1n-ir
**Time:** ~20 minutes
**Prerequisites:** Python 3.11+, k1n-ir installed

---

## Overview

In this tutorial you will:
1. Install k1n-ir and configure your environment
2. Open a simulated incident
3. Follow the initial triage playbook
4. Record a timeline event
5. Generate a basic report

No live systems are required — this tutorial uses simulated data.

---

## Step 1: Install k1n-ir

```bash
# Clone the repository
git clone https://github.com/hiagokinlevi/ir-playbooks-automation.git
cd ir-playbooks-automation

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate

# Install the package
pip install -e .

# Verify installation
k1n-ir --version
# Expected output: k1n-ir, version 1.0.0
```

---

## Step 2: Configure Your Environment

```bash
# Copy the example environment file
cp .env.example .env
```

For this tutorial, the defaults are fine. You do not need to change anything in `.env`.

Key settings for safe training use:
- `SAFE_AUTOMATION_MODE=true` — all automation scripts are in dry-run mode
- `APPROVAL_REQUIRED_FOR_CONTAINMENT=true` — containment actions require confirmation
- `MASKING_MODE=true` — sensitive values will be masked in output

---

## Step 3: Open a Simulated Incident

Imagine you have received the following alert from your SIEM:

> **Alert:** "Successful login from an IP in Ukraine for user jsmith@company.com — previous login was 2 hours ago from New York."

This looks like a potential credential compromise (impossible travel). Let's open an incident.

```bash
k1n-ir open-incident \
  --type credential_compromise \
  --severity high \
  --title "Impossible travel alert for jsmith@company.com" \
  --owner analyst_trainee \
  --assets "jsmith@company.com,corp-portal.company.com"
```

You should see output like:

```
╭─────────────────── k1n-ir ────────────────────╮
│ Incident Opened                               │
│                                               │
│ ID:       INC-20250101-001                    │
│ Title:    Impossible travel alert for ...     │
│ Type:     credential_compromise               │
│ Severity: high                                │
│ Owner:    analyst_trainee                     │
│ Status:   detected                            │
╰───────────────────────────────────────────────╯

Next: run triage playbook → k1n-ir start-playbook --playbook triage/initial_triage
```

Note your **Incident ID** — you will use it in subsequent steps.

---

## Step 4: Follow the Initial Triage Playbook

```bash
k1n-ir start-playbook \
  --playbook triage/initial_triage \
  --incident-id INC-20250101-001
```

The playbook will display in your terminal. Work through each step:

- **Step 1 (Validate the alert):** For our simulation, assume you pulled the authentication logs and confirmed: two logins from geographically impossible locations within 2 hours. This is not a known false positive for this user. Corroborating signal confirmed — proceed.

- **Step 2 (Classify):** Type: Credential Compromise.

- **Step 3 (Assign severity):** Privileged account? Check — jsmith is in the IT team. Customer impact possible. Severity: **High** (already set). If the user were an admin, it would be Critical.

- **Step 4 (Open formal record):** Already done in Step 3.

- **Step 5 (Determine response path):** High severity → activate IR team, begin containment immediately.

---

## Step 5: Update Severity (if needed)

In this simulation, let's say further investigation reveals jsmith has admin access. Upgrade to Critical:

```bash
k1n-ir set-severity \
  --incident-id INC-20250101-001 \
  --severity critical \
  --justification "jsmith confirmed to be a cloud admin — elevated blast radius"
```

---

## Step 6: Record a Timeline Event

Document what you found:

```bash
k1n-ir create-timeline \
  --incident-id INC-20250101-001 \
  --event "Authentication log confirms impossible travel: login from New York at 10:00 UTC, then login from Kyiv at 11:47 UTC. Same valid credential used." \
  --actor attacker \
  --phase "Initial Access" \
  --confidence high \
  --technique "T1078.004" \
  --output /tmp/INC-20250101-001-timeline.json
```

---

## Step 7: Generate a Report

```bash
k1n-ir generate-report \
  --incident-id INC-20250101-001 \
  --format markdown \
  --verbosity standard \
  --output /tmp/INC-20250101-001-report.md
```

Open the report file and review its structure. In a real incident, you would populate each section with actual findings.

---

## What's Next?

- Try the lab: `training/labs/lab_01_credential_compromise.md` — a full walkthrough with simulated evidence
- Read the playbooks in `playbooks/containment/compromised_credentials.md` — the next step in a real response
- Explore the automation scripts in `automations/` — understand what they do and their safety controls

---

Congratulations — you have completed your first k1n-ir playbook run.
