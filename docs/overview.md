# ir-playbooks-automation — Architecture Overview

## Purpose

`ir-playbooks-automation` is a practitioner toolkit for Security Operations Centers (SOC) and incident response teams. It provides structured playbooks, data schemas, automation scripts, and CLI tooling to support the full NIST SP 800-61r2 incident response lifecycle.

## Design Principles

**1. Practitioner-first:** Every playbook, template, and automation is designed for real-world use in production IR environments. Content is operational, not theoretical.

**2. Safety by default:** All automation scripts run in dry-run mode unless explicitly configured otherwise. Destructive actions require confirmation. The `SAFE_AUTOMATION_MODE` and `APPROVAL_REQUIRED_FOR_CONTAINMENT` environment flags enforce this.

**3. Evidence preservation:** The tool never deletes forensic data. Containment automation isolates systems; eradication guidance preserves copies before removal.

**4. Auditable:** All state transitions, automation runs, and evidence collection events are logged with structured logging (structlog). Logs are JSON-formatted for SIEM ingestion.

**5. Composable:** Components (schemas, state machine, automations, CLI) are independently usable. Teams can adopt only the parts they need.

## Component Map

```
┌─────────────────────────────────────────────────────┐
│                     CLI (click)                     │
│   open-incident  set-severity  start-playbook       │
│   create-timeline  generate-report                  │
└────────────────────────┬────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
┌──────────────┐  ┌────────────┐  ┌──────────────┐
│   Schemas    │  │  Workflows │  │  Automations │
│  (Pydantic)  │  │ state_mach │  │  cloud/      │
│  incident.py │  │ ine.py     │  │  identity/   │
└──────────────┘  └────────────┘  │  evidence/   │
                                  └──────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────┐
│                    Playbooks                         │
│  triage/  containment/  eradication/  recovery/      │
│  incident-types/                                     │
└──────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────┐
│                    Templates                         │
│  incident-records/  timelines/  reports/  comms/     │
└──────────────────────────────────────────────────────┘
```

## Data Flow

1. An alert fires in the SIEM or EDR. The analyst runs `k1n-ir open-incident` to create a formal record.
2. The record is initialized with status `DETECTED`. The state machine manages subsequent transitions.
3. The analyst follows the appropriate playbook (retrieved via `k1n-ir start-playbook`).
4. Automation scripts (cloud isolation, session revocation, evidence packaging) are called as needed.
5. Evidence items are recorded in the incident record with SHA-256 hashes.
6. Reports and communications are generated from templates populated with incident data.
7. The incident is closed via the state machine after PIR.

## Security Considerations

- The tool processes and logs incident data. Ensure log storage is restricted to authorized personnel.
- When `MASKING_MODE=true`, the tool avoids logging raw IPs, usernames, and tokens.
- Automation credentials (AWS, Azure) should be scoped to minimum required permissions and stored in a secrets manager, not in `.env` files on shared systems.
- Evidence packages should be stored on access-controlled storage, not on shared developer workstations.
