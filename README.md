# ir-playbooks-automation

**Incident response playbooks, automated triage workflows, and containment automation for SOC teams and blue teamers.**

---

## Overview

`ir-playbooks-automation` is a structured, practitioner-focused toolkit for Security Operations Center (SOC) analysts, incident responders, and blue teamers. It provides:

- **Operational playbooks** covering triage, containment, eradication, and recovery phases
- **Automation scripts** for safe, auditable containment actions (AWS isolation, S3 lockdown, GCP VM isolation, Azure session revocation, evidence packaging)
- **Incident record and report templates** for consistent documentation
- **Pydantic data schemas** for machine-readable incident state
- **CLI tooling** for opening incidents, managing severity, running playbooks, and generating reports
- **Training labs and tutorials** for onboarding new analysts

The tool follows the NIST SP 800-61r2 incident response lifecycle and is designed for real-world production SOC environments.

---

## Repository Structure

```
ir-playbooks-automation/
├── playbooks/
│   ├── triage/             # Alert validation and initial classification
│   ├── containment/        # Isolation and containment procedures
│   ├── eradication/        # Persistence removal and cleanup
│   ├── recovery/           # Controlled service restoration
│   └── incident-types/     # Type-specific response guidance
├── automations/
│   ├── evidence_packaging/ # Evidence collection and hash verification
│   ├── cloud/              # Cloud containment automation (AWS, Azure, GCP)
│   └── identity/           # Identity and session revocation
├── templates/
│   ├── incident-records/   # Incident record templates
│   ├── timelines/          # Attack timeline templates
│   ├── reports/            # Technical report templates
│   └── communications/     # Executive communication templates
├── schemas/                # Pydantic data models
├── workflows/              # Incident state machine
├── cli/                    # Click-based CLI entrypoint
├── docs/                   # Architecture and model documentation
├── training/               # Tutorials and hands-on labs
└── tests/                  # Unit tests
```

---

## Quickstart

### Prerequisites

- Python 3.11+
- AWS CLI configured (for cloud automations)
- Azure PowerShell module (for identity automations)

### Installation

```bash
# Clone the repository
git clone https://github.com/hiagokinlevi/ir-playbooks-automation.git
cd ir-playbooks-automation

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Install AWS automation support only when you need live AWS containment
pip install -e .[aws]

# Offline/dependency-light validation path
pip install -e . --no-deps --no-build-isolation

# Copy and configure environment
cp .env.example .env
# Edit .env with your environment settings
```

### Open Your First Incident

```bash
# Open a new incident
k1n-ir open-incident --type credential_compromise --severity high

# Start a playbook
k1n-ir start-playbook --incident-id INC-20250101-001 --playbook triage/initial_triage

# Set severity after investigation
k1n-ir set-severity --incident-id INC-20250101-001 --severity critical

# Generate a technical report
k1n-ir generate-report --incident-id INC-20250101-001 --format markdown

# Preview S3 public-access lockdown before live containment
k1n-ir lockdown-s3-bucket \
  --bucket-name exposed-data-bucket \
  --incident-id INC-20250101-001 \
  --output s3-lockdown-preview.json

# Preview Azure VM NSG isolation before live containment
k1n-ir isolate-azure-vm \
  --subscription-id 00000000-0000-0000-0000-000000000000 \
  --resource-group rg-production \
  --vm-name app-server-01 \
  --incident-id INC-20250101-001 \
  --output azure-isolation-preview.json

# Preview GCP Compute Engine isolation before live containment
k1n-ir isolate-gcp-instance \
  --project-id production-project \
  --zone us-central1-a \
  --instance-name web-01 \
  --incident-id INC-20250101-001 \
  --output gcp-isolation-preview.json
```

---

## Playbooks

| Playbook | Phase | Description |
|----------|-------|-------------|
| `triage/initial_triage` | Triage | Alert validation, classification, severity assignment |
| `containment/compromised_credentials` | Containment | Credential revocation, session termination, MFA enforcement |
| `containment/cloud_exposure` | Containment | Cloud resource isolation, policy remediation |
| `eradication/remove_persistence` | Eradication | Persistence mechanism removal and verification |
| `recovery/controlled_return` | Recovery | Controlled service restoration checklist |
| `incident-types/api_abuse` | Full lifecycle | API-specific abuse response |
| `incident-types/phishing` | Full lifecycle | Phishing email and credential harvesting response |
| `incident-types/secret_leakage` | Full lifecycle | Leaked credentials and secrets response |

---

## Automations

| Script | Platform | Description |
|--------|----------|-------------|
| `evidence_packaging/packager.py` | Any | Creates structured evidence packages with SHA-256 manifest |
| `cloud/isolate_aws_instance.py` | AWS | Isolates EC2 instance via isolation security group |
| `cloud/lockdown_s3_bucket.py` | AWS | Locks down public S3 buckets and preserves rollback state |
| `cloud/isolate_azure_vm.py` | Azure | Isolates Azure VMs with incident NSG rules and rollback state |
| `cloud/isolate_gcp_instance.py` | GCP | Isolates Compute Engine VMs with deny-all firewall tags and rollback state |
| `identity/revoke_azure_sessions.ps1` | Azure AD | Revokes all active sessions for a compromised user |

> **Safety note:** All automation scripts support a `--dry-run` flag. When `APPROVAL_REQUIRED_FOR_CONTAINMENT=true` in `.env`, destructive actions require explicit confirmation. Always validate scope before executing.

### Azure VM Network Containment

The installed `k1n-ir isolate-azure-vm` command previews Azure VM isolation by default. It records the rollback metadata that a live containment run would preserve, previews the incident-specific NSG creation and NIC association, and can optionally deallocate the VM after approval.

Use `--execute` only after containment approval. Live mode requires the Azure identity, compute, and network SDK packages plus the RBAC permissions listed in `automations/cloud/isolate_azure_vm.py`.

### GCP Compute Engine Containment

The installed `k1n-ir isolate-gcp-instance` command runs in dry-run mode by default. It previews the incident-specific network tag, ingress deny-all firewall rule, egress deny-all firewall rule, saved rollback state, and optional stop action without calling GCP APIs.

Use `--execute` only after containment approval. When `APPROVAL_REQUIRED_FOR_CONTAINMENT=true`, the CLI prompts before live execution. Live mode uses Application Default Credentials and requires Compute Engine instance administration plus firewall-rule permissions.

### S3 Bucket Exposure Containment

The installed `k1n-ir lockdown-s3-bucket` command previews a bucket lockdown by default. It records the bucket's public access block, bucket policy, ACL grants, and tag set for rollback, then shows the Public Access Block, public-policy removal, ACL hardening, and incident-tagging steps that live mode would apply.

Use `--execute` only after containment approval. Live mode requires boto3 support (`pip install -e .[aws]` or `pip install boto3`) plus the S3 permissions listed in `automations/cloud/lockdown_s3_bucket.py`.

---

## Incident State Machine

Incidents progress through the following states:

```
DETECTED → TRIAGING → CONFIRMED → CONTAINING → ERADICATING → RECOVERING → CLOSED
                                                                          ↑
                                                            POST_INCIDENT_REVIEW ←┘
```

False positives can be closed at any state with `CLOSED_FALSE_POSITIVE`.

---

## Configuration

All runtime behavior is controlled via `.env` (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `INCIDENT_TYPE` | `generic` | Default incident type for new records |
| `SEVERITY_MODEL` | `standard` | Severity classification model |
| `EVIDENCE_DIR` | `./evidence` | Local directory for evidence storage |
| `SAFE_AUTOMATION_MODE` | `true` | Enables dry-run mode for all automations |
| `APPROVAL_REQUIRED_FOR_CONTAINMENT` | `true` | Requires explicit confirmation before containment |
| `MASKING_MODE` | `true` | Masks sensitive data in logs and reports |

---

## Security

Please report vulnerabilities via the process described in [SECURITY.md](SECURITY.md). Do not open public issues for security findings.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and pull request process.

---

## License

CC BY 4.0 — see [LICENSE](LICENSE). Free to use, share, and adapt with attribution to **Hiago Kin Levi**.
