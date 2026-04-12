# Cloud Exposure — Containment Playbook
**Phase:** Containment | **Maturity:** Operational | **Version:** 1.0

## Objective
Remediate an exposed cloud resource (storage bucket, database, compute instance, API,
or misconfigured IAM policy) to eliminate public or unauthorized access while preserving
evidence and minimizing service disruption.

## Prerequisites
- Incident ID opened (severity typically Medium–Critical depending on data sensitivity)
- Cloud console or CLI access with sufficient permissions to modify resource policies
- Inventory of services that legitimately depend on the exposed resource
- Change management approval (for production resources)

---

## Step 1 — Identify and Scope the Exposure (10 min)

1. Identify the resource type and location:
   - Storage bucket (S3, GCS, Azure Blob)
   - Database (RDS, Cloud SQL, Cosmos DB)
   - Compute instance (EC2, GCE, Azure VM)
   - API endpoint (API Gateway, Cloud Endpoints)
   - IAM policy (overly permissive role, public trust)

2. Determine the exposure vector:
   - Public access enabled on resource policy
   - Misconfigured security group / network ACL
   - Overly permissive IAM role or resource-based policy
   - Public IP with no authentication

3. Assess what data is accessible:
   - Enumerate objects/records accessible without authentication
   - Classify data sensitivity (PII, financial, secrets, internal configs)
   - Estimate the volume of potentially accessed data

4. Review access logs for evidence of unauthorized access:
   - AWS: CloudTrail + S3 access logs
   - GCP: Cloud Audit Logs + GCS access logs
   - Azure: Azure Activity Log + Storage analytics

**Decision gate:**
- If sensitive data (PII, credentials, financial) is confirmed accessible → escalate to Critical, notify Legal/Compliance
- If access logs show external reads → treat as confirmed data exposure

---

## Step 2 — Preserve Evidence (5 min)

Before making any changes to the resource:

```bash
# Package current resource configuration as evidence
python automations/evidence_packaging/packager.py \
  --incident-id <INC-ID> \
  --source-type cloud_config \
  --notes "Pre-remediation snapshot of exposed resource"
```

Manually capture:
- [ ] Screenshot or JSON export of current resource policy/ACL
- [ ] Access log export for the past 30 days (or since last known-good configuration)
- [ ] List of IAM principals with access to the resource

---

## Step 3 — Contain the Exposure (10 min)

### S3 Bucket (AWS)
```bash
# Preview the lockdown and save rollback state to a file
k1n-ir lockdown-s3-bucket \
  --bucket-name <bucket-name> \
  --incident-id <INC-ID> \
  --output s3-lockdown-preview.json

# Execute only after containment approval
k1n-ir lockdown-s3-bucket \
  --bucket-name <bucket-name> \
  --incident-id <INC-ID> \
  --execute
```

### EC2 Instance (AWS) — Network Exposure
```bash
# Isolate via automation script (dry_run=False requires approval)
python automations/cloud/isolate_aws_instance.py \
  --instance-id <i-XXXXXXX> \
  --incident-id <INC-ID> \
  --region us-east-1
```

### Compute Engine VM (GCP) — Network Exposure
```bash
# Preview isolation and save rollback state to a file
k1n-ir isolate-gcp-instance \
  --project-id <project-id> \
  --zone us-central1-a \
  --instance-name <instance-name> \
  --incident-id <INC-ID> \
  --output gcp-isolation-preview.json

# Execute only after containment approval
k1n-ir isolate-gcp-instance \
  --project-id <project-id> \
  --zone us-central1-a \
  --instance-name <instance-name> \
  --incident-id <INC-ID> \
  --execute
```

### Azure VM — Network Exposure
```bash
# Preview NSG isolation and save rollback state to a file
k1n-ir isolate-azure-vm \
  --subscription-id <subscription-id> \
  --resource-group <resource-group> \
  --vm-name <vm-name> \
  --incident-id <INC-ID> \
  --output azure-isolation-preview.json

# Execute only after containment approval
k1n-ir isolate-azure-vm \
  --subscription-id <subscription-id> \
  --resource-group <resource-group> \
  --vm-name <vm-name> \
  --incident-id <INC-ID> \
  --execute
```

### Azure Blob Container
```bash
# Set container to private (removes anonymous access)
az storage container set-permission \
  --name <container-name> \
  --account-name <storage-account> \
  --public-access off
```

### Overly Permissive IAM Policy (AWS)
```bash
# Detach the permissive policy from role
aws iam detach-role-policy \
  --role-name <role-name> \
  --policy-arn <policy-arn>

# Apply a deny policy to block access immediately while replacement is prepared
# (See templates/incident-records/incident_template.md for policy template)
```

---

## Step 4 — Verify Containment (5 min)

1. Attempt to reproduce the original exposure from an external/unauthenticated context
2. Confirm access is now blocked
3. Verify that legitimate services still function (check monitoring/alerting)
4. If a legitimate service is broken → roll back only that specific change and find an alternative containment

---

## Step 5 — Rotate Exposed Credentials

If the exposed resource contained secrets (API keys, database passwords, tokens):

- [ ] Identify all secrets in the exposed resource
- [ ] Rotate each secret immediately
- [ ] Update all consumers of the rotated secrets
- [ ] Verify no hardcoded versions remain in code or config files

---

## Step 6 — Notify Stakeholders

| Audience | Trigger | Content |
|---|---|---|
| Service owners | Resource modified | What changed, expected impact, rollback plan |
| Security leadership | Any confirmed exposure | Scope, data accessed, containment status |
| Legal/Compliance | PII or regulated data involved | Regulatory notification obligations |
| Customers | If customer data confirmed exposed | Per legal guidance |

---

## Documentation Checkpoint
- [ ] Exposure vector identified and documented
- [ ] Evidence preserved before changes
- [ ] Resource access restricted
- [ ] Containment verified from external perspective
- [ ] Exposed secrets rotated
- [ ] Stakeholders notified
- [ ] Proceed to Eradication playbook to identify root cause (misconfiguration origin)
