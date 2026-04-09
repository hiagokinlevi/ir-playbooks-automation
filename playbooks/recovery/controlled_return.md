# Recovery — Controlled Return to Service Playbook
**Phase:** Recovery | **Maturity:** Operational | **Version:** 1.0

## Objective
Restore affected systems and services to normal operation in a controlled, monitored
manner — confirming at each step that the threat has been fully expelled and that
restored services are not re-compromised.

## Prerequisites
- Eradication phase completed and documented
- Eradication validation passed (all persistence checks clean)
- Change management record open for recovery actions
- Enhanced monitoring in place for re-compromise detection

---

## Pre-Recovery Checklist

Before restoring any service:

- [ ] Eradication sign-off obtained from IR lead
- [ ] New credentials issued for all accounts involved in the incident
- [ ] MFA enforced on all restored accounts
- [ ] Patching or remediation of initial access vector confirmed
- [ ] Security monitoring (SIEM rules, EDR alerts) confirmed active on affected systems
- [ ] Rollback plan documented in case re-compromise is detected

---

## Step 1 — Prioritize Recovery Order (10 min)

Not all services need to be restored simultaneously. Prioritize by:

1. **Business criticality** — restore revenue-generating or customer-facing services first
2. **Security risk** — restore services with lower risk of re-compromise first
3. **Dependencies** — restore foundational services (auth, DNS, databases) before dependent services

Create a recovery order table:

| Priority | Service | Owner | Estimated Restore Time | Dependencies |
|---|---|---|---|---|
| 1 | Authentication service | Identity Team | 30 min | None |
| 2 | Core API | Platform Team | 45 min | Auth |
| 3 | Customer portal | Web Team | 1h | Core API |

---

## Step 2 — Restore from Known-Good State

Choose the appropriate restoration method for each affected system:

### Option A: Restore from Backup
1. Identify the last known-good backup (must predate the attacker's initial access time)
2. Verify backup integrity: compare hash against backup manifest
3. Restore to a staging environment first and validate functionality
4. Promote to production after validation

### Option B: Rebuild from Infrastructure as Code
```bash
# Example: rebuild EC2 instance from Terraform
terraform apply -target=aws_instance.<instance_name>
```

1. Apply the IaC configuration to a new instance
2. Deploy the application from the known-good artifact (signed container image, release tag)
3. Verify the new instance is clean before routing traffic

### Option C: In-Place Recovery (lower-risk systems only)
1. Verify clean state confirmed by eradication validation
2. Restore original configuration from version control
3. Restart services
4. Monitor closely for 24–48h post-recovery

---

## Step 3 — Validate Before Restoring Traffic

For each restored service, run the following validation gates:

**Security validation:**
- [ ] EDR/AV scan clean
- [ ] No unexpected outbound connections
- [ ] New credentials in place; old credentials revoked
- [ ] MFA enforced on all accounts

**Functional validation:**
- [ ] Application health check endpoints returning 200
- [ ] Core user flows tested (login, key operations)
- [ ] Integration points with dependent services tested
- [ ] Performance metrics within normal range

**Only route production traffic after both security and functional validation pass.**

---

## Step 4 — Restore Traffic Incrementally

For high-impact services, use a staged traffic restoration:

1. **Canary (5%):** Route a small percentage of traffic; monitor for 30 minutes
2. **Partial (25%):** If canary is clean, expand; monitor for 1 hour
3. **Full (100%):** If partial is clean, route all traffic; monitor for 4 hours

Automate rollback triggers if:
- Error rate exceeds 1%
- Latency exceeds 2x baseline
- Security alert fires on restored infrastructure

---

## Step 5 — Enhanced Monitoring Window

After full restoration, maintain an enhanced monitoring posture for a minimum of 7 days:

- [ ] SIEM alerting lowered threshold on affected asset class
- [ ] Daily review of authentication logs for affected accounts
- [ ] Daily review of network flows from restored systems
- [ ] EDR real-time protection confirmed active
- [ ] Alert fatigue review after 48h — tune any noisy rules

---

## Step 6 — Communicate Restoration

| Audience | Message | Timing |
|---|---|---|
| Internal stakeholders | Service restored, monitoring active | Immediately after full restoration |
| Customers (if impacted) | Service fully restored, investigation complete | Per legal/comms guidance |
| Regulators (if applicable) | Follow statutory notification timelines | Per legal guidance |

---

## Documentation Checkpoint
- [ ] Recovery order documented
- [ ] Restoration method documented for each system
- [ ] Security and functional validation passed for all restored services
- [ ] Traffic restoration approach documented
- [ ] Enhanced monitoring period start time recorded
- [ ] Stakeholders notified of restoration
- [ ] Recovery timestamp recorded in incident record
- [ ] Schedule Post-Incident Review (PIR) within 5 business days
