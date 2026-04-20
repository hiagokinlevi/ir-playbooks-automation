# Roadmap

This roadmap outlines planned improvements and features. Priorities may shift based on community feedback and real-world IR needs.

---

## v1.1 — Expanded Cloud Coverage

- [x] Azure VM network isolation via NSG automation
- [x] S3 bucket public-access lockdown automation
- [ ] GCS bucket exposure containment

## v1.2 — Enhanced Evidence Collection

- [ ] Automated memory image metadata packaging
- [ ] Cloud trail export packaging (CloudTrail, Azure Activity Log, GCP Audit Log)
- [ ] Velociraptor artifact integration for endpoint evidence
- [ ] Evidence chain-of-custody signature support (GPG signing)

## v1.3 — Reporting and Metrics

- [ ] HTML report generation (Jinja2 templates)
- [ ] PDF export for executive briefs
- [ ] MTTR / MTTD metrics dashboard (Markdown + CSV output)
- [ ] STIX/TAXII output for threat intel sharing

## v1.4 — Integrations

- [ ] PagerDuty incident creation via CLI
- [ ] Jira ticket creation and update
- [ ] Slack notification on severity escalation
- [ ] TheHive case creation automation

## v2.0 — Workflow Engine

- [ ] YAML-defined playbook workflows with conditional branching
- [ ] Playbook execution engine with state persistence
- [ ] Analyst assignment and SLA tracking
- [ ] Multi-tenant incident isolation for MSSP deployments

---

## Completed

- [x] Initial triage playbook
- [x] Credential compromise containment playbook
- [x] Cloud exposure containment playbook
- [x] AWS EC2 isolation automation
- [x] Azure VM network isolation automation (`isolate_azure_vm.py`)
- [x] GCP Compute Engine isolation automation (`isolate_gcp_instance.py`)
- [x] Azure session revocation script
- [x] Evidence packaging with SHA-256 manifest
- [x] Pydantic incident schemas
- [x] Incident state machine
- [x] Click CLI (open-incident, set-severity,

## Automated Completions
- [x] Add triage checklist for analysts (cycle 22)
