# Documentation Directory

This directory contains architecture notes, usage guidance, and contributor-facing documentation for `ir-playbooks-automation`.

## Purpose

Use `docs/` for:
- Design and architecture decisions
- Contributor guides and standards
- Operational documentation that does **not** belong inside a specific playbook/template folder

## How to Add New Documentation

1. Create a focused Markdown file under `docs/` (or a clearly named subfolder if needed).
2. Use descriptive filenames (for example: `workflow-engine-design.md`).
3. Keep content actionable, version-aware, and aligned with current CLI/workflow behavior.
4. Cross-link related documents and relevant playbooks/templates.

## Related Directories

- `playbooks/` — executable response procedures (triage, containment, eradication, recovery, incident-type specific)
- `templates/` — reusable document templates (incident records, timelines, reports, communications)

## Contributor Notes for Playbooks and Templates

When adding a new playbook or template:

- Place it in the correct lifecycle/category subdirectory.
- Start with a clear scope, prerequisites, and expected outcome.
- Include safety checks and rollback guidance for any containment/automation steps.
- Prefer consistent section headers and markdown style across files.
- Add or update references here in `docs/` when introducing new conventions.
