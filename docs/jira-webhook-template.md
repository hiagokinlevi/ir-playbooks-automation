# Jira Incident Update Payload Template

Use `templates/communications/jira-incident-update-payload.json` as a base payload for Jira issue updates from incident state.

## Usage

1. Load the JSON template.
2. Replace `{{ ... }}` placeholders from your incident schema object.
3. POST to your Jira integration endpoint (or automation bridge) that performs authenticated Jira API calls.

> This repository currently provides only the payload template and mapping guidance. It does **not** include direct Jira API integration in this increment.

## Placeholder mapping

- `incident.id` → internal incident identifier
- `incident.title` → incident title/name
- `incident.status` → workflow status
- `incident.severity` → current severity level
- `incident.owner` → assigned analyst/owner
- `incident.detected_at` / `incident.updated_at` → timestamps
- `incident.affected_assets` → list of impacted systems/assets
- `incident.iocs` → list of IOCs
- `incident.latest_timeline_entry` → most recent timeline note
- `incident.next_actions` → analyst-defined next steps
- `incident.external_refs.jira.issue_key` → Jira issue key (for update target)
- `incident.detection_source` → source that triggered detection
- `incident.containment_status` → current containment state

## Notes

- `customfield_*` keys are examples and should be replaced with your Jira instance custom field IDs.
- Keep labels constrained and normalized for reliable Jira filtering.
