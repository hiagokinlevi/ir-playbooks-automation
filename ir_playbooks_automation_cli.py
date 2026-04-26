import json
from datetime import datetime
from pathlib import Path

import click

INCIDENT_DB = Path(".incidents.json")


def _load_incidents() -> dict:
    if not INCIDENT_DB.exists():
        return {}
    return json.loads(INCIDENT_DB.read_text(encoding="utf-8"))


@click.group()
def cli():
    """IR Playbooks Automation CLI."""


@cli.command("incident-summary")
@click.argument("incident_id")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help=(
        "Emit machine-readable JSON with keys: incident_id, current_state, severity, opened_at, updated_at. "
        "Example: ir incident-summary IR-2026-001 --json | jq -r '.severity'"
    ),
)
def incident_summary(incident_id: str, as_json: bool) -> None:
    """Show summary for an incident by ID."""
    incidents = _load_incidents()
    incident = incidents.get(incident_id)

    if not incident:
        raise click.ClickException(f"Incident not found: {incident_id}")

    summary = {
        "incident_id": incident_id,
        "current_state": incident.get("current_state", "unknown"),
        "severity": incident.get("severity", "unknown"),
        "opened_at": incident.get("opened_at"),
        "updated_at": incident.get("updated_at") or datetime.utcnow().isoformat() + "Z",
    }

    if as_json:
        click.echo(json.dumps(summary))
        return

    click.echo(f"Incident ID: {summary['incident_id']}")
    click.echo(f"Current State: {summary['current_state']}")
    click.echo(f"Severity: {summary['severity']}")
    click.echo(f"Opened At: {summary['opened_at']}")
    click.echo(f"Updated At: {summary['updated_at']}")


if __name__ == "__main__":
    cli()
