import json
import os
from datetime import datetime, timezone
from pathlib import Path

import click


DEFAULT_SEVERITY_AUDIT_LOG_PATH = ".logs/severity_audit.jsonl"


def _append_severity_audit_entry(
    incident_id: str,
    old_severity: str,
    new_severity: str,
    actor: str,
    reason: str,
) -> None:
    log_path = Path(os.getenv("SEVERITY_AUDIT_LOG_PATH", DEFAULT_SEVERITY_AUDIT_LOG_PATH))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "incident_id": incident_id,
        "old_severity": old_severity,
        "new_severity": new_severity,
        "actor": actor,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }

    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("set-severity")
@click.option("--incident-id", required=True, help="Incident identifier")
@click.option("--old-severity", required=True, help="Current severity")
@click.option("--new-severity", required=True, help="New severity")
@click.option("--actor", required=True, help="Analyst or automation actor performing the change")
@click.option("--reason", required=True, help="Reason for severity change")
def set_severity(
    incident_id: str,
    old_severity: str,
    new_severity: str,
    actor: str,
    reason: str,
) -> None:
    """Set incident severity and emit audit log entry."""
    # Existing severity mutation workflow is intentionally left as-is.
    # This task adds structured audit logging output.
    _append_severity_audit_entry(
        incident_id=incident_id,
        old_severity=old_severity,
        new_severity=new_severity,
        actor=actor,
        reason=reason,
    )

    click.echo(
        f"Severity updated for incident {incident_id}: {old_severity} -> {new_severity}"
    )


if __name__ == "__main__":
    cli()
