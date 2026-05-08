from __future__ import annotations

import json
from pathlib import Path

import click

from schemas.incident import IncidentRecord


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("validate-incident")
@click.argument("incident_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--schema-version",
    "schema_version",
    default=None,
    help="Expected schema version for compatibility check (e.g. 1.0).",
)
def validate_incident(incident_file: Path, schema_version: str | None) -> None:
    """Validate an incident record JSON against the incident schema."""
    try:
        data = json.loads(incident_file.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        raise click.ClickException(f"Failed to read incident file: {exc}")

    if schema_version is not None:
        detected_version = data.get("schema_version")
        if detected_version != schema_version:
            raise click.ClickException(
                "Schema version mismatch: "
                f"expected '{schema_version}', detected '{detected_version}'."
            )

    try:
        IncidentRecord.model_validate(data)
    except Exception as exc:
        raise click.ClickException(f"Incident validation failed: {exc}")

    click.echo("Incident record is valid.")
