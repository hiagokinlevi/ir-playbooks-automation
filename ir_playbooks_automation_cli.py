#!/usr/bin/env python3
"""CLI for incident response playbooks automation."""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.group(help="Incident response playbooks automation CLI")
def cli() -> None:
    pass


@cli.command("validate-record", help="Validate an incident record JSON against the incident schema.")
@click.argument("record_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_record(record_path: Path) -> None:
    """Validate incident record JSON file syntax and shape.

    Note: validation flow intentionally kept stable for existing automation.
    """
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise click.ClickException("Incident record must be a JSON object")

    # Existing lightweight validation behavior (kept unchanged)
    required_keys = {"incident_id", "title", "severity", "status"}
    missing = sorted(required_keys - set(payload.keys()))
    if missing:
        raise click.ClickException(f"Missing required fields: {', '.join(missing)}")

    click.echo("Incident record schema validation passed")


@cli.command(
    "validate-schema",
    help="Preferred alias for incident record schema validation (same behavior as 'validate-record').",
)
@click.argument("record_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_schema(record_path: Path) -> None:
    """Alias for validate-record.

    Kept as a thin wrapper to preserve behavior and return codes.
    """
    validate_record.callback(record_path)  # type: ignore[attr-defined]


if __name__ == "__main__":
    cli()
