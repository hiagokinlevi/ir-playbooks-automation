#!/usr/bin/env python3
"""CLI for incident response playbooks automation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import click


INCIDENTS_DIR = Path("incidents")


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("incident-summary")
@click.argument("incident_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "format_template",
    default=None,
    help=(
        "Custom one-line template using incident placeholders. "
        "Allowed: {id} {title} {severity} {state} {owner} {created_at} {updated_at}.\n"
        "Examples:\n"
        "  ir incident-summary incidents/IR-2026-0042.json --format '{id} {severity} {state} {owner}'\n"
        "  ir incident-summary incidents/IR-2026-0042.json --format '[{severity}] {id} - {title}'\n"
        "  ir incident-summary incidents/IR-2026-0042.json --format '{id}:{state}'"
    ),
)
def incident_summary(incident_file: Path, format_template: str | None) -> None:
    """Print a concise incident summary."""
    with incident_file.open("r", encoding="utf-8") as fh:
        incident: dict[str, Any] = json.load(fh)

    if format_template:
        placeholder_map: dict[str, Any] = {
            "id": incident.get("id", ""),
            "title": incident.get("title", ""),
            "severity": incident.get("severity", ""),
            "state": incident.get("state", ""),
            "owner": incident.get("owner", ""),
            "created_at": incident.get("created_at", ""),
            "updated_at": incident.get("updated_at", ""),
        }

        keys = set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", format_template))
        unknown = sorted(k for k in keys if k not in placeholder_map)
        if unknown:
            allowed = " ".join(f"{{{k}}}" for k in placeholder_map)
            unknown_joined = ", ".join(unknown)
            raise click.ClickException(
                f"Unknown placeholder(s): {unknown_joined}. Allowed placeholders: {allowed}"
            )

        rendered = format_template
        for key, value in placeholder_map.items():
            rendered = rendered.replace(f"{{{key}}}", str(value))
        click.echo(rendered)
        return

    click.echo(
        f"{incident.get('id', 'N/A')} "
        f"severity={incident.get('severity', 'unknown')} "
        f"state={incident.get('state', 'unknown')} "
        f"owner={incident.get('owner', 'unassigned')}"
    )


if __name__ == "__main__":
    cli()
