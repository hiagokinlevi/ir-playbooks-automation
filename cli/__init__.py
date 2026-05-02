from __future__ import annotations

import json
from pathlib import Path

import click
import yaml

from schemas.incident import IncidentRecord


@click.group()
def cli() -> None:
    pass


@cli.command("incident-summary")
@click.option("--file", "file_path", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Path to incident JSON/YAML record.")
@click.option("--json", "as_json", is_flag=True, help="Render summary as JSON.")
@click.option("--format", "output_format", type=click.Choice(["text", "json"], case_sensitive=False), default="text", show_default=True)
def incident_summary(file_path: Path | None, as_json: bool, output_format: str) -> None:
    """Render incident summary from a record file."""

    incident_path = file_path if file_path is not None else Path("incident-record.json")

    if not incident_path.exists():
        raise click.ClickException(f"Incident record file not found: {incident_path}")

    try:
        raw = incident_path.read_text(encoding="utf-8")
        suffix = incident_path.suffix.lower()
        if suffix in {".yaml", ".yml"}:
            payload = yaml.safe_load(raw)
        else:
            payload = json.loads(raw)
        incident = IncidentRecord.model_validate(payload)
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(f"Failed to parse incident record '{incident_path}': {exc}") from exc

    render_json = as_json or output_format.lower() == "json"
    if render_json:
        click.echo(json.dumps(incident.model_dump(mode="json"), indent=2, default=str))
        return

    click.echo(f"Incident ID: {incident.incident_id}")
    click.echo(f"Title: {incident.title}")
    click.echo(f"Severity: {incident.severity}")
