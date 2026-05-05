from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from schemas.incident import IncidentRecord


def _load_incident_record(path: str) -> IncidentRecord:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    return IncidentRecord.model_validate(data)


def _incident_context(record: IncidentRecord) -> dict[str, Any]:
    return {
        "incident_id": getattr(record, "id", None),
        "severity": getattr(record, "severity", None),
        "status": getattr(record, "status", None),
        "created_at": getattr(record, "created_at", None),
        "updated_at": getattr(record, "updated_at", None),
        "closed_at": getattr(record, "closed_at", None),
        "owner": getattr(record, "owner", None),
    }


@click.group()
def ir() -> None:
    pass


@ir.command("report-html")
@click.option("--template", "template_name", required=True, help="Report template filename under templates/reports")
@click.option("--output", "output_path", required=True, help="Output HTML path")
@click.option("--incident", "incident_path", type=click.Path(exists=True, dir_okay=False), help="Path to incident record JSON/YAML to preload report context")
@click.option("--incident-id", "incident_id", help="Incident ID")
@click.option("--severity", "severity", help="Incident severity")
@click.option("--status", "status", help="Incident status")
@click.option("--created-at", "created_at", help="Incident created timestamp")
@click.option("--updated-at", "updated_at", help="Incident updated timestamp")
@click.option("--closed-at", "closed_at", help="Incident closed timestamp")
@click.option("--owner", "owner", help="Incident owner")
def report_html(
    template_name: str,
    output_path: str,
    incident_path: str | None,
    incident_id: str | None,
    severity: str | None,
    status: str | None,
    created_at: str | None,
    updated_at: str | None,
    closed_at: str | None,
    owner: str | None,
) -> None:
    context: dict[str, Any] = {}

    if incident_path:
        try:
            record = _load_incident_record(incident_path)
            context.update(_incident_context(record))
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValidationError) as exc:
            raise click.ClickException(f"Failed to load incident record from '{incident_path}': {exc}") from exc

    explicit = {
        "incident_id": incident_id,
        "severity": severity,
        "status": status,
        "created_at": created_at,
        "updated_at": updated_at,
        "closed_at": closed_at,
        "owner": owner,
    }
    context.update({k: v for k, v in explicit.items() if v is not None})

    env = Environment(
        loader=FileSystemLoader("templates/reports"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)
    rendered = template.render(**context)
    Path(output_path).write_text(rendered, encoding="utf-8")
