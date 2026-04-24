#!/usr/bin/env python3
"""IR Playbooks Automation CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception as exc:  # pragma: no cover
    raise RuntimeError("Jinja2 is required for report rendering") from exc


@click.group(help="IR Playbooks Automation CLI")
def cli() -> None:
    pass


@cli.command("report-html")
@click.argument("incident_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    required=True,
    help="Deterministic output HTML file path.",
)
def report_html(incident_file: Path, out_path: Path) -> None:
    """Render a single-incident HTML report from JSON/YAML input."""

    def _load_input(path: Path) -> dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()

        try:
            if suffix in {".yaml", ".yml"}:
                if yaml is None:
                    raise click.ClickException("PyYAML is required to read YAML incident files")
                parsed = yaml.safe_load(raw)
            else:
                parsed = json.loads(raw)
        except click.ClickException:
            raise
        except Exception as e:
            raise click.ClickException(f"Failed parsing incident input: {e}") from e

        if not isinstance(parsed, dict):
            raise click.ClickException("Incident input must be a JSON/YAML object")

        required_any = ["incident_id", "id"]
        if not any(k in parsed and parsed.get(k) for k in required_any):
            raise click.ClickException("Incident input missing required identifier field: incident_id or id")

        return parsed

    def _safe_defaults(incident: dict[str, Any]) -> dict[str, Any]:
        incident_id = incident.get("incident_id") or incident.get("id") or "unknown-incident"
        title = incident.get("title") or incident.get("name") or "Untitled Incident"
        severity = incident.get("severity") or "unknown"
        status = incident.get("status") or "unknown"
        summary = incident.get("summary") or incident.get("description") or ""
        indicators = incident.get("indicators")
        if not isinstance(indicators, list):
            indicators = []
        timeline = incident.get("timeline")
        if not isinstance(timeline, list):
            timeline = []
        return {
            "incident": incident,
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "status": status,
            "summary": summary,
            "indicators": indicators,
            "timeline": timeline,
        }

    incident = _load_input(incident_file)
    context = _safe_defaults(incident)

    templates_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    candidate_templates = [
        "reports/incident_report.html.j2",
        "reports/incident-report.html.j2",
        "reports/incident_report.j2",
        "reports/incident-report.j2",
        "reports/incident_report.html",
        "reports/incident-report.html",
    ]

    template = None
    for tpl_name in candidate_templates:
        try:
            template = env.get_template(tpl_name)
            break
        except Exception:
            continue

    if template is None:
        raise click.ClickException(
            "No report template found under templates/reports/. "
            "Expected one of: " + ", ".join(candidate_templates)
        )

    try:
        rendered = template.render(**context)
    except Exception as e:
        raise click.ClickException(f"Failed rendering HTML report: {e}") from e

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    click.echo(str(out_path))


if __name__ == "__main__":
    cli()
