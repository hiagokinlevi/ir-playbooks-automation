#!/usr/bin/env python3
"""
IR Playbooks Automation CLI
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape


DEFAULT_HTML_TEMPLATE = Path("templates/reports/incident_report.html.j2")


@click.group()
def cli() -> None:
    """Incident response playbooks automation CLI."""


@cli.command("report-html")
@click.option("--incident", "incident_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to incident JSON file")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Output HTML report path")
@click.option(
    "--template",
    "template_path",
    required=False,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Optional path to a custom Jinja2 HTML template",
)
def report_html(incident_path: Path, out_path: Path, template_path: Path | None) -> None:
    """Generate an HTML incident report from incident JSON."""

    if template_path is not None:
        if not template_path.exists():
            raise click.ClickException(f"Template file not found: {template_path}")
        if not template_path.is_file():
            raise click.ClickException(f"Template path is not a file: {template_path}")
        selected_template = template_path
    else:
        selected_template = DEFAULT_HTML_TEMPLATE

    if not selected_template.exists():
        raise click.ClickException(
            f"Default template not found: {selected_template}. "
            "Provide a template with --template."
        )

    try:
        incident_data = _load_incident_json(incident_path)
        html = _render_html_report(incident_data, selected_template)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(f"Failed generating HTML report: {exc}") from exc

    click.echo(f"HTML report generated: {out_path}")


def _load_incident_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid incident JSON at {path}: {exc}") from exc


def _render_html_report(incident: Dict[str, Any], template_path: Path) -> str:
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_path.name)
    return template.render(incident=incident)


if __name__ == "__main__":
    cli()
