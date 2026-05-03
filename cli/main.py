from __future__ import annotations

import json
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.argument("incident_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path to write rendered HTML report.",
)
@click.option(
    "--title",
    "report_title",
    type=str,
    required=False,
    help="Optional custom heading for the HTML report; defaults to incident title.",
)
def report_html(incident_file: Path, output_file: Path, report_title: str | None) -> None:
    """Generate an HTML incident report from an incident JSON record."""
    incident = json.loads(incident_file.read_text(encoding="utf-8"))

    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("reports/incident_report.html.j2")

    effective_title = report_title or incident.get("title") or "Incident Report"

    html = template.render(
        incident=incident,
        title=effective_title,
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(html, encoding="utf-8")
    click.echo(f"HTML report written to {output_file}")


if __name__ == "__main__":
    cli()
