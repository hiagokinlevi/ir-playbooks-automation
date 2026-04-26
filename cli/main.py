from __future__ import annotations

import json
import webbrowser
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, StrictUndefined


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.argument("incident_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("incident-report.html"),
    show_default=True,
    help="Write rendered HTML report to this file path.",
)
@click.option("--open", "open_in_browser", is_flag=True, help="Open generated report in the default browser.")
@click.option(
    "--stdout",
    "to_stdout",
    is_flag=True,
    help="Emit rendered HTML to standard output instead of writing a file.",
)
def report_html(incident_file: Path, output_file: Path, open_in_browser: bool, to_stdout: bool) -> None:
    """Render an incident JSON file as an HTML report."""
    try:
        incident = json.loads(incident_file.read_text(encoding="utf-8"))
        env = Environment(
            loader=FileSystemLoader("templates/reports"),
            autoescape=True,
            undefined=StrictUndefined,
        )
        template = env.get_template("incident_report.html.j2")
        rendered = template.render(incident=incident)
    except Exception as exc:  # production CLI error surface
        raise click.ClickException(f"Failed to render HTML report: {exc}") from exc

    if to_stdout:
        click.echo(rendered)
        return

    output_file.write_text(rendered, encoding="utf-8")
    click.echo(f"HTML report written: {output_file}")

    if open_in_browser:
        webbrowser.open(output_file.resolve().as_uri())
