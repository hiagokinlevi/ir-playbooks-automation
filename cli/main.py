from __future__ import annotations

import json
import webbrowser
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.group("ir")
def ir_group() -> None:
    """Incident response commands."""


@ir_group.command("report-html")
@click.option("--incident", "incident_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to incident JSON file.")
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Path to write generated HTML report.")
@click.option("--open", "open_in_browser", is_flag=True, help="Open generated report in the default browser after creation.")
def report_html(incident_path: Path, output_path: Path, open_in_browser: bool) -> None:
    """Generate HTML incident report from incident JSON."""
    with incident_path.open("r", encoding="utf-8") as f:
        incident = json.load(f)

    templates_dir = Path(__file__).resolve().parents[1] / "templates" / "reports"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("incident_report.html.j2")
    rendered = template.render(incident=incident)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")

    click.echo(f"Generated HTML report: {output_path}")

    if open_in_browser:
        webbrowser.open(output_path.resolve().as_uri())
