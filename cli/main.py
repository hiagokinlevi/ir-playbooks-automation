from __future__ import annotations

import json
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape


def _build_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Incident JSON input")
@click.option("--output", "output_path", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Rendered HTML output path")
@click.option(
    "--css",
    "css_path",
    required=False,
    type=click.Path(exists=False, dir_okay=False, path_type=Path),
    help="Optional local CSS file to inject into the report.",
)
def report_html(input_path: Path, output_path: Path, css_path: Path | None) -> None:
    """Render incident report HTML from JSON."""
    with input_path.open("r", encoding="utf-8") as f:
        incident = json.load(f)

    custom_css = ""
    if css_path is not None:
        if not css_path.exists():
            raise click.ClickException(f"CSS file not found: {css_path}")
        if not css_path.is_file():
            raise click.ClickException(f"CSS path is not a file: {css_path}")
        try:
            custom_css = css_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise click.ClickException(f"Unable to read CSS file '{css_path}': {exc}") from exc

    env = _build_jinja_env()
    template = env.get_template("reports/incident_report.html.j2")
    rendered = template.render(incident=incident, custom_css=custom_css)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    click.echo(f"HTML report written: {output_path}")


if __name__ == "__main__":
    cli()
