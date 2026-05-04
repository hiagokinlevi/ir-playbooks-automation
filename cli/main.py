from __future__ import annotations

import json
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.option("--incident", "incident_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="Path to incident JSON file")
@click.option("--template", "template_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True, help="Path to Jinja2 HTML template")
@click.option("--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), required=False, help="Write rendered HTML to explicit file path")
@click.option("--force", is_flag=True, default=False, help="Overwrite output file if it already exists")
def report_html(incident_path: Path, template_path: Path, output_path: Path | None, force: bool) -> None:
    """Render an incident report as HTML."""
    incident_data = json.loads(incident_path.read_text(encoding="utf-8"))

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_path.name)
    rendered = template.render(incident=incident_data)

    if output_path is None:
        click.echo(rendered)
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists() and not force:
        raise click.ClickException(
            f"Output file already exists: {output_path}. Use --force to overwrite."
        )

    output_path.write_text(rendered, encoding="utf-8")
    click.echo(f"Wrote HTML report to {output_path}")


if __name__ == "__main__":
    cli()
