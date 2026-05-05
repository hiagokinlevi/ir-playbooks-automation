from __future__ import annotations

import json
import webbrowser
from pathlib import Path

import click


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.option(
    "--input",
    "input_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Path to incident JSON file.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Path to write generated HTML report.",
)
@click.option(
    "--open",
    "open_in_browser",
    is_flag=True,
    default=False,
    help="Open generated report in default browser after successful generation.",
)
def report_html(input_path: Path, output_path: Path, open_in_browser: bool) -> None:
    """Generate an HTML incident report from incident JSON."""
    data = json.loads(input_path.read_text(encoding="utf-8"))
    title = data.get("title", "Incident Report")
    body = data.get("summary", "")

    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
</head>
<body>
  <h1>{title}</h1>
  <pre>{body}</pre>
</body>
</html>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    click.echo(f"HTML report written: {output_path}")

    if open_in_browser:
        try:
            report_uri = output_path.resolve().as_uri()
            webbrowser.open(report_uri, new=2)
        except Exception as exc:  # fail-safe: report generation already succeeded
            click.echo(f"Warning: failed to open browser: {exc}", err=True)


if __name__ == "__main__":
    cli()
