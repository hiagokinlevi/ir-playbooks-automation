from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("report-html")
@click.option("--incident-id", required=True, help="Incident identifier")
@click.option("--title", default="Incident Report", show_default=True, help="Report title")
@click.option("--output", "output_path", "-o", type=click.Path(path_type=Path), required=False, help="Write HTML report to an explicit path")
@click.option("--json", "json_mode", is_flag=True, help="Output machine-readable JSON")
def report_html(incident_id: str, title: str, output_path: Optional[Path], json_mode: bool) -> None:
    """Generate an HTML incident report."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if output_path is None:
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        final_path = reports_dir / f"{incident_id}-{timestamp}.html"
    else:
        final_path = output_path.expanduser()
        final_path.parent.mkdir(parents=True, exist_ok=True)

    html = f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>{title}</title>
  </head>
  <body>
    <h1>{title}</h1>
    <p><strong>Incident ID:</strong> {incident_id}</p>
    <p><strong>Generated (UTC):</strong> {timestamp}</p>
  </body>
</html>
"""

    final_path.write_text(html, encoding="utf-8")

    if json_mode:
        click.echo(json.dumps({"status": "ok", "path": str(final_path)}))
    else:
        click.echo(f"HTML report written: {final_path}")


if __name__ == "__main__":
    cli()
