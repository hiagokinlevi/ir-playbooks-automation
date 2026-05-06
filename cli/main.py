from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import click


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.group("ir")
def ir_group() -> None:
    """Incident response helpers."""


@ir_group.command("report-html")
@click.option("--incident", "incident_id", required=False, help="Incident identifier.")
@click.option("--template", "template_name", required=False, default="default", show_default=True, help="Report template name.")
@click.option("--output", "output_path", required=True, type=click.Path(path_type=Path), help="Output HTML report path.")
@click.option("--metadata", "emit_metadata", is_flag=True, default=False, help="Emit report generation metadata JSON to stdout.")
def report_html(incident_id: str | None, template_name: str, output_path: Path, emit_metadata: bool) -> None:
    """Generate an HTML incident report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("<html><body><h1>Incident Report</h1></body></html>", encoding="utf-8")

    click.echo(f"Generated HTML report: {output_path}")

    if emit_metadata:
        metadata = {
            "report_path": str(output_path),
            "incident_id": incident_id,
            "template": template_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "success": True,
        }
        click.echo(json.dumps(metadata, separators=(",", ":")))
