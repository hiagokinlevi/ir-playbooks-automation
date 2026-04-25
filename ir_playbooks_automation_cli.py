from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


def _load_incident_record(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")

    # Try JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Fallback to YAML
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return data
    except Exception as exc:  # pragma: no cover - defensive fallback
        raise click.ClickException(f"Failed to parse incident record: {exc}") from exc

    raise click.ClickException("Incident record must be a JSON or YAML object")


def _summary_from_record(record: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "incident_id": record.get("incident_id", "-"),
        "current_state": record.get("current_state", "-"),
        "severity": record.get("severity", "-"),
        "owner": record.get("owner"),
        "last_updated": record.get("last_updated", "-"),
    }
    return summary


@cli.command("incident-summary")
@click.argument("incident_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit summary as JSON")
def incident_summary(incident_file: Path, as_json: bool) -> None:
    """Print a single-line incident status summary from JSON/YAML incident record."""
    record = _load_incident_record(incident_file)
    summary = _summary_from_record(record)

    if as_json:
        click.echo(json.dumps(summary, separators=(",", ":")))
        return

    parts = [
        f"incident_id={summary['incident_id']}",
        f"current_state={summary['current_state']}",
        f"severity={summary['severity']}",
    ]
    if summary.get("owner"):
        parts.append(f"owner={summary['owner']}")
    parts.append(f"last_updated={summary['last_updated']}")

    click.echo(" ".join(parts))


if __name__ == "__main__":
    cli()
