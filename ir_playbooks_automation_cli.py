import json
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from schemas.incident import IncidentRecord


@click.group()
def cli():
    """IR Playbooks Automation CLI."""
    pass


@cli.command("validate-incident-record")
@click.argument("record_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate_incident_record(record_file: Path) -> None:
    """Validate an incident record JSON/YAML file against the IncidentRecord schema."""
    try:
        payload = _load_record_file(record_file)
    except Exception as exc:  # pragma: no cover - defensive parse errors
        click.echo(f"ERROR: failed to load file: {exc}")
        raise SystemExit(1)

    try:
        IncidentRecord.model_validate(payload)
        click.echo("VALID")
    except ValidationError as exc:
        click.echo("INVALID")
        for err in exc.errors():
            loc = ".".join(str(part) for part in err.get("loc", []))
            msg = err.get("msg", "validation error")
            typ = err.get("type", "unknown")
            click.echo(f"- field={loc} type={typ} message={msg}")
        raise SystemExit(1)


def _load_record_file(path: Path):
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix == ".json":
        return json.loads(text)
    if suffix in {".yaml", ".yml"}:
        loaded = yaml.safe_load(text)
        return loaded if loaded is not None else {}

    raise ValueError("unsupported file extension (use .json, .yaml, or .yml)")


if __name__ == "__main__":
    cli()
