from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError

from schemas.incident import IncidentRecord


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("validate-incident")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to incident record file (JSON/YAML).")
def validate_incident(file_path: Path) -> None:
    """Validate an incident record file against Pydantic schema."""
    try:
        payload = _load_incident_file(file_path)
        IncidentRecord.model_validate(payload)
    except ValidationError as exc:
        click.echo("Validation failed:", err=True)
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", []))
            msg = err.get("msg", "invalid value")
            click.echo(f"- {loc}: {msg}", err=True)
        raise SystemExit(1)
    except Exception as exc:  # pragma: no cover - defensive parse/runtime guard
        click.echo(f"Unable to validate incident file: {exc}", err=True)
        raise SystemExit(2)

    click.echo("Incident record is valid.")


def _load_incident_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix == ".json":
        return json.loads(text)

    if suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required to parse YAML incident files") from exc
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            raise ValueError("YAML incident content must be a mapping/object")
        return loaded

    raise ValueError("Unsupported file type. Use .json, .yml, or .yaml")
