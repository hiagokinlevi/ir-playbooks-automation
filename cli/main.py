from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel, ConfigDict, ValidationError, create_model

from schemas.incident import IncidentRecord


@click.group()
def ir() -> None:
    """IR Playbooks Automation CLI."""


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise click.ClickException(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON in {path}: {exc}") from exc


def _strict_model_for(model: type[BaseModel]) -> type[BaseModel]:
    """Create a runtime model equivalent to `model` but with extra fields forbidden."""
    fields: dict[str, tuple[Any, Any]] = {}
    for name, field in model.model_fields.items():
        default: Any
        if field.is_required():
            default = ...
        elif field.default_factory is not None:
            default = field.default_factory
        else:
            default = deepcopy(field.default)
        fields[name] = (field.annotation, default)

    return create_model(
        f"{model.__name__}Strict",
        __base__=model,
        __config__=ConfigDict(extra="forbid"),
        **fields,
    )


@ir.command("validate-incident")
@click.option("--file", "file_path", required=True, type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--strict", is_flag=True, default=False, help="Reject unknown/extra fields during schema validation.")
def validate_incident(file_path: Path, strict: bool) -> None:
    """Validate an incident record JSON file against schema."""
    payload = _load_json_file(file_path)
    model: type[BaseModel] = _strict_model_for(IncidentRecord) if strict else IncidentRecord

    try:
        model.model_validate(payload)
    except ValidationError as exc:
        lines = ["Incident validation failed:"]
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", [])) or "<root>"
            msg = err.get("msg", "Validation error")
            lines.append(f"- {loc}: {msg}")
        raise click.ClickException("\n".join(lines)) from exc

    click.echo("Incident validation passed.")
