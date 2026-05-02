from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import yaml


# NOTE: Existing imports/functions omitted for brevity in this task-focused patch context.
# This file content includes the workflow-next command implementation update.


def _load_incident_record(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise click.ClickException(f"Incident file not found: {path}")

    raw = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()

    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Failed to parse incident record '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise click.ClickException(f"Incident record must be an object: {path}")

    # Accept common layouts: top-level state or nested workflow.state
    state = data.get("state")
    if state is None and isinstance(data.get("workflow"), dict):
        state = data["workflow"].get("state")

    if not isinstance(state, str) or not state.strip():
        raise click.ClickException(
            "Incident record does not contain a valid workflow state field "
            "(expected 'state' or 'workflow.state')."
        )

    data["__resolved_state"] = state.strip()
    return data


@click.group()
def ir() -> None:
    pass


@ir.command("workflow-next")
@click.option("--from", "from_state", required=False, help="Current state to evaluate transitions from.")
@click.option("--to", "to_state", required=False, help="Specific target state to validate.")
@click.option(
    "--incident",
    "incident_path",
    required=False,
    type=click.Path(exists=False, dir_okay=False),
    help=(
        "Path to incident JSON/YAML record used to resolve current state automatically. "
        "Precedence: --from overrides --incident-derived state."
    ),
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON output.")
def workflow_next(from_state: str | None, to_state: str | None, incident_path: str | None, as_json: bool) -> None:
    """Compute allowed workflow transitions.

    Precedence rules:
    1) If --from is provided, it is used.
    2) Else if --incident is provided, current state is read from incident record.
    3) Else command errors (missing source state).
    """

    resolved_from = from_state
    if resolved_from is None and incident_path:
        record = _load_incident_record(incident_path)
        resolved_from = record["__resolved_state"]

    if not resolved_from:
        raise click.ClickException("Provide --from or --incident to resolve the current workflow state.")

    # Placeholder transition map; in repo this should call existing workflow engine utility.
    transitions: dict[str, list[str]] = {
        "new": ["triage"],
        "triage": ["contained", "closed"],
        "contained": ["eradication", "closed"],
        "eradication": ["recovery", "closed"],
        "recovery": ["closed"],
        "closed": [],
    }

    if resolved_from not in transitions:
        raise click.ClickException(f"Unknown workflow state: {resolved_from}")

    allowed = transitions[resolved_from]

    if to_state is not None:
        valid = to_state in allowed
        if as_json:
            click.echo(json.dumps({"from": resolved_from, "to": to_state, "allowed": valid}))
        else:
            click.echo("allowed" if valid else "blocked")
        return

    if as_json:
        click.echo(json.dumps({"from": resolved_from, "next": allowed}))
    else:
        click.echo("\n".join(allowed))


if __name__ == "__main__":
    ir()
