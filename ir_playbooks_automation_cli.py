#!/usr/bin/env python3
"""CLI for IR playbooks automation."""

from __future__ import annotations

import json
from pathlib import Path

import click

# Existing workflow state machine
WORKFLOW_TRANSITIONS = {
    "new": ["triage"],
    "triage": ["containment", "closed"],
    "containment": ["eradication", "closed"],
    "eradication": ["recovery", "closed"],
    "recovery": ["postmortem", "closed"],
    "postmortem": ["closed"],
    "closed": [],
}


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("workflow-next")
@click.option("--incident", "incident_path", type=click.Path(path_type=Path), required=False)
@click.option("--from", "from_state", type=str, required=False, help="Validate transition source state.")
@click.option("--to", "to_state", type=str, required=False, help="Validate transition destination state.")
def workflow_next(incident_path: Path | None, from_state: str | None, to_state: str | None) -> None:
    """Advance an incident workflow or validate an explicit transition.

    Validation mode (non-mutating):
      ir workflow-next --from triage --to containment
    """

    # Validation mode: requires both options and does not mutate any incident data
    if from_state is not None or to_state is not None:
        if not from_state or not to_state:
            raise click.UsageError("Validation mode requires both --from and --to.")

        from_state = from_state.strip().lower()
        to_state = to_state.strip().lower()

        if from_state not in WORKFLOW_TRANSITIONS:
            click.echo(f"FAIL: unknown source state '{from_state}'.")
            raise SystemExit(1)
        if to_state not in WORKFLOW_TRANSITIONS:
            click.echo(f"FAIL: unknown destination state '{to_state}'.")
            raise SystemExit(1)

        allowed = WORKFLOW_TRANSITIONS.get(from_state, [])
        if to_state in allowed:
            click.echo(f"PASS: valid transition '{from_state}' -> '{to_state}'.")
            return

        click.echo(
            f"FAIL: invalid transition '{from_state}' -> '{to_state}'. "
            f"Allowed: {', '.join(allowed) if allowed else '(none)'}"
        )
        raise SystemExit(1)

    # Existing mutate mode (kept minimal and safe)
    if incident_path is None:
        raise click.UsageError("Mutating mode requires --incident, or use --from/--to validation mode.")

    data = json.loads(incident_path.read_text(encoding="utf-8"))
    current = str(data.get("state", "new")).lower()
    next_states = WORKFLOW_TRANSITIONS.get(current, [])

    if not next_states:
        click.echo(f"No next state available from '{current}'.")
        return

    nxt = next_states[0]
    data["state"] = nxt
    incident_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    click.echo(f"Transitioned incident state: {current} -> {nxt}")


if __name__ == "__main__":
    cli()
