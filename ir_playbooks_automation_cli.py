from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from workflows.state_machine import IncidentStateMachine


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("workflow-next")
@click.option("--from-state", "from_state", required=True, help="Current workflow state")
@click.option("--to-state", "to_state", required=False, help="Desired next workflow state")
@click.option("--json", "as_json", is_flag=True, help="Return machine-readable JSON output")
def workflow_next(from_state: str, to_state: Optional[str], as_json: bool) -> None:
    """Show allowed next states or validate a transition."""
    sm = IncidentStateMachine()
    allowed_next_states = sm.get_next_states(from_state)

    if as_json:
        payload: dict[str, object] = {
            "from_state": from_state,
            "allowed_next_states": allowed_next_states,
        }

        if to_state is not None:
            valid = to_state in allowed_next_states
            payload["to_state"] = to_state
            payload["valid"] = valid
            if not valid:
                payload["reason"] = f"Invalid transition from '{from_state}' to '{to_state}'"

        click.echo(json.dumps(payload))
        return

    if to_state is None:
        if allowed_next_states:
            click.echo(f"From '{from_state}' you may transition to: {', '.join(allowed_next_states)}")
        else:
            click.echo(f"From '{from_state}' there are no allowed next states")
        return

    if to_state in allowed_next_states:
        click.echo(f"Valid transition: '{from_state}' -> '{to_state}'")
    else:
        click.echo(
            f"Invalid transition: '{from_state}' -> '{to_state}'. "
            f"Allowed: {', '.join(allowed_next_states) if allowed_next_states else 'none'}"
        )


if __name__ == "__main__":
    cli()
