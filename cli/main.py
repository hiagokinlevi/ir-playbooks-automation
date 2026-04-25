from __future__ import annotations

import json
from pathlib import Path

import click

from workflows.state_machine import IncidentState, WORKFLOW_TRANSITIONS


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("workflow-next")
@click.option("--state", "state_name", required=True, help="Current incident workflow state")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON output")
def workflow_next(state_name: str, as_json: bool) -> None:
    """Show allowed next workflow states from a given state."""
    try:
      current_state = IncidentState(state_name)
      valid = True
      allowed = [s.value for s in WORKFLOW_TRANSITIONS[current_state]]
    except ValueError:
      current_state = None
      valid = False
      allowed = []

    if as_json:
      payload = {
          "current_state": current_state.value if current_state else state_name,
          "allowed_next_states": allowed,
          "valid": valid,
      }
      click.echo(json.dumps(payload))
      return

    if not valid:
      click.echo(f"Invalid state: {state_name}")
      click.echo("Valid states:")
      for s in IncidentState:
          click.echo(f"- {s.value}")
      raise SystemExit(2)

    click.echo(f"Current state: {current_state.value}")
    click.echo("Allowed next states:")
    for s in allowed:
      click.echo(f"- {s}")


if __name__ == "__main__":
    cli()
