import json
from pathlib import Path

import click

from workflows.state_machine import IncidentStateMachine, WorkflowState


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("workflow-next")
@click.option("--incident", "incident_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=False, help="Path to incident record JSON file.")
@click.option("--from", "from_state", required=False, help="Return allowed next states from the provided workflow state without loading an incident.")
@click.option("--json", "as_json", is_flag=True, help="Output in JSON format.")
def workflow_next(incident_path: Path | None, from_state: str | None, as_json: bool) -> None:
    """Show allowed next workflow states.

    Default behavior (no --from) looks up current state from an incident record.
    """
    sm = IncidentStateMachine()

    if from_state:
        try:
            current_state = WorkflowState(from_state)
        except ValueError:
            valid = [s.value for s in WorkflowState]
            raise click.ClickException(
                f"Invalid state '{from_state}'. Valid states: {', '.join(valid)}"
            )
    else:
        if incident_path is None:
            raise click.ClickException("Provide --incident <path> or --from <state>.")
        data = json.loads(incident_path.read_text(encoding="utf-8"))
        state_value = data.get("state")
        if not state_value:
            raise click.ClickException("Incident record missing 'state'.")
        try:
            current_state = WorkflowState(state_value)
        except ValueError:
            valid = [s.value for s in WorkflowState]
            raise click.ClickException(
                f"Incident has invalid state '{state_value}'. Valid states: {', '.join(valid)}"
            )

    next_states = [s.value for s in sm.allowed_next_states(current_state)]

    if as_json:
        click.echo(json.dumps({"from": current_state.value, "next": next_states}))
    else:
        click.echo(f"from: {current_state.value}")
        if next_states:
            click.echo("next: " + ", ".join(next_states))
        else:
            click.echo("next: <none>")


if __name__ == "__main__":
    cli()
