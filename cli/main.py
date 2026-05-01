from __future__ import annotations

import json
from pathlib import Path

import click


WORKFLOW_PATH = Path("workflows/incident_state_machine.json")


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _transitions_map(workflow: dict) -> dict[str, list[str]]:
    # Supports either {"transitions": {"state": ["next"]}} or direct mapping
    if isinstance(workflow, dict) and "transitions" in workflow and isinstance(workflow["transitions"], dict):
        return workflow["transitions"]
    return workflow if isinstance(workflow, dict) else {}


@click.group()
def cli() -> None:
    pass


@cli.command("workflow-next")
@click.option("--from", "from_state", required=True, help="Current state to evaluate transitions from.")
@click.option("--to", "to_state", required=False, help="Optional target state to validate as an allowed transition.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON output.")
def workflow_next(from_state: str, to_state: str | None, as_json: bool) -> None:
    """Show next valid incident workflow states, or validate a specific --to target."""
    transitions = _transitions_map(_load_workflow())
    allowed = transitions.get(from_state, [])

    if to_state:
        valid = to_state in allowed
        if as_json:
            click.echo(
                json.dumps(
                    {
                        "from": from_state,
                        "to": to_state,
                        "allowed": allowed,
                        "valid": valid,
                    }
                )
            )
        else:
            if valid:
                click.echo(f"valid transition: {from_state} -> {to_state}")
            else:
                click.echo(f"invalid transition: {from_state} -> {to_state}; allowed: {', '.join(allowed) if allowed else '(none)'}")

        if not valid:
            raise click.exceptions.Exit(1)
        return

    if as_json:
        click.echo(json.dumps({"from": from_state, "allowed": allowed}))
    else:
        click.echo(", ".join(allowed) if allowed else "(no transitions)")


if __name__ == "__main__":
    cli()
