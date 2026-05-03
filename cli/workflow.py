from __future__ import annotations

import click

from workflows.state_machine import get_next_states


@click.command("workflow-next")
@click.argument("current_state")
@click.option("--severity", default=None, help="Incident severity context for gating checks.")
@click.option("--reason", "show_reason", is_flag=True, help="Include human-readable transition reason.")
def workflow_next(current_state: str, severity: str | None, show_reason: bool) -> None:
    """Show valid next workflow states from CURRENT_STATE."""
    next_states = get_next_states(current_state=current_state, severity=severity, include_reason=show_reason)

    if not next_states:
        click.echo("No valid next states.")
        return

    for entry in next_states:
        if show_reason:
            state = entry.get("state")
            reason = entry.get("reason")
            if reason:
                click.echo(f"{state}: {reason}")
            else:
                click.echo(f"{state}")
        else:
            click.echo(entry["state"])
