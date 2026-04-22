from pathlib import Path

import click
import yaml


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("lint-playbook")
@click.argument("playbook_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def lint_playbook(playbook_path: Path) -> None:
    """Validate required YAML front-matter keys in a playbook markdown file."""
    required_keys = ["incident_type", "severity", "owner", "last_reviewed"]

    try:
        content = playbook_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"Unable to read file '{playbook_path}': {exc}")

    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        raise click.ClickException(
            "Missing YAML front-matter block (expected file to start with '---')."
        )

    closing_idx = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            closing_idx = idx
            break

    if closing_idx is None:
        raise click.ClickException("Unterminated YAML front-matter block.")

    front_matter_raw = "\n".join(lines[1:closing_idx]).strip()
    if not front_matter_raw:
        raise click.ClickException("Front-matter is empty.")

    try:
        front_matter = yaml.safe_load(front_matter_raw)
    except yaml.YAMLError as exc:
        raise click.ClickException(f"Invalid YAML front-matter: {exc}")

    if not isinstance(front_matter, dict):
        raise click.ClickException("Front-matter must be a YAML mapping/object.")

    missing = [key for key in required_keys if key not in front_matter]
    if missing:
        raise click.ClickException(
            f"Missing required front-matter keys: {', '.join(missing)}"
        )

    click.echo(f"OK: {playbook_path} front-matter is valid")


if __name__ == "__main__":
    cli()
