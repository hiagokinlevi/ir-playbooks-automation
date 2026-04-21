from __future__ import annotations

from pathlib import Path

import click

from automations.evidence_packaging import verify_manifest


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.command("verify-evidence")
@click.argument("package_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--manifest",
    "manifest_filename",
    default="sha256_manifest.json",
    show_default=True,
    help="Manifest filename within the evidence package directory.",
)
def verify_evidence(package_dir: Path, manifest_filename: str) -> None:
    """Verify an evidence package against its SHA-256 manifest."""
    try:
        result = verify_manifest(package_dir=package_dir, manifest_filename=manifest_filename)
    except FileNotFoundError as exc:
        click.secho(str(exc), fg="red", err=True)
        raise SystemExit(2)
    except Exception as exc:  # pragma: no cover
        click.secho(f"Verification failed: {exc}", fg="red", err=True)
        raise SystemExit(2)

    missing = result["missing"]
    mismatched = result["mismatched"]
    verified = result["verified"]

    click.echo(f"Manifest: {result['manifest']}")
    click.echo(f"Verified files: {len(verified)}")

    if missing:
        click.secho("Missing files:", fg="yellow")
        for item in missing:
            click.echo(f"  - {item}")

    if mismatched:
        click.secho("Hash mismatches:", fg="red")
        for item in mismatched:
            click.echo(f"  - {item}")

    if not missing and not mismatched:
        click.secho("Evidence manifest verification PASSED.", fg="green")
        return

    click.secho("Evidence manifest verification FAILED.", fg="red", err=True)
    raise SystemExit(1)


if __name__ == "__main__":
    cli()
