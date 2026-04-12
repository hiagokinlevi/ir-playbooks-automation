"""
k1n-ir CLI
===========
Command-line interface for ir-playbooks-automation.

Commands:
    open-incident       Open a new incident record
    set-severity        Update the severity of an existing incident
    start-playbook      Display a playbook for the current terminal session
    create-timeline     Add a timeline event to an incident
    generate-report     Generate a Markdown report for an incident
    lockdown-s3-bucket
                        Preview or run S3 public-access containment
    isolate-azure-vm
                        Preview or run Azure VM network containment
    isolate-gcp-instance
                        Preview or run GCP Compute Engine containment

Usage:
    k1n-ir open-incident --type phishing --severity high --title "Phishing campaign targeting finance team"
    k1n-ir set-severity --incident-id INC-20250101-001 --severity critical
    k1n-ir start-playbook --playbook triage/initial_triage
    k1n-ir create-timeline --incident-id INC-20250101-001 --event "Alert triggered"
    k1n-ir generate-report --incident-id INC-20250101-001 --format markdown

All output is written to the terminal unless --output is specified.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import click

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*args: Any, **kwargs: Any) -> bool:
        return False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:
    class Console:
        def print(self, *objects: Any, **kwargs: Any) -> None:
            click.echo(" ".join(str(obj) for obj in objects))

    class Panel:
        @staticmethod
        def fit(renderable: Any, **kwargs: Any) -> Any:
            return renderable

    class Table:
        def __init__(self, title: str | None = None, **kwargs: Any) -> None:
            self.title = title
            self.rows: list[tuple[str, ...]] = []

        def add_column(self, *args: Any, **kwargs: Any) -> None:
            return None

        def add_row(self, *values: Any, **kwargs: Any) -> None:
            self.rows.append(tuple(str(value) for value in values))

        def __str__(self) -> str:
            lines = [self.title] if self.title else []
            lines.extend(" | ".join(row) for row in self.rows)
            return "\n".join(lines)

# Load .env if present — allows running without explicitly setting env vars
load_dotenv()

# Rich console for styled terminal output
console = Console()

# Base directory for playbooks — relative to the repo root
PLAYBOOKS_DIR = Path(__file__).parent.parent / "playbooks"

# Evidence directory from environment
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "./evidence"))


def _resolve_playbook_path(playbook: str) -> Path:
    requested = (playbook or "").strip()
    if not requested:
        raise click.ClickException("Playbook path must not be empty.")

    playbooks_root = PLAYBOOKS_DIR.resolve(strict=True)
    candidates = [
        PLAYBOOKS_DIR / f"{requested}.md",
        PLAYBOOKS_DIR / requested,
    ]
    escaped_root = False

    for candidate in candidates:
        resolved_candidate = candidate.resolve(strict=False)
        try:
            resolved_candidate.relative_to(playbooks_root)
        except ValueError:
            escaped_root = True
            continue

        if resolved_candidate.is_file():
            return resolved_candidate

    if escaped_root:
        raise click.ClickException("Playbook path must stay within playbooks/.")

    raise click.ClickException(f"Playbook not found: {playbook}")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version="1.0.0", prog_name="k1n-ir")
def cli() -> None:
    """k1n-ir — Incident response playbooks and automation for SOC teams."""
    pass


# ---------------------------------------------------------------------------
# open-incident
# ---------------------------------------------------------------------------

@cli.command("open-incident")
@click.option(
    "--type", "incident_type",
    default=os.getenv("INCIDENT_TYPE", "generic"),
    type=click.Choice([
        "generic", "credential_compromise", "malware", "data_exposure",
        "api_abuse", "phishing", "cloud_exposure", "secret_leakage",
    ]),
    help="Incident type classification.",
    show_default=True,
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Initial severity (can be updated later with set-severity).",
)
@click.option(
    "--title",
    default=None,
    help="Concise incident title. You will be prompted if not provided.",
)
@click.option(
    "--owner",
    default=os.getenv("USER", "unknown"),
    help="Incident owner (defaults to current OS user).",
    show_default=True,
)
@click.option(
    "--assets",
    default="",
    help="Comma-separated list of affected assets (hostnames, service names, account IDs).",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Optional path to write the incident record as JSON.",
)
def open_incident(
    incident_type: str,
    severity: Optional[str],
    title: Optional[str],
    owner: str,
    assets: str,
    output: Optional[str],
) -> None:
    """Open a new incident record and print the incident ID."""
    # Prompt for title if not provided
    if not title:
        title = click.prompt("Incident title")

    # Generate incident ID: INC-YYYYMMDD-NNN (NNN placeholder — real systems use a counter)
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    # In a real deployment, NNN would be a database sequence. Use 001 as a placeholder.
    incident_id = f"INC-{date_str}-001"

    affected_assets = [a.strip() for a in assets.split(",") if a.strip()]

    record = {
        "incident_id": incident_id,
        "title": title,
        "status": "detected",
        "severity": severity,
        "incident_type": incident_type,
        "owner": owner,
        "affected_assets": affected_assets,
        "detected_at": now.isoformat(),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "timeline": [],
        "evidence": [],
        "tags": [incident_type],
    }

    # Styled output
    console.print(Panel.fit(
        f"[bold green]Incident Opened[/bold green]\n\n"
        f"[bold]ID:[/bold]       {incident_id}\n"
        f"[bold]Title:[/bold]    {title}\n"
        f"[bold]Type:[/bold]     {incident_type}\n"
        f"[bold]Severity:[/bold] {severity or 'Not yet assigned'}\n"
        f"[bold]Owner:[/bold]    {owner}\n"
        f"[bold]Status:[/bold]   detected\n"
        f"[bold]Assets:[/bold]   {', '.join(affected_assets) or 'None specified'}",
        title="[bold cyan]k1n-ir[/bold cyan]",
    ))

    # Suggest next step
    console.print(f"\n[dim]Next: run triage playbook →[/dim] "
                  f"[cyan]k1n-ir start-playbook --playbook triage/initial_triage[/cyan]")

    # Optionally write JSON output
    if output:
        Path(output).write_text(json.dumps(record, indent=2))
        console.print(f"[dim]Record written to: {output}[/dim]")
    else:
        # Print JSON to stdout for piping
        click.echo(json.dumps(record, indent=2))


# ---------------------------------------------------------------------------
# set-severity
# ---------------------------------------------------------------------------

@cli.command("set-severity")
@click.option("--incident-id", required=True, help="Incident ID (e.g., INC-20250101-001).")
@click.option(
    "--severity", required=True,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="New severity level.",
)
@click.option("--justification", default="", help="Brief justification for the severity assignment.")
def set_severity(incident_id: str, severity: str, justification: str) -> None:
    """Update the severity level of an existing incident."""
    now = datetime.now(timezone.utc).isoformat()

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }
    color = severity_colors.get(severity, "white")

    console.print(Panel.fit(
        f"[bold]Incident:[/bold] {incident_id}\n"
        f"[bold]Severity:[/bold] [{color}]{severity.upper()}[/{color}]\n"
        f"[bold]Updated At:[/bold] {now}\n"
        f"[bold]Justification:[/bold] {justification or '(none provided)'}",
        title="[bold cyan]Severity Updated[/bold cyan]",
    ))

    if severity in ("critical", "high"):
        console.print(
            f"\n[yellow]ACTION REQUIRED:[/yellow] {severity.upper()} severity — "
            f"activate IR team and begin containment playbook immediately."
        )


# ---------------------------------------------------------------------------
# start-playbook
# ---------------------------------------------------------------------------

@cli.command("start-playbook")
@click.option(
    "--playbook", required=True,
    help="Playbook path relative to playbooks/ (e.g., triage/initial_triage).",
)
@click.option("--incident-id", default=None, help="Associate this run with an incident ID.")
def start_playbook(playbook: str, incident_id: Optional[str]) -> None:
    """Display a playbook in the terminal for guided execution."""
    playbook_path = _resolve_playbook_path(playbook)

    now = datetime.now(timezone.utc).isoformat()
    header = f"[bold cyan]Playbook:[/bold cyan] {playbook}"
    if incident_id:
        header += f"\n[bold cyan]Incident:[/bold cyan] {incident_id}"
    header += f"\n[bold cyan]Started:[/bold cyan] {now}"

    console.print(Panel.fit(header, title="[bold cyan]k1n-ir Playbook Runner[/bold cyan]"))
    console.print()

    # Read and print the playbook content
    content = playbook_path.read_text(encoding="utf-8")
    console.print(content)


# ---------------------------------------------------------------------------
# create-timeline
# ---------------------------------------------------------------------------

@cli.command("create-timeline")
@click.option("--incident-id", required=True, help="Incident ID.")
@click.option("--event", required=True, help="Description of the timeline event.")
@click.option(
    "--actor",
    type=click.Choice(["attacker", "defender", "system", "unknown"]),
    default="defender",
    help="Who performed this action.",
    show_default=True,
)
@click.option(
    "--phase",
    default="Investigation",
    help="Incident phase (e.g., 'Initial Access', 'Containment').",
    show_default=True,
)
@click.option(
    "--confidence",
    type=click.Choice(["high", "medium", "low"]),
    default="high",
    help="Confidence in this event.",
    show_default=True,
)
@click.option(
    "--technique",
    default=None,
    help="MITRE ATT&CK technique ID (e.g., T1078.004).",
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Append event to a JSON file.")
def create_timeline(
    incident_id: str,
    event: str,
    actor: str,
    phase: str,
    confidence: str,
    technique: Optional[str],
    output: Optional[str],
) -> None:
    """Add a timeline event to an incident."""
    from uuid import uuid4

    now = datetime.now(timezone.utc)

    timeline_event = {
        "event_id": f"TL-{uuid4().hex[:8].upper()}",
        "incident_id": incident_id,
        "observed_at": now.isoformat(),
        "actor": actor,
        "phase": phase,
        "description": event,
        "confidence": confidence,
        "mitre_attack_technique": technique,
    }

    actor_colors = {
        "attacker": "red",
        "defender": "green",
        "system": "blue",
        "unknown": "yellow",
    }
    color = actor_colors.get(actor, "white")

    console.print(Panel.fit(
        f"[bold]Incident:[/bold]  {incident_id}\n"
        f"[bold]Event ID:[/bold]  {timeline_event['event_id']}\n"
        f"[bold]Time:[/bold]      {now.isoformat()}\n"
        f"[bold]Actor:[/bold]     [{color}]{actor}[/{color}]\n"
        f"[bold]Phase:[/bold]     {phase}\n"
        f"[bold]Event:[/bold]     {event}\n"
        f"[bold]Confidence:[/bold] {confidence}"
        + (f"\n[bold]ATT&CK:[/bold]    {technique}" if technique else ""),
        title="[bold cyan]Timeline Event Added[/bold cyan]",
    ))

    if output:
        output_path = Path(output)
        if output_path.exists():
            existing = json.loads(output_path.read_text())
            if isinstance(existing, list):
                existing.append(timeline_event)
                output_path.write_text(json.dumps(existing, indent=2))
        else:
            output_path.write_text(json.dumps([timeline_event], indent=2))
        console.print(f"[dim]Event appended to: {output}[/dim]")
    else:
        click.echo(json.dumps(timeline_event, indent=2))


# ---------------------------------------------------------------------------
# generate-report
# ---------------------------------------------------------------------------

@cli.command("generate-report")
@click.option("--incident-id", required=True, help="Incident ID for the report.")
@click.option(
    "--format", "report_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format.",
    show_default=True,
)
@click.option(
    "--verbosity",
    type=click.Choice(["minimal", "standard", "verbose"]),
    default=os.getenv("REPORT_VERBOSITY", "standard"),
    help="Report detail level.",
    show_default=True,
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Write report to this file.")
def generate_report(
    incident_id: str,
    report_format: str,
    verbosity: str,
    output: Optional[str],
) -> None:
    """Generate an incident report from the incident record."""
    now = datetime.now(timezone.utc).isoformat()

    # Build a skeleton report — in a real deployment this would load from persistent storage
    report_md = f"""# Incident Report: {incident_id}

**Generated At:** {now}
**Verbosity:** {verbosity}
**Format:** {report_format}

---

## Incident Overview

| Field | Value |
|---|---|
| Incident ID | {incident_id} |
| Report Date | {now[:10]} |
| Status | _Load from incident record_ |
| Severity | _Load from incident record_ |

---

## Executive Summary

> _Populate from incident record summary field._

---

## Timeline

> _Populate from incident timeline events._

---

## Indicators of Compromise

> _Populate from incident evidence and timeline._

---

## Root Cause

> _Populate after eradication phase._

---

## Recommendations

> _Populate at post-incident review._

---

_Report generated by ir-playbooks-automation_
"""

    if report_format == "json":
        report_content = json.dumps({
            "incident_id": incident_id,
            "generated_at": now,
            "verbosity": verbosity,
            "note": "Populate fields from incident record in production use.",
        }, indent=2)
    else:
        report_content = report_md

    if output:
        Path(output).write_text(report_content, encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        console.print(report_content)


# ---------------------------------------------------------------------------
# lockdown-s3-bucket
# ---------------------------------------------------------------------------

@cli.command("lockdown-s3-bucket")
@click.option("--bucket-name", required=True, help="S3 bucket name.")
@click.option("--incident-id", required=True, help="Incident ID for audit tagging.")
@click.option(
    "--region",
    default="us-east-1",
    help="AWS region used to discover and operate on the bucket.",
    show_default=True,
)
@click.option(
    "--aws-profile",
    default=None,
    help="Optional AWS shared-credentials profile name.",
)
@click.option(
    "--execute",
    is_flag=True,
    help="Run live containment. Omit to keep the command in dry-run preview mode.",
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Write result JSON.")
def lockdown_s3_bucket_cmd(
    bucket_name: str,
    incident_id: str,
    region: str,
    aws_profile: Optional[str],
    execute: bool,
    output: Optional[str],
) -> None:
    """Preview or run reversible S3 public-access lockdown."""
    from dataclasses import asdict

    from automations.cloud.lockdown_s3_bucket import lockdown_s3_bucket

    if execute and os.getenv("APPROVAL_REQUIRED_FOR_CONTAINMENT", "true").lower() == "true":
        click.confirm(
            "Live S3 containment can remove public access immediately. Confirm approved execution",
            abort=True,
        )

    result = lockdown_s3_bucket(
        bucket_name=bucket_name,
        incident_id=incident_id,
        region=region,
        aws_profile=aws_profile,
        dry_run=not execute,
    )

    table = Table(title="S3 Bucket Lockdown")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Bucket", bucket_name)
    table.add_row("Region", result.region)
    table.add_row("Mode", "dry-run" if result.dry_run else "live")
    table.add_row("Success", str(result.success))
    table.add_row("Actions", str(len(result.actions_taken)))
    console.print(table)

    for action in result.actions_taken:
        console.print(f"- {action}")
    for error in result.errors:
        console.print(f"[red]- {error}[/red]")

    result_json = json.dumps(asdict(result), indent=2)
    if output:
        Path(output).write_text(result_json, encoding="utf-8")
        console.print(f"[dim]Result written to: {output}[/dim]")
    else:
        click.echo(result_json)

    if not result.success:
        raise click.ClickException("S3 bucket lockdown did not complete successfully.")


# ---------------------------------------------------------------------------
# isolate-azure-vm
# ---------------------------------------------------------------------------

@cli.command("isolate-azure-vm")
@click.option("--subscription-id", required=True, help="Azure subscription ID.")
@click.option("--resource-group", required=True, help="Azure resource group for the VM.")
@click.option("--vm-name", required=True, help="Azure VM name.")
@click.option("--incident-id", required=True, help="Incident ID for audit tagging.")
@click.option(
    "--location",
    default="eastus",
    help="Azure region for the incident isolation NSG.",
    show_default=True,
)
@click.option(
    "--deallocate-vm",
    is_flag=True,
    help="Also deallocate the VM after NSG isolation.",
)
@click.option(
    "--execute",
    is_flag=True,
    help="Run live containment. Omit to keep the command in dry-run preview mode.",
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Write result JSON.")
def isolate_azure_vm_cmd(
    subscription_id: str,
    resource_group: str,
    vm_name: str,
    incident_id: str,
    location: str,
    deallocate_vm: bool,
    execute: bool,
    output: Optional[str],
) -> None:
    """Preview or run reversible Azure VM NSG isolation."""
    from dataclasses import asdict

    from automations.cloud.isolate_azure_vm import isolate_azure_vm

    if execute and os.getenv("APPROVAL_REQUIRED_FOR_CONTAINMENT", "true").lower() == "true":
        click.confirm(
            "Live containment can disrupt production traffic. Confirm approved execution",
            abort=True,
        )

    try:
        result = isolate_azure_vm(
            subscription_id=subscription_id,
            resource_group=resource_group,
            vm_name=vm_name,
            incident_id=incident_id,
            location=location,
            deallocate_vm=deallocate_vm,
            dry_run=not execute,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    table = Table(title="Azure VM Isolation")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("VM", vm_name)
    table.add_row("Subscription", subscription_id)
    table.add_row("Resource group", resource_group)
    table.add_row("Mode", "dry-run" if result.dry_run else "live")
    table.add_row("Success", str(result.success))
    table.add_row("Actions", str(len(result.actions_taken)))
    console.print(table)

    for action in result.actions_taken:
        console.print(f"- {action}")
    for error in result.errors:
        console.print(f"[red]- {error}[/red]")

    result_json = json.dumps(asdict(result), indent=2)
    if output:
        Path(output).write_text(result_json, encoding="utf-8")
        console.print(f"[dim]Result written to: {output}[/dim]")
    else:
        click.echo(result_json)

    if not result.success:
        raise click.ClickException("Azure VM isolation did not complete successfully.")


# ---------------------------------------------------------------------------
# isolate-gcp-instance
# ---------------------------------------------------------------------------

@cli.command("isolate-gcp-instance")
@click.option("--project-id", required=True, help="GCP project ID.")
@click.option("--zone", required=True, help="GCP zone for the instance.")
@click.option("--instance-name", required=True, help="Compute Engine instance name.")
@click.option("--incident-id", required=True, help="Incident ID for audit tagging.")
@click.option(
    "--network",
    default="global/networks/default",
    help="GCP network resource path for the isolation firewall rules.",
    show_default=True,
)
@click.option(
    "--stop-instance",
    is_flag=True,
    help="Also stop the instance after network isolation.",
)
@click.option(
    "--execute",
    is_flag=True,
    help="Run live containment. Omit to keep the command in dry-run preview mode.",
)
@click.option("--output", "-o", default=None, type=click.Path(), help="Write result JSON.")
def isolate_gcp_instance_cmd(
    project_id: str,
    zone: str,
    instance_name: str,
    incident_id: str,
    network: str,
    stop_instance: bool,
    execute: bool,
    output: Optional[str],
) -> None:
    """Preview or run reversible GCP Compute Engine isolation."""
    from dataclasses import asdict

    from automations.cloud.isolate_gcp_instance import isolate_gcp_instance

    if execute and os.getenv("APPROVAL_REQUIRED_FOR_CONTAINMENT", "true").lower() == "true":
        click.confirm(
            "Live containment can disrupt production traffic. Confirm approved execution",
            abort=True,
        )

    result = isolate_gcp_instance(
        project_id=project_id,
        zone=zone,
        instance_name=instance_name,
        incident_id=incident_id,
        network=network,
        stop_instance=stop_instance,
        dry_run=not execute,
    )

    table = Table(title="GCP Instance Isolation")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Instance", instance_name)
    table.add_row("Project", project_id)
    table.add_row("Zone", zone)
    table.add_row("Mode", "dry-run" if result.dry_run else "live")
    table.add_row("Success", str(result.success))
    table.add_row("Actions", str(len(result.actions_taken)))
    console.print(table)

    for action in result.actions_taken:
        console.print(f"- {action}")
    for error in result.errors:
        console.print(f"[red]- {error}[/red]")

    result_json = json.dumps(asdict(result), indent=2)
    if output:
        Path(output).write_text(result_json, encoding="utf-8")
        console.print(f"[dim]Result written to: {output}[/dim]")
    else:
        click.echo(result_json)

    if not result.success:
        raise click.ClickException("GCP isolation did not complete successfully.")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
