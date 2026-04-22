import click

from automations.cloud.aws.isolate_ec2_instance import isolate_instance as aws_isolate_instance
from automations.cloud.aws.lockdown_s3_bucket import lockdown_bucket as aws_lockdown_bucket
from automations.cloud.azure.isolate_azure_vm import isolate_vm as azure_isolate_vm
from automations.cloud.gcp.isolate_gcp_instance import isolate_instance as gcp_isolate_instance


@click.group()
def cli() -> None:
    """IR Playbooks Automation CLI."""


@cli.group()
def containment() -> None:
    """Containment automation commands."""


@containment.command("aws-isolate-ec2")
@click.option("--instance-id", required=True, help="EC2 instance ID to isolate")
@click.option("--region", required=True, help="AWS region")
@click.option("--dry-run", is_flag=True, default=False, help="Print intended action without executing")
def aws_isolate_ec2(instance_id: str, region: str, dry_run: bool) -> None:
    if dry_run:
        click.echo(
            f"[DRY-RUN] Would isolate AWS EC2 instance '{instance_id}' in region '{region}'."
        )
        return

    aws_isolate_instance(instance_id=instance_id, region=region)
    click.echo(f"Isolated AWS EC2 instance '{instance_id}' in region '{region}'.")


@containment.command("aws-lockdown-s3")
@click.option("--bucket", required=True, help="S3 bucket name to lock down")
@click.option("--dry-run", is_flag=True, default=False, help="Print intended action without executing")
def aws_lockdown_s3(bucket: str, dry_run: bool) -> None:
    if dry_run:
        click.echo(f"[DRY-RUN] Would lock down AWS S3 bucket '{bucket}'.")
        return

    aws_lockdown_bucket(bucket_name=bucket)
    click.echo(f"Locked down AWS S3 bucket '{bucket}'.")


@containment.command("azure-isolate-vm")
@click.option("--subscription-id", required=True, help="Azure subscription ID")
@click.option("--resource-group", required=True, help="Azure resource group")
@click.option("--vm-name", required=True, help="Azure VM name")
@click.option("--dry-run", is_flag=True, default=False, help="Print intended action without executing")
def azure_isolate(subscription_id: str, resource_group: str, vm_name: str, dry_run: bool) -> None:
    if dry_run:
        click.echo(
            "[DRY-RUN] Would isolate Azure VM "
            f"'{vm_name}' in resource group '{resource_group}' (subscription '{subscription_id}')."
        )
        return

    azure_isolate_vm(
        subscription_id=subscription_id,
        resource_group=resource_group,
        vm_name=vm_name,
    )
    click.echo(
        f"Isolated Azure VM '{vm_name}' in resource group '{resource_group}' (subscription '{subscription_id}')."
    )


@containment.command("gcp-isolate-instance")
@click.option("--project", required=True, help="GCP project ID")
@click.option("--zone", required=True, help="GCP zone")
@click.option("--instance", required=True, help="GCP instance name")
@click.option("--dry-run", is_flag=True, default=False, help="Print intended action without executing")
def gcp_isolate(project: str, zone: str, instance: str, dry_run: bool) -> None:
    if dry_run:
        click.echo(
            f"[DRY-RUN] Would isolate GCP instance '{instance}' in project '{project}', zone '{zone}'."
        )
        return

    gcp_isolate_instance(project_id=project, zone=zone, instance_name=instance)
    click.echo(
        f"Isolated GCP instance '{instance}' in project '{project}', zone '{zone}'."
    )


if __name__ == "__main__":
    cli()
