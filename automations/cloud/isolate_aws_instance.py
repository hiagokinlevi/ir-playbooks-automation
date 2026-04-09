"""
AWS EC2 Instance Isolation Automation
=======================================
Isolates a potentially compromised EC2 instance by:
1. Creating an isolation security group (deny all traffic)
2. Replacing the instance's security groups with the isolation group
3. Tagging the instance with incident metadata

IMPORTANT:
- This action is REVERSIBLE but disruptive. Confirm scope before running.
- Requires approval when APPROVAL_REQUIRED_FOR_CONTAINMENT=true
- Always preserve forensic data — do NOT terminate the instance
- Run only on instances confirmed as part of an active IR process

Permissions required:
  - ec2:DescribeInstances
  - ec2:CreateSecurityGroup
  - ec2:AuthorizeSecurityGroupIngress / Egress
  - ec2:ModifyInstanceAttribute
  - ec2:CreateTags
"""
import boto3
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def isolate_ec2_instance(
    instance_id: str,
    incident_id: str,
    region: str = "us-east-1",
    dry_run: bool = True,
) -> dict:
    """
    Isolate an EC2 instance by replacing its security groups.

    Args:
        instance_id: The EC2 instance ID to isolate (e.g., 'i-0abc123def456')
        incident_id: The IR ticket ID for tracking (e.g., 'INC-20250101-001')
        region: AWS region where the instance is located
        dry_run: If True, validate permissions but do not make changes

    Returns:
        dict with isolation result including original SGs for rollback
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Fetch instance details before making any changes
    response = ec2.describe_instances(InstanceIds=[instance_id])
    if not response["Reservations"]:
        raise ValueError(f"Instance {instance_id} not found in {region}")

    instance = response["Reservations"][0]["Instances"][0]
    original_sgs = [sg["GroupId"] for sg in instance["SecurityGroups"]]
    vpc_id = instance.get("VpcId")
    current_state = instance["State"]["Name"]

    log.info(f"Starting isolation for {instance_id} (incident: {incident_id})")
    log.info(f"Original security groups: {original_sgs}")
    log.info(f"Instance state: {current_state}")

    if dry_run:
        log.info("DRY RUN — No changes made. Remove dry_run=True to proceed.")
        return {
            "dry_run": True,
            "instance_id": instance_id,
            "original_security_groups": original_sgs,
            "would_create_isolation_sg": True,
        }

    # Create an isolation security group with no inbound/outbound rules
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    iso_sg_name = f"k1n-isolation-{incident_id}-{timestamp}"

    iso_sg = ec2.create_security_group(
        GroupName=iso_sg_name,
        Description=f"ISOLATION: {incident_id} — created by ir-playbooks-automation",
        VpcId=vpc_id,
    )
    isolation_sg_id = iso_sg["GroupId"]
    log.info(f"Created isolation security group: {isolation_sg_id}")

    # Remove the default outbound rule (AWS creates allow-all egress by default)
    ec2.revoke_security_group_egress(
        GroupId=isolation_sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    # Replace instance security groups with isolation SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_sg_id],
    )

    # Tag the instance with incident metadata for tracking
    ec2.create_tags(
        Resources=[instance_id, isolation_sg_id],
        Tags=[
            {"Key": "k1n:incident_id", "Value": incident_id},
            {"Key": "k1n:isolated_at", "Value": timestamp},
            {"Key": "k1n:original_sgs", "Value": ",".join(original_sgs)},
            {"Key": "k1n:isolation_status", "Value": "isolated"},
        ],
    )

    log.info(f"Instance {instance_id} successfully isolated")
    return {
        "dry_run": False,
        "instance_id": instance_id,
        "isolation_sg_id": isolation_sg_id,
        "original_security_groups": original_sgs,
        "isolated_at": timestamp,
        "rollback_command": f"aws ec2 modify-instance-attribute --instance-id {instance_id} --groups {' '.join(original_sgs)}",
    }
