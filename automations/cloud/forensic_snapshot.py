"""
AWS EC2 Forensic Snapshot Automation
======================================
Creates EBS volume snapshots of a potentially compromised EC2 instance
*before* isolation, preserving forensic evidence for post-incident analysis.

Key behaviours:
  - Discovers all attached EBS volumes on the instance
  - Requests a snapshot of each volume in parallel (fire-and-forget)
  - Tags every snapshot with incident metadata for chain-of-custody
  - Does NOT terminate or modify the instance
  - dry_run=True (default) validates permissions without creating snapshots

IMPORTANT:
  - Always run this BEFORE calling isolate_ec2_instance() to avoid losing
    network-transmitted artefacts or in-flight connections in your evidence.
  - Snapshots are eventually consistent — call wait_for_snapshots() if you
    need them completed before proceeding.
  - Snapshots incur AWS storage costs; delete them after case is closed.

Permissions required:
  - ec2:DescribeInstances
  - ec2:DescribeVolumes
  - ec2:CreateSnapshot
  - ec2:CreateTags
  - ec2:DescribeSnapshots (for wait_for_snapshots)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import boto3

log = logging.getLogger(__name__)


def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class SnapshotRecord:
    """Lightweight record of a snapshot request."""

    __slots__ = ("volume_id", "snapshot_id", "device_name", "size_gib", "requested_at")

    def __init__(
        self,
        volume_id: str,
        snapshot_id: str,
        device_name: str,
        size_gib: int,
        requested_at: str,
    ) -> None:
        self.volume_id = volume_id
        self.snapshot_id = snapshot_id
        self.device_name = device_name
        self.size_gib = size_gib
        self.requested_at = requested_at

    def __repr__(self) -> str:
        return (
            f"SnapshotRecord(volume={self.volume_id}, snapshot={self.snapshot_id}, "
            f"device={self.device_name}, size={self.size_gib}GiB)"
        )


def create_forensic_snapshots(
    instance_id: str,
    incident_id: str,
    region: str = "us-east-1",
    dry_run: bool = True,
) -> list[SnapshotRecord]:
    """
    Create EBS snapshots for all volumes attached to a target instance.

    Args:
        instance_id: The EC2 instance to snapshot (e.g. 'i-0abc123def456').
        incident_id: IR ticket ID used to tag snapshots (e.g. 'INC-20250101-001').
        region:      AWS region where the instance is running.
        dry_run:     If True, validates permissions but does not create snapshots.

    Returns:
        List of SnapshotRecord objects. In dry_run mode, snapshot_id is
        'DRY-RUN-<volume_id>'.

    Raises:
        ValueError: If the instance is not found in the specified region.
        botocore.exceptions.ClientError: On AWS API errors (e.g. permissions).
    """
    ec2 = boto3.client("ec2", region_name=region)
    timestamp = _now_utc_str()

    # Describe the instance to get its attached volumes
    response = ec2.describe_instances(InstanceIds=[instance_id])
    if not response.get("Reservations"):
        raise ValueError(f"Instance {instance_id} not found in {region}")

    instance = response["Reservations"][0]["Instances"][0]
    block_devices = instance.get("BlockDeviceMappings", [])

    if not block_devices:
        log.warning(f"Instance {instance_id} has no attached EBS volumes — nothing to snapshot")
        return []

    records: list[SnapshotRecord] = []

    for bd in block_devices:
        volume_id = bd.get("Ebs", {}).get("VolumeId")
        device_name = bd.get("DeviceName", "unknown")

        if not volume_id:
            continue

        # Fetch volume size for the record
        vol_response = ec2.describe_volumes(VolumeIds=[volume_id])
        size_gib: int = vol_response["Volumes"][0].get("Size", 0) if vol_response.get("Volumes") else 0

        log.info(
            f"Requesting snapshot of {volume_id} ({device_name}, {size_gib}GiB) "
            f"for incident {incident_id}"
        )

        if dry_run:
            snapshot_id = f"DRY-RUN-{volume_id}"
            log.info(f"DRY RUN — would create snapshot for {volume_id}")
        else:
            snap_response = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=(
                    f"FORENSIC SNAPSHOT: incident={incident_id} "
                    f"instance={instance_id} device={device_name} "
                    f"created={timestamp}"
                ),
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "k1n:incident_id", "Value": incident_id},
                            {"Key": "k1n:instance_id", "Value": instance_id},
                            {"Key": "k1n:volume_id", "Value": volume_id},
                            {"Key": "k1n:device_name", "Value": device_name},
                            {"Key": "k1n:snapshot_purpose", "Value": "forensic"},
                            {"Key": "k1n:created_at", "Value": timestamp},
                        ],
                    }
                ],
            )
            snapshot_id = snap_response["SnapshotId"]
            log.info(f"Snapshot {snapshot_id} requested for volume {volume_id}")

        records.append(SnapshotRecord(
            volume_id=volume_id,
            snapshot_id=snapshot_id,
            device_name=device_name,
            size_gib=size_gib,
            requested_at=timestamp,
        ))

    log.info(
        f"Forensic snapshots requested: {len(records)} volume(s) for instance {instance_id}"
    )
    return records


def wait_for_snapshots(
    snapshot_ids: list[str],
    region: str = "us-east-1",
    poll_interval_seconds: int = 30,
    timeout_seconds: int = 3600,
) -> dict[str, str]:
    """
    Poll until all snapshots reach 'completed' status.

    Useful when you need snapshots completed before copying to another region
    or sharing with a forensics team.

    Args:
        snapshot_ids:           List of snapshot IDs to wait for.
        region:                 AWS region.
        poll_interval_seconds:  Seconds between polls (default: 30).
        timeout_seconds:        Maximum total wait time (default: 1 hour).

    Returns:
        Dict mapping snapshot_id → final status ('completed' | 'error').
    """
    import time

    ec2 = boto3.client("ec2", region_name=region)
    pending = set(snapshot_ids)
    results: dict[str, str] = {}
    start = time.monotonic()

    while pending and (time.monotonic() - start) < timeout_seconds:
        response = ec2.describe_snapshots(SnapshotIds=list(pending))
        for snap in response.get("Snapshots", []):
            sid = snap["SnapshotId"]
            state = snap["State"]  # 'pending' | 'completed' | 'error'
            if state != "pending":
                results[sid] = state
                pending.discard(sid)
                log.info(f"Snapshot {sid} reached state: {state}")

        if pending:
            log.debug(f"Waiting for {len(pending)} snapshot(s) to complete...")
            time.sleep(poll_interval_seconds)

    # Any snapshots still pending after timeout → mark as timeout
    for sid in pending:
        results[sid] = "timeout"
        log.warning(f"Snapshot {sid} did not complete within {timeout_seconds}s")

    return results
