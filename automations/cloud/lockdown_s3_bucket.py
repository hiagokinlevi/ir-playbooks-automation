"""
AWS S3 Bucket Public-Access Lockdown Automation
================================================
Locks down a potentially exposed S3 bucket by:
1. Capturing the current public-access controls for rollback
2. Enabling the full S3 Public Access Block configuration
3. Removing a public bucket policy when one is present
4. Replacing public ACL grants with the private canned ACL
5. Tagging the bucket with incident metadata for traceability

This containment flow is designed for cloud-exposure incidents where a bucket
has become publicly readable or writable. The action preserves the original
policy, ACL, public-access-block state, and tags so responders can review or
restore the prior configuration after the incident is resolved.

IMPORTANT SAFETY GUIDELINES:
- All operations default to dry_run=True.
- Containment is reversible via restore_s3_bucket().
- Never delete bucket contents as part of containment.
- Confirm business impact before executing against production buckets.

Authentication:
- Uses boto3 default credential chain (env -> ~/.aws/credentials -> IAM role).
- Required IAM permissions:
    s3:GetBucketLocation
    s3:GetBucketPolicy
    s3:GetBucketPolicyStatus
    s3:GetBucketAcl
    s3:GetBucketTagging
    s3:GetBucketPublicAccessBlock
    s3:PutBucketPublicAccessBlock
    s3:DeleteBucketPolicy
    s3:PutBucketAcl
    s3:PutBucketTagging
    s3:DeleteBucketTagging
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


@dataclass
class S3BucketLockdownResult:
    """
    Result of an S3 bucket public-access lockdown operation.

    Attributes:
        success:         True if all actions completed without error.
        dry_run:         Whether this was a dry run (no real changes).
        bucket_name:     Target S3 bucket name.
        region:          AWS region used for the bucket client.
        incident_id:     IR ticket reference.
        actions_taken:   List of action descriptions (or dry-run previews).
        lockdown_state:  Captured original state for rollback.
        errors:          List of error messages if any step failed.
        completed_at:    UTC timestamp when the operation completed.
    """

    success: bool
    dry_run: bool
    bucket_name: str
    region: str
    incident_id: str
    actions_taken: list[str] = field(default_factory=list)
    lockdown_state: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    completed_at: Optional[str] = None


def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public_access_block_config() -> dict[str, bool]:
    return {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }


def _incident_tags(incident_id: str, bucket_name: str) -> dict[str, str]:
    return {
        "k1n-ir-incident-id": incident_id,
        "k1n-ir-action": "lockdown",
        "k1n-ir-bucket": bucket_name,
        "k1n-ir-timestamp": _timestamp(),
        "k1n-ir-automated": "true",
    }


def _merge_tag_set(
    existing_tags: list[dict[str, str]],
    additional_tags: dict[str, str],
) -> list[dict[str, str]]:
    merged = {tag["Key"]: tag["Value"] for tag in existing_tags}
    merged.update(additional_tags)
    return [{"Key": key, "Value": value} for key, value in sorted(merged.items())]


def _is_public_acl(grants: list[dict[str, Any]]) -> bool:
    for grant in grants:
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in _PUBLIC_GRANTEE_URIS:
            return True
    return False


def _bucket_region_from_location(location_constraint: Optional[str]) -> str:
    if not location_constraint:
        return "us-east-1"
    if location_constraint == "EU":
        return "eu-west-1"
    return location_constraint


def _aws_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    if isinstance(response, dict):
        error = response.get("Error", {})
        if isinstance(error, dict):
            return str(error.get("Code", ""))
    return ""


def lockdown_s3_bucket(
    bucket_name: str,
    incident_id: str,
    region: str = "us-east-1",
    aws_profile: Optional[str] = None,
    dry_run: bool = True,
) -> S3BucketLockdownResult:
    """
    Lock down a publicly exposed S3 bucket while preserving rollback state.

    Steps:
      1. Resolve the bucket region and collect current policy/ACL/tag state.
      2. Save the current state for audit and rollback.
      3. Enable full S3 Public Access Block.
      4. Delete the bucket policy if it is publicly accessible.
      5. Replace public ACL grants with the private canned ACL.
      6. Tag the bucket with incident metadata.

    Args:
        bucket_name:  S3 bucket to contain.
        incident_id:  IR ticket identifier for traceability.
        region:       AWS region used to discover the bucket location.
        aws_profile:  Optional AWS profile name.
        dry_run:      If True (default), preview actions without making changes.

    Returns:
        S3BucketLockdownResult with captured state, actions, and status.
    """

    result = S3BucketLockdownResult(
        success=False,
        dry_run=dry_run,
        bucket_name=bucket_name,
        region=region,
        incident_id=incident_id,
    )

    simulated_tags = _merge_tag_set([], _incident_tags(incident_id, bucket_name))
    if dry_run:
        result.lockdown_state = {
            "bucket_region": region,
            "original_public_access_block": None,
            "original_bucket_policy": None,
            "original_policy_was_public": None,
            "original_acl": {
                "Owner": {"DisplayName": "preview-owner", "ID": "preview-owner-id"},
                "Grants": [],
            },
            "original_tags": [],
            "rollback_command": (
                f"restore_s3_bucket(bucket_name='{bucket_name}', lockdown_state=...)"
            ),
        }
        result.actions_taken = [
            f"[DRY RUN] Would resolve the actual region for bucket '{bucket_name}'",
            "[DRY RUN] Would snapshot the current public access block, bucket policy, "
            "bucket ACL, and bucket tags for rollback",
            f"[DRY RUN] Would enforce S3 Public Access Block on '{bucket_name}': "
            f"{_public_access_block_config()}",
            f"[DRY RUN] Would delete the bucket policy for '{bucket_name}' only if it "
            "currently grants public access",
            f"[DRY RUN] Would replace public ACL grants on '{bucket_name}' with the "
            "private canned ACL if needed",
            f"[DRY RUN] Would tag bucket '{bucket_name}' with incident metadata: "
            f"{simulated_tags}",
        ]
        result.success = True
        result.completed_at = _timestamp()
        return result

    try:
        import boto3  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "boto3 not installed. Install the AWS extra or run: pip install boto3"
        )
        result.completed_at = _timestamp()
        return result

    try:
        session_kwargs: dict[str, Any] = {"region_name": region}
        if aws_profile:
            session_kwargs["profile_name"] = aws_profile
        session = boto3.Session(**session_kwargs)
        s3 = session.client("s3", region_name=region)

        location = s3.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
        bucket_region = _bucket_region_from_location(location)
        if bucket_region != region:
            s3 = session.client("s3", region_name=bucket_region)
        result.region = bucket_region
        result.actions_taken.append(
            f"Resolved bucket '{bucket_name}' to region '{bucket_region}'"
        )

        try:
            public_access_block = s3.get_public_access_block(Bucket=bucket_name)[
                "PublicAccessBlockConfiguration"
            ]
        except Exception as exc:  # noqa: BLE001
            if _aws_error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                public_access_block = None
            else:
                raise

        try:
            bucket_policy = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        except Exception as exc:  # noqa: BLE001
            if _aws_error_code(exc) == "NoSuchBucketPolicy":
                bucket_policy = None
            else:
                raise

        policy_is_public: Optional[bool]
        if bucket_policy is None:
            policy_is_public = False
        else:
            status = s3.get_bucket_policy_status(Bucket=bucket_name)
            policy_is_public = status.get("PolicyStatus", {}).get("IsPublic", False)

        acl = s3.get_bucket_acl(Bucket=bucket_name)
        acl_is_public = _is_public_acl(acl.get("Grants", []))

        try:
            existing_tags = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
        except Exception as exc:  # noqa: BLE001
            if _aws_error_code(exc) == "NoSuchTagSet":
                existing_tags = []
            else:
                raise

        result.lockdown_state = {
            "bucket_region": bucket_region,
            "original_public_access_block": public_access_block,
            "original_bucket_policy": bucket_policy,
            "original_policy_was_public": policy_is_public,
            "original_acl": {
                "Owner": acl.get("Owner", {}),
                "Grants": acl.get("Grants", []),
            },
            "original_tags": existing_tags,
            "rollback_command": (
                f"restore_s3_bucket(bucket_name='{bucket_name}', lockdown_state=...)"
            ),
        }
        result.actions_taken.append(
            "Captured original public access block, bucket policy, ACL, and tag state"
        )

        desired_public_access_block = _public_access_block_config()
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=desired_public_access_block,
        )
        result.actions_taken.append(
            f"Applied full S3 Public Access Block to bucket '{bucket_name}'"
        )

        if bucket_policy and policy_is_public:
            s3.delete_bucket_policy(Bucket=bucket_name)
            result.actions_taken.append(
                f"Deleted public bucket policy from '{bucket_name}'"
            )
        elif bucket_policy:
            result.actions_taken.append(
                f"Retained existing non-public bucket policy on '{bucket_name}'"
            )
        else:
            result.actions_taken.append(
                f"No bucket policy was present on '{bucket_name}'"
            )

        if acl_is_public:
            s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
            result.actions_taken.append(
                f"Replaced public bucket ACL grants on '{bucket_name}' with ACL=private"
            )
        else:
            result.actions_taken.append(
                f"Bucket ACL for '{bucket_name}' was already non-public"
            )

        merged_tags = _merge_tag_set(existing_tags, _incident_tags(incident_id, bucket_name))
        s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": merged_tags})
        result.actions_taken.append(
            f"Tagged bucket '{bucket_name}' with incident metadata"
        )

        result.success = True

    except Exception as exc:  # noqa: BLE001
        log.exception("S3 bucket lockdown failed: %s", exc)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result


def restore_s3_bucket(
    bucket_name: str,
    lockdown_state: dict[str, Any],
    region: str = "us-east-1",
    aws_profile: Optional[str] = None,
    dry_run: bool = True,
) -> S3BucketLockdownResult:
    """
    Restore an S3 bucket to the state captured before lockdown.

    Args:
        bucket_name:      Bucket name to restore.
        lockdown_state:   State returned by lockdown_s3_bucket().
        region:           AWS region used if the saved state does not include one.
        aws_profile:      Optional AWS profile name.
        dry_run:          If True (default), preview actions without making changes.

    Returns:
        S3BucketLockdownResult describing the restoration actions.
    """

    bucket_region = lockdown_state.get("bucket_region", region)
    result = S3BucketLockdownResult(
        success=False,
        dry_run=dry_run,
        bucket_name=bucket_name,
        region=bucket_region,
        incident_id=str(lockdown_state.get("incident_id", "<restore>")),
    )

    original_public_access_block = lockdown_state.get("original_public_access_block")
    original_policy = lockdown_state.get("original_bucket_policy")
    original_acl = lockdown_state.get("original_acl", {})
    original_tags = lockdown_state.get("original_tags", [])

    if dry_run:
        result.actions_taken = [
            f"[DRY RUN] Would restore public access block on '{bucket_name}' to: "
            f"{original_public_access_block or 'no bucket-level config'}",
            f"[DRY RUN] Would restore the original bucket policy on '{bucket_name}'"
            if original_policy
            else f"[DRY RUN] Would keep '{bucket_name}' without a bucket policy",
            f"[DRY RUN] Would restore the original ACL grants on '{bucket_name}'",
            f"[DRY RUN] Would restore the original bucket tags on '{bucket_name}'"
            if original_tags
            else f"[DRY RUN] Would remove incident tags from '{bucket_name}'",
        ]
        result.success = True
        result.completed_at = _timestamp()
        return result

    try:
        import boto3  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "boto3 not installed. Install the AWS extra or run: pip install boto3"
        )
        result.completed_at = _timestamp()
        return result

    try:
        session_kwargs: dict[str, Any] = {"region_name": bucket_region}
        if aws_profile:
            session_kwargs["profile_name"] = aws_profile
        session = boto3.Session(**session_kwargs)
        s3 = session.client("s3", region_name=bucket_region)

        if original_public_access_block:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration=original_public_access_block,
            )
            result.actions_taken.append(
                f"Restored original public access block on '{bucket_name}'"
            )
        else:
            try:
                s3.delete_public_access_block(Bucket=bucket_name)
            except Exception as exc:  # noqa: BLE001
                if _aws_error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
            result.actions_taken.append(
                f"Removed bucket-level public access block from '{bucket_name}'"
            )

        if original_policy:
            s3.put_bucket_policy(Bucket=bucket_name, Policy=original_policy)
            result.actions_taken.append(
                f"Restored the original bucket policy on '{bucket_name}'"
            )
        else:
            try:
                s3.delete_bucket_policy(Bucket=bucket_name)
            except Exception as exc:  # noqa: BLE001
                if _aws_error_code(exc) != "NoSuchBucketPolicy":
                    raise
            result.actions_taken.append(
                f"Confirmed '{bucket_name}' has no bucket policy after restore"
            )

        if original_acl:
            s3.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=original_acl)
            result.actions_taken.append(
                f"Restored the original bucket ACL on '{bucket_name}'"
            )

        if original_tags:
            s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": original_tags})
            result.actions_taken.append(
                f"Restored the original bucket tags on '{bucket_name}'"
            )
        else:
            try:
                s3.delete_bucket_tagging(Bucket=bucket_name)
            except Exception as exc:  # noqa: BLE001
                if _aws_error_code(exc) != "NoSuchTagSet":
                    raise
            result.actions_taken.append(
                f"Removed incident bucket tags from '{bucket_name}'"
            )

        result.success = True

    except Exception as exc:  # noqa: BLE001
        log.exception("S3 bucket restore failed: %s", exc)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result
