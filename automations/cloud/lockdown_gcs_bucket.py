"""
GCS Bucket Public Exposure Lockdown Automation
==============================================
Locks down a potentially exposed Google Cloud Storage bucket by:
1. Capturing the current IAM policy, labels, and IAM configuration for rollback
2. Enforcing public access prevention
3. Enabling uniform bucket-level access
4. Removing public IAM principals (`allUsers`, `allAuthenticatedUsers`)
5. Labeling the bucket with incident metadata for audit traceability

This containment flow is designed for cloud-exposure incidents where a bucket
has become publicly readable or writable. The action preserves the original
policy and access configuration so responders can review or restore the prior
state after the incident is resolved.

IMPORTANT SAFETY GUIDELINES:
- All operations default to dry_run=True.
- Containment is reversible via restore_gcs_bucket().
- Never delete bucket contents as part of containment.
- Confirm business impact before executing against production buckets.

Authentication:
- Uses Application Default Credentials (ADC).
- Required IAM permissions typically include:
    storage.buckets.get
    storage.buckets.update
    storage.buckets.getIamPolicy
    storage.buckets.setIamPolicy
"""
from __future__ import annotations

import logging
import re
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


@dataclass
class GcsBucketLockdownResult:
    """
    Result of a GCS bucket public-exposure lockdown operation.

    Attributes:
        success:         True if all actions completed without error.
        dry_run:         Whether this was a dry run (no real changes).
        bucket_name:     Target bucket name.
        project_id:      GCP project used for the client, when known.
        incident_id:     IR ticket reference.
        actions_taken:   List of action descriptions (or dry-run previews).
        lockdown_state:  Captured original state for rollback.
        errors:          List of error messages if any step failed.
        completed_at:    UTC timestamp when the operation completed.
    """

    success: bool
    dry_run: bool
    bucket_name: str
    project_id: Optional[str]
    incident_id: str
    actions_taken: list[str] = field(default_factory=list)
    lockdown_state: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    completed_at: Optional[str] = None


def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label_value(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]", "-", value.lower()).strip("-_")
    return (cleaned or "na")[:63]


def _incident_labels(incident_id: str, bucket_name: str) -> dict[str, str]:
    return {
        "k1n-ir-incident-id": _label_value(incident_id),
        "k1n-ir-action": "lockdown",
        "k1n-ir-bucket": _label_value(bucket_name),
        "k1n-ir-timestamp": _label_value(_timestamp()),
        "k1n-ir-automated": "true",
    }


def _merge_labels(
    existing_labels: dict[str, str],
    additional_labels: dict[str, str],
) -> dict[str, str]:
    merged = dict(existing_labels)
    merged.update(additional_labels)
    return dict(sorted(merged.items()))


def _policy_snapshot(policy: Any) -> dict[str, Any]:
    if isinstance(policy, dict):
        return deepcopy(policy)
    return {
        "version": getattr(policy, "version", None),
        "etag": getattr(policy, "etag", None),
        "bindings": deepcopy(list(getattr(policy, "bindings", []) or [])),
    }


def _apply_policy_snapshot(policy: Any, snapshot: dict[str, Any]) -> Any:
    bindings = deepcopy(snapshot.get("bindings", []))
    if isinstance(policy, dict):
        policy["bindings"] = bindings
        if "version" in snapshot:
            policy["version"] = snapshot.get("version")
        if "etag" in snapshot:
            policy["etag"] = snapshot.get("etag")
        return policy

    if hasattr(policy, "bindings"):
        policy.bindings = bindings
    if hasattr(policy, "version") and "version" in snapshot:
        policy.version = snapshot.get("version")
    if hasattr(policy, "etag") and "etag" in snapshot:
        policy.etag = snapshot.get("etag")
    return policy


def _policy_has_public_members(policy_snapshot: dict[str, Any]) -> bool:
    for binding in policy_snapshot.get("bindings", []):
        for member in binding.get("members", []):
            if member in _PUBLIC_MEMBERS:
                return True
    return False


def _remove_public_members(
    policy_snapshot: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    updated = deepcopy(policy_snapshot)
    removed: list[str] = []
    sanitized_bindings: list[dict[str, Any]] = []

    for binding in updated.get("bindings", []):
        original_members = list(binding.get("members", []))
        kept_members = [member for member in original_members if member not in _PUBLIC_MEMBERS]
        removed.extend(member for member in original_members if member in _PUBLIC_MEMBERS)
        if kept_members:
            updated_binding = dict(binding)
            updated_binding["members"] = kept_members
            sanitized_bindings.append(updated_binding)

    updated["bindings"] = sanitized_bindings
    unique_removed = sorted(set(removed))
    return updated, unique_removed


def lockdown_gcs_bucket(
    bucket_name: str,
    incident_id: str,
    project_id: Optional[str] = None,
    dry_run: bool = True,
) -> GcsBucketLockdownResult:
    """
    Lock down a publicly exposed GCS bucket while preserving rollback state.

    Steps:
      1. Capture the current IAM policy, labels, and IAM configuration.
      2. Enforce public access prevention.
      3. Enable uniform bucket-level access.
      4. Remove public IAM principals from the bucket policy.
      5. Label the bucket with incident metadata.
    """

    result = GcsBucketLockdownResult(
        success=False,
        dry_run=dry_run,
        bucket_name=bucket_name,
        project_id=project_id,
        incident_id=incident_id,
    )

    incident_labels = _incident_labels(incident_id, bucket_name)
    if dry_run:
        result.lockdown_state = {
            "project_id": project_id or "<adc-project>",
            "original_public_access_prevention": "inherited",
            "original_uniform_bucket_level_access_enabled": False,
            "original_labels": {},
            "original_iam_policy": {
                "version": 3,
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"],
                    }
                ],
            },
            "rollback_command": (
                f"restore_gcs_bucket(bucket_name='{bucket_name}', lockdown_state=...)"
            ),
        }
        result.actions_taken = [
            f"[DRY RUN] Would resolve bucket '{bucket_name}' using Application Default Credentials",
            f"[DRY RUN] Would snapshot IAM policy, labels, and IAM configuration for '{bucket_name}'",
            f"[DRY RUN] Would enforce public access prevention on '{bucket_name}'",
            f"[DRY RUN] Would enable uniform bucket-level access on '{bucket_name}'",
            f"[DRY RUN] Would remove public IAM principals from '{bucket_name}': "
            "allUsers, allAuthenticatedUsers",
            f"[DRY RUN] Would label bucket '{bucket_name}' with incident metadata: "
            f"{incident_labels}",
        ]
        result.success = True
        result.completed_at = _timestamp()
        return result

    try:
        from google.cloud import storage  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "google-cloud-storage not installed. Install the GCP extra or run: "
            "pip install google-cloud-storage"
        )
        result.completed_at = _timestamp()
        return result

    try:
        client = storage.Client(project=project_id) if project_id else storage.Client()
        resolved_project = project_id or getattr(client, "project", None)
        bucket = client.bucket(bucket_name)
        bucket.reload()
        result.project_id = resolved_project

        iam_configuration = getattr(bucket, "iam_configuration", None)
        if iam_configuration is None:
            result.errors.append(
                f"Bucket '{bucket_name}' does not expose IAM configuration controls through the SDK."
            )
            result.completed_at = _timestamp()
            return result

        original_policy = _policy_snapshot(bucket.get_iam_policy(requested_policy_version=3))
        original_labels = dict(getattr(bucket, "labels", {}) or {})
        original_public_access_prevention = getattr(
            iam_configuration, "public_access_prevention", None
        )
        original_ubla_enabled = bool(
            getattr(iam_configuration, "uniform_bucket_level_access_enabled", False)
        )

        result.lockdown_state = {
            "project_id": resolved_project,
            "original_public_access_prevention": original_public_access_prevention,
            "original_uniform_bucket_level_access_enabled": original_ubla_enabled,
            "original_labels": original_labels,
            "original_iam_policy": original_policy,
            "rollback_command": (
                f"restore_gcs_bucket(bucket_name='{bucket_name}', lockdown_state=...)"
            ),
        }

        bucket_needs_patch = False
        if original_public_access_prevention != "enforced":
            iam_configuration.public_access_prevention = "enforced"
            bucket_needs_patch = True
            result.actions_taken.append(
                f"Enforced public access prevention on GCS bucket '{bucket_name}'"
            )
        else:
            result.actions_taken.append(
                f"Public access prevention already enforced on '{bucket_name}'"
            )

        if not original_ubla_enabled:
            iam_configuration.uniform_bucket_level_access_enabled = True
            bucket_needs_patch = True
            result.actions_taken.append(
                f"Enabled uniform bucket-level access on GCS bucket '{bucket_name}'"
            )
        else:
            result.actions_taken.append(
                f"Uniform bucket-level access already enabled on '{bucket_name}'"
            )

        merged_labels = _merge_labels(original_labels, incident_labels)
        if merged_labels != original_labels:
            bucket.labels = merged_labels
            bucket_needs_patch = True
            result.actions_taken.append(
                f"Updated labels on GCS bucket '{bucket_name}' with incident metadata"
            )
        else:
            result.actions_taken.append(
                f"GCS bucket '{bucket_name}' already contains the required incident labels"
            )

        sanitized_policy, removed_public_members = _remove_public_members(original_policy)
        if removed_public_members:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            bucket.set_iam_policy(_apply_policy_snapshot(policy, sanitized_policy))
            result.actions_taken.append(
                f"Removed public IAM principals from '{bucket_name}': "
                f"{', '.join(removed_public_members)}"
            )
        else:
            result.actions_taken.append(
                f"No public IAM principals found on GCS bucket '{bucket_name}'"
            )

        if bucket_needs_patch:
            bucket.patch()

        result.success = True
    except Exception as exc:  # pragma: no cover
        log.exception("Failed to lock down GCS bucket %s", bucket_name)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result


def restore_gcs_bucket(
    bucket_name: str,
    lockdown_state: dict[str, Any],
    project_id: Optional[str] = None,
    dry_run: bool = True,
) -> GcsBucketLockdownResult:
    """Restore a previously captured GCS bucket state."""

    resolved_project = project_id or lockdown_state.get("project_id")
    result = GcsBucketLockdownResult(
        success=False,
        dry_run=dry_run,
        bucket_name=bucket_name,
        project_id=resolved_project,
        incident_id=str(lockdown_state.get("incident_id", "")),
        lockdown_state=deepcopy(lockdown_state),
    )

    if dry_run:
        result.actions_taken = [
            f"[DRY RUN] Would restore public access prevention on '{bucket_name}' to "
            f"{lockdown_state.get('original_public_access_prevention')!r}",
            f"[DRY RUN] Would restore uniform bucket-level access on '{bucket_name}' to "
            f"{lockdown_state.get('original_uniform_bucket_level_access_enabled')!r}",
            f"[DRY RUN] Would restore labels on '{bucket_name}' to "
            f"{lockdown_state.get('original_labels', {})}",
            f"[DRY RUN] Would restore IAM policy bindings on '{bucket_name}'",
        ]
        result.success = True
        result.completed_at = _timestamp()
        return result

    try:
        from google.cloud import storage  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "google-cloud-storage not installed. Install the GCP extra or run: "
            "pip install google-cloud-storage"
        )
        result.completed_at = _timestamp()
        return result

    try:
        client = storage.Client(project=resolved_project) if resolved_project else storage.Client()
        bucket = client.bucket(bucket_name)
        bucket.reload()

        iam_configuration = getattr(bucket, "iam_configuration", None)
        if iam_configuration is None:
            result.errors.append(
                f"Bucket '{bucket_name}' does not expose IAM configuration controls through the SDK."
            )
            result.completed_at = _timestamp()
            return result

        iam_configuration.public_access_prevention = lockdown_state.get(
            "original_public_access_prevention"
        )
        iam_configuration.uniform_bucket_level_access_enabled = bool(
            lockdown_state.get("original_uniform_bucket_level_access_enabled", False)
        )
        bucket.labels = dict(lockdown_state.get("original_labels", {}))
        bucket.patch()

        original_policy = lockdown_state.get("original_iam_policy")
        if original_policy:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            bucket.set_iam_policy(_apply_policy_snapshot(policy, original_policy))
            result.actions_taken.append(
                f"Restored IAM policy bindings on GCS bucket '{bucket_name}'"
            )

        result.actions_taken.extend(
            [
                f"Restored public access prevention on '{bucket_name}'",
                f"Restored uniform bucket-level access on '{bucket_name}'",
                f"Restored labels on GCS bucket '{bucket_name}'",
            ]
        )
        result.success = True
    except Exception as exc:  # pragma: no cover
        log.exception("Failed to restore GCS bucket %s", bucket_name)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result
