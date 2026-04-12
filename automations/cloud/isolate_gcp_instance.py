"""
GCP Compute Instance Isolation Containment Automation
======================================================
Contains a potentially compromised GCP VM instance by:
1. Adding a deny-all firewall rule targeting the instance via a network tag
2. Tagging the instance with incident metadata for traceability
3. Optionally stopping the instance to prevent further activity

This is the GCP equivalent of isolate_azure_vm.py.

IMPORTANT SAFETY GUIDELINES:
- All operations default to dry_run=True — no changes are made unless
  dry_run=False is explicitly set.
- This action is REVERSIBLE: saved original tags and firewall rule names allow
  full restoration via restore_gcp_instance().
- Never delete the instance or its disks — preserve forensic evidence.
- Always tag with incident_id so isolation is traceable in Cloud Audit Logs.
- Confirm with the incident commander before running in production.

GCP Isolation Strategy:
  GCP uses project-level firewall rules, not per-instance rules. Isolation
  is achieved by:
    (a) Adding an instance-specific network tag (e.g. "k1n-ir-isolated-<incident>")
    (b) Creating a deny-all ingress + egress firewall rule targeting that tag
    (c) This effectively air-gaps the instance without touching other instances

Authentication:
- Uses Application Default Credentials (ADC): gcloud auth application-default login
  or GOOGLE_APPLICATION_CREDENTIALS env var pointing to a service account key.
- The service account needs the following IAM roles:
    roles/compute.instanceAdmin.v1   (read/write instances and tags)
    roles/compute.securityAdmin      (create/delete firewall rules)

Usage:
    from automations.cloud.isolate_gcp_instance import (
        isolate_gcp_instance,
        restore_gcp_instance,
    )

    result = isolate_gcp_instance(
        project_id="my-gcp-project",
        zone="us-central1-a",
        instance_name="compromised-server",
        incident_id="INC-2026-042",
        dry_run=True,   # default: safe preview
    )
    print(result.actions_taken)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)
_NETWORK_SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class GcpIsolationResult:
    """
    Result of a GCP instance isolation operation.

    Attributes:
        success:         True if all actions completed without error.
        dry_run:         Whether this was a dry run (no real changes).
        instance_name:   Target instance name.
        project_id:      GCP project ID.
        zone:            GCP zone of the instance.
        incident_id:     IR ticket reference.
        actions_taken:   List of action descriptions (or dry-run previews).
        saved_state:     Dict containing original tags and firewall rule names for rollback.
        errors:          List of error messages if any step failed.
        completed_at:    UTC timestamp when isolation completed.
    """
    success:        bool
    dry_run:        bool
    instance_name:  str
    project_id:     str
    zone:           str
    incident_id:    str
    actions_taken:  list[str]       = field(default_factory=list)
    saved_state:    dict[str, Any]  = field(default_factory=dict)
    errors:         list[str]       = field(default_factory=list)
    completed_at:   Optional[str]   = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_required_identifier(value: object, *, field_name: str) -> str:
    """Reject blank, control-character, whitespace, or path-like identifiers."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized):
        raise ValueError(f"{field_name} must not contain control characters")
    if "/" in normalized or "\\" in normalized:
        raise ValueError(f"{field_name} must not contain path separators")
    if any(ch.isspace() for ch in normalized):
        raise ValueError(f"{field_name} must not contain whitespace")
    return normalized


def _normalize_network_path(network: object) -> str:
    """Validate a relative Compute Engine network resource path."""
    if not isinstance(network, str):
        raise ValueError("Network path must be a string")

    normalized = network.strip()
    if not normalized:
        raise ValueError("Network path must not be blank")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized):
        raise ValueError("Network path must not contain control characters")
    if any(ch.isspace() for ch in normalized):
        raise ValueError("Network path must not contain whitespace")
    if normalized.startswith("/"):
        raise ValueError("Network path must be relative, not absolute")
    if "\\" in normalized:
        raise ValueError("Network path must use forward slashes only")
    if "://" in normalized:
        raise ValueError("Network path must not be a URL")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Network path must not contain empty, '.' or '..' segments")
    if any(_NETWORK_SEGMENT_RE.fullmatch(part) is None for part in parts):
        raise ValueError("Network path contains unsupported characters")

    is_global_path = len(parts) == 3 and parts[0] == "global" and parts[1] == "networks"
    is_project_path = (
        len(parts) == 5
        and parts[0] == "projects"
        and parts[2] == "global"
        and parts[3] == "networks"
    )
    if not (is_global_path or is_project_path):
        raise ValueError(
            "Network path must use 'global/networks/<name>' or "
            "'projects/<project>/global/networks/<name>'"
        )

    return normalized


def _isolation_tag(incident_id: str) -> str:
    """
    Return a GCP-safe network tag derived from the incident ID.

    GCP network tags must be lowercase letters, numbers, and hyphens only,
    starting with a letter. Max 63 characters.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", incident_id.lower()).strip("-")
    if not slug:
        raise ValueError("Incident ID must contain at least one letter or number")
    tag = f"k1n-ir-isolated-{slug}"
    return tag[:63]


def _firewall_rule_name(incident_id: str) -> str:
    """Return a GCP-safe firewall rule name for the isolation rule."""
    slug = re.sub(r"[^a-z0-9-]", "-", incident_id.lower()).strip("-")
    if not slug:
        raise ValueError("Incident ID must contain at least one letter or number")
    name = f"k1n-ir-deny-all-{slug}"
    return name[:63]


def _directional_firewall_rule_name(incident_id: str, direction: str) -> str:
    """Return a GCP-safe firewall rule name with a direction suffix."""
    suffix = f"-{direction}"
    base = _firewall_rule_name(incident_id)
    return f"{base[: 63 - len(suffix)]}{suffix}"


def _label_value(value: str) -> str:
    """Return a GCP-label-safe value preserving enough context for audit use."""
    cleaned = re.sub(r"[^a-z0-9_-]", "-", value.lower()).strip("-_")
    return cleaned[:63]


def _incident_metadata(incident_id: str, instance_name: str) -> dict[str, str]:
    """Return GCP instance metadata labels for incident traceability."""
    return {
        "k1n-ir-incident-id":  _label_value(incident_id),
        "k1n-ir-action":       "isolation",
        "k1n-ir-instance":     _label_value(instance_name),
        "k1n-ir-timestamp":    _timestamp(),
        "k1n-ir-automated":    "true",
    }


def _build_deny_all_firewall_body(
    incident_id: str,
    network: str = "global/networks/default",
) -> dict[str, Any]:
    """
    Return a Compute Engine firewall rule resource dict that denies all
    ingress and egress traffic for instances tagged with the isolation tag.

    GCP does not support a single rule for both ingress and egress, so
    two rules are needed; this helper returns the config for one direction.
    The caller creates two rules: one for ingress, one for egress.
    """
    tag = _isolation_tag(incident_id)
    return {
        "ingress_rule": {
            "name": _directional_firewall_rule_name(incident_id, "ingress"),
            "description": f"Incident containment: deny all ingress — {incident_id}",
            "network": network,
            "priority": 100,
            "direction": "INGRESS",
            "denied": [{"IPProtocol": "all"}],
            "targetTags": [tag],
            "sourceRanges": ["0.0.0.0/0"],
        },
        "egress_rule": {
            "name": _directional_firewall_rule_name(incident_id, "egress"),
            "description": f"Incident containment: deny all egress — {incident_id}",
            "network": network,
            "priority": 100,
            "direction": "EGRESS",
            "denied": [{"IPProtocol": "all"}],
            "targetTags": [tag],
            "destinationRanges": ["0.0.0.0/0"],
        },
        "isolation_tag": tag,
    }


# ---------------------------------------------------------------------------
# Main isolation function
# ---------------------------------------------------------------------------

def isolate_gcp_instance(
    project_id: str,
    zone: str,
    instance_name: str,
    incident_id: str,
    network: str = "global/networks/default",
    stop_instance: bool = False,
    dry_run: bool = True,
) -> GcpIsolationResult:
    """
    Isolate a compromised GCP instance by applying a deny-all firewall rule
    via a dedicated network tag.

    Steps:
      1. Fetch the instance to get current network tags and metadata.
      2. Save current tags for rollback.
      3. Add isolation tag to the instance.
      4. Create deny-all ingress + egress firewall rules targeting the isolation tag.
      5. Apply incident metadata labels to the instance.
      6. Optionally stop the instance.

    Args:
        project_id:     GCP project ID.
        zone:           Zone of the instance (e.g. "us-central1-a").
        instance_name:  Name of the instance to isolate.
        incident_id:    IR ticket ID (used for tagging and firewall rule naming).
        network:        Full network resource path (default: global/networks/default).
        stop_instance:  If True, stop the instance after firewall isolation.
        dry_run:        If True (default), preview actions without making changes.

    Returns:
        GcpIsolationResult with actions_taken, saved_state, and success flag.
    """
    project_id = _normalize_required_identifier(project_id, field_name="Project ID")
    zone = _normalize_required_identifier(zone, field_name="Zone")
    instance_name = _normalize_required_identifier(instance_name, field_name="Instance name")
    incident_id = _normalize_required_identifier(incident_id, field_name="Incident ID")
    network = _normalize_network_path(network)

    result = GcpIsolationResult(
        success=False,
        dry_run=dry_run,
        instance_name=instance_name,
        project_id=project_id,
        zone=zone,
        incident_id=incident_id,
    )

    isolation_tag = _isolation_tag(incident_id)
    fw_body = _build_deny_all_firewall_body(incident_id, network)
    ingress_rule_name = fw_body["ingress_rule"]["name"]
    egress_rule_name = fw_body["egress_rule"]["name"]

    if dry_run:
        # Simulate the saved state that would be captured from the live instance
        result.saved_state = {
            "original_tags": [],          # would contain current network tags
            "original_labels": {},        # would contain current metadata labels
            "ingress_firewall_rule": ingress_rule_name,
            "egress_firewall_rule": egress_rule_name,
            "isolation_tag": isolation_tag,
            "stop_instance": stop_instance,
            "was_running": True,           # assume running for dry-run preview
        }
        result.actions_taken = [
            f"[DRY RUN] Would fetch instance '{instance_name}' in project '{project_id}', zone '{zone}'",
            f"[DRY RUN] Would save current network tags for rollback",
            f"[DRY RUN] Would add isolation tag '{isolation_tag}' to instance tags",
            f"[DRY RUN] Would create ingress deny-all firewall rule '{ingress_rule_name}' "
            f"(priority 100, target tag: {isolation_tag})",
            f"[DRY RUN] Would create egress deny-all firewall rule '{egress_rule_name}' "
            f"(priority 100, target tag: {isolation_tag})",
            f"[DRY RUN] Would apply incident labels to instance: incident_id={incident_id}",
        ]
        if stop_instance:
            result.actions_taken.append(
                f"[DRY RUN] Would stop instance '{instance_name}' to prevent further activity"
            )
        result.success = True
        result.completed_at = _timestamp()
        return result

    # --- Live execution path ---
    try:
        from google.cloud import compute_v1  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "google-cloud-compute not installed. "
            "Run: pip install google-cloud-compute"
        )
        result.completed_at = _timestamp()
        return result

    try:
        instances_client = compute_v1.InstancesClient()
        firewalls_client = compute_v1.FirewallsClient()

        # Step 1: Fetch current instance state
        instance = instances_client.get(
            project=project_id, zone=zone, instance=instance_name
        )
        current_tags = list(instance.tags.items) if instance.tags else []
        current_labels = dict(instance.labels) if instance.labels else {}
        result.saved_state = {
            "original_tags": current_tags,
            "original_labels": current_labels,
            "ingress_firewall_rule": ingress_rule_name,
            "egress_firewall_rule": egress_rule_name,
            "isolation_tag": isolation_tag,
            "stop_instance": stop_instance,
            "was_running": instance.status == "RUNNING",
        }
        result.actions_taken.append(
            f"Fetched instance '{instance_name}': "
            f"status={instance.status}, existing_tags={current_tags}"
        )

        # Step 2: Add isolation network tag
        new_tags = list(set(current_tags) | {isolation_tag})
        tags_body = compute_v1.Tags(items=new_tags, fingerprint=instance.tags.fingerprint)
        op = instances_client.set_tags(
            project=project_id, zone=zone, instance=instance_name, tags_resource=tags_body
        )
        op.result()  # wait for completion
        result.actions_taken.append(
            f"Added isolation tag '{isolation_tag}' to instance '{instance_name}'"
        )

        # Step 3: Create deny-all ingress firewall rule
        ingress_fw = compute_v1.Firewall(**fw_body["ingress_rule"])  # type: ignore[arg-type]
        op = firewalls_client.insert(project=project_id, firewall_resource=ingress_fw)
        op.result()
        result.actions_taken.append(
            f"Created ingress deny-all firewall rule '{ingress_rule_name}'"
        )

        # Step 4: Create deny-all egress firewall rule
        egress_fw = compute_v1.Firewall(**fw_body["egress_rule"])  # type: ignore[arg-type]
        op = firewalls_client.insert(project=project_id, firewall_resource=egress_fw)
        op.result()
        result.actions_taken.append(
            f"Created egress deny-all firewall rule '{egress_rule_name}'"
        )

        # Step 5: Apply incident labels
        incident_labels = _incident_metadata(incident_id, instance_name)
        merged_labels = {**current_labels, **incident_labels}
        labels_body = compute_v1.InstancesSetLabelsRequest(
            labels=merged_labels,
            label_fingerprint=instance.label_fingerprint,
        )
        op = instances_client.set_labels(
            project=project_id, zone=zone, instance=instance_name,
            instances_set_labels_request_resource=labels_body,
        )
        op.result()
        result.actions_taken.append(
            f"Applied incident labels to instance '{instance_name}': "
            f"incident_id={incident_id}"
        )

        # Step 6: Optionally stop the instance
        if stop_instance:
            op = instances_client.stop(project=project_id, zone=zone, instance=instance_name)
            op.result()
            result.actions_taken.append(
                f"Stopped instance '{instance_name}' to prevent further activity"
            )

        result.success = True

    except Exception as exc:  # noqa: BLE001
        log.exception("GCP isolation failed: %s", exc)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result


# ---------------------------------------------------------------------------
# Restoration function
# ---------------------------------------------------------------------------

def restore_gcp_instance(
    project_id: str,
    zone: str,
    instance_name: str,
    saved_state: dict[str, Any],
    dry_run: bool = True,
) -> GcpIsolationResult:
    """
    Restore a GCP instance to its pre-isolation state.

    Uses the saved_state dict returned by isolate_gcp_instance() to:
      1. Remove the isolation network tag from the instance.
      2. Delete the ingress and egress deny-all firewall rules.
      3. Restore original metadata labels.
      4. Optionally restart the instance if it was stopped during isolation.

    Args:
        project_id:     GCP project ID.
        zone:           Zone of the instance.
        instance_name:  Name of the instance to restore.
        saved_state:    The saved_state dict from GcpIsolationResult.
        dry_run:        If True (default), preview actions without making changes.

    Returns:
        GcpIsolationResult with actions_taken and success flag.
    """
    project_id = _normalize_required_identifier(project_id, field_name="Project ID")
    zone = _normalize_required_identifier(zone, field_name="Zone")
    instance_name = _normalize_required_identifier(instance_name, field_name="Instance name")
    if not isinstance(saved_state, dict):
        raise ValueError("saved_state must be a dict returned by isolate_gcp_instance()")

    result = GcpIsolationResult(
        success=False,
        dry_run=dry_run,
        instance_name=instance_name,
        project_id=project_id,
        zone=zone,
        incident_id=saved_state.get("isolation_tag", "<unknown>"),
    )

    isolation_tag = saved_state.get("isolation_tag", "")
    ingress_rule = saved_state.get("ingress_firewall_rule", "")
    egress_rule = saved_state.get("egress_firewall_rule", "")
    original_tags = saved_state.get("original_tags", [])
    original_labels = saved_state.get("original_labels", {})
    was_running = saved_state.get("was_running", False)
    was_stopped = saved_state.get("stop_instance", False)

    if dry_run:
        result.actions_taken = [
            f"[DRY RUN] Would remove isolation tag '{isolation_tag}' from instance '{instance_name}'",
            f"[DRY RUN] Would restore original tags: {original_tags}",
            f"[DRY RUN] Would delete ingress deny-all firewall rule '{ingress_rule}'",
            f"[DRY RUN] Would delete egress deny-all firewall rule '{egress_rule}'",
            f"[DRY RUN] Would restore original instance labels",
        ]
        if was_stopped and was_running:
            result.actions_taken.append(
                f"[DRY RUN] Would start instance '{instance_name}' (was running before isolation)"
            )
        result.success = True
        result.completed_at = _timestamp()
        return result

    # --- Live execution path ---
    try:
        from google.cloud import compute_v1  # type: ignore[import]
    except ImportError:
        result.errors.append(
            "google-cloud-compute not installed. "
            "Run: pip install google-cloud-compute"
        )
        result.completed_at = _timestamp()
        return result

    try:
        instances_client = compute_v1.InstancesClient()
        firewalls_client = compute_v1.FirewallsClient()

        # Step 1: Restore original network tags (removes isolation tag)
        instance = instances_client.get(
            project=project_id, zone=zone, instance=instance_name
        )
        tags_body = compute_v1.Tags(
            items=original_tags, fingerprint=instance.tags.fingerprint
        )
        op = instances_client.set_tags(
            project=project_id, zone=zone, instance=instance_name, tags_resource=tags_body
        )
        op.result()
        result.actions_taken.append(
            f"Removed isolation tag '{isolation_tag}', restored tags: {original_tags}"
        )

        # Step 2: Delete ingress firewall rule
        op = firewalls_client.delete(project=project_id, firewall=ingress_rule)
        op.result()
        result.actions_taken.append(f"Deleted ingress deny-all firewall rule '{ingress_rule}'")

        # Step 3: Delete egress firewall rule
        op = firewalls_client.delete(project=project_id, firewall=egress_rule)
        op.result()
        result.actions_taken.append(f"Deleted egress deny-all firewall rule '{egress_rule}'")

        # Step 4: Restore original labels
        labels_body = compute_v1.InstancesSetLabelsRequest(
            labels=original_labels,
            label_fingerprint=instance.label_fingerprint,
        )
        op = instances_client.set_labels(
            project=project_id, zone=zone, instance=instance_name,
            instances_set_labels_request_resource=labels_body,
        )
        op.result()
        result.actions_taken.append(f"Restored original instance labels")

        # Step 5: Restart if it was stopped during isolation
        if was_stopped and was_running:
            op = instances_client.start(project=project_id, zone=zone, instance=instance_name)
            op.result()
            result.actions_taken.append(
                f"Started instance '{instance_name}' (was running before isolation)"
            )

        result.success = True

    except Exception as exc:  # noqa: BLE001
        log.exception("GCP restoration failed: %s", exc)
        result.errors.append(str(exc))

    result.completed_at = _timestamp()
    return result
