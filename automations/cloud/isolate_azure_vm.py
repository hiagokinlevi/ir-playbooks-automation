"""
Azure VM Isolation Containment Automation
==========================================
Contains a potentially compromised Azure VM by:
1. Applying a deny-all NSG (Network Security Group) rule to the VM's NIC
2. Optionally deallocating (stopping) the VM to prevent further activity
3. Tagging the VM and NIC with incident metadata for traceability

This is the Azure equivalent of isolate_aws_instance.py.

IMPORTANT SAFETY GUIDELINES:
- All operations default to dry_run=True — no changes are made unless
  dry_run=False is explicitly set.
- This action is REVERSIBLE: saved original NSG IDs and VM state allow
  full restoration via restore_azure_vm().
- Never delete the VM or its disks — preserve forensic evidence.
- Always tag with incident_id so isolation is traceable in Azure Activity Log.
- Confirm with the incident commander before running in production.

Authentication:
- Uses azure-identity DefaultAzureCredential chain (env → managed identity →
  CLI → VS Code → …).
- Alternatively, pass explicit client_id, client_secret, tenant_id for SPN auth.

Required RBAC permissions:
  - Microsoft.Network/networkInterfaces/read
  - Microsoft.Network/networkInterfaces/write
  - Microsoft.Network/networkSecurityGroups/read
  - Microsoft.Network/networkSecurityGroups/write
  - Microsoft.Compute/virtualMachines/read
  - Microsoft.Compute/virtualMachines/write  (for deallocate)
  - Microsoft.Resources/subscriptions/resourceGroups/read

Usage:
    from automations.cloud.isolate_azure_vm import isolate_azure_vm, restore_azure_vm

    result = isolate_azure_vm(
        subscription_id="00000000-0000-0000-0000-000000000000",
        resource_group="rg-production",
        vm_name="app-server-01",
        incident_id="INC-2026-042",
        dry_run=True,   # default: safe preview
    )
    print(result["actions_taken"])
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AzureIsolationResult:
    """
    Result of an Azure VM isolation operation.

    Attributes:
        success:              True if all actions completed without error.
        dry_run:              Whether this was a dry run (no real changes).
        vm_name:              Target VM name.
        resource_group:       Resource group containing the VM.
        incident_id:          IR ticket reference.
        actions_taken:        List of action descriptions (or dry-run previews).
        saved_state:          Dict containing original NIC/NSG config for rollback.
        errors:               List of error messages if any step failed.
        completed_at:         UTC timestamp when isolation completed.
    """
    success:       bool
    dry_run:       bool
    vm_name:       str
    resource_group: str
    incident_id:   str
    actions_taken: list[str]           = field(default_factory=list)
    saved_state:   dict[str, Any]      = field(default_factory=dict)
    errors:        list[str]           = field(default_factory=list)
    completed_at:  Optional[str]       = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_deny_all_nsg_rules() -> list[dict[str, Any]]:
    """
    Return a list of NSG security rule dicts that deny all inbound and outbound.
    """
    return [
        {
            "name": "DenyAllInbound",
            "properties": {
                "priority": 100,
                "protocol": "*",
                "access": "Deny",
                "direction": "Inbound",
                "sourceAddressPrefix": "*",
                "sourcePortRange": "*",
                "destinationAddressPrefix": "*",
                "destinationPortRange": "*",
                "description": "Incident containment — deny all inbound traffic",
            },
        },
        {
            "name": "DenyAllOutbound",
            "properties": {
                "priority": 100,
                "protocol": "*",
                "access": "Deny",
                "direction": "Outbound",
                "sourceAddressPrefix": "*",
                "sourcePortRange": "*",
                "destinationAddressPrefix": "*",
                "destinationPortRange": "*",
                "description": "Incident containment — deny all outbound traffic",
            },
        },
    ]


def _incident_tags(incident_id: str, vm_name: str) -> dict[str, str]:
    return {
        "k1n-ir-incident-id":    incident_id,
        "k1n-ir-action":         "isolation",
        "k1n-ir-isolated-vm":    vm_name,
        "k1n-ir-timestamp":      _timestamp(),
        "k1n-ir-automated":      "true",
    }


# ---------------------------------------------------------------------------
# Main isolation function
# ---------------------------------------------------------------------------

def isolate_azure_vm(
    subscription_id: str,
    resource_group: str,
    vm_name: str,
    incident_id: str,
    location: str = "eastus",
    deallocate_vm: bool = False,
    dry_run: bool = True,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> AzureIsolationResult:
    """
    Isolate a compromised Azure VM by applying a deny-all NSG to its NIC.

    Steps:
      1. Fetch the VM and its primary NIC.
      2. Save the current NSG association for rollback.
      3. Create (or reuse) an incident-specific isolation NSG with deny-all rules.
      4. Associate the isolation NSG with the NIC.
      5. Tag the VM and NIC with incident metadata.
      6. Optionally deallocate (stop) the VM.

    Args:
        subscription_id: Azure subscription ID.
        resource_group:  Resource group containing the VM.
        vm_name:         Name of the VM to isolate.
        incident_id:     IR ticket ID (used for tagging and NSG naming).
        location:        Azure region for the isolation NSG (default: eastus).
        deallocate_vm:   If True, deallocate (stop) the VM after NSG isolation.
        dry_run:         If True (default), preview actions without making changes.
        tenant_id:       Azure tenant ID for SPN authentication (optional).
        client_id:       SPN client ID (optional — uses DefaultAzureCredential if absent).
        client_secret:   SPN client secret (optional).

    Returns:
        AzureIsolationResult with success status, actions taken, and saved state.
    """
    result = AzureIsolationResult(
        success=False,
        dry_run=dry_run,
        vm_name=vm_name,
        resource_group=resource_group,
        incident_id=incident_id,
    )

    isolation_nsg_name = f"nsg-ir-isolation-{incident_id.lower().replace(' ', '-')}"

    if dry_run:
        # Preview mode: describe what would happen without SDK calls
        actions = [
            f"[DRY RUN] Would fetch VM '{vm_name}' in resource group '{resource_group}'",
            f"[DRY RUN] Would retrieve primary NIC from VM '{vm_name}'",
            f"[DRY RUN] Would save current NSG association to saved_state for rollback",
            f"[DRY RUN] Would create isolation NSG '{isolation_nsg_name}' in '{location}' "
            f"with deny-all rules",
            f"[DRY RUN] Would associate '{isolation_nsg_name}' with NIC of '{vm_name}'",
            f"[DRY RUN] Would tag VM '{vm_name}' with incident metadata: "
            f"incident_id={incident_id}",
        ]
        if deallocate_vm:
            actions.append(f"[DRY RUN] Would deallocate (stop) VM '{vm_name}'")

        result.actions_taken = actions
        result.saved_state = {
            "original_nsg_id":  "PREVIEW_ONLY — no live state captured in dry run",
            "vm_state_before":  "PREVIEW_ONLY",
            "rollback_command": (
                f"restore_azure_vm(subscription_id, resource_group='{resource_group}', "
                f"vm_name='{vm_name}', incident_id='{incident_id}', saved_state=...)"
            ),
        }
        result.success = True
        result.completed_at = _timestamp()
        return result

    # Live execution path — requires azure-mgmt-network and azure-mgmt-compute
    try:
        from azure.identity import (
            ClientSecretCredential,
            DefaultAzureCredential,
        )
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except ImportError as exc:
        result.errors.append(
            f"Azure SDK not installed. Install azure-mgmt-compute and azure-mgmt-network: {exc}"
        )
        return result

    try:
        # Build credential
        if tenant_id and client_id and client_secret:
            cred = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            cred = DefaultAzureCredential()

        compute_client  = ComputeManagementClient(cred, subscription_id)
        network_client  = NetworkManagementClient(cred, subscription_id)
        tags            = _incident_tags(incident_id, vm_name)

        # Step 1: Fetch VM
        vm = compute_client.virtual_machines.get(resource_group, vm_name)
        result.actions_taken.append(f"Fetched VM '{vm_name}' (id: {vm.id})")

        # Step 2: Retrieve primary NIC
        if not vm.network_profile or not vm.network_profile.network_interfaces:
            result.errors.append(f"VM '{vm_name}' has no network interfaces.")
            return result

        nic_ref = vm.network_profile.network_interfaces[0]
        nic_name = nic_ref.id.split("/")[-1]
        nic = network_client.network_interfaces.get(resource_group, nic_name)
        result.actions_taken.append(f"Retrieved primary NIC '{nic_name}'")

        # Step 3: Save current NSG for rollback
        original_nsg_id = (
            nic.network_security_group.id
            if nic.network_security_group else None
        )
        result.saved_state = {
            "nic_name":         nic_name,
            "original_nsg_id":  original_nsg_id,
            "vm_state_before":  vm.instance_view.statuses[-1].code if vm.instance_view else "unknown",
        }
        result.actions_taken.append(
            f"Saved original NSG: {original_nsg_id or 'none'} (for rollback)"
        )

        # Step 4: Create isolation NSG with deny-all rules
        nsg_params = {
            "location": location,
            "tags": tags,
            "security_rules": _build_deny_all_nsg_rules(),
        }
        nsg = network_client.network_security_groups.begin_create_or_update(
            resource_group, isolation_nsg_name, nsg_params
        ).result()
        result.actions_taken.append(
            f"Created isolation NSG '{isolation_nsg_name}' in '{location}' (id: {nsg.id})"
        )

        # Step 5: Associate isolation NSG with NIC
        nic.network_security_group = {"id": nsg.id}
        nic.tags = {**(nic.tags or {}), **tags}
        network_client.network_interfaces.begin_create_or_update(
            resource_group, nic_name, nic
        ).result()
        result.actions_taken.append(
            f"Associated isolation NSG '{isolation_nsg_name}' with NIC '{nic_name}'"
        )

        # Step 6: Tag the VM
        current_tags = vm.tags or {}
        current_tags.update(tags)
        compute_client.virtual_machines.begin_update(
            resource_group, vm_name, {"tags": current_tags}
        ).result()
        result.actions_taken.append(f"Tagged VM '{vm_name}' with incident metadata")

        # Step 7: Optionally deallocate the VM
        if deallocate_vm:
            compute_client.virtual_machines.begin_deallocate(resource_group, vm_name).result()
            result.actions_taken.append(f"Deallocated (stopped) VM '{vm_name}'")
            result.saved_state["deallocated"] = True

        result.success = True
        result.completed_at = _timestamp()
        log.info(
            "Azure VM isolation complete",
            vm=vm_name, incident_id=incident_id, nsg=isolation_nsg_name,
        )

    except Exception as exc:
        result.errors.append(f"Isolation failed: {type(exc).__name__}: {exc}")
        log.error("Azure VM isolation failed", vm=vm_name, error=str(exc))

    return result


# ---------------------------------------------------------------------------
# Restoration function
# ---------------------------------------------------------------------------

def restore_azure_vm(
    subscription_id: str,
    resource_group: str,
    vm_name: str,
    incident_id: str,
    saved_state: dict[str, Any],
    dry_run: bool = True,
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> AzureIsolationResult:
    """
    Restore an isolated Azure VM to its pre-isolation network configuration.

    Args:
        subscription_id: Azure subscription ID.
        resource_group:  Resource group containing the VM.
        vm_name:         Name of the VM to restore.
        incident_id:     IR ticket ID (used for logging).
        saved_state:     The saved_state dict returned by isolate_azure_vm().
        dry_run:         If True, preview actions without making changes.
        tenant_id:       SPN tenant ID (optional).
        client_id:       SPN client ID (optional).
        client_secret:   SPN client secret (optional).

    Returns:
        AzureIsolationResult describing the restoration actions.
    """
    result = AzureIsolationResult(
        success=False,
        dry_run=dry_run,
        vm_name=vm_name,
        resource_group=resource_group,
        incident_id=incident_id,
    )

    nic_name        = saved_state.get("nic_name", "unknown")
    original_nsg_id = saved_state.get("original_nsg_id")

    if dry_run:
        result.actions_taken = [
            f"[DRY RUN] Would restore NIC '{nic_name}' to original NSG: "
            f"{original_nsg_id or 'none (no NSG attached before isolation)'}",
            f"[DRY RUN] Would remove incident tags from VM '{vm_name}'",
        ]
        if saved_state.get("deallocated"):
            result.actions_taken.append(
                f"[DRY RUN] Would start VM '{vm_name}' (was deallocated during isolation)"
            )
        result.success = True
        result.completed_at = _timestamp()
        return result

    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
    except ImportError as exc:
        result.errors.append(f"Azure SDK not installed: {exc}")
        return result

    try:
        cred = (
            ClientSecretCredential(tenant_id, client_id, client_secret)  # type: ignore
            if tenant_id and client_id and client_secret
            else DefaultAzureCredential()
        )
        compute_client = ComputeManagementClient(cred, subscription_id)
        network_client = NetworkManagementClient(cred, subscription_id)

        nic = network_client.network_interfaces.get(resource_group, nic_name)

        # Restore original NSG (or remove NSG if there was none)
        nic.network_security_group = {"id": original_nsg_id} if original_nsg_id else None
        # Remove incident tags from NIC
        nic.tags = {
            k: v for k, v in (nic.tags or {}).items()
            if not k.startswith("k1n-ir-")
        }
        network_client.network_interfaces.begin_create_or_update(
            resource_group, nic_name, nic
        ).result()
        result.actions_taken.append(
            f"Restored NIC '{nic_name}' to original NSG: {original_nsg_id or 'none'}"
        )

        # Remove incident tags from VM
        vm = compute_client.virtual_machines.get(resource_group, vm_name)
        clean_tags = {k: v for k, v in (vm.tags or {}).items() if not k.startswith("k1n-ir-")}
        compute_client.virtual_machines.begin_update(
            resource_group, vm_name, {"tags": clean_tags}
        ).result()
        result.actions_taken.append(f"Removed incident tags from VM '{vm_name}'")

        # Restart VM if it was deallocated during isolation
        if saved_state.get("deallocated"):
            compute_client.virtual_machines.begin_start(resource_group, vm_name).result()
            result.actions_taken.append(f"Started VM '{vm_name}'")

        result.success = True
        result.completed_at = _timestamp()

    except Exception as exc:
        result.errors.append(f"Restore failed: {type(exc).__name__}: {exc}")

    return result
