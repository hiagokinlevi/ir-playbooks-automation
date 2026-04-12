"""
Tests for automations/cloud/isolate_azure_vm.py

Validates:
  - AzureIsolationResult dataclass defaults
  - _build_deny_all_nsg_rules() rule structure
  - _incident_tags() tag key/value format
  - isolate_azure_vm() dry-run preview: actions, saved_state, success flag
  - isolate_azure_vm() with deallocate_vm=True adds deallocation to preview
  - isolate_azure_vm() with missing Azure SDK returns an error, success=False
  - restore_azure_vm() dry-run preview: NIC and tag restoration actions
  - restore_azure_vm() with deallocated=True adds start-VM action
  - isolation_nsg_name is sanitised (lowercased, spaces replaced)
  - completed_at is set on successful dry runs
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.cloud.isolate_azure_vm import (
    AzureIsolationResult,
    _build_deny_all_nsg_rules,
    _incident_tags,
    _isolation_nsg_name,
    _timestamp,
    isolate_azure_vm,
    restore_azure_vm,
)


# ---------------------------------------------------------------------------
# _build_deny_all_nsg_rules
# ---------------------------------------------------------------------------

class TestBuildDenyAllNsgRules:
    rules = _build_deny_all_nsg_rules()

    def test_returns_two_rules(self):
        assert len(self.rules) == 2

    def test_has_inbound_rule(self):
        directions = [r["properties"]["direction"] for r in self.rules]
        assert "Inbound" in directions

    def test_has_outbound_rule(self):
        directions = [r["properties"]["direction"] for r in self.rules]
        assert "Outbound" in directions

    def test_inbound_access_is_deny(self):
        inbound = next(r for r in self.rules if r["properties"]["direction"] == "Inbound")
        assert inbound["properties"]["access"] == "Deny"

    def test_outbound_access_is_deny(self):
        outbound = next(r for r in self.rules if r["properties"]["direction"] == "Outbound")
        assert outbound["properties"]["access"] == "Deny"

    def test_protocol_wildcard(self):
        for rule in self.rules:
            assert rule["properties"]["protocol"] == "*"

    def test_source_prefix_wildcard(self):
        for rule in self.rules:
            assert rule["properties"]["sourceAddressPrefix"] == "*"

    def test_destination_prefix_wildcard(self):
        for rule in self.rules:
            assert rule["properties"]["destinationAddressPrefix"] == "*"

    def test_priority_is_100(self):
        for rule in self.rules:
            assert rule["properties"]["priority"] == 100

    def test_names_set(self):
        names = {r["name"] for r in self.rules}
        assert "DenyAllInbound" in names
        assert "DenyAllOutbound" in names


# ---------------------------------------------------------------------------
# _incident_tags
# ---------------------------------------------------------------------------

class TestIncidentTags:
    tags = _incident_tags("INC-2026-001", "web-server-01")

    def test_has_incident_id_tag(self):
        assert self.tags["k1n-ir-incident-id"] == "INC-2026-001"

    def test_has_action_tag(self):
        assert self.tags["k1n-ir-action"] == "isolation"

    def test_has_isolated_vm_tag(self):
        assert self.tags["k1n-ir-isolated-vm"] == "web-server-01"

    def test_has_timestamp_tag(self):
        assert "k1n-ir-timestamp" in self.tags
        ts = self.tags["k1n-ir-timestamp"]
        # Must match %Y-%m-%dT%H:%M:%SZ format
        assert ts.endswith("Z")
        assert "T" in ts

    def test_automated_is_true(self):
        assert self.tags["k1n-ir-automated"] == "true"

    def test_all_keys_have_k1n_prefix(self):
        for key in self.tags:
            assert key.startswith("k1n-ir-")


class TestIsolationNsgName:
    def test_replaces_non_alnum_segments_with_dashes(self):
        assert _isolation_nsg_name("INC 2026 / PROD") == "nsg-ir-isolation-inc-2026-prod"

    def test_rejects_ids_without_letters_or_numbers(self):
        with pytest.raises(ValueError, match="at least one letter or number"):
            _isolation_nsg_name(" / --- ")


# ---------------------------------------------------------------------------
# isolate_azure_vm — dry run (default)
# ---------------------------------------------------------------------------

class TestIsolateAzureVmDryRun:

    def _run(self, **kwargs):
        defaults = dict(
            subscription_id="00000000-0000-0000-0000-000000000000",
            resource_group="rg-test",
            vm_name="test-vm-01",
            incident_id="INC-2026-099",
            dry_run=True,
        )
        defaults.update(kwargs)
        return isolate_azure_vm(**defaults)

    def test_success_is_true(self):
        result = self._run()
        assert result.success is True

    def test_dry_run_flag_set(self):
        result = self._run()
        assert result.dry_run is True

    def test_vm_name_preserved(self):
        result = self._run(vm_name="my-vm")
        assert result.vm_name == "my-vm"

    def test_resource_group_preserved(self):
        result = self._run(resource_group="rg-prod")
        assert result.resource_group == "rg-prod"

    def test_incident_id_preserved(self):
        result = self._run(incident_id="INC-2026-042")
        assert result.incident_id == "INC-2026-042"

    def test_actions_not_empty(self):
        result = self._run()
        assert len(result.actions_taken) > 0

    def test_actions_are_dry_run_prefixed(self):
        result = self._run()
        for action in result.actions_taken:
            assert action.startswith("[DRY RUN]")

    def test_actions_mention_vm_name(self):
        result = self._run(vm_name="app-server")
        texts = " ".join(result.actions_taken)
        assert "app-server" in texts

    def test_nsg_name_in_actions(self):
        result = self._run(incident_id="INC-2026-099")
        texts = " ".join(result.actions_taken)
        assert "nsg-ir-isolation-inc-2026-099" in texts

    def test_saved_state_has_rollback_info(self):
        result = self._run()
        assert "rollback_command" in result.saved_state

    def test_errors_empty_on_success(self):
        result = self._run()
        assert result.errors == []

    def test_completed_at_is_set(self):
        result = self._run()
        assert result.completed_at is not None
        assert result.completed_at.endswith("Z")

    def test_no_deallocate_action_by_default(self):
        result = self._run(deallocate_vm=False)
        texts = " ".join(result.actions_taken).lower()
        assert "deallocate" not in texts

    def test_deallocate_action_added_when_requested(self):
        result = self._run(deallocate_vm=True)
        texts = " ".join(result.actions_taken).lower()
        assert "deallocate" in texts

    def test_nsg_name_sanitises_spaces(self):
        # Incident IDs with spaces should be sanitised to dashes
        result = self._run(incident_id="INC 2026 SPACE")
        texts = " ".join(result.actions_taken)
        assert " " not in texts.split("nsg-ir-isolation-")[1].split("'")[0]

    def test_nsg_name_lowercased(self):
        result = self._run(incident_id="INC-2026-UPPER")
        texts = " ".join(result.actions_taken)
        # NSG name appears in actions — should be all lowercase
        nsg_segment = [t for t in result.actions_taken if "nsg-ir-isolation" in t][0]
        assert nsg_segment == nsg_segment.lower() or "nsg-ir-isolation-inc-2026-upper" in nsg_segment

    def test_strips_safe_whitespace_from_identifiers(self):
        result = self._run(
            subscription_id=" 00000000-0000-0000-0000-000000000000 ",
            resource_group=" rg-prod ",
            vm_name="web-01 ",
            incident_id=" INC-2026-042 ",
            location=" westus2 ",
        )
        assert result.vm_name == "web-01"
        assert result.resource_group == "rg-prod"
        assert result.incident_id == "INC-2026-042"
        assert any("westus2" in action for action in result.actions_taken)

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"subscription_id": "sub/id"}, "Subscription ID"),
            ({"resource_group": "rg/prod"}, "Resource group"),
            ({"vm_name": "web/01"}, "VM name"),
            ({"incident_id": "../INC-2026-042"}, "Incident ID"),
            ({"location": "westus2\nprod"}, "Location"),
        ],
    )
    def test_rejects_path_like_or_control_character_identifiers(self, kwargs, message):
        with pytest.raises(ValueError, match=message):
            self._run(**kwargs)


# ---------------------------------------------------------------------------
# isolate_azure_vm — missing SDK (simulated live run without SDK)
# ---------------------------------------------------------------------------

class TestIsolateAzureVmSdkMissing:
    """
    Force live-path by setting dry_run=False.  The Azure SDK is not installed
    in the test environment, so we expect an ImportError caught gracefully.
    """

    def test_returns_result_with_error_on_missing_sdk(self, monkeypatch):
        # Prevent azure imports from succeeding
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("azure"):
                raise ImportError(f"Simulated missing SDK: {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = isolate_azure_vm(
            subscription_id="sub-id",
            resource_group="rg",
            vm_name="vm",
            incident_id="INC-TEST",
            dry_run=False,
        )
        assert result.success is False
        assert len(result.errors) > 0
        assert "Azure SDK" in result.errors[0] or "azure" in result.errors[0].lower()


# ---------------------------------------------------------------------------
# restore_azure_vm — dry run
# ---------------------------------------------------------------------------

class TestRestoreAzureVmDryRun:

    def _run(self, saved_state=None, **kwargs):
        if saved_state is None:
            saved_state = {
                "nic_name": "nic-test-01",
                "original_nsg_id": "/subscriptions/xxx/resourceGroups/rg/providers/"
                                   "Microsoft.Network/networkSecurityGroups/nsg-original",
                "vm_state_before": "running",
            }
        defaults = dict(
            subscription_id="00000000-0000-0000-0000-000000000000",
            resource_group="rg-test",
            vm_name="test-vm-01",
            incident_id="INC-2026-099",
            saved_state=saved_state,
            dry_run=True,
        )
        defaults.update(kwargs)
        return restore_azure_vm(**defaults)

    def test_success_is_true(self):
        assert self._run().success is True

    def test_dry_run_flag_set(self):
        assert self._run().dry_run is True

    def test_actions_mention_nic_name(self):
        result = self._run()
        texts = " ".join(result.actions_taken)
        assert "nic-test-01" in texts

    def test_actions_mention_original_nsg(self):
        result = self._run()
        texts = " ".join(result.actions_taken)
        assert "nsg-original" in texts or "/subscriptions" in texts

    def test_actions_mention_vm_tag_removal(self):
        result = self._run(vm_name="victim-vm")
        texts = " ".join(result.actions_taken)
        assert "victim-vm" in texts

    def test_no_start_action_without_deallocated_flag(self):
        result = self._run(saved_state={
            "nic_name": "nic01",
            "original_nsg_id": None,
        })
        texts = " ".join(result.actions_taken).lower()
        assert "start" not in texts

    def test_start_action_added_when_deallocated(self):
        result = self._run(saved_state={
            "nic_name": "nic01",
            "original_nsg_id": None,
            "deallocated": True,
        })
        texts = " ".join(result.actions_taken).lower()
        assert "start" in texts

    def test_no_nsg_case_handled(self):
        result = self._run(saved_state={
            "nic_name": "nic01",
            "original_nsg_id": None,
        })
        assert result.success is True
        texts = " ".join(result.actions_taken)
        assert "none" in texts.lower() or "no nsg" in texts.lower()

    def test_completed_at_is_set(self):
        result = self._run()
        assert result.completed_at is not None

    def test_errors_empty_on_success(self):
        assert self._run().errors == []

    def test_rejects_invalid_nic_name_in_saved_state(self):
        with pytest.raises(ValueError, match="NIC name"):
            self._run(saved_state={"nic_name": "../nic-01", "original_nsg_id": None})


# ---------------------------------------------------------------------------
# AzureIsolationResult dataclass defaults
# ---------------------------------------------------------------------------

class TestAzureIsolationResultDefaults:

    def test_actions_taken_defaults_empty(self):
        r = AzureIsolationResult(
            success=True,
            dry_run=True,
            vm_name="vm",
            resource_group="rg",
            incident_id="INC-1",
        )
        assert r.actions_taken == []

    def test_saved_state_defaults_empty(self):
        r = AzureIsolationResult(
            success=False,
            dry_run=True,
            vm_name="vm",
            resource_group="rg",
            incident_id="INC-1",
        )
        assert r.saved_state == {}

    def test_errors_defaults_empty(self):
        r = AzureIsolationResult(
            success=False,
            dry_run=False,
            vm_name="vm",
            resource_group="rg",
            incident_id="INC-1",
        )
        assert r.errors == []

    def test_completed_at_defaults_none(self):
        r = AzureIsolationResult(
            success=False,
            dry_run=True,
            vm_name="vm",
            resource_group="rg",
            incident_id="INC-1",
        )
        assert r.completed_at is None
