"""
Tests for automations/cloud/isolate_gcp_instance.py.

The live containment path depends on google-cloud-compute. These tests keep the
offline safety contract locked down: deterministic tag/rule construction,
dry-run previews, rollback state, and graceful missing-SDK handling.
"""
from __future__ import annotations

import builtins
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.cloud.isolate_gcp_instance import (
    GcpIsolationResult,
    _build_deny_all_firewall_body,
    _directional_firewall_rule_name,
    _firewall_rule_name,
    _incident_metadata,
    _isolation_tag,
    _label_value,
    isolate_gcp_instance,
    restore_gcp_instance,
)


class TestGcpFirewallBody:
    body = _build_deny_all_firewall_body("INC-2026-099", "global/networks/ir-vpc")

    def test_builds_ingress_and_egress_rules(self):
        assert set(self.body) == {"ingress_rule", "egress_rule", "isolation_tag"}

    def test_rules_target_same_isolation_tag(self):
        tag = self.body["isolation_tag"]
        assert self.body["ingress_rule"]["targetTags"] == [tag]
        assert self.body["egress_rule"]["targetTags"] == [tag]

    def test_rules_deny_all_protocols(self):
        assert self.body["ingress_rule"]["denied"] == [{"IPProtocol": "all"}]
        assert self.body["egress_rule"]["denied"] == [{"IPProtocol": "all"}]

    def test_rules_are_low_priority_containment(self):
        assert self.body["ingress_rule"]["priority"] == 100
        assert self.body["egress_rule"]["priority"] == 100

    def test_ingress_covers_public_sources(self):
        assert self.body["ingress_rule"]["direction"] == "INGRESS"
        assert self.body["ingress_rule"]["sourceRanges"] == ["0.0.0.0/0"]

    def test_egress_covers_public_destinations(self):
        assert self.body["egress_rule"]["direction"] == "EGRESS"
        assert self.body["egress_rule"]["destinationRanges"] == ["0.0.0.0/0"]


class TestGcpNamingAndMetadata:
    def test_isolation_tag_is_gcp_safe(self):
        tag = _isolation_tag("INC 2026/Upper_Case!!")
        assert tag == "k1n-ir-isolated-inc-2026-upper-case"
        assert tag == tag.lower()
        assert len(tag) <= 63

    def test_firewall_rule_name_is_gcp_safe(self):
        rule = _firewall_rule_name("INC 2026/Upper_Case!!")
        assert rule == "k1n-ir-deny-all-inc-2026-upper-case"
        assert rule == rule.lower()
        assert len(rule) <= 63

    def test_directional_firewall_rule_name_remains_gcp_safe(self):
        rule = _directional_firewall_rule_name("INC-" + "A" * 80, "ingress")
        assert rule.endswith("-ingress")
        assert len(rule) <= 63
        assert rule == rule.lower()

    def test_label_value_is_gcp_safe(self):
        label = _label_value("INC 2026/Upper_Case!!")
        assert label == "inc-2026-upper_case"
        assert label == label.lower()
        assert len(label) <= 63

    def test_incident_metadata_is_traceable(self):
        metadata = _incident_metadata("INC-2026-099", "compromised-vm")
        assert metadata["k1n-ir-incident-id"] == "inc-2026-099"
        assert metadata["k1n-ir-action"] == "isolation"
        assert metadata["k1n-ir-instance"] == "compromised-vm"
        assert metadata["k1n-ir-automated"] == "true"
        assert metadata["k1n-ir-timestamp"].endswith("Z")

    def test_isolation_tag_rejects_all_punctuation_incident_ids(self):
        try:
            _isolation_tag("!!!")
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "Incident ID must contain at least one letter or number" in str(exc)


class TestIsolateGcpInstanceDryRun:
    def _run(self, **kwargs):
        defaults = dict(
            project_id="ir-project",
            zone="us-central1-a",
            instance_name="compromised-vm",
            incident_id="INC-2026-099",
            dry_run=True,
        )
        defaults.update(kwargs)
        return isolate_gcp_instance(**defaults)

    def test_successful_preview(self):
        result = self._run()
        assert result.success is True
        assert result.dry_run is True
        assert result.errors == []

    def test_preview_actions_are_dry_run_prefixed(self):
        result = self._run()
        assert result.actions_taken
        assert all(action.startswith("[DRY RUN]") for action in result.actions_taken)

    def test_preview_records_rollback_state(self):
        result = self._run()
        assert result.saved_state["isolation_tag"] == "k1n-ir-isolated-inc-2026-099"
        assert result.saved_state["ingress_firewall_rule"].endswith("-ingress")
        assert result.saved_state["egress_firewall_rule"].endswith("-egress")

    def test_custom_network_is_reflected_in_firewall_body(self):
        body = _build_deny_all_firewall_body("INC-2026-099", "global/networks/blue-team")
        assert body["ingress_rule"]["network"] == "global/networks/blue-team"
        assert body["egress_rule"]["network"] == "global/networks/blue-team"

    def test_stop_instance_preview_is_explicit(self):
        result = self._run(stop_instance=True)
        assert any("Would stop instance" in action for action in result.actions_taken)
        assert result.saved_state["stop_instance"] is True

    def test_completed_at_is_set(self):
        result = self._run()
        assert result.completed_at is not None
        assert result.completed_at.endswith("Z")

    def test_rejects_path_like_instance_name(self):
        try:
            self._run(instance_name="../compromised-vm")
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "Instance name must not contain path separators" in str(exc)

    def test_rejects_url_like_network_path(self):
        try:
            self._run(network="https://compute.googleapis.com/projects/x/global/networks/default")
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "Network path must not be a URL" in str(exc)


class TestRestoreGcpInstanceDryRun:
    saved_state = {
        "original_tags": ["prod", "web"],
        "original_labels": {"team": "blue"},
        "ingress_firewall_rule": "k1n-ir-deny-all-inc-2026-099-ingress",
        "egress_firewall_rule": "k1n-ir-deny-all-inc-2026-099-egress",
        "isolation_tag": "k1n-ir-isolated-inc-2026-099",
        "stop_instance": True,
        "was_running": True,
    }

    def test_restore_preview_removes_firewall_rules_and_tag(self):
        result = restore_gcp_instance(
            project_id="ir-project",
            zone="us-central1-a",
            instance_name="compromised-vm",
            saved_state=self.saved_state,
            dry_run=True,
        )

        text = " ".join(result.actions_taken)
        assert result.success is True
        assert "k1n-ir-isolated-inc-2026-099" in text
        assert "k1n-ir-deny-all-inc-2026-099-ingress" in text
        assert "k1n-ir-deny-all-inc-2026-099-egress" in text
        assert "Would start instance" in text

    def test_restore_rejects_non_dict_saved_state(self):
        try:
            restore_gcp_instance(
                project_id="ir-project",
                zone="us-central1-a",
                instance_name="compromised-vm",
                saved_state="invalid",
                dry_run=True,
            )
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "saved_state must be a dict returned by isolate_gcp_instance()" in str(exc)


class TestGcpMissingSdk:
    def test_live_mode_reports_missing_google_sdk(self, monkeypatch):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("google"):
                raise ImportError(f"Simulated missing SDK: {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = isolate_gcp_instance(
            project_id="ir-project",
            zone="us-central1-a",
            instance_name="compromised-vm",
            incident_id="INC-2026-099",
            dry_run=False,
        )

        assert result.success is False
        assert result.completed_at is not None
        assert "google-cloud-compute not installed" in result.errors[0]


class TestGcpIsolationResultDefaults:
    def test_default_lists_and_dicts_are_independent(self):
        first = GcpIsolationResult(True, True, "a", "p", "z", "INC-1")
        second = GcpIsolationResult(True, True, "b", "p", "z", "INC-2")
        first.actions_taken.append("changed")
        first.saved_state["tag"] = "changed"
        first.errors.append("changed")

        assert second.actions_taken == []
        assert second.saved_state == {}
        assert second.errors == []
