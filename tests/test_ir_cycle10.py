"""
Tests for Cycle 10 k1n-ir additions:
  - automations/cloud/isolate_gcp_instance.py
  - automations/cloud/quarantine_aws_lambda.py
  - automations/mitre_attack_tagger.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.cloud.isolate_gcp_instance import (
    GcpIsolationResult,
    _build_deny_all_firewall_body,
    _firewall_rule_name,
    _incident_metadata,
    _isolation_tag,
    _timestamp,
    isolate_gcp_instance,
    restore_gcp_instance,
)
from automations.cloud.quarantine_aws_lambda import (
    LambdaQuarantineResult,
    _build_deny_all_policy_statement,
    _incident_tags,
    quarantine_lambda,
    restore_lambda,
)
from automations.mitre_attack_tagger import (
    AttackTag,
    AttackTaggingResult,
    enrich_incident_dict,
    tag_incident,
)


# ===========================================================================
# GCP Instance Isolation
# ===========================================================================

class TestIsolationTag:
    def test_contains_k1n_ir_prefix(self):
        tag = _isolation_tag("INC-2026-042")
        assert tag.startswith("k1n-ir-isolated-")

    def test_lowercase_and_hyphens_only(self):
        tag = _isolation_tag("INC 2026 UPPER!")
        assert tag == tag.lower()
        assert all(c.isalnum() or c == "-" for c in tag)

    def test_max_63_chars(self):
        long_incident = "INC-" + "X" * 100
        assert len(_isolation_tag(long_incident)) <= 63

    def test_strips_leading_trailing_hyphens(self):
        tag = _isolation_tag("---test---")
        assert not tag.startswith("-")


class TestFirewallRuleName:
    def test_contains_k1n_ir_deny_prefix(self):
        name = _firewall_rule_name("INC-2026-042")
        assert name.startswith("k1n-ir-deny-all-")

    def test_max_63_chars(self):
        assert len(_firewall_rule_name("INC-" + "X" * 100)) <= 63


class TestBuildDenyAllFirewallBody:
    body = _build_deny_all_firewall_body("INC-2026-042")

    def test_has_ingress_and_egress_keys(self):
        assert "ingress_rule" in self.body
        assert "egress_rule" in self.body

    def test_has_isolation_tag_key(self):
        assert "isolation_tag" in self.body

    def test_ingress_direction(self):
        assert self.body["ingress_rule"]["direction"] == "INGRESS"

    def test_egress_direction(self):
        assert self.body["egress_rule"]["direction"] == "EGRESS"

    def test_deny_all_protocol(self):
        assert self.body["ingress_rule"]["denied"] == [{"IPProtocol": "all"}]
        assert self.body["egress_rule"]["denied"] == [{"IPProtocol": "all"}]

    def test_priority_100(self):
        assert self.body["ingress_rule"]["priority"] == 100
        assert self.body["egress_rule"]["priority"] == 100


class TestIncidentMetadata:
    meta = _incident_metadata("INC-2026-042", "compromised-vm")

    def test_has_incident_id(self):
        assert self.meta["k1n-ir-incident-id"] == "inc-2026-042"

    def test_action_is_isolation(self):
        assert self.meta["k1n-ir-action"] == "isolation"

    def test_has_instance_name(self):
        assert self.meta["k1n-ir-instance"] == "compromised-vm"

    def test_automated_true(self):
        assert self.meta["k1n-ir-automated"] == "true"


class TestIsolateGcpInstanceDryRun:
    result = isolate_gcp_instance(
        project_id="my-project",
        zone="us-central1-a",
        instance_name="compromised-vm",
        incident_id="INC-2026-042",
        dry_run=True,
    )

    def test_success_true(self):
        assert self.result.success is True

    def test_dry_run_flag(self):
        assert self.result.dry_run is True

    def test_actions_non_empty(self):
        assert len(self.result.actions_taken) > 0

    def test_all_actions_dry_run_prefixed(self):
        for action in self.result.actions_taken:
            assert action.startswith("[DRY RUN]"), action

    def test_saved_state_contains_isolation_tag(self):
        assert "isolation_tag" in self.result.saved_state

    def test_saved_state_contains_firewall_rules(self):
        assert "ingress_firewall_rule" in self.result.saved_state
        assert "egress_firewall_rule" in self.result.saved_state

    def test_completed_at_set(self):
        assert self.result.completed_at is not None

    def test_no_errors(self):
        assert self.result.errors == []


class TestIsolateGcpInstanceWithStop:
    result = isolate_gcp_instance(
        project_id="my-project",
        zone="us-central1-a",
        instance_name="compromised-vm",
        incident_id="INC-2026-042",
        stop_instance=True,
        dry_run=True,
    )

    def test_stop_action_included(self):
        combined = " ".join(self.result.actions_taken)
        assert "stop" in combined.lower()


class TestIsolateGcpNoSdk:
    def test_missing_sdk_returns_error(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "google.cloud":
                raise ImportError("no google-cloud-compute")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = isolate_gcp_instance(
            project_id="p", zone="z", instance_name="vm",
            incident_id="INC-X", dry_run=False,
        )
        assert result.success is False
        assert result.errors


class TestRestoreGcpInstanceDryRun:
    saved_state = {
        "original_tags":         ["web-server"],
        "original_labels":       {"env": "prod"},
        "ingress_firewall_rule": "k1n-ir-deny-all-inc-2026-042-ingress",
        "egress_firewall_rule":  "k1n-ir-deny-all-inc-2026-042-egress",
        "isolation_tag":         "k1n-ir-isolated-inc-2026-042",
        "stop_instance":         True,
        "was_running":           True,
    }
    result = restore_gcp_instance(
        project_id="my-project",
        zone="us-central1-a",
        instance_name="compromised-vm",
        saved_state=saved_state,
        dry_run=True,
    )

    def test_success_true(self):
        assert self.result.success is True

    def test_actions_mention_tag_removal(self):
        combined = " ".join(self.result.actions_taken)
        assert "remove" in combined.lower() or "isolation tag" in combined.lower()

    def test_actions_mention_firewall_deletion(self):
        combined = " ".join(self.result.actions_taken)
        assert "delete" in combined.lower() or "firewall" in combined.lower()

    def test_actions_mention_start_when_was_running(self):
        combined = " ".join(self.result.actions_taken)
        assert "start" in combined.lower()


# ===========================================================================
# AWS Lambda Quarantine
# ===========================================================================

class TestLambdaIncidentTags:
    tags = _incident_tags("INC-2026-042", "payment-processor")

    def test_has_incident_id(self):
        assert self.tags["k1n-ir-incident-id"] == "INC-2026-042"

    def test_action_is_quarantine(self):
        assert self.tags["k1n-ir-action"] == "quarantine"

    def test_has_function_name(self):
        assert self.tags["k1n-ir-function"] == "payment-processor"


class TestBuildDenyAllPolicyStatement:
    arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
    stmt = _build_deny_all_policy_statement(arn)

    def test_effect_deny(self):
        assert self.stmt["Effect"] == "Deny"

    def test_principal_wildcard(self):
        assert self.stmt["Principal"] == "*"

    def test_action_invoke(self):
        assert self.stmt["Action"] == "lambda:InvokeFunction"

    def test_resource_matches_arn(self):
        assert self.stmt["Resource"] == self.arn


class TestQuarantineLambdaDryRun:
    result = quarantine_lambda(
        function_name="payment-processor",
        incident_id="INC-2026-042",
        region="us-east-1",
        dry_run=True,
    )

    def test_success_true(self):
        assert self.result.success is True

    def test_dry_run_flag(self):
        assert self.result.dry_run is True

    def test_actions_non_empty(self):
        assert len(self.result.actions_taken) > 0

    def test_all_actions_dry_run_prefixed(self):
        for action in self.result.actions_taken:
            assert action.startswith("[DRY RUN]"), action

    def test_quarantine_state_has_arn(self):
        assert "function_arn" in self.result.quarantine_state

    def test_quarantine_state_has_concurrency(self):
        assert "original_concurrency" in self.result.quarantine_state

    def test_completed_at_set(self):
        assert self.result.completed_at is not None

    def test_no_errors(self):
        assert self.result.errors == []


class TestQuarantineLambdaWithSnapshot:
    result = quarantine_lambda(
        function_name="payment-processor",
        incident_id="INC-2026-042",
        region="us-east-1",
        publish_snapshot=True,
        dry_run=True,
    )

    def test_snapshot_action_included(self):
        combined = " ".join(self.result.actions_taken)
        assert "snapshot" in combined.lower()


class TestQuarantineLambdaNoBoto3:
    def test_missing_boto3_returns_error(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("no boto3")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        result = quarantine_lambda(
            function_name="fn", incident_id="INC-X",
            region="us-east-1", dry_run=False,
        )
        assert result.success is False
        assert result.errors


class TestRestoreLambdaDryRun:
    state = {
        "function_arn":         "arn:aws:lambda:us-east-1:123456789012:function:test",
        "original_concurrency": None,
        "policy_statement_id":  "k1n-ir-quarantine-deny-all",
        "publish_snapshot":     False,
        "snapshot_version":     None,
    }
    result = restore_lambda(
        function_name="payment-processor",
        quarantine_state=state,
        region="us-east-1",
        dry_run=True,
    )

    def test_success_true(self):
        assert self.result.success is True

    def test_actions_mention_concurrency(self):
        combined = " ".join(self.result.actions_taken)
        assert "concurrency" in combined.lower()

    def test_actions_mention_policy_removal(self):
        combined = " ".join(self.result.actions_taken)
        assert "policy" in combined.lower() or "statement" in combined.lower()


class TestRestoreLambdaWithConcurrency:
    state = {
        "function_arn":         "arn:aws:lambda:us-east-1:123456789012:function:test",
        "original_concurrency": 50,
        "policy_statement_id":  "k1n-ir-quarantine-deny-all",
        "publish_snapshot":     False,
        "snapshot_version":     None,
    }
    result = restore_lambda(
        function_name="fn",
        quarantine_state=state,
        region="us-east-1",
        dry_run=True,
    )

    def test_mentions_restore_to_50(self):
        combined = " ".join(self.result.actions_taken)
        assert "50" in combined


# ===========================================================================
# MITRE ATT&CK Auto-Tagger
# ===========================================================================

class TestAttackTag:
    tag = AttackTag(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Initial Access",
        source="incident_type",
        confidence="high",
    )

    def test_str_contains_tactic(self):
        assert "Initial Access" in str(self.tag)

    def test_str_contains_technique_id(self):
        assert "T1078" in str(self.tag)


class TestAttackTaggingResult:
    tags = [
        AttackTag("T1078", "Valid Accounts", "Initial Access", "incident_type", "high"),
        AttackTag("T1552", "Unsecured Credentials", "Credential Access", "incident_type", "high"),
    ]
    result = AttackTaggingResult(incident_id="INC-2026-042", tags=tags)

    def test_tactics_derived_from_tags(self):
        assert "Initial Access" in self.result.tactics
        assert "Credential Access" in self.result.tactics

    def test_technique_ids_derived(self):
        assert "T1078" in self.result.technique_ids
        assert "T1552" in self.result.technique_ids

    def test_to_dict_has_required_keys(self):
        d = self.result.to_dict()
        assert "mitre_tactics" in d
        assert "mitre_techniques" in d
        assert "mitre_tags" in d
        assert "incident_id" in d

    def test_summary_contains_incident_id(self):
        assert "INC-2026-042" in self.result.summary()

    def test_summary_contains_tactic_count(self):
        assert "2" in self.result.summary()


class TestTagIncidentByType:
    def test_credential_compromise_tags_t1078(self):
        result = tag_incident({"incident_id": "X", "incident_type": "credential_compromise"})
        ids = result.technique_ids
        assert "T1078" in ids

    def test_phishing_tags_t1566(self):
        result = tag_incident({"incident_id": "X", "incident_type": "phishing"})
        assert "T1566" in result.technique_ids

    def test_malware_tags_execution_tactic(self):
        result = tag_incident({"incident_id": "X", "incident_type": "malware"})
        assert "Execution" in result.tactics

    def test_data_exposure_tags_collection(self):
        result = tag_incident({"incident_id": "X", "incident_type": "data_exposure"})
        assert "Collection" in result.tactics

    def test_api_abuse_tags_initial_access(self):
        result = tag_incident({"incident_id": "X", "incident_type": "api_abuse"})
        assert "Initial Access" in result.tactics

    def test_cloud_exposure_tags_discovery(self):
        result = tag_incident({"incident_id": "X", "incident_type": "cloud_exposure"})
        assert "Discovery" in result.tactics

    def test_secret_leakage_tags_credential_access(self):
        result = tag_incident({"incident_id": "X", "incident_type": "secret_leakage"})
        assert "Credential Access" in result.tactics

    def test_generic_incident_type_gets_fallback_tag(self):
        result = tag_incident({"incident_id": "X", "incident_type": "generic"})
        assert len(result.tags) > 0

    def test_unknown_type_falls_back_to_generic(self):
        result = tag_incident({"incident_id": "X", "incident_type": "unknown_xyz"})
        assert len(result.tags) > 0


class TestTagIncidentKeywordScan:
    def test_brute_force_keyword_adds_t1110(self):
        incident = {
            "incident_id": "X",
            "incident_type": "generic",
            "title": "Brute force attack on SSH service",
        }
        result = tag_incident(incident)
        assert "T1110" in result.technique_ids

    def test_password_spray_adds_t1110_003(self):
        incident = {
            "incident_id": "X",
            "incident_type": "generic",
            "description": "Password spray detected against Azure AD",
        }
        result = tag_incident(incident)
        assert "T1110.003" in result.technique_ids

    def test_crypto_mining_adds_t1496(self):
        incident = {
            "incident_id": "X",
            "incident_type": "generic",
            "title": "Crypto mining process detected in container",
        }
        result = tag_incident(incident)
        assert "T1496" in result.technique_ids

    def test_container_escape_adds_t1611(self):
        incident = {
            "incident_id": "X",
            "incident_type": "malware",
            "title": "Suspected container escape via privileged container",
        }
        result = tag_incident(incident)
        assert "T1611" in result.technique_ids

    def test_ransomware_adds_t1486(self):
        incident = {
            "incident_id": "X",
            "incident_type": "malware",
            "title": "Ransomware encryption detected on file shares",
        }
        result = tag_incident(incident)
        assert "T1486" in result.technique_ids

    def test_disable_keyword_scan(self):
        incident = {
            "incident_id": "X",
            "incident_type": "generic",
            "title": "Brute force attack detected",
        }
        result_with = tag_incident(incident, include_keyword_scan=True)
        result_without = tag_incident(incident, include_keyword_scan=False)
        # With keyword scan should produce more tags
        assert len(result_with.tags) >= len(result_without.tags)


class TestTagIncidentIoCHints:
    def test_api_key_ioc_adds_credential_tag(self):
        incident = {
            "incident_id": "X",
            "incident_type": "secret_leakage",
            "iocs": [{"evidence_type": "api_key", "value": "sk-test-123"}],
        }
        result = tag_incident(incident)
        assert "T1552.001" in result.technique_ids

    def test_jwt_ioc_adds_token_theft_tag(self):
        incident = {
            "incident_id": "X",
            "incident_type": "credential_compromise",
            "iocs": [{"evidence_type": "jwt", "value": "eyJhbGciOiJIUzI1NiJ9..."}],
        }
        result = tag_incident(incident)
        assert "T1528" in result.technique_ids

    def test_no_iocs_still_works(self):
        result = tag_incident({"incident_id": "X", "incident_type": "generic"})
        assert isinstance(result.tags, list)


class TestTagIncidentDedup:
    def test_no_duplicate_technique_tactic_pairs(self):
        incident = {
            "incident_id": "X",
            "incident_type": "credential_compromise",
            "title": "Brute force credential compromise",
        }
        result = tag_incident(incident)
        keys = [(t.technique_id, t.tactic) for t in result.tags]
        assert len(keys) == len(set(keys))


class TestTagIncidentInputForms:
    def test_accepts_plain_dict(self):
        result = tag_incident({"incident_id": "X", "incident_type": "phishing"})
        assert result.incident_id == "X"

    def test_accepts_object_with_dict(self):
        class FakeIncident:
            def __init__(self):
                self.incident_id = "Y"
                self.incident_type = "malware"
                self.title = ""
                self.description = None
                self.iocs = []

        result = tag_incident(FakeIncident())
        assert result.incident_id == "Y"

    def test_empty_dict_returns_result(self):
        result = tag_incident({})
        assert isinstance(result, AttackTaggingResult)


class TestEnrichIncidentDict:
    def test_adds_mitre_fields(self):
        enriched = enrich_incident_dict({
            "incident_id": "INC-X",
            "incident_type": "phishing",
            "title": "Spearphishing email campaign",
        })
        assert "mitre_tactics" in enriched
        assert "mitre_techniques" in enriched
        assert "mitre_tags" in enriched

    def test_original_fields_preserved(self):
        enriched = enrich_incident_dict({
            "incident_id": "INC-X",
            "incident_type": "phishing",
            "custom_field": "keep_me",
        })
        assert enriched["custom_field"] == "keep_me"

    def test_original_dict_not_mutated(self):
        original = {"incident_id": "X", "incident_type": "generic"}
        enrich_incident_dict(original)
        assert "mitre_tactics" not in original
