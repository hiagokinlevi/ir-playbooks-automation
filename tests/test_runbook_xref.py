"""
Tests for automations/runbook_xref.py

Validates:
  - PlaybookRef.applies_to() for type-specific and universal playbooks
  - PlaybookRef.is_universal for empty incident_types set
  - RUNBOOK_REGISTRY completeness: all phases, universal entries, automation refs
  - lookup_playbooks() returns matching entries, sorted by phase then title
  - lookup_playbooks() with phase filter returns only that phase
  - lookup_by_phase() returns all entries for a phase
  - reverse_lookup() finds by path, returns None for unknown path
  - playbooks_with_automation() returns only automated playbooks
  - xref_incident() derives correct phase from incident status
  - xref_incident() by_phase grouping and current_phase_refs shortcut
  - xref_incident() all_refs is flat and sorted by phase
  - RunbookXrefReport.has_automations is True when any ref has automation_ref
  - RunbookXrefReport.summary() contains incident_id, type, phase
  - Phase order: TRIAGE < CONTAINMENT < ERADICATION < RECOVERY
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from schemas.incident import IncidentRecord, IncidentStatus, IncidentType
from automations.runbook_xref import (
    RUNBOOK_REGISTRY,
    PlaybookPhase,
    PlaybookRef,
    RunbookXrefReport,
    _PHASE_ORDER,
    _STATUS_TO_PHASE,
    lookup_by_phase,
    lookup_playbooks,
    playbooks_with_automation,
    reverse_lookup,
    xref_incident,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(
    incident_type: IncidentType = IncidentType.GENERIC,
    status: IncidentStatus = IncidentStatus.TRIAGING,
) -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-20260101-001",
        title="Test incident for xref unit tests",
        incident_type=incident_type,
        status=status,
    )


# ---------------------------------------------------------------------------
# PlaybookRef
# ---------------------------------------------------------------------------

class TestPlaybookRef:

    def test_is_universal_when_empty_incident_types(self):
        ref = PlaybookRef(
            path="p/test.md",
            title="Test",
            phase=PlaybookPhase.TRIAGE,
            incident_types=frozenset(),
            description="test",
        )
        assert ref.is_universal is True

    def test_is_not_universal_when_types_specified(self):
        ref = PlaybookRef(
            path="p/test.md",
            title="Test",
            phase=PlaybookPhase.TRIAGE,
            incident_types=frozenset({IncidentType.PHISHING}),
            description="test",
        )
        assert ref.is_universal is False

    def test_applies_to_matching_type(self):
        ref = PlaybookRef(
            path="p/test.md",
            title="Test",
            phase=PlaybookPhase.CONTAINMENT,
            incident_types=frozenset({IncidentType.PHISHING}),
            description="test",
        )
        assert ref.applies_to(IncidentType.PHISHING) is True

    def test_does_not_apply_to_unmatched_type(self):
        ref = PlaybookRef(
            path="p/test.md",
            title="Test",
            phase=PlaybookPhase.CONTAINMENT,
            incident_types=frozenset({IncidentType.PHISHING}),
            description="test",
        )
        assert ref.applies_to(IncidentType.MALWARE) is False

    def test_universal_applies_to_any_type(self):
        ref = PlaybookRef(
            path="p/universal.md",
            title="Universal",
            phase=PlaybookPhase.TRIAGE,
            incident_types=frozenset(),
            description="applies everywhere",
        )
        for t in IncidentType:
            assert ref.applies_to(t) is True

    def test_automation_ref_defaults_none(self):
        ref = PlaybookRef(
            path="p/test.md",
            title="Test",
            phase=PlaybookPhase.ERADICATION,
            incident_types=frozenset(),
            description="test",
        )
        assert ref.automation_ref is None


# ---------------------------------------------------------------------------
# RUNBOOK_REGISTRY integrity
# ---------------------------------------------------------------------------

class TestRunbookRegistry:

    def test_registry_not_empty(self):
        assert len(RUNBOOK_REGISTRY) > 0

    def test_all_phases_covered(self):
        phases_present = {ref.phase for ref in RUNBOOK_REGISTRY}
        for phase in PlaybookPhase:
            assert phase in phases_present, f"No playbook for phase {phase}"

    def test_at_least_one_universal_playbook(self):
        assert any(ref.is_universal for ref in RUNBOOK_REGISTRY)

    def test_at_least_one_playbook_with_automation(self):
        assert any(ref.automation_ref is not None for ref in RUNBOOK_REGISTRY)

    def test_all_paths_are_strings(self):
        for ref in RUNBOOK_REGISTRY:
            assert isinstance(ref.path, str) and len(ref.path) > 0

    def test_all_titles_are_strings(self):
        for ref in RUNBOOK_REGISTRY:
            assert isinstance(ref.title, str) and len(ref.title) > 0

    def test_all_descriptions_are_strings(self):
        for ref in RUNBOOK_REGISTRY:
            assert isinstance(ref.description, str) and len(ref.description) > 0

    def test_paths_are_unique(self):
        paths = [ref.path for ref in RUNBOOK_REGISTRY]
        assert len(paths) == len(set(paths)), "Duplicate paths in RUNBOOK_REGISTRY"

    def test_initial_triage_is_universal(self):
        ref = reverse_lookup("playbooks/triage/initial_triage.md")
        assert ref is not None
        assert ref.is_universal is True

    def test_recovery_playbook_is_universal(self):
        ref = reverse_lookup("playbooks/recovery/controlled_return.md")
        assert ref is not None
        assert ref.is_universal is True

    def test_phishing_playbook_registered(self):
        ref = reverse_lookup("playbooks/incident-types/phishing.md")
        assert ref is not None
        assert IncidentType.PHISHING in ref.incident_types

    def test_cloud_exposure_playbook_has_automation(self):
        ref = reverse_lookup("playbooks/containment/cloud_exposure.md")
        assert ref is not None
        assert ref.automation_ref is not None


# ---------------------------------------------------------------------------
# lookup_playbooks
# ---------------------------------------------------------------------------

class TestLookupPlaybooks:

    def test_returns_list(self):
        result = lookup_playbooks(IncidentType.PHISHING)
        assert isinstance(result, list)

    def test_phishing_gets_universal_playbooks(self):
        result = lookup_playbooks(IncidentType.PHISHING)
        titles = [r.title for r in result]
        assert "Initial Triage Checklist" in titles

    def test_phishing_gets_type_specific_playbook(self):
        result = lookup_playbooks(IncidentType.PHISHING)
        paths = [r.path for r in result]
        assert "playbooks/incident-types/phishing.md" in paths

    def test_malware_does_not_get_phishing_playbook(self):
        result = lookup_playbooks(IncidentType.MALWARE)
        paths = [r.path for r in result]
        assert "playbooks/incident-types/phishing.md" not in paths

    def test_results_sorted_by_phase_order(self):
        result = lookup_playbooks(IncidentType.CLOUD_EXPOSURE)
        phases = [_PHASE_ORDER[r.phase] for r in result]
        assert phases == sorted(phases)

    def test_phase_filter_returns_only_that_phase(self):
        result = lookup_playbooks(IncidentType.PHISHING, phase=PlaybookPhase.TRIAGE)
        for ref in result:
            assert ref.phase == PlaybookPhase.TRIAGE

    def test_phase_filter_excludes_other_phases(self):
        result = lookup_playbooks(IncidentType.PHISHING, phase=PlaybookPhase.RECOVERY)
        for ref in result:
            assert ref.phase == PlaybookPhase.RECOVERY

    def test_generic_type_gets_only_universal_playbooks(self):
        result = lookup_playbooks(IncidentType.GENERIC)
        # GENERIC should still get universal playbooks
        assert len(result) > 0
        for ref in result:
            assert ref.is_universal

    def test_api_abuse_gets_type_specific_playbook(self):
        result = lookup_playbooks(IncidentType.API_ABUSE)
        paths = [r.path for r in result]
        assert "playbooks/incident-types/api_abuse.md" in paths

    def test_secret_leakage_gets_containment_playbook(self):
        result = lookup_playbooks(IncidentType.SECRET_LEAKAGE)
        paths = [r.path for r in result]
        assert "playbooks/containment/cloud_exposure.md" in paths


# ---------------------------------------------------------------------------
# lookup_by_phase
# ---------------------------------------------------------------------------

class TestLookupByPhase:

    def test_returns_list(self):
        assert isinstance(lookup_by_phase(PlaybookPhase.TRIAGE), list)

    def test_all_triage_playbooks_are_triage(self):
        for ref in lookup_by_phase(PlaybookPhase.TRIAGE):
            assert ref.phase == PlaybookPhase.TRIAGE

    def test_containment_phase_not_empty(self):
        assert len(lookup_by_phase(PlaybookPhase.CONTAINMENT)) > 0

    def test_sorted_by_title(self):
        result = lookup_by_phase(PlaybookPhase.TRIAGE)
        titles = [r.title for r in result]
        assert titles == sorted(titles)


# ---------------------------------------------------------------------------
# reverse_lookup
# ---------------------------------------------------------------------------

class TestReverseLookup:

    def test_finds_known_path(self):
        ref = reverse_lookup("playbooks/triage/initial_triage.md")
        assert ref is not None

    def test_returns_correct_ref(self):
        ref = reverse_lookup("playbooks/triage/initial_triage.md")
        assert ref.phase == PlaybookPhase.TRIAGE

    def test_returns_none_for_unknown_path(self):
        ref = reverse_lookup("playbooks/nonexistent/fake.md")
        assert ref is None

    def test_returns_none_for_empty_string(self):
        assert reverse_lookup("") is None


# ---------------------------------------------------------------------------
# playbooks_with_automation
# ---------------------------------------------------------------------------

class TestPlaybooksWithAutomation:

    def test_returns_list(self):
        assert isinstance(playbooks_with_automation(), list)

    def test_all_have_automation_ref(self):
        for ref in playbooks_with_automation():
            assert ref.automation_ref is not None

    def test_sorted_by_phase_then_title(self):
        result = playbooks_with_automation()
        orders = [(_PHASE_ORDER[r.phase], r.title) for r in result]
        assert orders == sorted(orders)


# ---------------------------------------------------------------------------
# _STATUS_TO_PHASE mapping
# ---------------------------------------------------------------------------

class TestStatusToPhaseMapping:

    def test_detected_maps_to_triage(self):
        assert _STATUS_TO_PHASE[IncidentStatus.DETECTED] == PlaybookPhase.TRIAGE

    def test_containing_maps_to_containment(self):
        assert _STATUS_TO_PHASE[IncidentStatus.CONTAINING] == PlaybookPhase.CONTAINMENT

    def test_eradicating_maps_to_eradication(self):
        assert _STATUS_TO_PHASE[IncidentStatus.ERADICATING] == PlaybookPhase.ERADICATION

    def test_recovering_maps_to_recovery(self):
        assert _STATUS_TO_PHASE[IncidentStatus.RECOVERING] == PlaybookPhase.RECOVERY

    def test_closed_maps_to_recovery(self):
        assert _STATUS_TO_PHASE[IncidentStatus.CLOSED] == PlaybookPhase.RECOVERY


# ---------------------------------------------------------------------------
# xref_incident
# ---------------------------------------------------------------------------

class TestXrefIncident:

    def test_returns_runbook_xref_report(self):
        incident = _make_incident(IncidentType.PHISHING)
        assert isinstance(xref_incident(incident), RunbookXrefReport)

    def test_incident_id_preserved(self):
        incident = _make_incident()
        report = xref_incident(incident)
        assert report.incident_id == "INC-20260101-001"

    def test_incident_type_preserved(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        assert report.incident_type == IncidentType.PHISHING

    def test_current_phase_triage_when_triaging(self):
        incident = _make_incident(status=IncidentStatus.TRIAGING)
        report = xref_incident(incident)
        assert report.current_phase == PlaybookPhase.TRIAGE

    def test_current_phase_containment_when_containing(self):
        incident = _make_incident(status=IncidentStatus.CONTAINING)
        report = xref_incident(incident)
        assert report.current_phase == PlaybookPhase.CONTAINMENT

    def test_current_phase_eradication_when_eradicating(self):
        incident = _make_incident(status=IncidentStatus.ERADICATING)
        report = xref_incident(incident)
        assert report.current_phase == PlaybookPhase.ERADICATION

    def test_current_phase_recovery_when_recovering(self):
        incident = _make_incident(status=IncidentStatus.RECOVERING)
        report = xref_incident(incident)
        assert report.current_phase == PlaybookPhase.RECOVERY

    def test_all_refs_not_empty(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        assert len(report.all_refs) > 0

    def test_all_refs_sorted_by_phase(self):
        incident = _make_incident(IncidentType.CLOUD_EXPOSURE)
        report = xref_incident(incident)
        phases = [_PHASE_ORDER[r.phase] for r in report.all_refs]
        assert phases == sorted(phases)

    def test_by_phase_groups_correctly(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        for phase, refs in report.by_phase.items():
            for ref in refs:
                assert ref.phase == phase

    def test_current_phase_refs_subset_of_all(self):
        incident = _make_incident(IncidentType.PHISHING, status=IncidentStatus.TRIAGING)
        report = xref_incident(incident)
        for ref in report.current_phase_refs:
            assert ref in report.all_refs

    def test_current_phase_refs_all_match_current_phase(self):
        incident = _make_incident(IncidentType.PHISHING, status=IncidentStatus.TRIAGING)
        report = xref_incident(incident)
        for ref in report.current_phase_refs:
            assert ref.phase == PlaybookPhase.TRIAGE

    def test_has_automations_true_for_cloud_exposure(self):
        incident = _make_incident(IncidentType.CLOUD_EXPOSURE)
        report = xref_incident(incident)
        assert report.has_automations is True

    def test_has_automations_false_when_no_automation_refs(self):
        # Build a minimal report with no automation refs
        report = RunbookXrefReport(
            incident_id="INC-20260101-001",
            incident_type=IncidentType.GENERIC,
            current_phase=PlaybookPhase.TRIAGE,
            all_refs=[
                PlaybookRef(
                    path="x.md",
                    title="X",
                    phase=PlaybookPhase.TRIAGE,
                    incident_types=frozenset(),
                    description="x",
                    automation_ref=None,
                )
            ],
        )
        assert report.has_automations is False


# ---------------------------------------------------------------------------
# RunbookXrefReport.summary()
# ---------------------------------------------------------------------------

class TestRunbookXrefReportSummary:

    def test_summary_contains_incident_id(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        assert "INC-20260101-001" in report.summary()

    def test_summary_contains_incident_type(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        assert "phishing" in report.summary().lower()

    def test_summary_contains_phase(self):
        incident = _make_incident(status=IncidentStatus.TRIAGING)
        report = xref_incident(incident)
        assert "TRIAGE" in report.summary()

    def test_summary_contains_playbook_title(self):
        incident = _make_incident(IncidentType.PHISHING)
        report = xref_incident(incident)
        assert "Initial Triage Checklist" in report.summary()

    def test_summary_contains_automation_ref_when_present(self):
        incident = _make_incident(IncidentType.CLOUD_EXPOSURE)
        report = xref_incident(incident)
        summary = report.summary()
        assert "automation:" in summary

    def test_summary_is_string(self):
        incident = _make_incident()
        report = xref_incident(incident)
        assert isinstance(report.summary(), str)
