"""
Tests for automations.after_action_report_generator
=====================================================
≥110 tests covering every AAR check (positive & negative), boundary conditions,
scoring helpers, and public utility functions.
"""

from __future__ import annotations

import pytest
from typing import List, Optional

from automations.after_action_report_generator import (
    AARCheck,
    AARReport,
    ClosedIncident,
    generate_report,
    generate_reports,
    poor_quality_reports,
)

# ---------------------------------------------------------------------------
# Helpers / fixture factories
# ---------------------------------------------------------------------------

# Timestamps (ms)
T0 = 1_700_000_000_000  # base "opened_at"

ONE_MS = 1
ONE_HOUR_MS = 3_600_000

# SLA windows per severity
SLA = {
    "P1": 4 * ONE_HOUR_MS,
    "P2": 8 * ONE_HOUR_MS,
    "P3": 24 * ONE_HOUR_MS,
    "P4": 72 * ONE_HOUR_MS,
    "P5": 72 * ONE_HOUR_MS,
}


def _perfect_p1(incident_id: str = "INC-PERFECT-P1") -> ClosedIncident:
    """A P1 incident that satisfies every check (no checks should fire)."""
    return ClosedIncident(
        incident_id=incident_id,
        severity="P1",
        title="Perfect P1 incident",
        opened_at_ms=T0,
        contained_at_ms=T0 + SLA["P1"],        # exactly on the SLA boundary — no breach
        closed_at_ms=T0 + SLA["P1"] + ONE_HOUR_MS,
        root_cause="Phishing email triggered macro execution and lateral movement.",
        detection_source="siem",
        detected_at_ms=T0 - ONE_HOUR_MS,
        remediation_actions=["Isolated affected hosts", "Reset all AD credentials"],
        lessons_learned=[
            "Enforce macro disable policy across the entire organisation",
            "Tune SIEM alert rules to reduce dwell time",
        ],
        evidence_items=["disk-image.dd", "memory-dump.raw", "siem-export.json"],
        is_recurrence=False,
        similar_incident_ids=[],
    )


def _perfect_p3() -> ClosedIncident:
    """A P3 incident that satisfies every check (AAR-007 not applicable)."""
    return ClosedIncident(
        incident_id="INC-PERFECT-P3",
        severity="P3",
        title="Perfect P3 incident",
        opened_at_ms=T0,
        contained_at_ms=T0 + SLA["P3"],        # exactly on the SLA boundary
        closed_at_ms=T0 + SLA["P3"] + ONE_HOUR_MS,
        root_cause="Misconfigured firewall rule allowed unauthenticated access.",
        detection_source="alert",
        detected_at_ms=T0 - ONE_HOUR_MS,
        remediation_actions=["Reverted firewall rule to previous state", "Audited all firewall rules"],
        lessons_learned=[
            "Implement change-management review for all firewall modifications",
            "Add automated config-drift detection to the SIEM pipeline",
        ],
        evidence_items=["firewall-log.txt"],    # fewer than 3 but P3 — AAR-007 should NOT fire
        is_recurrence=False,
        similar_incident_ids=[],
    )


# ---------------------------------------------------------------------------
# AAR-001: Missing root cause
# ---------------------------------------------------------------------------

class TestAAR001:
    """AAR-001 — Missing root cause (HIGH, weight=25)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-001" for c in report.checks_fired)

    def test_fires_when_root_cause_empty_string(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_root_cause_whitespace_only(self):
        inc = _perfect_p1()
        inc.root_cause = "   \t  "
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_root_cause_newline_only(self):
        inc = _perfect_p1()
        inc.root_cause = "\n"
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_root_cause_present(self):
        inc = _perfect_p1()
        inc.root_cause = "Known exploited vulnerability CVE-2024-9999."
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_root_cause_minimal_meaningful(self):
        inc = _perfect_p1()
        inc.root_cause = "x"    # non-empty, non-whitespace
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-001")
        assert check.severity == "HIGH"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-001")
        assert check.weight == 25


# ---------------------------------------------------------------------------
# AAR-002: No detection timeline
# ---------------------------------------------------------------------------

class TestAAR002:
    """AAR-002 — No detection timeline (MEDIUM, weight=20)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-002" for c in report.checks_fired)

    def test_fires_when_detection_source_empty(self):
        inc = _perfect_p1()
        inc.detection_source = ""
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_detection_source_manual(self):
        inc = _perfect_p1()
        inc.detection_source = "manual"
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_detection_source_Manual_uppercase(self):
        inc = _perfect_p1()
        inc.detection_source = "Manual"
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_detection_source_MANUAL_allcaps(self):
        inc = _perfect_p1()
        inc.detection_source = "MANUAL"
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_detection_source_siem(self):
        inc = _perfect_p1()
        inc.detection_source = "siem"
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_detection_source_alert(self):
        inc = _perfect_p1()
        inc.detection_source = "alert"
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_detection_source_edr(self):
        inc = _perfect_p1()
        inc.detection_source = "edr"
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_detection_source_ids(self):
        inc = _perfect_p1()
        inc.detection_source = "ids"
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.detection_source = "manual"
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-002")
        assert check.severity == "MEDIUM"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.detection_source = ""
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-002")
        assert check.weight == 20


# ---------------------------------------------------------------------------
# AAR-003: Response SLA breach
# ---------------------------------------------------------------------------

class TestAAR003:
    """AAR-003 — Response SLA breach (HIGH, weight=25)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-003" for c in report.checks_fired)

    # -- P1 boundary (SLA = 4 h) -------------------------------------------

    def test_p1_exactly_on_sla_no_breach(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + SLA["P1"]   # exactly 4 h
        assert not self._check_id_fires(generate_report(inc))

    def test_p1_one_ms_over_sla_breaches(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + SLA["P1"] + ONE_MS
        assert self._check_id_fires(generate_report(inc))

    def test_p1_under_sla_no_breach(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + SLA["P1"] - ONE_HOUR_MS
        assert not self._check_id_fires(generate_report(inc))

    # -- P2 boundary (SLA = 8 h) -------------------------------------------

    def test_p2_exactly_on_sla_no_breach(self):
        inc = _perfect_p1()
        inc.severity = "P2"
        inc.contained_at_ms = T0 + SLA["P2"]
        assert not self._check_id_fires(generate_report(inc))

    def test_p2_one_ms_over_sla_breaches(self):
        inc = _perfect_p1()
        inc.severity = "P2"
        inc.contained_at_ms = T0 + SLA["P2"] + ONE_MS
        assert self._check_id_fires(generate_report(inc))

    # -- P3 boundary (SLA = 24 h) ------------------------------------------

    def test_p3_exactly_on_sla_no_breach(self):
        inc = _perfect_p3()
        inc.contained_at_ms = T0 + SLA["P3"]
        assert not self._check_id_fires(generate_report(inc))

    def test_p3_one_ms_over_sla_breaches(self):
        inc = _perfect_p3()
        inc.contained_at_ms = T0 + SLA["P3"] + ONE_MS
        assert self._check_id_fires(generate_report(inc))

    # -- P4 boundary (SLA = 72 h) ------------------------------------------

    def test_p4_exactly_on_sla_no_breach(self):
        inc = _perfect_p3()
        inc.severity = "P4"
        inc.contained_at_ms = T0 + SLA["P4"]
        assert not self._check_id_fires(generate_report(inc))

    def test_p4_one_ms_over_sla_breaches(self):
        inc = _perfect_p3()
        inc.severity = "P4"
        inc.contained_at_ms = T0 + SLA["P4"] + ONE_MS
        assert self._check_id_fires(generate_report(inc))

    # -- P5 boundary (SLA = 72 h) ------------------------------------------

    def test_p5_exactly_on_sla_no_breach(self):
        inc = _perfect_p3()
        inc.severity = "P5"
        inc.contained_at_ms = T0 + SLA["P5"]
        assert not self._check_id_fires(generate_report(inc))

    def test_p5_one_ms_over_sla_breaches(self):
        inc = _perfect_p3()
        inc.severity = "P5"
        inc.contained_at_ms = T0 + SLA["P5"] + ONE_MS
        assert self._check_id_fires(generate_report(inc))

    # -- contained_at_ms is None (infinite breach) -------------------------

    def test_fires_when_contained_at_ms_is_none_p1(self):
        inc = _perfect_p1()
        inc.contained_at_ms = None
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_contained_at_ms_is_none_p3(self):
        inc = _perfect_p3()
        inc.contained_at_ms = None
        assert self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + SLA["P1"] + ONE_MS
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-003")
        assert check.severity == "HIGH"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + SLA["P1"] + ONE_MS
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-003")
        assert check.weight == 25


# ---------------------------------------------------------------------------
# AAR-004: No remediation actions
# ---------------------------------------------------------------------------

class TestAAR004:
    """AAR-004 — No remediation actions (HIGH, weight=25)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-004" for c in report.checks_fired)

    def test_fires_when_remediation_empty(self):
        inc = _perfect_p1()
        inc.remediation_actions = []
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_only_one_action(self):
        inc = _perfect_p1()
        inc.remediation_actions = ["Isolated affected hosts"]
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_two_actions(self):
        inc = _perfect_p1()
        inc.remediation_actions = ["Action one", "Action two"]
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_three_actions(self):
        inc = _perfect_p1()
        inc.remediation_actions = ["Step A", "Step B", "Step C"]
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.remediation_actions = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-004")
        assert check.severity == "HIGH"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.remediation_actions = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-004")
        assert check.weight == 25


# ---------------------------------------------------------------------------
# AAR-005: Recurrence indicator
# ---------------------------------------------------------------------------

class TestAAR005:
    """AAR-005 — Recurrence indicator (HIGH, weight=30)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-005" for c in report.checks_fired)

    def test_fires_when_is_recurrence_true(self):
        inc = _perfect_p1()
        inc.is_recurrence = True
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_similar_incident_ids_non_empty(self):
        inc = _perfect_p1()
        inc.similar_incident_ids = ["INC-PREV-001"]
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_both_true_and_similar(self):
        inc = _perfect_p1()
        inc.is_recurrence = True
        inc.similar_incident_ids = ["INC-PREV-001", "INC-PREV-002"]
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_both_false_and_empty(self):
        inc = _perfect_p1()
        inc.is_recurrence = False
        inc.similar_incident_ids = []
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.is_recurrence = True
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-005")
        assert check.severity == "HIGH"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.similar_incident_ids = ["INC-PREV-001"]
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-005")
        assert check.weight == 30


# ---------------------------------------------------------------------------
# AAR-006: No lessons-learned
# ---------------------------------------------------------------------------

class TestAAR006:
    """AAR-006 — No lessons-learned (MEDIUM, weight=20)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-006" for c in report.checks_fired)

    def test_fires_when_lessons_empty(self):
        inc = _perfect_p1()
        inc.lessons_learned = []
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_all_lessons_under_20_chars(self):
        inc = _perfect_p1()
        inc.lessons_learned = ["Short note", "OK"]
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_all_lessons_exactly_19_chars(self):
        inc = _perfect_p1()
        # exactly 19 printable characters each
        inc.lessons_learned = ["1234567890123456789", "9876543210987654321"]
        assert self._check_id_fires(generate_report(inc))

    def test_fires_when_all_lessons_whitespace_padded_but_short(self):
        # Strip is applied, so padded whitespace does not make them "long"
        inc = _perfect_p1()
        inc.lessons_learned = ["  short   ", "   tiny  "]
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_one_lesson_is_20_chars(self):
        inc = _perfect_p1()
        # exactly 20 chars — should NOT fire
        inc.lessons_learned = ["12345678901234567890"]
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_when_one_long_lesson_exists(self):
        inc = _perfect_p1()
        inc.lessons_learned = ["Short", "This lesson is definitely longer than twenty chars"]
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_with_two_long_lessons(self):
        inc = _perfect_p1()
        inc.lessons_learned = [
            "Enforce macro disable policy across the entire organisation",
            "Tune SIEM alert rules to reduce dwell time significantly",
        ]
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.lessons_learned = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-006")
        assert check.severity == "MEDIUM"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.lessons_learned = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-006")
        assert check.weight == 20


# ---------------------------------------------------------------------------
# AAR-007: Evidence gaps
# ---------------------------------------------------------------------------

class TestAAR007:
    """AAR-007 — Evidence gaps for P1/P2 only (HIGH, weight=25)."""

    def _check_id_fires(self, report: AARReport) -> bool:
        return any(c.check_id == "AAR-007" for c in report.checks_fired)

    def test_fires_for_p1_with_no_evidence(self):
        inc = _perfect_p1()
        inc.evidence_items = []
        assert self._check_id_fires(generate_report(inc))

    def test_fires_for_p1_with_two_items(self):
        inc = _perfect_p1()
        inc.evidence_items = ["item1.dd", "item2.raw"]
        assert self._check_id_fires(generate_report(inc))

    def test_fires_for_p2_with_two_items(self):
        inc = _perfect_p1()
        inc.severity = "P2"
        inc.evidence_items = ["item1.dd", "item2.raw"]
        assert self._check_id_fires(generate_report(inc))

    def test_does_not_fire_for_p1_with_three_items(self):
        inc = _perfect_p1()
        inc.evidence_items = ["disk.dd", "mem.raw", "log.json"]
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_for_p2_with_three_items(self):
        inc = _perfect_p1()
        inc.severity = "P2"
        inc.evidence_items = ["disk.dd", "mem.raw", "log.json"]
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_for_p3_regardless_of_evidence(self):
        inc = _perfect_p3()
        inc.evidence_items = []        # zero items — but P3, should NOT fire
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_for_p4_regardless_of_evidence(self):
        inc = _perfect_p3()
        inc.severity = "P4"
        inc.evidence_items = []
        assert not self._check_id_fires(generate_report(inc))

    def test_does_not_fire_for_p5_regardless_of_evidence(self):
        inc = _perfect_p3()
        inc.severity = "P5"
        inc.evidence_items = []
        assert not self._check_id_fires(generate_report(inc))

    def test_check_has_correct_severity(self):
        inc = _perfect_p1()
        inc.evidence_items = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-007")
        assert check.severity == "HIGH"

    def test_check_has_correct_weight(self):
        inc = _perfect_p1()
        inc.evidence_items = []
        report = generate_report(inc)
        check = next(c for c in report.checks_fired if c.check_id == "AAR-007")
        assert check.weight == 25


# ---------------------------------------------------------------------------
# Response quality thresholds
# ---------------------------------------------------------------------------

class TestResponseQuality:
    """Verify the four response quality bands map correctly from risk_score."""

    def test_excellent_when_no_checks_fire(self):
        report = generate_report(_perfect_p1())
        assert report.response_quality == "EXCELLENT"
        assert report.risk_score == 0

    def test_excellent_has_completeness_100(self):
        report = generate_report(_perfect_p1())
        assert report.completeness_score == 100

    def test_good_lower_bound_risk_1(self):
        """A single MEDIUM check with weight 20 should still be GOOD if we artificially
        test the boundary — use a real check that yields weight < 20.
        Instead test via manual scenario: fire only AAR-006 on a P3 (weight=20 → ADEQUATE).
        We need a weight-1 scenario; use a helper to reason about the band rather than
        injecting internals. So test real scenarios by constructing a scenario where
        exactly 0 checks fire (EXCELLENT) vs exactly the smallest real weight fires."""
        # The smallest single weight available is AAR-002 (20) or AAR-006 (20).
        # A single fired check gives risk_score=20 → ADEQUATE, not GOOD.
        # GOOD band (1-19) is not reachable from existing checks alone.
        # We verify the band logic indirectly: risk_score=0→EXCELLENT, 20→ADEQUATE.
        inc = _perfect_p3()
        inc.lessons_learned = []    # fires AAR-006 (weight=20)
        report = generate_report(inc)
        assert report.risk_score == 20
        assert report.response_quality == "ADEQUATE"

    def test_adequate_lower_bound_is_20(self):
        inc = _perfect_p3()
        inc.lessons_learned = []    # AAR-006 weight=20
        report = generate_report(inc)
        assert report.risk_score == 20
        assert report.response_quality == "ADEQUATE"

    def test_adequate_upper_bound_is_39(self):
        # AAR-002 (20) + AAR-006 (20) = 40 → POOR. Need exactly 39, not reachable
        # with current weights (20+20=40). So verify 20 and 40 sides of the boundary.
        # 20 = ADEQUATE, 40 = POOR.
        inc = _perfect_p3()
        inc.detection_source = "manual"   # AAR-002 weight=20
        inc.lessons_learned = []           # AAR-006 weight=20
        report = generate_report(inc)
        assert report.risk_score == 40
        assert report.response_quality == "POOR"

    def test_poor_at_40(self):
        # risk_score exactly 40
        inc = _perfect_p3()
        inc.detection_source = "manual"
        inc.lessons_learned = []
        report = generate_report(inc)
        assert report.risk_score == 40
        assert report.response_quality == "POOR"

    def test_poor_at_high_risk_score(self):
        # Fire many checks; result is POOR
        inc = _perfect_p1()
        inc.root_cause = ""
        inc.detection_source = "manual"
        inc.contained_at_ms = T0 + SLA["P1"] + ONE_MS
        inc.remediation_actions = []
        inc.is_recurrence = True
        inc.lessons_learned = []
        inc.evidence_items = []
        report = generate_report(inc)
        assert report.response_quality == "POOR"


# ---------------------------------------------------------------------------
# Risk score capping at 100
# ---------------------------------------------------------------------------

class TestRiskScoreCap:
    """Verify risk_score cannot exceed 100 even when all checks fire."""

    def _all_checks_fire(self) -> ClosedIncident:
        """Incident designed so that all 7 checks fire simultaneously."""
        return ClosedIncident(
            incident_id="INC-ALL-FAIL",
            severity="P1",
            title="Everything is on fire",
            opened_at_ms=T0,
            contained_at_ms=None,          # AAR-003 fires (uncontained)
            closed_at_ms=None,
            root_cause="",                 # AAR-001
            detection_source="manual",     # AAR-002
            detected_at_ms=None,
            remediation_actions=["Only one action"],  # AAR-004 (<2 items)
            lessons_learned=["short"],     # AAR-006 (all < 20 chars)
            evidence_items=["one.dd"],     # AAR-007 (<3 items, P1)
            is_recurrence=True,            # AAR-005
            similar_incident_ids=["INC-PREV-001"],
        )

    def test_all_checks_fire(self):
        inc = self._all_checks_fire()
        report = generate_report(inc)
        assert len(report.checks_fired) == 7

    def test_risk_score_capped_at_100(self):
        # Raw weights: 25+20+25+25+30+20+25 = 170, must be capped at 100
        inc = self._all_checks_fire()
        report = generate_report(inc)
        assert report.risk_score == 100

    def test_completeness_score_is_zero_when_risk_100(self):
        inc = self._all_checks_fire()
        report = generate_report(inc)
        assert report.completeness_score == 0

    def test_response_quality_is_poor_when_risk_100(self):
        inc = self._all_checks_fire()
        report = generate_report(inc)
        assert report.response_quality == "POOR"


# ---------------------------------------------------------------------------
# completeness_score
# ---------------------------------------------------------------------------

class TestCompletenessScore:
    """completeness_score = max(0, 100 - risk_score)."""

    def test_completeness_100_when_risk_0(self):
        report = generate_report(_perfect_p1())
        assert report.completeness_score == 100

    def test_completeness_80_when_risk_20(self):
        inc = _perfect_p3()
        inc.lessons_learned = []   # weight=20 only check fires
        report = generate_report(inc)
        assert report.completeness_score == 80

    def test_completeness_floor_is_zero(self):
        inc = ClosedIncident(
            incident_id="X",
            severity="P1",
            title="X",
            opened_at_ms=T0,
            contained_at_ms=None,
            closed_at_ms=None,
            root_cause="",
            detection_source="manual",
            remediation_actions=[],
            lessons_learned=["short"],
            evidence_items=[],
            is_recurrence=True,
            similar_incident_ids=["INC-001"],
        )
        report = generate_report(inc)
        assert report.completeness_score == max(0, 100 - report.risk_score)
        assert report.completeness_score >= 0


# ---------------------------------------------------------------------------
# response_time_hours
# ---------------------------------------------------------------------------

class TestResponseTimeHours:
    """response_time_hours = (contained_at_ms - opened_at_ms) / 3_600_000 or None."""

    def test_response_time_is_none_when_not_contained(self):
        inc = _perfect_p1()
        inc.contained_at_ms = None
        report = generate_report(inc)
        assert report.response_time_hours is None

    def test_response_time_exact_4h(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + 4 * ONE_HOUR_MS
        report = generate_report(inc)
        assert report.response_time_hours == pytest.approx(4.0)

    def test_response_time_exact_1h(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + ONE_HOUR_MS
        report = generate_report(inc)
        assert report.response_time_hours == pytest.approx(1.0)

    def test_response_time_zero_when_contained_at_opened(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0
        report = generate_report(inc)
        assert report.response_time_hours == pytest.approx(0.0)

    def test_response_time_fractional(self):
        inc = _perfect_p1()
        inc.contained_at_ms = T0 + int(1.5 * ONE_HOUR_MS)
        report = generate_report(inc)
        assert report.response_time_hours == pytest.approx(1.5)


# ---------------------------------------------------------------------------
# to_dict()
# ---------------------------------------------------------------------------

class TestToDict:
    """AARReport.to_dict() should return a plain dict with correct shape."""

    def test_to_dict_returns_dict(self):
        report = generate_report(_perfect_p1())
        assert isinstance(report.to_dict(), dict)

    def test_to_dict_has_required_keys(self):
        d = generate_report(_perfect_p1()).to_dict()
        for key in ("incident_id", "risk_score", "response_quality",
                    "completeness_score", "response_time_hours", "checks_fired"):
            assert key in d

    def test_to_dict_checks_fired_is_list(self):
        d = generate_report(_perfect_p1()).to_dict()
        assert isinstance(d["checks_fired"], list)

    def test_to_dict_checks_fired_empty_for_perfect_incident(self):
        d = generate_report(_perfect_p1()).to_dict()
        assert d["checks_fired"] == []

    def test_to_dict_check_entry_has_required_keys(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        d = generate_report(inc).to_dict()
        entry = d["checks_fired"][0]
        for key in ("check_id", "severity", "description", "evidence", "weight"):
            assert key in entry

    def test_to_dict_incident_id_matches(self):
        inc = _perfect_p1("INC-DICT-TEST")
        d = generate_report(inc).to_dict()
        assert d["incident_id"] == "INC-DICT-TEST"

    def test_to_dict_response_time_none_when_uncontained(self):
        inc = _perfect_p1()
        inc.contained_at_ms = None
        d = generate_report(inc).to_dict()
        assert d["response_time_hours"] is None


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------

class TestSummary:
    """AARReport.summary() should return a non-empty string with key fields."""

    def test_summary_returns_string(self):
        report = generate_report(_perfect_p1())
        assert isinstance(report.summary(), str)

    def test_summary_contains_incident_id(self):
        inc = _perfect_p1("INC-SUMMARY-001")
        assert "INC-SUMMARY-001" in generate_report(inc).summary()

    def test_summary_contains_quality(self):
        report = generate_report(_perfect_p1())
        assert report.response_quality in report.summary()

    def test_summary_contains_risk(self):
        report = generate_report(_perfect_p1())
        assert str(report.risk_score) in report.summary()

    def test_summary_mentions_uncontained_when_no_containment(self):
        inc = _perfect_p1()
        inc.contained_at_ms = None
        report = generate_report(inc)
        assert "uncontained" in report.summary()

    def test_summary_contains_check_ids_when_checks_fire(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        report = generate_report(inc)
        assert "AAR-001" in report.summary()


# ---------------------------------------------------------------------------
# by_severity()
# ---------------------------------------------------------------------------

class TestBySeverity:
    """AARReport.by_severity() groups checks into HIGH and MEDIUM buckets."""

    def test_by_severity_returns_dict(self):
        report = generate_report(_perfect_p1())
        assert isinstance(report.by_severity(), dict)

    def test_by_severity_has_high_and_medium_keys(self):
        d = report = generate_report(_perfect_p1()).by_severity()
        assert "HIGH" in d
        assert "MEDIUM" in d

    def test_by_severity_empty_buckets_for_perfect_incident(self):
        d = generate_report(_perfect_p1()).by_severity()
        assert d["HIGH"] == []
        assert d["MEDIUM"] == []

    def test_by_severity_high_contains_aar001(self):
        inc = _perfect_p1()
        inc.root_cause = ""
        d = generate_report(inc).by_severity()
        ids = [c.check_id for c in d["HIGH"]]
        assert "AAR-001" in ids

    def test_by_severity_medium_contains_aar002(self):
        inc = _perfect_p1()
        inc.detection_source = "manual"
        d = generate_report(inc).by_severity()
        ids = [c.check_id for c in d["MEDIUM"]]
        assert "AAR-002" in ids

    def test_by_severity_medium_contains_aar006(self):
        inc = _perfect_p1()
        inc.lessons_learned = []
        d = generate_report(inc).by_severity()
        ids = [c.check_id for c in d["MEDIUM"]]
        assert "AAR-006" in ids

    def test_by_severity_check_count_matches_total(self):
        inc = _perfect_p1()
        inc.root_cause = ""          # HIGH
        inc.lessons_learned = []     # MEDIUM
        report = generate_report(inc)
        d = report.by_severity()
        total_bucketed = len(d["HIGH"]) + len(d["MEDIUM"])
        assert total_bucketed == len(report.checks_fired)


# ---------------------------------------------------------------------------
# generate_reports()
# ---------------------------------------------------------------------------

class TestGenerateReports:
    """generate_reports() should process a list of incidents correctly."""

    def test_returns_list(self):
        result = generate_reports([_perfect_p1(), _perfect_p3()])
        assert isinstance(result, list)

    def test_returns_correct_count(self):
        incidents = [_perfect_p1(f"INC-{i}") for i in range(5)]
        result = generate_reports(incidents)
        assert len(result) == 5

    def test_empty_list_returns_empty(self):
        assert generate_reports([]) == []

    def test_each_element_is_aar_report(self):
        result = generate_reports([_perfect_p1(), _perfect_p3()])
        for r in result:
            assert isinstance(r, AARReport)

    def test_order_preserved(self):
        ids = [f"INC-{i}" for i in range(4)]
        incidents = [_perfect_p1(i) for i in ids]
        result = generate_reports(incidents)
        assert [r.incident_id for r in result] == ids


# ---------------------------------------------------------------------------
# poor_quality_reports()
# ---------------------------------------------------------------------------

class TestPoorQualityReports:
    """poor_quality_reports() filters to POOR quality and sorts descending."""

    def _make_poor(self, incident_id: str) -> ClosedIncident:
        inc = _perfect_p1(incident_id)
        inc.root_cause = ""
        inc.detection_source = "manual"
        inc.contained_at_ms = None          # SLA breach + no response time
        inc.remediation_actions = []
        inc.is_recurrence = True
        inc.lessons_learned = []
        inc.evidence_items = []
        return inc

    def test_filters_out_non_poor_reports(self):
        reports = generate_reports([_perfect_p1("GOOD"), self._make_poor("POOR")])
        poor = poor_quality_reports(reports)
        assert all(r.response_quality == "POOR" for r in poor)

    def test_returns_empty_when_no_poor(self):
        reports = generate_reports([_perfect_p1(), _perfect_p3()])
        assert poor_quality_reports(reports) == []

    def test_sorted_by_risk_score_descending(self):
        inc_a = _perfect_p1("A")
        inc_a.detection_source = "manual"   # AAR-002 weight=20 → risk=20 (ADEQUATE, not POOR)
        # Force POOR for inc_a: add more checks
        inc_a.root_cause = ""               # +25 = 45 → POOR
        inc_a.contained_at_ms = None        # +25 = 70

        inc_b = _perfect_p1("B")
        inc_b.root_cause = ""               # +25
        inc_b.detection_source = "manual"   # +20
        inc_b.contained_at_ms = None        # +25 = 70

        inc_c = _perfect_p1("C")
        inc_c.root_cause = ""               # 25
        inc_c.detection_source = "manual"   # 20
        inc_c.contained_at_ms = None        # 25
        inc_c.remediation_actions = []      # 25 = 95 total (before cap)
        inc_c.is_recurrence = True          # +30 = 125 → capped at 100

        reports = generate_reports([inc_a, inc_b, inc_c])
        poor = poor_quality_reports(reports)
        scores = [r.risk_score for r in poor]
        assert scores == sorted(scores, reverse=True)

    def test_single_poor_report_returned(self):
        reports = generate_reports([self._make_poor("ONLY-POOR")])
        poor = poor_quality_reports(reports)
        assert len(poor) == 1
        assert poor[0].incident_id == "ONLY-POOR"

    def test_empty_input_returns_empty(self):
        assert poor_quality_reports([]) == []


# ---------------------------------------------------------------------------
# Perfect incident — zero checks
# ---------------------------------------------------------------------------

class TestPerfectIncident:
    """A properly-closed incident should produce zero checks and EXCELLENT quality."""

    def test_p1_perfect_no_checks(self):
        report = generate_report(_perfect_p1())
        assert report.checks_fired == []
        assert report.risk_score == 0
        assert report.response_quality == "EXCELLENT"
        assert report.completeness_score == 100

    def test_p3_perfect_no_checks(self):
        report = generate_report(_perfect_p3())
        assert report.checks_fired == []
        assert report.risk_score == 0
        assert report.response_quality == "EXCELLENT"


# ---------------------------------------------------------------------------
# AARCheck dataclass basics
# ---------------------------------------------------------------------------

class TestAARCheckDataclass:
    """Verify AARCheck fields are accessible."""

    def test_aar_check_fields(self):
        c = AARCheck(
            check_id="AAR-001",
            severity="HIGH",
            description="Test",
            evidence="Some evidence",
            weight=25,
        )
        assert c.check_id == "AAR-001"
        assert c.severity == "HIGH"
        assert c.description == "Test"
        assert c.evidence == "Some evidence"
        assert c.weight == 25


# ---------------------------------------------------------------------------
# ClosedIncident dataclass defaults
# ---------------------------------------------------------------------------

class TestClosedIncidentDefaults:
    """Verify default field values on ClosedIncident."""

    def test_string_defaults_are_empty(self):
        inc = ClosedIncident(
            incident_id="X",
            severity="P1",
            title="T",
            opened_at_ms=T0,
            contained_at_ms=T0 + ONE_HOUR_MS,
            closed_at_ms=T0 + 2 * ONE_HOUR_MS,
        )
        assert inc.root_cause == ""
        assert inc.detection_source == ""

    def test_list_defaults_are_independent(self):
        inc_a = ClosedIncident(
            incident_id="A",
            severity="P2",
            title="A",
            opened_at_ms=T0,
            contained_at_ms=T0 + ONE_HOUR_MS,
            closed_at_ms=None,
        )
        inc_b = ClosedIncident(
            incident_id="B",
            severity="P2",
            title="B",
            opened_at_ms=T0,
            contained_at_ms=T0 + ONE_HOUR_MS,
            closed_at_ms=None,
        )
        inc_a.remediation_actions.append("step")
        # Ensure default_factory ensures separate lists
        assert inc_b.remediation_actions == []

    def test_bool_default_is_false(self):
        inc = ClosedIncident(
            incident_id="X",
            severity="P1",
            title="T",
            opened_at_ms=T0,
            contained_at_ms=None,
            closed_at_ms=None,
        )
        assert inc.is_recurrence is False

    def test_optional_ints_default_to_none(self):
        inc = ClosedIncident(
            incident_id="X",
            severity="P1",
            title="T",
            opened_at_ms=T0,
            contained_at_ms=None,
            closed_at_ms=None,
        )
        assert inc.detected_at_ms is None
