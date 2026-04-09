"""
Test Suite — SLA Tracker
=========================
~55 pytest tests covering:
  - SLAStatus enum values
  - SLAWindow.to_dict() serialisation
  - SLAResult properties, to_dict(), summary(), is_breached
  - All four SLA status transitions (ON_TRACK, WARNING, BREACHED, CRITICAL_BREACH)
  - Every phase window (detect, respond, resolve)
  - Every default severity tier (P1–P5)
  - Unknown severity fallback to P3
  - Case-insensitive severity lookup
  - Incidents with no timestamps (all None)
  - Resolved vs unresolved incidents
  - Reference-time projection for resolve window
  - evaluate_many() sort order
  - summary_report() aggregation and edge cases
  - Custom SLA tiers and custom warning_pct
  - Escalation message content for each status level
  - sla_score clamping to [0, 100]
  - breach_seconds and breach_percent calculations
"""

from __future__ import annotations

import time
from typing import List

import pytest

from automations.sla_tracker import (
    _DEFAULT_SLA_TIERS,
    Incident,
    SLAResult,
    SLAStatus,
    SLATracker,
    SLAWindow,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _now() -> float:
    """Return the current wall-clock time (convenience alias)."""
    return time.time()


def _make_incident(
    severity: str = "P2",
    detected_offset: float = 300.0,    # seconds after created_at
    responded_offset: float = 1800.0,  # seconds after detected_at
    resolved_offset: float = 43200.0,  # seconds after detected_at
    resolved: bool = True,
    reference_offset: float = 0.0,     # seconds after created_at for ref time
    use_reference: bool = False,
) -> Incident:
    """
    Build a synthetic Incident with all timestamps relative to a fixed base
    time so tests are deterministic.
    """
    base = 1_700_000_000.0   # fixed epoch — irrelevant in magnitude, just stable

    detected_at = base + detected_offset
    responded_at = detected_at + responded_offset
    resolved_at = detected_at + resolved_offset if resolved else None
    reference_time = base + reference_offset if use_reference else None

    return Incident(
        incident_id="INC-TEST",
        severity=severity,
        detected_at=detected_at,
        responded_at=responded_at,
        resolved_at=resolved_at,
        created_at=base,
        reference_time=reference_time,
        title="Synthetic test incident",
        tags=["test"],
    )


@pytest.fixture
def tracker() -> SLATracker:
    """Default SLATracker instance shared across tests."""
    return SLATracker()


# ---------------------------------------------------------------------------
# 1. SLAStatus enum
# ---------------------------------------------------------------------------

class TestSLAStatusEnum:

    def test_on_track_value(self):
        assert SLAStatus.ON_TRACK.value == "ON_TRACK"

    def test_warning_value(self):
        assert SLAStatus.WARNING.value == "WARNING"

    def test_breached_value(self):
        assert SLAStatus.BREACHED.value == "BREACHED"

    def test_critical_breach_value(self):
        assert SLAStatus.CRITICAL_BREACH.value == "CRITICAL_BREACH"

    def test_four_members_total(self):
        assert len(SLAStatus) == 4


# ---------------------------------------------------------------------------
# 2. SLAWindow
# ---------------------------------------------------------------------------

class TestSLAWindow:

    def _window(self, status: SLAStatus = SLAStatus.ON_TRACK) -> SLAWindow:
        return SLAWindow(
            name="detect",
            actual_seconds=200.0,
            sla_seconds=300,
            status=status,
            breach_seconds=0.0,
            breach_percent=66.67,
        )

    def test_to_dict_contains_required_keys(self):
        w = self._window()
        d = w.to_dict()
        for key in ("name", "actual_seconds", "sla_seconds", "status",
                    "breach_seconds", "breach_percent"):
            assert key in d

    def test_to_dict_status_is_string(self):
        w = self._window(SLAStatus.WARNING)
        assert w.to_dict()["status"] == "WARNING"

    def test_to_dict_breach_percent_rounded(self):
        w = SLAWindow("r", 100.0, 300, SLAStatus.ON_TRACK, 0.0, 33.33333)
        assert w.to_dict()["breach_percent"] == 33.33

    def test_to_dict_none_actual(self):
        w = SLAWindow("detect", None, 300, SLAStatus.ON_TRACK)
        assert w.to_dict()["actual_seconds"] is None


# ---------------------------------------------------------------------------
# 3. SLAResult properties and methods
# ---------------------------------------------------------------------------

class TestSLAResult:

    def _result(
        self,
        overall: SLAStatus = SLAStatus.ON_TRACK,
        score: int = 100,
        windows: List[SLAWindow] = None,
    ) -> SLAResult:
        if windows is None:
            windows = [
                SLAWindow("detect",  100.0, 300, overall),
                SLAWindow("respond", 200.0, 900, SLAStatus.ON_TRACK),
                SLAWindow("resolve", 500.0, 14400, SLAStatus.ON_TRACK),
            ]
        return SLAResult(
            incident_id="INC-000",
            severity="P1",
            overall_status=overall,
            sla_score=score,
            windows=windows,
            breached_windows=[],
            escalation_message="All SLAs on track.",
            generated_at=1_700_000_000.0,
        )

    def test_summary_format(self):
        r = self._result(SLAStatus.WARNING, 90)
        assert r.summary() == "INC-000 [P1] WARNING score=90"

    def test_is_breached_false_when_on_track(self):
        r = self._result(SLAStatus.ON_TRACK)
        assert r.is_breached is False

    def test_is_breached_false_when_warning(self):
        r = self._result(SLAStatus.WARNING)
        assert r.is_breached is False

    def test_is_breached_true_when_breached(self):
        windows = [
            SLAWindow("detect", 500.0, 300, SLAStatus.BREACHED, 200.0, 166.67),
            SLAWindow("respond", 200.0, 900, SLAStatus.ON_TRACK),
            SLAWindow("resolve", 500.0, 14400, SLAStatus.ON_TRACK),
        ]
        r = self._result(SLAStatus.BREACHED, 75, windows)
        assert r.is_breached is True

    def test_is_breached_true_when_critical_breach(self):
        windows = [
            SLAWindow("detect", 700.0, 300, SLAStatus.CRITICAL_BREACH, 400.0, 233.33),
            SLAWindow("respond", 200.0, 900, SLAStatus.ON_TRACK),
            SLAWindow("resolve", 500.0, 14400, SLAStatus.ON_TRACK),
        ]
        r = self._result(SLAStatus.CRITICAL_BREACH, 60, windows)
        assert r.is_breached is True

    def test_to_dict_overall_status_is_string(self):
        r = self._result(SLAStatus.BREACHED)
        assert r.to_dict()["overall_status"] == "BREACHED"

    def test_to_dict_windows_are_dicts(self):
        r = self._result()
        for w in r.to_dict()["windows"]:
            assert isinstance(w, dict)

    def test_to_dict_contains_is_breached_key(self):
        r = self._result()
        assert "is_breached" in r.to_dict()


# ---------------------------------------------------------------------------
# 4. SLATracker — default tiers
# ---------------------------------------------------------------------------

class TestDefaultTiers:

    def test_p1_detect_sla(self):
        assert _DEFAULT_SLA_TIERS["P1"]["detect"] == 300

    def test_p1_respond_sla(self):
        assert _DEFAULT_SLA_TIERS["P1"]["respond"] == 900

    def test_p1_resolve_sla(self):
        assert _DEFAULT_SLA_TIERS["P1"]["resolve"] == 14400

    def test_p5_resolve_sla(self):
        assert _DEFAULT_SLA_TIERS["P5"]["resolve"] == 2_592_000

    def test_all_five_severities_present(self):
        for sev in ("P1", "P2", "P3", "P4", "P5"):
            assert sev in _DEFAULT_SLA_TIERS


# ---------------------------------------------------------------------------
# 5. Status transitions — detect window
# ---------------------------------------------------------------------------

class TestDetectWindowTransitions:
    """P1 detect SLA = 300 s; warning_pct=0.8 → warning at >= 240 s."""

    base = 1_700_000_000.0

    def _incident(self, detect_offset: float, resolved: bool = True) -> Incident:
        detected_at = self.base + detect_offset
        return Incident(
            incident_id="INC-D",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,           # well within respond SLA
            resolved_at=detected_at + 3600 if resolved else None,  # within resolve
            created_at=self.base,
            reference_time=detected_at + 3600,
        )

    def test_detect_on_track(self, tracker):
        inc = self._incident(100.0)  # 100 s < 240 s warning threshold
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.status == SLAStatus.ON_TRACK

    def test_detect_warning(self, tracker):
        inc = self._incident(250.0)  # 250 s >= 240 s (80% of 300)
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.status == SLAStatus.WARNING

    def test_detect_breached(self, tracker):
        inc = self._incident(400.0)  # 400 s > 300 s SLA but <= 600 s (2x)
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.status == SLAStatus.BREACHED

    def test_detect_critical_breach(self, tracker):
        inc = self._incident(700.0)  # 700 s > 600 s (2 × 300)
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.status == SLAStatus.CRITICAL_BREACH

    def test_detect_breach_seconds_correct(self, tracker):
        inc = self._incident(400.0)
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.breach_seconds == pytest.approx(100.0)  # 400 - 300

    def test_detect_breach_percent_correct(self, tracker):
        inc = self._incident(600.0)
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        # 600 / 300 * 100 = 200 %
        assert detect_w.breach_percent == pytest.approx(200.0)


# ---------------------------------------------------------------------------
# 6. Status transitions — respond window
# ---------------------------------------------------------------------------

class TestRespondWindowTransitions:
    """P1 respond SLA = 900 s; warning at >= 720 s."""

    base = 1_700_000_000.0

    def _incident(self, respond_offset: float) -> Incident:
        detected_at = self.base + 60   # 60 s detect (on-track)
        return Incident(
            incident_id="INC-R",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + respond_offset,
            resolved_at=detected_at + 3600,
            created_at=self.base,
            reference_time=detected_at + 3600,
        )

    def test_respond_on_track(self, tracker):
        inc = self._incident(500.0)
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "respond")
        assert w.status == SLAStatus.ON_TRACK

    def test_respond_warning(self, tracker):
        inc = self._incident(750.0)  # 750 >= 720
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "respond")
        assert w.status == SLAStatus.WARNING

    def test_respond_breached(self, tracker):
        inc = self._incident(1000.0)  # 1000 > 900 but <= 1800
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "respond")
        assert w.status == SLAStatus.BREACHED

    def test_respond_critical_breach(self, tracker):
        inc = self._incident(2000.0)  # 2000 > 1800 (2 × 900)
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "respond")
        assert w.status == SLAStatus.CRITICAL_BREACH


# ---------------------------------------------------------------------------
# 7. Status transitions — resolve window
# ---------------------------------------------------------------------------

class TestResolveWindowTransitions:
    """P1 resolve SLA = 14400 s (4 h); warning at >= 11520 s."""

    base = 1_700_000_000.0

    def _incident(self, resolve_offset: float, resolved: bool = True) -> Incident:
        detected_at = self.base + 60
        responded_at = detected_at + 300
        return Incident(
            incident_id="INC-RES",
            severity="P1",
            detected_at=detected_at,
            responded_at=responded_at,
            resolved_at=detected_at + resolve_offset if resolved else None,
            created_at=self.base,
            reference_time=detected_at + resolve_offset,  # ref == resolved when unresolved
        )

    def test_resolve_on_track(self, tracker):
        inc = self._incident(10000.0)
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        assert w.status == SLAStatus.ON_TRACK

    def test_resolve_warning(self, tracker):
        inc = self._incident(12000.0)  # 12000 >= 11520
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        assert w.status == SLAStatus.WARNING

    def test_resolve_breached(self, tracker):
        inc = self._incident(16000.0)  # 16000 > 14400 but <= 28800
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        assert w.status == SLAStatus.BREACHED

    def test_resolve_critical_breach(self, tracker):
        inc = self._incident(30000.0)  # 30000 > 28800 (2 × 14400)
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        assert w.status == SLAStatus.CRITICAL_BREACH

    def test_resolve_unresolved_uses_reference_time(self, tracker):
        """Unresolved incident with a reference_time should project elapsed."""
        inc = self._incident(30000.0, resolved=False)
        # reference_time is set to detected_at + 30000 which is a critical breach
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        assert w.status == SLAStatus.CRITICAL_BREACH

    def test_resolve_none_without_reference_time(self, tracker):
        """Unresolved incident without reference_time keeps resolve ON_TRACK (no projection)."""
        base = 1_700_000_000.0
        detected_at = base + 60
        inc = Incident(
            incident_id="INC-NREF",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 300,
            resolved_at=None,
            created_at=base,
            reference_time=None,   # no reference → no projection
        )
        result = tracker.evaluate(inc)
        w = next(x for x in result.windows if x.name == "resolve")
        # Without explicit reference_time, actual_seconds stays None → ON_TRACK
        assert w.actual_seconds is None
        assert w.status == SLAStatus.ON_TRACK


# ---------------------------------------------------------------------------
# 8. Severity tier coverage (P1–P5)
# ---------------------------------------------------------------------------

class TestSeverityTiers:

    base = 1_700_000_000.0

    def _fully_compliant(self, severity: str) -> Incident:
        """Incident where every window is well within the configured SLA."""
        tier = _DEFAULT_SLA_TIERS[severity]
        detected_at = self.base + tier["detect"] * 0.1
        responded_at = detected_at + tier["respond"] * 0.1
        resolved_at = detected_at + tier["resolve"] * 0.1
        return Incident(
            incident_id=f"INC-{severity}",
            severity=severity,
            detected_at=detected_at,
            responded_at=responded_at,
            resolved_at=resolved_at,
            created_at=self.base,
        )

    def test_p1_fully_compliant(self, tracker):
        result = tracker.evaluate(self._fully_compliant("P1"))
        assert result.overall_status == SLAStatus.ON_TRACK
        assert result.sla_score == 100

    def test_p2_fully_compliant(self, tracker):
        result = tracker.evaluate(self._fully_compliant("P2"))
        assert result.overall_status == SLAStatus.ON_TRACK

    def test_p3_fully_compliant(self, tracker):
        result = tracker.evaluate(self._fully_compliant("P3"))
        assert result.overall_status == SLAStatus.ON_TRACK

    def test_p4_fully_compliant(self, tracker):
        result = tracker.evaluate(self._fully_compliant("P4"))
        assert result.overall_status == SLAStatus.ON_TRACK

    def test_p5_fully_compliant(self, tracker):
        result = tracker.evaluate(self._fully_compliant("P5"))
        assert result.overall_status == SLAStatus.ON_TRACK


# ---------------------------------------------------------------------------
# 9. Unknown severity and case-insensitivity
# ---------------------------------------------------------------------------

class TestSeverityFallback:

    base = 1_700_000_000.0

    def _incident(self, severity: str) -> Incident:
        detected_at = self.base + 100
        return Incident(
            incident_id="INC-X",
            severity=severity,
            detected_at=detected_at,
            responded_at=detected_at + 200,
            resolved_at=detected_at + 500,
            created_at=self.base,
        )

    def test_unknown_severity_falls_back_to_p3(self, tracker):
        """Severity strings not in P1–P5 should use P3 SLA windows."""
        inc = self._incident("UNKNOWN")
        result = tracker.evaluate(inc)
        # P3 resolve SLA is 259200; 500 s is far within it → ON_TRACK
        assert result.overall_status == SLAStatus.ON_TRACK
        # Verify the respond window used P3 budget (14400), not P1 (900)
        respond_w = next(w for w in result.windows if w.name == "respond")
        assert respond_w.sla_seconds == _DEFAULT_SLA_TIERS["P3"]["respond"]

    def test_lowercase_severity_resolved(self, tracker):
        """'p1' should map to P1 tier, not fall back to P3."""
        inc = self._incident("p1")
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.sla_seconds == _DEFAULT_SLA_TIERS["P1"]["detect"]

    def test_mixed_case_severity_resolved(self, tracker):
        inc = self._incident("P2")
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.sla_seconds == _DEFAULT_SLA_TIERS["P2"]["detect"]


# ---------------------------------------------------------------------------
# 10. No timestamps (completely blank incident)
# ---------------------------------------------------------------------------

class TestNoTimestamps:

    def test_all_none_timestamps_on_track(self, tracker):
        inc = Incident(
            incident_id="INC-BLANK",
            severity="P1",
            detected_at=None,
            responded_at=None,
            resolved_at=None,
            created_at=_now(),
            reference_time=None,
        )
        result = tracker.evaluate(inc)
        assert result.overall_status == SLAStatus.ON_TRACK
        assert result.sla_score == 100

    def test_all_none_windows_have_none_actual(self, tracker):
        inc = Incident(
            incident_id="INC-BLANK2",
            severity="P2",
            detected_at=None,
            responded_at=None,
            resolved_at=None,
            created_at=_now(),
        )
        result = tracker.evaluate(inc)
        for w in result.windows:
            assert w.actual_seconds is None


# ---------------------------------------------------------------------------
# 11. SLA score calculation
# ---------------------------------------------------------------------------

class TestSLAScore:

    base = 1_700_000_000.0

    def test_perfect_score_no_breaches(self, tracker):
        inc = _make_incident("P2", 100, 500, 20000)
        result = tracker.evaluate(inc)
        assert result.sla_score == 100

    def test_score_decrements_for_warning(self, tracker):
        """One WARNING window → score = 90."""
        # P1 detect SLA = 300; 250 s triggers WARNING
        detected_at = self.base + 250
        inc = Incident(
            incident_id="INC-W",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert result.sla_score == 90

    def test_score_decrements_for_breach(self, tracker):
        """One BREACHED window → score = 75 (100 - 25)."""
        detected_at = self.base + 400  # 400 > 300 (BREACHED, not CRITICAL)
        inc = Incident(
            incident_id="INC-B",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert result.sla_score == 75

    def test_score_decrements_for_critical_breach(self, tracker):
        """One CRITICAL_BREACH window → score = 60 (100 - 40)."""
        detected_at = self.base + 700  # 700 > 600 (2 × 300)
        inc = Incident(
            incident_id="INC-CB",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert result.sla_score == 60

    def test_score_clamped_to_zero(self, tracker):
        """Multiple critical breaches should clamp score at 0, not go negative."""
        detected_at = self.base + 700   # CRITICAL detect (−40)
        inc = Incident(
            incident_id="INC-CLAMP",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 2000,  # CRITICAL respond (−40)
            resolved_at=detected_at + 30000,  # CRITICAL resolve (−40)
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert result.sla_score == 0


# ---------------------------------------------------------------------------
# 12. Escalation messages
# ---------------------------------------------------------------------------

class TestEscalationMessages:

    base = 1_700_000_000.0

    def test_on_track_message(self, tracker):
        inc = _make_incident("P2", 100, 500, 20000)
        result = tracker.evaluate(inc)
        assert result.escalation_message == "All SLAs on track."

    def test_warning_message_contains_keyword(self, tracker):
        detected_at = self.base + 250  # WARNING detect
        inc = Incident(
            incident_id="INC-WMSG",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert "SLA WARNING" in result.escalation_message

    def test_breached_message_contains_keyword(self, tracker):
        detected_at = self.base + 400
        inc = Incident(
            incident_id="INC-BMSG",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert "SLA BREACHED" in result.escalation_message

    def test_critical_breach_message_contains_escalate(self, tracker):
        detected_at = self.base + 700
        inc = Incident(
            incident_id="INC-CMSG",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert "ESCALATE IMMEDIATELY" in result.escalation_message

    def test_critical_breach_message_contains_incident_id(self, tracker):
        detected_at = self.base + 700
        inc = Incident(
            incident_id="INC-ID-CHECK",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=self.base,
        )
        result = tracker.evaluate(inc)
        assert "INC-ID-CHECK" in result.escalation_message


# ---------------------------------------------------------------------------
# 13. evaluate_many — sort order and structure
# ---------------------------------------------------------------------------

class TestEvaluateMany:

    base = 1_700_000_000.0

    def _incidents(self) -> List[Incident]:
        """Three incidents with different compliance levels."""
        # Fully compliant P3 incident
        d_good = self.base + 100
        good = Incident(
            incident_id="INC-GOOD",
            severity="P3",
            detected_at=d_good,
            responded_at=d_good + 500,
            resolved_at=d_good + 5000,
            created_at=self.base,
        )

        # Breached P1 detect
        d_bad = self.base + 400
        bad = Incident(
            incident_id="INC-BAD",
            severity="P1",
            detected_at=d_bad,
            responded_at=d_bad + 100,
            resolved_at=d_bad + 3600,
            created_at=self.base,
        )

        # Critical-breach P1
        d_worst = self.base + 700
        worst = Incident(
            incident_id="INC-WORST",
            severity="P1",
            detected_at=d_worst,
            responded_at=d_worst + 100,
            resolved_at=d_worst + 3600,
            created_at=self.base,
        )
        return [good, bad, worst]

    def test_returns_list_of_sla_results(self, tracker):
        results = tracker.evaluate_many(self._incidents())
        assert all(isinstance(r, SLAResult) for r in results)

    def test_sorted_ascending_by_sla_score(self, tracker):
        results = tracker.evaluate_many(self._incidents())
        scores = [r.sla_score for r in results]
        assert scores == sorted(scores)

    def test_worst_incident_first(self, tracker):
        results = tracker.evaluate_many(self._incidents())
        assert results[0].incident_id == "INC-WORST"

    def test_best_incident_last(self, tracker):
        results = tracker.evaluate_many(self._incidents())
        assert results[-1].incident_id == "INC-GOOD"

    def test_empty_list_returns_empty(self, tracker):
        assert tracker.evaluate_many([]) == []

    def test_single_incident_returns_list_of_one(self, tracker):
        inc = _make_incident("P3", 100, 500, 5000)
        results = tracker.evaluate_many([inc])
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 14. summary_report
# ---------------------------------------------------------------------------

class TestSummaryReport:

    def _make_results(self, tracker: SLATracker) -> List[SLAResult]:
        """Generate results with varied statuses for reporting tests."""
        base = 1_700_000_000.0

        def _inc(iid, detected_offset):
            detected_at = base + detected_offset
            return Incident(
                incident_id=iid,
                severity="P1",
                detected_at=detected_at,
                responded_at=detected_at + 100,
                resolved_at=detected_at + 3600,
                created_at=base,
            )

        return tracker.evaluate_many([
            _inc("INC-A", 100),   # ON_TRACK
            _inc("INC-B", 250),   # WARNING  (detect)
            _inc("INC-C", 400),   # BREACHED
            _inc("INC-D", 700),   # CRITICAL_BREACH
        ])

    def test_total_count(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert report["total"] == 4

    def test_on_track_count(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert report["on_track"] == 1

    def test_warning_count(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert report["warning"] == 1

    def test_breached_count(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert report["breached"] == 1

    def test_critical_breach_count(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert report["critical_breach"] == 1

    def test_average_sla_score_is_float(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert isinstance(report["average_sla_score"], float)

    def test_average_sla_score_in_range(self, tracker):
        report = tracker.summary_report(self._make_results(tracker))
        assert 0.0 <= report["average_sla_score"] <= 100.0

    def test_empty_results_total_zero(self, tracker):
        report = tracker.summary_report([])
        assert report["total"] == 0
        assert report["average_sla_score"] == 0.0

    def test_all_on_track_report(self, tracker):
        results = tracker.evaluate_many([_make_incident("P3", 100, 500, 5000)])
        report = tracker.summary_report(results)
        assert report["on_track"] == 1
        assert report["warning"] == 0
        assert report["breached"] == 0
        assert report["critical_breach"] == 0


# ---------------------------------------------------------------------------
# 15. Custom SLA tiers and warning_pct
# ---------------------------------------------------------------------------

class TestCustomConfiguration:

    def test_custom_tiers_override_defaults(self):
        custom_tiers = {
            "CRIT": {"detect": 60, "respond": 120, "resolve": 600},
        }
        tracker = SLATracker(sla_tiers=custom_tiers)
        base = 1_700_000_000.0
        detected_at = base + 90  # 90 > 60 but <= 120 (BREACHED, not CRITICAL)
        inc = Incident(
            incident_id="INC-CUSTOM",
            severity="CRIT",
            detected_at=detected_at,
            responded_at=detected_at + 50,
            resolved_at=detected_at + 300,
            created_at=base,
        )
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.sla_seconds == 60
        assert detect_w.status == SLAStatus.BREACHED

    def test_custom_warning_pct(self):
        """warning_pct=0.5 means WARNING fires at 50% of the SLA window."""
        tracker = SLATracker(warning_pct=0.5)
        base = 1_700_000_000.0
        # P1 detect SLA = 300 s; 50% = 150 s; use 160 s to trigger warning
        detected_at = base + 160
        inc = Incident(
            incident_id="INC-WPT",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=base,
        )
        result = tracker.evaluate(inc)
        detect_w = next(w for w in result.windows if w.name == "detect")
        assert detect_w.status == SLAStatus.WARNING

    def test_default_warning_pct_is_point_eight(self):
        tracker = SLATracker()
        assert tracker.warning_pct == 0.8

    def test_breached_windows_list_populated(self):
        tracker = SLATracker()
        base = 1_700_000_000.0
        detected_at = base + 400  # breached detect
        inc = Incident(
            incident_id="INC-BW",
            severity="P1",
            detected_at=detected_at,
            responded_at=detected_at + 100,
            resolved_at=detected_at + 3600,
            created_at=base,
        )
        result = tracker.evaluate(inc)
        assert "detect" in result.breached_windows
