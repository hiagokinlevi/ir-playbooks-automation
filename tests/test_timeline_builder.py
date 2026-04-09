"""
Tests for automations.timeline_builder
========================================
Comprehensive pytest suite covering:
  - Empty input
  - Single event
  - Chronological sort guarantee
  - Gap detection and gap_count
  - Automatic phase splitting at gap boundaries
  - auto_phase=False (single phase)
  - IncidentTimeline filter helpers: events_in_window, events_by_source,
    events_by_type
  - Critical / HIGH event properties
  - Duration calculations (timeline and phase)
  - summary() output
  - to_dict() structure and completeness
  - add_event / add_events / reset accumulation API
  - build_from_accumulated()
  - severity_level property (valid strings, wrong case, unknown value)
  - TimelinePhase properties: event_count, duration_seconds
"""

from __future__ import annotations

import time

import pytest

from automations.timeline_builder import (
    EventSeverity,
    IncidentTimeline,
    TimelineBuilder,
    TimelineEvent,
    TimelinePhase,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def make_event(
    timestamp: float,
    source: str = "test.log",
    event_type: str = "generic",
    description: str = "test event",
    severity: str = "INFO",
    actor: str = "",
    source_ip: str = "",
    target: str = "",
    tags=None,
    raw: str = "",
) -> TimelineEvent:
    """Convenience wrapper so tests do not repeat keyword spam."""
    return TimelineEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        description=description,
        severity=severity,
        actor=actor,
        source_ip=source_ip,
        target=target,
        tags=tags or [],
        raw=raw,
    )


@pytest.fixture
def builder() -> TimelineBuilder:
    """Default TimelineBuilder with a 300-second gap threshold."""
    return TimelineBuilder()


@pytest.fixture
def small_event_list() -> list:
    """Five events within a 60-second window — no gaps at default threshold."""
    base = 1_700_000_000.0
    return [
        make_event(base + 0, source="auth.log", event_type="auth_failure", severity="HIGH"),
        make_event(base + 10, source="auth.log", event_type="auth_failure", severity="HIGH"),
        make_event(base + 20, source="syslog", event_type="privilege_escalation", severity="CRITICAL"),
        make_event(base + 30, source="network", event_type="outbound_connection", severity="MEDIUM"),
        make_event(base + 60, source="auth.log", event_type="auth_success", severity="LOW"),
    ]


# ---------------------------------------------------------------------------
# 1. Empty input
# ---------------------------------------------------------------------------


class TestEmptyInput:
    def test_returns_incident_timeline(self, builder):
        result = builder.build([])
        assert isinstance(result, IncidentTimeline)

    def test_empty_events_list(self, builder):
        result = builder.build([])
        assert result.events == []

    def test_empty_phases_list(self, builder):
        result = builder.build([])
        assert result.phases == []

    def test_incident_start_zero(self, builder):
        result = builder.build([])
        assert result.incident_start == 0.0

    def test_incident_end_zero(self, builder):
        result = builder.build([])
        assert result.incident_end == 0.0

    def test_gap_count_zero(self, builder):
        result = builder.build([])
        assert result.gap_count == 0

    def test_total_events_zero(self, builder):
        result = builder.build([])
        assert result.total_events == 0

    def test_duration_seconds_zero(self, builder):
        result = builder.build([])
        assert result.duration_seconds == 0.0

    def test_critical_events_empty(self, builder):
        result = builder.build([])
        assert result.critical_events == []

    def test_high_events_empty(self, builder):
        result = builder.build([])
        assert result.high_events == []


# ---------------------------------------------------------------------------
# 2. Single event
# ---------------------------------------------------------------------------


class TestSingleEvent:
    def test_total_events_one(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.total_events == 1

    def test_incident_start_equals_timestamp(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.incident_start == 1_700_000_000.0

    def test_incident_end_equals_timestamp(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.incident_end == 1_700_000_000.0

    def test_duration_is_zero(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.duration_seconds == 0.0

    def test_gap_count_zero(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.gap_count == 0

    def test_single_phase_created(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert len(result.phases) == 1

    def test_phase_contains_event(self, builder):
        ev = make_event(1_700_000_000.0)
        result = builder.build([ev])
        assert result.phases[0].events[0] is ev


# ---------------------------------------------------------------------------
# 3. Chronological sorting
# ---------------------------------------------------------------------------


class TestChronologicalSorting:
    def test_events_sorted_ascending(self, builder):
        events = [
            make_event(300.0),
            make_event(100.0),
            make_event(200.0),
        ]
        result = builder.build(events)
        timestamps = [e.timestamp for e in result.events]
        assert timestamps == sorted(timestamps)

    def test_original_list_not_mutated(self, builder):
        events = [make_event(300.0), make_event(100.0), make_event(200.0)]
        original_first_ts = events[0].timestamp
        builder.build(events)
        assert events[0].timestamp == original_first_ts

    def test_incident_start_is_minimum(self, builder):
        events = [make_event(500.0), make_event(100.0), make_event(300.0)]
        result = builder.build(events)
        assert result.incident_start == 100.0

    def test_incident_end_is_maximum(self, builder):
        events = [make_event(500.0), make_event(100.0), make_event(300.0)]
        result = builder.build(events)
        assert result.incident_end == 500.0


# ---------------------------------------------------------------------------
# 4. Gap detection
# ---------------------------------------------------------------------------


class TestGapDetection:
    def test_no_gap_within_threshold(self, builder):
        events = [make_event(0.0), make_event(299.0)]  # 299 s < 300 s threshold
        result = builder.build(events)
        assert result.gap_count == 0

    def test_gap_exactly_at_threshold_not_counted(self, builder):
        """A delta equal to the threshold is not strictly greater, so no gap."""
        events = [make_event(0.0), make_event(300.0)]
        result = builder.build(events)
        assert result.gap_count == 0

    def test_gap_just_above_threshold(self, builder):
        events = [make_event(0.0), make_event(301.0)]
        result = builder.build(events)
        assert result.gap_count == 1

    def test_multiple_gaps_counted(self, builder):
        events = [
            make_event(0.0),
            make_event(1000.0),   # gap 1
            make_event(2000.0),   # gap 2
            make_event(2100.0),   # within threshold
        ]
        result = builder.build(events)
        assert result.gap_count == 2

    def test_no_gaps_small_cluster(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert result.gap_count == 0

    def test_custom_threshold_respected(self):
        tight_builder = TimelineBuilder(gap_threshold_seconds=5)
        events = [make_event(0.0), make_event(6.0)]  # delta=6 > threshold=5
        result = tight_builder.build(events)
        assert result.gap_count == 1


# ---------------------------------------------------------------------------
# 5. Phase splitting (auto_phase=True)
# ---------------------------------------------------------------------------


class TestPhaseSplitting:
    def test_no_gap_yields_single_phase(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert len(result.phases) == 1

    def test_one_gap_yields_two_phases(self, builder):
        events = [make_event(0.0), make_event(1000.0)]
        result = builder.build(events)
        assert len(result.phases) == 2

    def test_two_gaps_yield_three_phases(self, builder):
        events = [make_event(0.0), make_event(1000.0), make_event(2000.0)]
        result = builder.build(events)
        assert len(result.phases) == 3

    def test_phase_names_contain_phase_number(self, builder):
        events = [make_event(0.0), make_event(1000.0)]
        result = builder.build(events)
        assert "Phase 1" in result.phases[0].name
        assert "Phase 2" in result.phases[1].name

    def test_phase_name_contains_first_source(self, builder):
        events = [
            make_event(0.0, source="auth.log"),
            make_event(1000.0, source="syslog"),
        ]
        result = builder.build(events)
        assert "auth.log" in result.phases[0].name
        assert "syslog" in result.phases[1].name

    def test_phase_events_are_correct_subset(self, builder):
        events = [
            make_event(0.0),
            make_event(50.0),
            make_event(1000.0),
            make_event(1050.0),
        ]
        result = builder.build(events)
        assert result.phases[0].event_count == 2
        assert result.phases[1].event_count == 2

    def test_phase_start_ts(self, builder):
        events = [make_event(0.0), make_event(1000.0)]
        result = builder.build(events)
        assert result.phases[0].start_ts == 0.0
        assert result.phases[1].start_ts == 1000.0

    def test_phase_end_ts(self, builder):
        events = [make_event(0.0), make_event(50.0), make_event(1000.0)]
        result = builder.build(events)
        assert result.phases[0].end_ts == 50.0

    def test_all_events_covered_by_phases(self, builder):
        events = [make_event(float(i * 600)) for i in range(4)]
        result = builder.build(events)
        phase_event_count = sum(p.event_count for p in result.phases)
        assert phase_event_count == len(events)


# ---------------------------------------------------------------------------
# 6. auto_phase=False
# ---------------------------------------------------------------------------


class TestAutoPhaseDisabled:
    def test_single_phase_regardless_of_gaps(self):
        flat_builder = TimelineBuilder(auto_phase=False)
        events = [make_event(0.0), make_event(1000.0), make_event(2000.0)]
        result = flat_builder.build(events)
        assert len(result.phases) == 1

    def test_gap_count_still_reported(self):
        flat_builder = TimelineBuilder(auto_phase=False)
        events = [make_event(0.0), make_event(1000.0)]
        result = flat_builder.build(events)
        assert result.gap_count == 1

    def test_single_phase_contains_all_events(self):
        flat_builder = TimelineBuilder(auto_phase=False)
        events = [make_event(float(i)) for i in range(5)]
        result = flat_builder.build(events)
        assert result.phases[0].event_count == 5

    def test_single_phase_start_end(self):
        flat_builder = TimelineBuilder(auto_phase=False)
        events = [make_event(100.0), make_event(200.0), make_event(50.0)]
        result = flat_builder.build(events)
        assert result.phases[0].start_ts == 50.0
        assert result.phases[0].end_ts == 200.0


# ---------------------------------------------------------------------------
# 7. Filter helpers
# ---------------------------------------------------------------------------


class TestEventsInWindow:
    def test_returns_events_within_bounds(self, builder):
        events = [make_event(float(i)) for i in range(10)]
        result = builder.build(events)
        windowed = result.events_in_window(2.0, 5.0)
        assert len(windowed) == 4  # timestamps 2, 3, 4, 5

    def test_inclusive_start_boundary(self, builder):
        events = [make_event(10.0), make_event(20.0), make_event(30.0)]
        result = builder.build(events)
        windowed = result.events_in_window(10.0, 15.0)
        assert any(e.timestamp == 10.0 for e in windowed)

    def test_inclusive_end_boundary(self, builder):
        events = [make_event(10.0), make_event(20.0), make_event(30.0)]
        result = builder.build(events)
        windowed = result.events_in_window(25.0, 30.0)
        assert any(e.timestamp == 30.0 for e in windowed)

    def test_no_match_returns_empty(self, builder):
        events = [make_event(10.0), make_event(20.0)]
        result = builder.build(events)
        assert result.events_in_window(100.0, 200.0) == []


class TestEventsBySource:
    def test_filters_by_source(self, builder):
        events = [
            make_event(1.0, source="auth.log"),
            make_event(2.0, source="syslog"),
            make_event(3.0, source="auth.log"),
        ]
        result = builder.build(events)
        filtered = result.events_by_source("auth.log")
        assert len(filtered) == 2
        assert all(e.source == "auth.log" for e in filtered)

    def test_no_match_returns_empty(self, builder):
        events = [make_event(1.0, source="auth.log")]
        result = builder.build(events)
        assert result.events_by_source("cloudtrail") == []


class TestEventsByType:
    def test_filters_by_event_type(self, builder):
        events = [
            make_event(1.0, event_type="auth_failure"),
            make_event(2.0, event_type="privilege_escalation"),
            make_event(3.0, event_type="auth_failure"),
        ]
        result = builder.build(events)
        filtered = result.events_by_type("auth_failure")
        assert len(filtered) == 2

    def test_no_match_returns_empty(self, builder):
        events = [make_event(1.0, event_type="auth_failure")]
        result = builder.build(events)
        assert result.events_by_type("dns_query") == []


# ---------------------------------------------------------------------------
# 8. Severity filters
# ---------------------------------------------------------------------------


class TestSeverityFilters:
    def test_critical_events_only_critical(self, builder):
        events = [
            make_event(1.0, severity="CRITICAL"),
            make_event(2.0, severity="HIGH"),
            make_event(3.0, severity="CRITICAL"),
            make_event(4.0, severity="INFO"),
        ]
        result = builder.build(events)
        assert len(result.critical_events) == 2
        assert all(e.severity_level == EventSeverity.CRITICAL for e in result.critical_events)

    def test_high_events_only_high(self, builder):
        events = [
            make_event(1.0, severity="HIGH"),
            make_event(2.0, severity="MEDIUM"),
            make_event(3.0, severity="HIGH"),
        ]
        result = builder.build(events)
        assert len(result.high_events) == 2
        assert all(e.severity_level == EventSeverity.HIGH for e in result.high_events)

    def test_no_critical_returns_empty_list(self, builder):
        events = [make_event(1.0, severity="LOW")]
        result = builder.build(events)
        assert result.critical_events == []


# ---------------------------------------------------------------------------
# 9. Duration
# ---------------------------------------------------------------------------


class TestDuration:
    def test_timeline_duration(self, builder):
        events = [make_event(1000.0), make_event(1600.0)]
        result = builder.build(events)
        assert result.duration_seconds == pytest.approx(600.0)

    def test_phase_duration_seconds(self, builder):
        events = [
            make_event(0.0),
            make_event(120.0),
            make_event(5000.0),
            make_event(5300.0),
        ]
        result = builder.build(events)
        assert result.phases[0].duration_seconds == pytest.approx(120.0)
        assert result.phases[1].duration_seconds == pytest.approx(300.0)


# ---------------------------------------------------------------------------
# 10. summary()
# ---------------------------------------------------------------------------


class TestSummary:
    def test_summary_contains_total_events(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert "5" in result.summary()

    def test_summary_contains_gap_count_label(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert "Silence gaps" in result.summary()

    def test_summary_contains_critical_label(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert "Critical events" in result.summary()

    def test_summary_is_string(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert isinstance(result.summary(), str)

    def test_summary_empty_timeline(self, builder):
        result = builder.build([])
        summary = result.summary()
        assert "0" in summary


# ---------------------------------------------------------------------------
# 11. to_dict()
# ---------------------------------------------------------------------------


class TestToDict:
    def test_returns_dict(self, builder, small_event_list):
        result = builder.build(small_event_list)
        assert isinstance(result.to_dict(), dict)

    def test_top_level_keys_present(self, builder, small_event_list):
        d = builder.build(small_event_list).to_dict()
        for key in (
            "incident_start", "incident_end", "duration_seconds",
            "total_events", "gap_count", "generated_at",
            "critical_event_count", "high_event_count",
            "phases", "events",
        ):
            assert key in d, f"Missing key: {key}"

    def test_events_is_list_of_dicts(self, builder, small_event_list):
        d = builder.build(small_event_list).to_dict()
        assert isinstance(d["events"], list)
        assert all(isinstance(e, dict) for e in d["events"])

    def test_phases_is_list_of_dicts(self, builder, small_event_list):
        d = builder.build(small_event_list).to_dict()
        assert isinstance(d["phases"], list)
        assert all(isinstance(p, dict) for p in d["phases"])

    def test_event_dict_has_required_keys(self, builder, small_event_list):
        d = builder.build(small_event_list).to_dict()
        event_dict = d["events"][0]
        for key in ("timestamp", "source", "event_type", "description", "severity"):
            assert key in event_dict

    def test_phase_dict_has_required_keys(self, builder, small_event_list):
        d = builder.build(small_event_list).to_dict()
        phase_dict = d["phases"][0]
        for key in ("name", "start_ts", "end_ts", "duration_seconds", "event_count"):
            assert key in phase_dict

    def test_event_count_matches(self, builder, small_event_list):
        result = builder.build(small_event_list)
        d = result.to_dict()
        assert d["total_events"] == len(small_event_list)

    def test_empty_timeline_to_dict(self, builder):
        d = builder.build([]).to_dict()
        assert d["total_events"] == 0
        assert d["events"] == []
        assert d["phases"] == []


# ---------------------------------------------------------------------------
# 12. Accumulation API
# ---------------------------------------------------------------------------


class TestAccumulationApi:
    def test_add_event_increments_accumulated(self, builder):
        builder.add_event(make_event(1.0))
        builder.add_event(make_event(2.0))
        result = builder.build_from_accumulated()
        assert result.total_events == 2

    def test_add_events_bulk(self, builder):
        events = [make_event(float(i)) for i in range(5)]
        builder.add_events(events)
        result = builder.build_from_accumulated()
        assert result.total_events == 5

    def test_reset_clears_buffer(self, builder):
        builder.add_event(make_event(1.0))
        builder.reset()
        result = builder.build_from_accumulated()
        assert result.total_events == 0

    def test_accumulated_events_not_cleared_after_build(self, builder):
        builder.add_event(make_event(1.0))
        builder.build_from_accumulated()
        # buffer still has the event
        result2 = builder.build_from_accumulated()
        assert result2.total_events == 1

    def test_add_event_then_add_events(self, builder):
        builder.add_event(make_event(1.0))
        builder.add_events([make_event(2.0), make_event(3.0)])
        result = builder.build_from_accumulated()
        assert result.total_events == 3

    def test_build_from_accumulated_independent_of_build(self, builder):
        """build() on a separate list should not affect accumulation buffer."""
        external = [make_event(100.0)]
        builder.build(external)
        builder.add_event(make_event(200.0))
        result = builder.build_from_accumulated()
        assert result.total_events == 1


# ---------------------------------------------------------------------------
# 13. severity_level property
# ---------------------------------------------------------------------------


class TestSeverityLevel:
    @pytest.mark.parametrize("sev_str,expected", [
        ("CRITICAL", EventSeverity.CRITICAL),
        ("HIGH", EventSeverity.HIGH),
        ("MEDIUM", EventSeverity.MEDIUM),
        ("LOW", EventSeverity.LOW),
        ("INFO", EventSeverity.INFO),
    ])
    def test_standard_severity_strings(self, sev_str, expected):
        ev = make_event(1.0, severity=sev_str)
        assert ev.severity_level == expected

    def test_lowercase_severity_maps_correctly(self):
        ev = make_event(1.0, severity="critical")
        assert ev.severity_level == EventSeverity.CRITICAL

    def test_mixed_case_severity(self):
        ev = make_event(1.0, severity="High")
        assert ev.severity_level == EventSeverity.HIGH

    def test_unknown_severity_defaults_to_info(self):
        ev = make_event(1.0, severity="BOGUS")
        assert ev.severity_level == EventSeverity.INFO

    def test_empty_severity_defaults_to_info(self):
        ev = make_event(1.0, severity="")
        assert ev.severity_level == EventSeverity.INFO

    def test_severity_level_used_in_critical_filter(self, builder):
        """Lowercase severity string should still be captured by critical_events."""
        ev = make_event(1.0, severity="critical")
        result = builder.build([ev])
        assert len(result.critical_events) == 1


# ---------------------------------------------------------------------------
# 14. TimelinePhase properties
# ---------------------------------------------------------------------------


class TestTimelinePhaseDirect:
    def test_event_count_property(self):
        phase = TimelinePhase(
            name="Phase 1",
            start_ts=0.0,
            end_ts=100.0,
            events=[make_event(float(i)) for i in range(7)],
        )
        assert phase.event_count == 7

    def test_duration_seconds_property(self):
        phase = TimelinePhase(name="Phase 1", start_ts=500.0, end_ts=800.0)
        assert phase.duration_seconds == pytest.approx(300.0)

    def test_phase_to_dict_events_key(self):
        phase = TimelinePhase(
            name="Phase 1",
            start_ts=0.0,
            end_ts=10.0,
            events=[make_event(5.0)],
        )
        d = phase.to_dict()
        assert "events" in d
        assert len(d["events"]) == 1


# ---------------------------------------------------------------------------
# 15. generated_at is recent
# ---------------------------------------------------------------------------


class TestGeneratedAt:
    def test_generated_at_is_recent(self, builder):
        before = time.time()
        result = builder.build([make_event(1.0)])
        after = time.time()
        assert before <= result.generated_at <= after
