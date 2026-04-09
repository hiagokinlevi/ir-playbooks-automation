"""Unit tests for SLA tracking module."""
from datetime import datetime, timedelta, timezone

import pytest

from schemas.incident import IncidentRecord, SeverityLevel, IncidentStatus, IncidentType
from schemas.sla import (
    DEFAULT_SLA_HOURS,
    SlaStatus,
    check_portfolio_sla,
    evaluate_sla,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _record(
    severity: SeverityLevel = SeverityLevel.HIGH,
    hours_elapsed: float = 0.0,
    contained: bool = False,
    incident_id: str = "INC-20260101-001",
) -> IncidentRecord:
    detected = _BASE_TIME
    now = detected + timedelta(hours=hours_elapsed)
    r = IncidentRecord(
        incident_id=incident_id,
        title="Test incident for SLA evaluation",
        severity=severity,
        incident_type=IncidentType.GENERIC,
        detected_at=detected,
    )
    if contained:
        r.contained_at = now
    return r, now


# ---------------------------------------------------------------------------
# Basic evaluation
# ---------------------------------------------------------------------------


def test_no_breach_within_window():
    r, now = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=12.0)
    status = evaluate_sla(r, now=now)
    assert not status.is_breached
    assert status.remaining_hours == pytest.approx(12.0, abs=0.01)
    assert status.sla_hours == DEFAULT_SLA_HOURS[SeverityLevel.CRITICAL]


def test_breach_past_deadline():
    r, now = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=30.0)
    status = evaluate_sla(r, now=now)
    assert status.is_breached
    assert status.overdue_hours == pytest.approx(6.0, abs=0.01)


def test_exactly_at_deadline_not_breached():
    threshold = DEFAULT_SLA_HOURS[SeverityLevel.HIGH]
    r, now = _record(severity=SeverityLevel.HIGH, hours_elapsed=threshold)
    status = evaluate_sla(r, now=now)
    # At exactly the threshold remaining == 0, not breached
    assert not status.is_breached
    assert status.remaining_hours == pytest.approx(0.0, abs=0.01)


def test_warning_zone():
    # Within 20% of the threshold → is_warning = True
    threshold = DEFAULT_SLA_HOURS[SeverityLevel.HIGH]
    # 85% elapsed = 15% remaining < 20% → warning
    r, now = _record(severity=SeverityLevel.HIGH, hours_elapsed=threshold * 0.85)
    status = evaluate_sla(r, now=now)
    assert status.is_warning
    assert not status.is_breached


def test_not_warning_zone_far_from_deadline():
    threshold = DEFAULT_SLA_HOURS[SeverityLevel.HIGH]
    # Only 10% elapsed = 90% remaining → no warning
    r, now = _record(severity=SeverityLevel.HIGH, hours_elapsed=threshold * 0.10)
    status = evaluate_sla(r, now=now)
    assert not status.is_warning
    assert not status.is_breached


# ---------------------------------------------------------------------------
# No severity
# ---------------------------------------------------------------------------


def test_no_severity_returns_no_threshold():
    r = IncidentRecord(
        incident_id="INC-20260101-002",
        title="Unclassified incident",
        severity=None,
        incident_type=IncidentType.GENERIC,
        detected_at=_BASE_TIME,
    )
    status = evaluate_sla(r, now=_BASE_TIME + timedelta(hours=5))
    assert status.sla_hours is None
    assert not status.is_breached
    assert status.measurement_basis == "no_severity"


# ---------------------------------------------------------------------------
# Containment time vs ongoing
# ---------------------------------------------------------------------------


def test_contained_incident_uses_containment_time():
    threshold = DEFAULT_SLA_HOURS[SeverityLevel.CRITICAL]
    r, contained_at = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=20.0, contained=True)
    # "now" is 50 hours after detection — but containment was at 20h
    future_now = _BASE_TIME + timedelta(hours=50)
    status = evaluate_sla(r, now=future_now)
    # elapsed should be based on contained_at (20h), not now (50h)
    assert status.elapsed_hours == pytest.approx(20.0, abs=0.01)
    assert not status.is_breached


def test_percent_used_calculation():
    threshold = DEFAULT_SLA_HOURS[SeverityLevel.CRITICAL]  # 24h
    r, now = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=6.0)
    status = evaluate_sla(r, now=now)
    assert status.percent_used == pytest.approx(25.0, abs=0.1)


# ---------------------------------------------------------------------------
# Portfolio evaluation
# ---------------------------------------------------------------------------


def test_portfolio_sorted_by_urgency():
    r1, _ = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=23.0, incident_id="INC-20260101-001")
    r2, _ = _record(severity=SeverityLevel.HIGH, hours_elapsed=10.0, incident_id="INC-20260101-002")
    r3, _ = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=5.0, incident_id="INC-20260101-003")

    now = _BASE_TIME + timedelta(hours=23)
    statuses = check_portfolio_sla([r1, r2, r3], now=now)

    # INC-001 critical with 23h elapsed → 1h remaining → most urgent first
    assert statuses[0].incident_id == "INC-20260101-001"


def test_portfolio_breached_comes_first():
    r_breached, _ = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=30.0, incident_id="INC-20260101-001")
    r_ok, _ = _record(severity=SeverityLevel.HIGH, hours_elapsed=1.0, incident_id="INC-20260101-002")

    now = _BASE_TIME + timedelta(hours=30)
    statuses = check_portfolio_sla([r_ok, r_breached], now=now)
    assert statuses[0].incident_id == "INC-20260101-001"
    assert statuses[0].is_breached


# ---------------------------------------------------------------------------
# Custom SLA thresholds
# ---------------------------------------------------------------------------


def test_custom_sla_thresholds():
    custom = {SeverityLevel.CRITICAL: 2.0}  # 2-hour SLA for testing
    r, now = _record(severity=SeverityLevel.CRITICAL, hours_elapsed=3.0)
    status = evaluate_sla(r, sla_hours=custom, now=now)
    assert status.is_breached
    assert status.sla_hours == 2.0
    assert status.overdue_hours == pytest.approx(1.0, abs=0.01)
