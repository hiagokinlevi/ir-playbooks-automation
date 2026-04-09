"""
SLA (Service Level Agreement) tracking for incident response.

Defines SLA tiers per severity and detects breaches in real time.
All times in hours.

SLA tiers (k1N default, configurable):
  Critical  → 24 h to containment
  High      → 7 d (168 h) to containment
  Medium    → 30 d (720 h) to containment
  Low       → 90 d (2160 h) to containment

Usage:
    from schemas.incident import IncidentRecord, SeverityLevel
    from schemas.sla import evaluate_sla, SlaStatus

    status = evaluate_sla(record)
    if status.is_breached:
        print(f"SLA BREACHED by {status.overdue_hours:.1f} hours")
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from schemas.incident import IncidentRecord, IncidentStatus, SeverityLevel


# ---------------------------------------------------------------------------
# Default SLA thresholds (hours to containment for each severity)
# ---------------------------------------------------------------------------

DEFAULT_SLA_HOURS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 24.0,    # 1 day
    SeverityLevel.HIGH: 168.0,       # 7 days
    SeverityLevel.MEDIUM: 720.0,     # 30 days
    SeverityLevel.LOW: 2160.0,       # 90 days
}


@dataclass(frozen=True)
class SlaStatus:
    """Result of an SLA evaluation for a single incident."""

    incident_id: str
    severity: Optional[SeverityLevel]
    sla_hours: Optional[float]          # Threshold in hours; None if severity not set
    elapsed_hours: float                 # Time since detection to now (or containment)
    remaining_hours: Optional[float]    # Positive = time left; negative = overdue
    is_breached: bool
    is_warning: bool                     # True if within 20% of threshold
    measurement_basis: str              # "time_to_containment" | "time_to_detection" | "no_severity"
    contained_at: Optional[datetime]

    @property
    def overdue_hours(self) -> float:
        """Hours past the SLA deadline; 0 if not breached."""
        if self.remaining_hours is None or self.remaining_hours >= 0:
            return 0.0
        return abs(self.remaining_hours)

    @property
    def percent_used(self) -> Optional[float]:
        """Percentage of the SLA window consumed (can exceed 100% if breached)."""
        if self.sla_hours is None or self.sla_hours == 0:
            return None
        return round((self.elapsed_hours / self.sla_hours) * 100, 1)


def evaluate_sla(
    record: IncidentRecord,
    sla_hours: Optional[dict[SeverityLevel, float]] = None,
    now: Optional[datetime] = None,
) -> SlaStatus:
    """
    Evaluate the SLA status of an incident record.

    Args:
        record:    The incident to evaluate.
        sla_hours: Override the default SLA thresholds (mapping SeverityLevel → hours).
                   If None, DEFAULT_SLA_HOURS is used.
        now:       Override the current timestamp (useful for testing).

    Returns:
        SlaStatus with breach/warning flags and timing details.
    """
    thresholds = sla_hours if sla_hours is not None else DEFAULT_SLA_HOURS
    current_time = now or datetime.now(timezone.utc)

    # Determine the endpoint for elapsed time:
    # - Use contained_at if available (captures actual response time)
    # - Otherwise measure up to now
    endpoint = record.contained_at or current_time
    elapsed_seconds = (endpoint - record.detected_at).total_seconds()
    elapsed_hours = max(0.0, elapsed_seconds / 3600)

    # If no severity is set, we cannot evaluate against a threshold
    if record.severity is None:
        return SlaStatus(
            incident_id=record.incident_id,
            severity=None,
            sla_hours=None,
            elapsed_hours=elapsed_hours,
            remaining_hours=None,
            is_breached=False,
            is_warning=False,
            measurement_basis="no_severity",
            contained_at=record.contained_at,
        )

    threshold = thresholds.get(record.severity)
    if threshold is None:
        return SlaStatus(
            incident_id=record.incident_id,
            severity=record.severity,
            sla_hours=None,
            elapsed_hours=elapsed_hours,
            remaining_hours=None,
            is_breached=False,
            is_warning=False,
            measurement_basis="no_threshold_configured",
            contained_at=record.contained_at,
        )

    remaining_hours = threshold - elapsed_hours
    is_breached = remaining_hours < 0
    # Warning zone: within 20% of the SLA threshold remaining
    warning_threshold = threshold * 0.20
    is_warning = not is_breached and remaining_hours <= warning_threshold

    basis = "time_to_containment" if record.contained_at else "time_to_detection_ongoing"

    return SlaStatus(
        incident_id=record.incident_id,
        severity=record.severity,
        sla_hours=threshold,
        elapsed_hours=round(elapsed_hours, 2),
        remaining_hours=round(remaining_hours, 2),
        is_breached=is_breached,
        is_warning=is_warning,
        measurement_basis=basis,
        contained_at=record.contained_at,
    )


def check_portfolio_sla(
    records: list[IncidentRecord],
    sla_hours: Optional[dict[SeverityLevel, float]] = None,
    now: Optional[datetime] = None,
) -> list[SlaStatus]:
    """
    Evaluate SLA status for a list of open incidents.

    Closed incidents are included for historical reporting (their elapsed time
    is measured up to contained_at, not now).

    Args:
        records:   List of IncidentRecord objects to evaluate.
        sla_hours: Override SLA thresholds (same as evaluate_sla).
        now:       Override current timestamp (useful for testing).

    Returns:
        List of SlaStatus objects, sorted by remaining_hours ascending
        (most at-risk incidents first; breached incidents at top).
    """
    statuses = [evaluate_sla(r, sla_hours=sla_hours, now=now) for r in records]

    def _sort_key(s: SlaStatus) -> float:
        # Breached → most negative remaining first
        # Active → least remaining first
        # No threshold → last
        if s.remaining_hours is None:
            return float("inf")
        return s.remaining_hours

    return sorted(statuses, key=_sort_key)
