"""
After-Action Report (AAR) Generator
=====================================
Generates structured after-action reports from closed incident data.
Scores the quality of the incident response process, identifies control
gaps, and tracks remediation commitments.

Check IDs
---------
AAR-001  Missing root cause          HIGH   weight=25
AAR-002  No detection timeline       MEDIUM weight=20
AAR-003  Response SLA breach         HIGH   weight=25
AAR-004  No remediation actions      HIGH   weight=25
AAR-005  Recurrence indicator        HIGH   weight=30
AAR-006  No lessons-learned          MEDIUM weight=20
AAR-007  Evidence gaps (P1/P2 only)  HIGH   weight=25

Response Quality Bands
-----------------------
EXCELLENT   risk_score == 0
GOOD        1  <= risk_score <= 19
ADEQUATE    20 <= risk_score <= 39
POOR        risk_score >= 40

Usage::

    from automations.after_action_report_generator import (
        ClosedIncident, generate_report, generate_reports, poor_quality_reports
    )

    incident = ClosedIncident(
        incident_id="INC-2024-001",
        severity="P1",
        title="Ransomware outbreak – finance subnet",
        opened_at_ms=1700000000000,
        contained_at_ms=1700010000000,
        closed_at_ms=1700020000000,
        root_cause="Phishing email triggered macro execution",
        detection_source="siem",
        detected_at_ms=1699999000000,
        remediation_actions=["Isolated affected hosts", "Reset all AD credentials"],
        lessons_learned=["Enforce macro disable policy across org", "Tune SIEM rules"],
        evidence_items=["disk-image-host-01.dd", "memory-dump-host-01.raw", "siem-export.json"],
        is_recurrence=False,
        similar_incident_ids=[],
    )
    report = generate_report(incident)
    print(report.response_quality, report.risk_score)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# SLA windows per severity (milliseconds)
# ---------------------------------------------------------------------------
_SLA_MS: Dict[str, int] = {
    "P1": 4 * 3_600_000,    # 4 h  = 14_400_000 ms
    "P2": 8 * 3_600_000,    # 8 h  = 28_800_000 ms
    "P3": 24 * 3_600_000,   # 24 h = 86_400_000 ms
    "P4": 72 * 3_600_000,   # 72 h = 259_200_000 ms
    "P5": 72 * 3_600_000,   # 72 h = 259_200_000 ms (same as P4)
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ClosedIncident:
    """Represents a closed incident record submitted for AAR evaluation."""

    incident_id: str
    severity: str                          # "P1" … "P5"
    title: str
    opened_at_ms: int                      # epoch milliseconds
    contained_at_ms: Optional[int]         # None if never contained
    closed_at_ms: Optional[int]

    root_cause: str = ""
    detection_source: str = ""             # "alert", "manual", "siem", etc.
    detected_at_ms: Optional[int] = None

    remediation_actions: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    evidence_items: List[str] = field(default_factory=list)

    is_recurrence: bool = False
    similar_incident_ids: List[str] = field(default_factory=list)


@dataclass
class AARCheck:
    """A single quality check that fired during AAR evaluation."""

    check_id: str
    severity: str    # "HIGH" or "MEDIUM"
    description: str
    evidence: str    # human-readable detail of what triggered the check
    weight: int


@dataclass
class AARReport:
    """Compiled after-action report for one closed incident."""

    incident_id: str
    checks_fired: List[AARCheck]
    risk_score: int           # min(100, sum of weights from fired checks)
    response_quality: str     # EXCELLENT / GOOD / ADEQUATE / POOR
    completeness_score: int   # max(0, 100 - risk_score)
    response_time_hours: Optional[float]  # hours from opened to contained; None if uncontained

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "incident_id": self.incident_id,
            "risk_score": self.risk_score,
            "response_quality": self.response_quality,
            "completeness_score": self.completeness_score,
            "response_time_hours": self.response_time_hours,
            "checks_fired": [
                {
                    "check_id": c.check_id,
                    "severity": c.severity,
                    "description": c.description,
                    "evidence": c.evidence,
                    "weight": c.weight,
                }
                for c in self.checks_fired
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the report."""
        fired_ids = ", ".join(c.check_id for c in self.checks_fired) or "none"
        rt = (
            f"{self.response_time_hours:.2f}h"
            if self.response_time_hours is not None
            else "uncontained"
        )
        return (
            f"[{self.incident_id}] quality={self.response_quality} "
            f"risk={self.risk_score} completeness={self.completeness_score} "
            f"response_time={rt} checks_fired=[{fired_ids}]"
        )

    def by_severity(self) -> Dict[str, List[AARCheck]]:
        """Return checks grouped by severity level (HIGH / MEDIUM)."""
        result: Dict[str, List[AARCheck]] = {"HIGH": [], "MEDIUM": []}
        for check in self.checks_fired:
            bucket = check.severity if check.severity in result else "MEDIUM"
            result[bucket].append(check)
        return result


# ---------------------------------------------------------------------------
# Internal check helpers
# ---------------------------------------------------------------------------

def _check_aar001(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-001: Missing root cause."""
    if not inc.root_cause or not inc.root_cause.strip():
        return AARCheck(
            check_id="AAR-001",
            severity="HIGH",
            description="Missing root cause",
            evidence=(
                "Incident has no documented root cause. "
                "A closed incident without root cause cannot drive systemic improvement."
            ),
            weight=25,
        )
    return None


def _check_aar002(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-002: No detection timeline — no automated detection source recorded."""
    source = inc.detection_source.lower().strip()
    # Fire when detection source is empty or 'manual' (no automated detection).
    if source in ("", "manual"):
        detail = (
            f"detection_source={repr(inc.detection_source)!s}. "
            "No automated detection source recorded; incident appears to have been manually reported."
        )
        return AARCheck(
            check_id="AAR-002",
            severity="MEDIUM",
            description="No detection timeline",
            evidence=detail,
            weight=20,
        )
    return None


def _check_aar003(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-003: Response SLA breach."""
    sla_ms = _SLA_MS.get(inc.severity.upper(), _SLA_MS["P5"])

    # Incident was never contained — treat as an infinite SLA breach.
    if inc.contained_at_ms is None:
        return AARCheck(
            check_id="AAR-003",
            severity="HIGH",
            description="Response SLA breach",
            evidence=(
                f"Incident was never contained (contained_at_ms is None). "
                f"SLA for {inc.severity} is {sla_ms // 3_600_000}h. Treated as infinite breach."
            ),
            weight=25,
        )

    response_ms = inc.contained_at_ms - inc.opened_at_ms
    if response_ms > sla_ms:
        actual_h = response_ms / 3_600_000
        sla_h = sla_ms / 3_600_000
        return AARCheck(
            check_id="AAR-003",
            severity="HIGH",
            description="Response SLA breach",
            evidence=(
                f"Response time {actual_h:.2f}h exceeded {inc.severity} SLA of {sla_h:.0f}h "
                f"(delta={actual_h - sla_h:.2f}h)."
            ),
            weight=25,
        )
    return None


def _check_aar004(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-004: No remediation actions."""
    if len(inc.remediation_actions) < 2:
        count = len(inc.remediation_actions)
        return AARCheck(
            check_id="AAR-004",
            severity="HIGH",
            description="No remediation actions",
            evidence=(
                f"Only {count} remediation action(s) recorded. "
                "A well-formed AAR requires at least 2 specific remediation steps."
            ),
            weight=25,
        )
    return None


def _check_aar005(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-005: Recurrence indicator."""
    is_recur = inc.is_recurrence
    has_similar = bool(inc.similar_incident_ids)
    if is_recur or has_similar:
        parts = []
        if is_recur:
            parts.append("is_recurrence=True")
        if has_similar:
            parts.append(f"similar_incident_ids={inc.similar_incident_ids}")
        detail = "; ".join(parts)
        return AARCheck(
            check_id="AAR-005",
            severity="HIGH",
            description="Recurrence indicator",
            evidence=(
                f"{detail}. Repeated incidents indicate persistent control gaps."
            ),
            weight=30,
        )
    return None


def _check_aar006(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-006: No lessons-learned."""
    lessons = inc.lessons_learned
    if not lessons:
        return AARCheck(
            check_id="AAR-006",
            severity="MEDIUM",
            description="No lessons-learned",
            evidence="lessons_learned list is empty. Generic or empty lessons do not drive improvement.",
            weight=20,
        )
    # All entries shorter than 20 characters (stripped).
    if all(len(entry.strip()) < 20 for entry in lessons):
        short_examples = [repr(e) for e in lessons[:3]]
        return AARCheck(
            check_id="AAR-006",
            severity="MEDIUM",
            description="No lessons-learned",
            evidence=(
                f"All {len(lessons)} lesson(s) are fewer than 20 characters "
                f"(e.g. {', '.join(short_examples)}). "
                "Entries are too generic to drive improvement."
            ),
            weight=20,
        )
    return None


def _check_aar007(inc: ClosedIncident) -> Optional[AARCheck]:
    """AAR-007: Evidence gaps (P1 / P2 only)."""
    if inc.severity.upper() not in ("P1", "P2"):
        return None  # Only applies to critical incidents.
    if len(inc.evidence_items) < 3:
        count = len(inc.evidence_items)
        return AARCheck(
            check_id="AAR-007",
            severity="HIGH",
            description="Evidence gaps",
            evidence=(
                f"Only {count} evidence item(s) recorded for a {inc.severity} incident. "
                "Critical incidents must have at least 3 documented evidence items."
            ),
            weight=25,
        )
    return None


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _compute_quality(risk_score: int) -> str:
    """Map a numeric risk score to a response quality band."""
    if risk_score == 0:
        return "EXCELLENT"
    if risk_score <= 19:
        return "GOOD"
    if risk_score <= 39:
        return "ADEQUATE"
    return "POOR"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(incident: ClosedIncident) -> AARReport:
    """
    Run all AAR checks against a single closed incident and return the report.

    Parameters
    ----------
    incident:
        A fully-populated :class:`ClosedIncident` record.

    Returns
    -------
    AARReport
        Compiled quality report with risk score, quality band, and check details.
    """
    # Run each check in order; collect only the ones that fired.
    checkers = [
        _check_aar001,
        _check_aar002,
        _check_aar003,
        _check_aar004,
        _check_aar005,
        _check_aar006,
        _check_aar007,
    ]
    checks_fired: List[AARCheck] = []
    for checker in checkers:
        result = checker(incident)
        if result is not None:
            checks_fired.append(result)

    # Aggregate risk score (capped at 100).
    raw_score = sum(c.weight for c in checks_fired)
    risk_score = min(100, raw_score)

    response_quality = _compute_quality(risk_score)
    completeness_score = max(0, 100 - risk_score)

    # Response time in hours (only when containment timestamp is available).
    if incident.contained_at_ms is not None:
        response_time_hours: Optional[float] = (
            (incident.contained_at_ms - incident.opened_at_ms) / 3_600_000
        )
    else:
        response_time_hours = None

    return AARReport(
        incident_id=incident.incident_id,
        checks_fired=checks_fired,
        risk_score=risk_score,
        response_quality=response_quality,
        completeness_score=completeness_score,
        response_time_hours=response_time_hours,
    )


def generate_reports(incidents: List[ClosedIncident]) -> List[AARReport]:
    """
    Generate AAR reports for a list of closed incidents.

    Parameters
    ----------
    incidents:
        Collection of :class:`ClosedIncident` records.

    Returns
    -------
    List[AARReport]
        One report per incident, in the same order as the input list.
    """
    return [generate_report(inc) for inc in incidents]


def poor_quality_reports(reports: List[AARReport]) -> List[AARReport]:
    """
    Return reports whose response_quality is POOR, sorted by risk_score descending.

    Parameters
    ----------
    reports:
        List of :class:`AARReport` objects to filter.

    Returns
    -------
    List[AARReport]
        Only POOR-quality reports, highest risk score first.
    """
    poor = [r for r in reports if r.response_quality == "POOR"]
    poor.sort(key=lambda r: r.risk_score, reverse=True)
    return poor
