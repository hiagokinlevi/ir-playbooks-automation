"""
Incident Response SLA Tracker
================================
Tracks SLA compliance for incident response timelines. Computes time-to-detect,
time-to-respond, and time-to-resolve against configurable SLA tiers and
generates breach reports with escalation recommendations.

SLA Status Values
-----------------
ON_TRACK    Within all SLA time windows
WARNING     Within 80% of a time window (approaching breach)
BREACHED    Exceeded a time window
CRITICAL_BREACH  Exceeded time window by > 2x

Usage::

    from automations.sla_tracker import SLATracker, Incident

    incident = Incident(
        incident_id="INC-001",
        severity="P1",
        detected_at=1700000000.0,
        responded_at=1700001200.0,  # 20 min
        resolved_at=None,            # not yet resolved
        reference_time=1700010000.0, # "now" for SLA calc
    )
    tracker = SLATracker()
    result = tracker.evaluate(incident)
    print(result.overall_status, result.sla_score)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# SLA status enum
# ---------------------------------------------------------------------------

class SLAStatus(Enum):
    """Enumeration of all possible SLA compliance states for a time window."""

    ON_TRACK = "ON_TRACK"             # well within the time window
    WARNING = "WARNING"               # approaching the boundary (>= warning_pct)
    BREACHED = "BREACHED"             # exceeded the SLA window
    CRITICAL_BREACH = "CRITICAL_BREACH"  # exceeded by more than 2x the SLA window


# ---------------------------------------------------------------------------
# Default SLA tier definitions (seconds per phase)
# ---------------------------------------------------------------------------

_DEFAULT_SLA_TIERS: Dict[str, Dict[str, int]] = {
    "P1": {"detect": 300,   "respond": 900,    "resolve": 14400},    # 5m / 15m / 4h
    "P2": {"detect": 900,   "respond": 3600,   "resolve": 86400},    # 15m / 1h / 24h
    "P3": {"detect": 3600,  "respond": 14400,  "resolve": 259200},   # 1h / 4h / 3d
    "P4": {"detect": 14400, "respond": 86400,  "resolve": 604800},   # 4h / 24h / 7d
    "P5": {"detect": 86400, "respond": 259200, "resolve": 2592000},  # 24h / 3d / 30d
}

# Severity weights used in escalation copy — ordered worst-first for lookup
_SEVERITY_LABELS: Dict[str, str] = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
    "P5": "Informational",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """
    Represents a single incident under SLA evaluation.

    Attributes
    ----------
    incident_id:
        Unique identifier for the incident (e.g. "INC-2024-001").
    severity:
        Severity tier string: P1–P5 (case-insensitive). Unknown values fall
        back to P3.
    detected_at:
        Unix timestamp when the incident was first detected. ``None`` means
        detection has not yet been recorded.
    responded_at:
        Unix timestamp when an analyst first acknowledged / responded.
        ``None`` means response has not yet been recorded.
    resolved_at:
        Unix timestamp when the incident was fully resolved. ``None`` means
        resolution is still pending.
    created_at:
        Unix timestamp when the incident was created / opened in the system.
        Defaults to the current wall-clock time at object creation.
    reference_time:
        Optional "now" timestamp used for elapsed-time calculations during
        evaluation. If ``None``, ``time.time()`` is used at evaluation time.
    title:
        Human-readable title / short description of the incident.
    tags:
        Arbitrary string labels for filtering and reporting.
    """

    incident_id: str
    severity: str
    detected_at: Optional[float] = None
    responded_at: Optional[float] = None
    resolved_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    reference_time: Optional[float] = None
    title: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class SLAWindow:
    """
    Represents the SLA compliance result for a single time phase
    (detect, respond, or resolve).

    Attributes
    ----------
    name:
        Phase label — one of ``"detect"``, ``"respond"``, ``"resolve"``.
    actual_seconds:
        Measured elapsed seconds for this phase. ``None`` when data is not
        yet available.
    sla_seconds:
        Contracted SLA budget in seconds for this phase.
    status:
        Compliance status computed from the ratio of actual / sla.
    breach_seconds:
        How many seconds past the SLA deadline this phase is (0 if on-track).
    breach_percent:
        ``actual / sla * 100``; > 100 means the SLA has been exceeded.
    """

    name: str
    actual_seconds: Optional[float]
    sla_seconds: int
    status: SLAStatus
    breach_seconds: float = 0.0
    breach_percent: float = 0.0

    def to_dict(self) -> Dict:
        """Serialise the window to a plain dictionary (status as string value)."""
        return {
            "name": self.name,
            "actual_seconds": self.actual_seconds,
            "sla_seconds": self.sla_seconds,
            "status": self.status.value,          # string, not enum member
            "breach_seconds": self.breach_seconds,
            "breach_percent": round(self.breach_percent, 2),
        }


@dataclass
class SLAResult:
    """
    Aggregated SLA evaluation result for one incident.

    Attributes
    ----------
    incident_id:
        Identifier of the evaluated incident.
    severity:
        Severity tier of the incident as provided (original case).
    overall_status:
        Worst ``SLAStatus`` across all evaluated windows.
    sla_score:
        Integer 0-100 compliance score. 100 = fully compliant; decrements
        for WARNING, BREACHED, and CRITICAL_BREACH windows.
    windows:
        Ordered list of ``SLAWindow`` objects (detect → respond → resolve).
    breached_windows:
        Names of windows whose status is BREACHED or CRITICAL_BREACH.
    escalation_message:
        Human-readable escalation recommendation derived from overall_status.
    generated_at:
        Unix timestamp when this result was produced.
    """

    incident_id: str
    severity: str
    overall_status: SLAStatus
    sla_score: int
    windows: List[SLAWindow]
    breached_windows: List[str]
    escalation_message: str
    generated_at: float

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def is_breached(self) -> bool:
        """Return ``True`` when any window has a breach or critical-breach status."""
        breach_states = {SLAStatus.BREACHED, SLAStatus.CRITICAL_BREACH}
        return any(w.status in breach_states for w in self.windows)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Serialise result to a plain dictionary suitable for JSON output."""
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "overall_status": self.overall_status.value,   # string, not enum member
            "sla_score": self.sla_score,
            "windows": [w.to_dict() for w in self.windows],
            "breached_windows": self.breached_windows,
            "escalation_message": self.escalation_message,
            "generated_at": self.generated_at,
            "is_breached": self.is_breached,
        }

    def summary(self) -> str:
        """Return a single-line summary string for logging or quick display."""
        return (
            f"{self.incident_id} [{self.severity}] "
            f"{self.overall_status.value} score={self.sla_score}"
        )


# ---------------------------------------------------------------------------
# Core tracker
# ---------------------------------------------------------------------------

class SLATracker:
    """
    Evaluates one or many incidents against configurable SLA tiers.

    Parameters
    ----------
    sla_tiers:
        Mapping of severity string → phase budgets (seconds). When ``None``
        the module-level ``_DEFAULT_SLA_TIERS`` is used.
    warning_pct:
        Fraction (0–1) of the SLA budget at which a window transitions from
        ON_TRACK to WARNING. Default is ``0.8`` (80 %).
    """

    def __init__(
        self,
        sla_tiers: Optional[Dict[str, Dict[str, int]]] = None,
        warning_pct: float = 0.8,
    ) -> None:
        # Use a shallow copy so external mutations do not affect the tracker
        self.sla_tiers: Dict[str, Dict[str, int]] = (
            dict(sla_tiers) if sla_tiers is not None else dict(_DEFAULT_SLA_TIERS)
        )
        self.warning_pct = warning_pct

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_tier(self, severity: str) -> Dict[str, int]:
        """
        Look up the SLA tier for *severity* (case-insensitive).
        Falls back to P3 when the severity string is not recognised.
        """
        normalised = severity.upper()
        if normalised in self.sla_tiers:
            return self.sla_tiers[normalised]
        # Unknown severity — default to P3 (medium) as a safe fallback
        return self.sla_tiers.get("P3", _DEFAULT_SLA_TIERS["P3"])

    def _classify(
        self,
        actual: Optional[float],
        sla: int,
    ) -> SLAStatus:
        """
        Classify a single phase measurement against its SLA budget.

        Rules (evaluated top-to-bottom):
        1. No data yet  → ON_TRACK (no breach possible without evidence)
        2. actual > sla * 2  → CRITICAL_BREACH
        3. actual > sla      → BREACHED
        4. actual >= sla * warning_pct → WARNING
        5. else              → ON_TRACK
        """
        if actual is None:
            return SLAStatus.ON_TRACK

        if actual > sla * 2:
            return SLAStatus.CRITICAL_BREACH
        if actual > sla:
            return SLAStatus.BREACHED
        if actual >= sla * self.warning_pct:
            return SLAStatus.WARNING
        return SLAStatus.ON_TRACK

    @staticmethod
    def _worst_status(statuses: List[SLAStatus]) -> SLAStatus:
        """Return the most severe status from *statuses*."""
        # Priority order (highest index = worst)
        priority = [
            SLAStatus.ON_TRACK,
            SLAStatus.WARNING,
            SLAStatus.BREACHED,
            SLAStatus.CRITICAL_BREACH,
        ]
        worst = SLAStatus.ON_TRACK
        for s in statuses:
            if priority.index(s) > priority.index(worst):
                worst = s
        return worst

    @staticmethod
    def _compute_score(windows: List[SLAWindow]) -> int:
        """
        Compute a 0-100 compliance score.

        Penalties:
        - CRITICAL_BREACH : −40 per window
        - BREACHED         : −25 per window
        - WARNING          : −10 per window

        Result is clamped to [0, 100].
        """
        score = 100
        for w in windows:
            if w.status == SLAStatus.CRITICAL_BREACH:
                score -= 40
            elif w.status == SLAStatus.BREACHED:
                score -= 25
            elif w.status == SLAStatus.WARNING:
                score -= 10
        return max(0, min(100, score))

    def _build_escalation_message(
        self,
        incident: Incident,
        overall: SLAStatus,
        breached_windows: List[str],
        windows: List[SLAWindow],
    ) -> str:
        """
        Produce a human-readable escalation recommendation based on the
        worst observed status.
        """
        iid = incident.incident_id
        sev = incident.severity.upper()
        label = _SEVERITY_LABELS.get(sev, sev)

        if overall == SLAStatus.CRITICAL_BREACH:
            phases = ", ".join(breached_windows)
            return (
                f"ESCALATE IMMEDIATELY: Incident {iid} ({label}) has critically "
                f"breached SLA on phase(s): {phases}. Immediate escalation to "
                f"senior responders and management required."
            )

        if overall == SLAStatus.BREACHED:
            phases = ", ".join(breached_windows)
            return (
                f"SLA BREACHED: Incident {iid} ({label}) has exceeded SLA on "
                f"phase(s): {phases}. Escalate to team lead and update stakeholders."
            )

        if overall == SLAStatus.WARNING:
            # List all warning window names for actionable guidance
            warning_names = [
                w.name for w in windows if w.status == SLAStatus.WARNING
            ]
            phases = ", ".join(warning_names)
            return (
                f"SLA WARNING: Incident {iid} ({label}) is approaching breach "
                f"on phase(s): {phases}. Prioritise response to avoid SLA breach."
            )

        return "All SLAs on track."

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, incident: Incident) -> SLAResult:
        """
        Evaluate a single incident against its SLA tier.

        Parameters
        ----------
        incident:
            The incident to evaluate.

        Returns
        -------
        SLAResult
            Fully populated evaluation result including per-window status,
            overall status, compliance score, and escalation message.
        """
        # Determine the "now" reference point for elapsed-time calculations
        ref = incident.reference_time if incident.reference_time is not None else time.time()

        # Resolve tier (case-insensitive, with P3 fallback)
        tier = self._resolve_tier(incident.severity)

        # Derive the anchor timestamp — detection is preferred; otherwise creation
        detection_anchor = (
            incident.detected_at
            if incident.detected_at is not None
            else incident.created_at
        )

        # ---- Phase 1: detect ----------------------------------------
        # Measures how long it took to detect the incident from creation.
        detect_actual: Optional[float] = None
        if incident.detected_at is not None:
            detect_actual = incident.detected_at - incident.created_at

        detect_sla = tier["detect"]
        detect_status = self._classify(detect_actual, detect_sla)
        detect_window = SLAWindow(
            name="detect",
            actual_seconds=detect_actual,
            sla_seconds=detect_sla,
            status=detect_status,
            breach_seconds=max(0.0, (detect_actual - detect_sla) if detect_actual is not None else 0.0),
            breach_percent=(detect_actual / detect_sla * 100) if (detect_actual is not None and detect_sla > 0) else 0.0,
        )

        # ---- Phase 2: respond ----------------------------------------
        # Measures time from detection (or creation if not detected) to response.
        respond_actual: Optional[float] = None
        if incident.responded_at is not None:
            respond_actual = incident.responded_at - detection_anchor

        respond_sla = tier["respond"]
        respond_status = self._classify(respond_actual, respond_sla)
        respond_window = SLAWindow(
            name="respond",
            actual_seconds=respond_actual,
            sla_seconds=respond_sla,
            status=respond_status,
            breach_seconds=max(0.0, (respond_actual - respond_sla) if respond_actual is not None else 0.0),
            breach_percent=(respond_actual / respond_sla * 100) if (respond_actual is not None and respond_sla > 0) else 0.0,
        )

        # ---- Phase 3: resolve ----------------------------------------
        # Measures time from detection (or creation) to resolution.
        # When unresolved, the elapsed time so far is used as the actual value
        # so that approaching breaches can be surfaced proactively.
        resolve_actual: Optional[float] = None
        if incident.resolved_at is not None:
            resolve_actual = incident.resolved_at - detection_anchor
        elif incident.reference_time is not None:
            # Only project elapsed time when a reference_time was explicitly
            # provided; avoids noisy warnings for very new incidents evaluated
            # without a fixed reference point.
            resolve_actual = ref - detection_anchor

        resolve_sla = tier["resolve"]
        resolve_status = self._classify(resolve_actual, resolve_sla)
        resolve_window = SLAWindow(
            name="resolve",
            actual_seconds=resolve_actual,
            sla_seconds=resolve_sla,
            status=resolve_status,
            breach_seconds=max(0.0, (resolve_actual - resolve_sla) if resolve_actual is not None else 0.0),
            breach_percent=(resolve_actual / resolve_sla * 100) if (resolve_actual is not None and resolve_sla > 0) else 0.0,
        )

        # ---- Aggregate -----------------------------------------------
        windows = [detect_window, respond_window, resolve_window]
        overall = self._worst_status([w.status for w in windows])
        score = self._compute_score(windows)

        breach_states = {SLAStatus.BREACHED, SLAStatus.CRITICAL_BREACH}
        breached_windows = [w.name for w in windows if w.status in breach_states]

        escalation = self._build_escalation_message(
            incident, overall, breached_windows, windows
        )

        return SLAResult(
            incident_id=incident.incident_id,
            severity=incident.severity,
            overall_status=overall,
            sla_score=score,
            windows=windows,
            breached_windows=breached_windows,
            escalation_message=escalation,
            generated_at=time.time(),
        )

    def evaluate_many(self, incidents: List[Incident]) -> List[SLAResult]:
        """
        Evaluate a list of incidents and return results sorted by SLA score
        ascending — the most at-risk incidents appear first.

        Parameters
        ----------
        incidents:
            Collection of incidents to evaluate.

        Returns
        -------
        List[SLAResult]
            Sorted results, worst compliance first.
        """
        results = [self.evaluate(inc) for inc in incidents]
        return sorted(results, key=lambda r: r.sla_score)

    def summary_report(self, results: List[SLAResult]) -> Dict:
        """
        Produce a high-level aggregation report across a list of results.

        Parameters
        ----------
        results:
            Previously evaluated ``SLAResult`` objects.

        Returns
        -------
        dict
            Contains counts by status and the average SLA score:
            ``total``, ``on_track``, ``warning``, ``breached``,
            ``critical_breach``, ``average_sla_score``.
        """
        total = len(results)
        on_track = sum(1 for r in results if r.overall_status == SLAStatus.ON_TRACK)
        warning = sum(1 for r in results if r.overall_status == SLAStatus.WARNING)
        breached = sum(1 for r in results if r.overall_status == SLAStatus.BREACHED)
        critical_breach = sum(1 for r in results if r.overall_status == SLAStatus.CRITICAL_BREACH)

        avg_score: float = (
            sum(r.sla_score for r in results) / total if total > 0 else 0.0
        )

        return {
            "total": total,
            "on_track": on_track,
            "warning": warning,
            "breached": breached,
            "critical_breach": critical_breach,
            "average_sla_score": round(avg_score, 2),
        }
