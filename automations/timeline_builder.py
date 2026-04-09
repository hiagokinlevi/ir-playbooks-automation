"""
Incident Response Timeline Builder
=====================================
Assembles a chronological incident timeline from heterogeneous event sources:
auth logs, system logs, cloud API events, network events, and custom entries.
Classifies event significance, detects time gaps, and generates narrative
summaries for each phase of an incident.

Operates on structured TimelineEvent inputs — no live system access required.

Usage::

    from automations.timeline_builder import TimelineBuilder, TimelineEvent

    events = [
        TimelineEvent(
            timestamp=1700000000.0,
            source="auth.log",
            event_type="auth_failure",
            description="SSH authentication failure for root from 203.0.113.5",
            severity="HIGH",
            actor="root",
            source_ip="203.0.113.5",
        ),
    ]
    builder = TimelineBuilder()
    timeline = builder.build(events)
    print(timeline.summary())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EventSeverity(Enum):
    """Canonical severity levels for incident timeline events."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class TimelineEvent:
    """A single event observed during an incident.

    Attributes:
        timestamp:   Unix epoch float when the event occurred.
        source:      Log source or system that produced the event
                     (e.g. "auth.log", "cloudtrail", "network").
        event_type:  Short machine-readable type label
                     (e.g. "auth_failure", "privilege_escalation").
        description: Human-readable description of what happened.
        severity:    Severity string — must map to an EventSeverity member.
                     Defaults to "INFO".
        actor:       Identity (user, service account, process) that performed
                     the action.  Empty string if unknown.
        source_ip:   Originating IP address.  Empty string if not applicable.
        target:      Affected resource (host, bucket, service, etc.).
                     Empty string if unknown.
        tags:        Arbitrary labels useful for grouping or filtering.
        raw:         Original raw log line or JSON blob for forensic reference.
    """

    timestamp: float
    source: str
    event_type: str
    description: str
    severity: str = "INFO"
    actor: str = ""
    source_ip: str = ""
    target: str = ""
    tags: List[str] = field(default_factory=list)
    raw: str = ""

    @property
    def severity_level(self) -> EventSeverity:
        """Return the EventSeverity member that corresponds to self.severity.

        The lookup is case-insensitive.  Any unrecognised string defaults to
        EventSeverity.INFO rather than raising so that malformed log data does
        not crash the builder.
        """
        try:
            return EventSeverity[self.severity.upper()]
        except KeyError:
            return EventSeverity.INFO

    def to_dict(self) -> Dict:
        """Serialise the event to a plain dictionary."""
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "target": self.target,
            "tags": list(self.tags),
            "raw": self.raw,
        }


@dataclass
class TimelinePhase:
    """A contiguous block of events that form a logical phase of the incident.

    Phases are separated by silence gaps longer than
    ``TimelineBuilder.gap_threshold_seconds``.

    Attributes:
        name:        Human-readable label, e.g. "Phase 1 (source: auth.log)".
        start_ts:    Unix epoch of the first event in this phase.
        end_ts:      Unix epoch of the last event in this phase.
        events:      Ordered list of events belonging to this phase.
        description: Optional narrative description.
    """

    name: str
    start_ts: float
    end_ts: float
    events: List[TimelineEvent] = field(default_factory=list)
    description: str = ""

    @property
    def duration_seconds(self) -> float:
        """Return the wall-clock span of this phase in seconds."""
        return self.end_ts - self.start_ts

    @property
    def event_count(self) -> int:
        """Return the number of events in this phase."""
        return len(self.events)

    def to_dict(self) -> Dict:
        """Serialise the phase to a plain dictionary."""
        return {
            "name": self.name,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration_seconds": self.duration_seconds,
            "event_count": self.event_count,
            "description": self.description,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class IncidentTimeline:
    """The assembled result of a timeline build operation.

    Attributes:
        events:         All events in chronological order.
        phases:         Detected phases, each a contiguous cluster of events.
        incident_start: Timestamp of the earliest event (0.0 if no events).
        incident_end:   Timestamp of the latest event (0.0 if no events).
        gap_count:      Number of silence gaps detected between consecutive
                        events.
        generated_at:   Unix epoch when this timeline object was created.
    """

    events: List[TimelineEvent] = field(default_factory=list)
    phases: List[TimelinePhase] = field(default_factory=list)
    incident_start: float = 0.0
    incident_end: float = 0.0
    gap_count: int = 0
    generated_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def duration_seconds(self) -> float:
        """Total span from first to last event in seconds."""
        return self.incident_end - self.incident_start

    @property
    def total_events(self) -> int:
        """Count of all events in this timeline."""
        return len(self.events)

    @property
    def critical_events(self) -> List[TimelineEvent]:
        """All events whose severity_level is CRITICAL."""
        return [e for e in self.events if e.severity_level == EventSeverity.CRITICAL]

    @property
    def high_events(self) -> List[TimelineEvent]:
        """All events whose severity_level is HIGH."""
        return [e for e in self.events if e.severity_level == EventSeverity.HIGH]

    # ------------------------------------------------------------------
    # Filter helpers
    # ------------------------------------------------------------------

    def events_by_source(self, source: str) -> List[TimelineEvent]:
        """Return all events that originated from *source*.

        Args:
            source: Exact source string to match (case-sensitive).

        Returns:
            A list (possibly empty) of matching TimelineEvent objects.
        """
        return [e for e in self.events if e.source == source]

    def events_by_type(self, event_type: str) -> List[TimelineEvent]:
        """Return all events whose event_type equals *event_type*.

        Args:
            event_type: Exact event_type string to match (case-sensitive).

        Returns:
            A list (possibly empty) of matching TimelineEvent objects.
        """
        return [e for e in self.events if e.event_type == event_type]

    def events_in_window(self, start: float, end: float) -> List[TimelineEvent]:
        """Return all events whose timestamp falls within [start, end].

        Both endpoints are inclusive.

        Args:
            start: Window start as Unix epoch float.
            end:   Window end as Unix epoch float.

        Returns:
            A list (possibly empty) of matching TimelineEvent objects.
        """
        return [e for e in self.events if start <= e.timestamp <= end]

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a compact human-readable summary of the timeline.

        Includes total event count, duration, gap count, and counts of
        CRITICAL and HIGH severity events.
        """
        lines = [
            "=== Incident Timeline Summary ===",
            f"Total events    : {self.total_events}",
            f"Duration        : {self.duration_seconds:.1f}s",
            f"Silence gaps    : {self.gap_count}",
            f"Critical events : {len(self.critical_events)}",
            f"High events     : {len(self.high_events)}",
            f"Phases          : {len(self.phases)}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """Serialise the entire timeline to a plain dictionary.

        All nested objects (events, phases) are also serialised recursively
        so the result is JSON-serialisable with the standard library.
        """
        return {
            "incident_start": self.incident_start,
            "incident_end": self.incident_end,
            "duration_seconds": self.duration_seconds,
            "total_events": self.total_events,
            "gap_count": self.gap_count,
            "generated_at": self.generated_at,
            "critical_event_count": len(self.critical_events),
            "high_event_count": len(self.high_events),
            "phases": [p.to_dict() for p in self.phases],
            "events": [e.to_dict() for e in self.events],
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class TimelineBuilder:
    """Assembles an IncidentTimeline from a flat collection of TimelineEvents.

    The builder sorts events chronologically, detects silence gaps, and
    (optionally) splits the timeline into phases at those gap boundaries.

    Args:
        gap_threshold_seconds: Consecutive events separated by more than this
                               many seconds are considered a silence gap.
                               A new phase begins after each gap.
                               Default: 300 (five minutes).
        auto_phase:            When True (default), phases are derived
                               automatically from gap boundaries.  When False,
                               all events are placed in a single phase.

    Example::

        builder = TimelineBuilder(gap_threshold_seconds=60, auto_phase=True)
        timeline = builder.build(events)
    """

    def __init__(
        self,
        gap_threshold_seconds: float = 300,
        auto_phase: bool = True,
    ) -> None:
        self.gap_threshold_seconds = gap_threshold_seconds
        self.auto_phase = auto_phase
        self._accumulated: List[TimelineEvent] = []

    # ------------------------------------------------------------------
    # Core build logic
    # ------------------------------------------------------------------

    def build(self, events: List[TimelineEvent]) -> IncidentTimeline:
        """Build and return an IncidentTimeline from *events*.

        Steps
        -----
        1. Sort events by timestamp (ascending).
        2. Walk consecutive pairs to detect silence gaps.
        3. Split into phases at each gap boundary when auto_phase is True.
        4. Populate and return an IncidentTimeline.

        Args:
            events: Unsorted (or pre-sorted) list of TimelineEvent objects.
                    The original list is not mutated.

        Returns:
            A fully populated IncidentTimeline instance.
        """
        # Guard: empty input
        if not events:
            return IncidentTimeline()

        # Step 1 — chronological sort (stable, does not mutate caller's list)
        sorted_events: List[TimelineEvent] = sorted(events, key=lambda e: e.timestamp)

        incident_start = sorted_events[0].timestamp
        incident_end = sorted_events[-1].timestamp

        # Step 2 — gap detection
        gap_count = 0
        # gap_indices holds the index of the *first* event of each new phase
        gap_indices: List[int] = [0]  # phase 1 always starts at index 0

        for i in range(1, len(sorted_events)):
            delta = sorted_events[i].timestamp - sorted_events[i - 1].timestamp
            if delta > self.gap_threshold_seconds:
                gap_count += 1
                gap_indices.append(i)  # next phase begins at this index

        # Step 3 — phase construction
        phases: List[TimelinePhase] = []

        if self.auto_phase:
            # Iterate over phase start indices; each phase ends just before
            # the start of the next one (or at the last event).
            for phase_num, start_idx in enumerate(gap_indices, start=1):
                # Determine exclusive end index for slicing
                if phase_num < len(gap_indices):
                    end_idx = gap_indices[phase_num]
                else:
                    end_idx = len(sorted_events)

                phase_events = sorted_events[start_idx:end_idx]
                first_source = phase_events[0].source if phase_events else "unknown"
                phase = TimelinePhase(
                    name=f"Phase {phase_num} (source: {first_source})",
                    start_ts=phase_events[0].timestamp,
                    end_ts=phase_events[-1].timestamp,
                    events=phase_events,
                )
                phases.append(phase)
        else:
            # Single phase containing everything
            phases.append(
                TimelinePhase(
                    name="Phase 1 (source: {})".format(
                        sorted_events[0].source if sorted_events else "unknown"
                    ),
                    start_ts=incident_start,
                    end_ts=incident_end,
                    events=sorted_events,
                )
            )

        return IncidentTimeline(
            events=sorted_events,
            phases=phases,
            incident_start=incident_start,
            incident_end=incident_end,
            gap_count=gap_count,
        )

    # ------------------------------------------------------------------
    # Accumulation interface
    # ------------------------------------------------------------------

    def add_event(self, event: TimelineEvent) -> None:
        """Append a single event to the internal accumulation buffer.

        Args:
            event: A TimelineEvent to stage for a later build operation.
        """
        self._accumulated.append(event)

    def add_events(self, events: List[TimelineEvent]) -> None:
        """Append multiple events to the internal accumulation buffer.

        Args:
            events: An iterable of TimelineEvent objects.
        """
        self._accumulated.extend(events)

    def reset(self) -> None:
        """Clear all events from the internal accumulation buffer."""
        self._accumulated = []

    def build_from_accumulated(self) -> IncidentTimeline:
        """Build a timeline from all events staged via add_event / add_events.

        The accumulation buffer is *not* cleared after calling this method,
        allowing the caller to inspect or extend it before resetting manually.

        Returns:
            A fully populated IncidentTimeline from the accumulated events.
        """
        return self.build(self._accumulated)
