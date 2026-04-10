"""
Incident State Machine
=======================
Enforces valid lifecycle transitions for incidents.

State graph:

    DETECTED
        └─► TRIAGING
                └─► CONFIRMED ──────────────────────────────────► CLOSED_FALSE_POSITIVE
                        └─► CONTAINING
                                └─► ERADICATING
                                        └─► RECOVERING
                                                └─► POST_INCIDENT_REVIEW
                                                            └─► CLOSED

Any state can also transition to CLOSED_FALSE_POSITIVE if the incident
is determined to be a false positive after triage or investigation.

Usage:
    from schemas.incident import IncidentRecord, IncidentStatus
    from workflows.state_machine import IncidentStateMachine

    machine = IncidentStateMachine(record)
    machine.transition(IncidentStatus.TRIAGING)  # Advances state
    machine.transition(IncidentStatus.CLOSED)    # Raises InvalidTransitionError

Design:
  - Transitions are explicit — no "skip" transitions allowed by default
  - Each transition records a timestamp on the IncidentRecord
  - Raises InvalidTransitionError for invalid transitions (rather than silently ignoring)
  - Supports a force parameter for emergency overrides (logs a warning)
"""

from datetime import datetime, timezone
from typing import Optional

from automations.logging_compat import structlog
from schemas.incident import IncidentRecord, IncidentStatus

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------

class InvalidTransitionError(Exception):
    """Raised when an attempted state transition is not valid."""

    def __init__(self, from_state: IncidentStatus, to_state: IncidentStatus) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"Invalid transition: {from_state.value!r} → {to_state.value!r}. "
            f"See VALID_TRANSITIONS in state_machine.py for allowed transitions."
        )


# ---------------------------------------------------------------------------
# Valid transition map
# Each key maps to the set of states it can legally transition to
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.DETECTED: {
        IncidentStatus.TRIAGING,
        IncidentStatus.CLOSED_FALSE_POSITIVE,  # Skip triage for obvious FPs
    },
    IncidentStatus.TRIAGING: {
        IncidentStatus.CONFIRMED,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
    },
    IncidentStatus.CONFIRMED: {
        IncidentStatus.CONTAINING,
        IncidentStatus.CLOSED_FALSE_POSITIVE,  # Re-classified as FP after confirmation
    },
    IncidentStatus.CONTAINING: {
        IncidentStatus.ERADICATING,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
    },
    IncidentStatus.ERADICATING: {
        IncidentStatus.RECOVERING,
        IncidentStatus.CLOSED_FALSE_POSITIVE,
    },
    IncidentStatus.RECOVERING: {
        IncidentStatus.POST_INCIDENT_REVIEW,
        IncidentStatus.CLOSED,               # Skip PIR only with justification (use force=True)
    },
    IncidentStatus.POST_INCIDENT_REVIEW: {
        IncidentStatus.CLOSED,
    },
    # Terminal states — no outbound transitions
    IncidentStatus.CLOSED: set(),
    IncidentStatus.CLOSED_FALSE_POSITIVE: set(),
}

# Human-readable descriptions for each state (used in log messages and CLI output)
STATE_DESCRIPTIONS: dict[IncidentStatus, str] = {
    IncidentStatus.DETECTED: "Alert received — triage not yet started",
    IncidentStatus.TRIAGING: "Analyst actively triaging — validating alert and assessing scope",
    IncidentStatus.CONFIRMED: "Incident confirmed — preparing containment",
    IncidentStatus.CONTAINING: "Containment in progress — limiting blast radius",
    IncidentStatus.ERADICATING: "Eradication in progress — removing attacker presence",
    IncidentStatus.RECOVERING: "Recovery in progress — restoring services",
    IncidentStatus.POST_INCIDENT_REVIEW: "Post-incident review scheduled or in progress",
    IncidentStatus.CLOSED: "Incident resolved and closed",
    IncidentStatus.CLOSED_FALSE_POSITIVE: "Closed as false positive — no incident confirmed",
}


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class IncidentStateMachine:
    """
    Manages lifecycle state transitions for a single IncidentRecord.

    This machine is intentionally simple — it enforces valid transitions
    and records timestamps on the record. It does not persist state; that is
    the responsibility of the calling code (CLI, workflow engine, etc.).

    Args:
        record: The IncidentRecord this machine manages.
    """

    def __init__(self, record: IncidentRecord) -> None:
        self.record = record

    @property
    def current_state(self) -> IncidentStatus:
        """The current state of the managed incident."""
        return self.record.status

    def can_transition_to(self, target: IncidentStatus) -> bool:
        """
        Check whether a transition to the target state is valid from the current state.

        Args:
            target: The state to check.

        Returns:
            True if the transition is allowed, False otherwise.
        """
        return target in VALID_TRANSITIONS.get(self.current_state, set())

    def transition(
        self,
        target: IncidentStatus,
        analyst: Optional[str] = None,
        notes: Optional[str] = None,
        force: bool = False,
    ) -> None:
        """
        Transition the incident to the target state.

        Updates the incident record's status and the appropriate phase timestamp.

        Args:
            target: The state to transition to.
            analyst: Name or ID of the analyst triggering the transition (for audit log).
            notes: Optional notes explaining the transition (especially useful for FP closures).
            force: If True, bypass the transition validation. Use only for emergency corrections.
                   Forces are logged as warnings.

        Raises:
            InvalidTransitionError: If the transition is not valid and force=False.
        """
        from_state = self.current_state

        # Validate the transition unless force is set
        if not self.can_transition_to(target):
            if force:
                log.warning(
                    "forced_state_transition",
                    incident_id=self.record.incident_id,
                    from_state=from_state.value,
                    to_state=target.value,
                    analyst=analyst,
                    notes=notes,
                )
            else:
                raise InvalidTransitionError(from_state, target)

        now = datetime.now(timezone.utc)

        # Update the record status
        self.record.status = target
        self.record.updated_at = now

        # Record phase-specific timestamps on the record
        timestamp_fields: dict[IncidentStatus, str] = {
            IncidentStatus.TRIAGING: "triaged_at",
            IncidentStatus.CONTAINING: "contained_at",      # Record when containment started
            IncidentStatus.RECOVERING: "recovered_at",
            IncidentStatus.CLOSED: "closed_at",
            IncidentStatus.CLOSED_FALSE_POSITIVE: "closed_at",
        }

        # Set the appropriate timestamp field if this state has one
        if target in timestamp_fields:
            field = timestamp_fields[target]
            if getattr(self.record, field, None) is None:
                setattr(self.record, field, now)

        log.info(
            "incident_state_transition",
            incident_id=self.record.incident_id,
            from_state=from_state.value,
            to_state=target.value,
            description=STATE_DESCRIPTIONS[target],
            analyst=analyst or "unknown",
            forced=force,
            notes=notes,
            timestamp=now.isoformat(),
        )

    def available_transitions(self) -> list[IncidentStatus]:
        """
        Return the list of valid target states from the current state.

        Useful for CLI tab-completion and validation UIs.
        """
        return sorted(
            VALID_TRANSITIONS.get(self.current_state, set()),
            key=lambda s: s.value,
        )

    def describe(self) -> str:
        """Return a human-readable description of the current state."""
        return STATE_DESCRIPTIONS.get(self.current_state, "Unknown state")
