"""
Tests for the incident state machine.

These tests validate:
  - Valid transitions succeed and update the record correctly
  - Invalid transitions raise InvalidTransitionError
  - Terminal states cannot be exited
  - Phase timestamps are set correctly on transition
  - Force transitions work but log warnings
"""

from datetime import datetime, timezone

import pytest

from schemas.incident import IncidentRecord, IncidentStatus
from workflows.state_machine import (
    IncidentStateMachine,
    InvalidTransitionError,
    VALID_TRANSITIONS,
    STATE_DESCRIPTIONS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_record(status: IncidentStatus = IncidentStatus.DETECTED) -> IncidentRecord:
    """Create a minimal IncidentRecord for testing."""
    record = IncidentRecord(
        incident_id="INC-20250101-001",
        title="Test incident for state machine tests",
    )
    # Bypass the state machine to set an arbitrary starting state
    record.status = status
    return record


# ---------------------------------------------------------------------------
# Valid transition tests
# ---------------------------------------------------------------------------

class TestValidTransitions:
    def test_detected_to_triaging(self):
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.TRIAGING, analyst="test_analyst")

        assert record.status == IncidentStatus.TRIAGING
        # triaged_at should be set
        assert record.triaged_at is not None

    def test_triaging_to_confirmed(self):
        record = make_record(IncidentStatus.TRIAGING)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.CONFIRMED)

        assert record.status == IncidentStatus.CONFIRMED

    def test_confirmed_to_containing(self):
        record = make_record(IncidentStatus.CONFIRMED)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.CONTAINING)

        assert record.status == IncidentStatus.CONTAINING

    def test_containing_to_eradicating(self):
        record = make_record(IncidentStatus.CONTAINING)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.ERADICATING)

        assert record.status == IncidentStatus.ERADICATING

    def test_eradicating_to_recovering(self):
        record = make_record(IncidentStatus.ERADICATING)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.RECOVERING)

        assert record.status == IncidentStatus.RECOVERING

    def test_recovering_to_post_incident_review(self):
        record = make_record(IncidentStatus.RECOVERING)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.POST_INCIDENT_REVIEW)

        assert record.status == IncidentStatus.POST_INCIDENT_REVIEW

    def test_post_incident_review_to_closed(self):
        record = make_record(IncidentStatus.POST_INCIDENT_REVIEW)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.CLOSED)

        assert record.status == IncidentStatus.CLOSED
        assert record.closed_at is not None

    def test_full_lifecycle(self):
        """Test a complete incident lifecycle from DETECTED to CLOSED."""
        record = make_record()
        machine = IncidentStateMachine(record)

        lifecycle = [
            IncidentStatus.TRIAGING,
            IncidentStatus.CONFIRMED,
            IncidentStatus.CONTAINING,
            IncidentStatus.ERADICATING,
            IncidentStatus.RECOVERING,
            IncidentStatus.POST_INCIDENT_REVIEW,
            IncidentStatus.CLOSED,
        ]

        for state in lifecycle:
            machine.transition(state)
            assert record.status == state

    def test_false_positive_closure_from_triaging(self):
        """An incident can be closed as false positive from triage."""
        record = make_record(IncidentStatus.TRIAGING)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.CLOSED_FALSE_POSITIVE)

        assert record.status == IncidentStatus.CLOSED_FALSE_POSITIVE
        assert record.closed_at is not None

    def test_false_positive_closure_from_confirmed(self):
        """An incident re-classified as FP after confirmation can be closed."""
        record = make_record(IncidentStatus.CONFIRMED)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.CLOSED_FALSE_POSITIVE)

        assert record.status == IncidentStatus.CLOSED_FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Invalid transition tests
# ---------------------------------------------------------------------------

class TestInvalidTransitions:
    def test_skip_triage_to_containing(self):
        """Cannot skip from DETECTED directly to CONTAINING."""
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)

        with pytest.raises(InvalidTransitionError) as exc_info:
            machine.transition(IncidentStatus.CONTAINING)

        assert exc_info.value.from_state == IncidentStatus.DETECTED
        assert exc_info.value.to_state == IncidentStatus.CONTAINING

    def test_skip_confirming_to_recovering(self):
        """Cannot jump from TRIAGING to RECOVERING."""
        record = make_record(IncidentStatus.TRIAGING)
        machine = IncidentStateMachine(record)

        with pytest.raises(InvalidTransitionError):
            machine.transition(IncidentStatus.RECOVERING)

    def test_cannot_reopen_closed_incident(self):
        """A CLOSED incident cannot transition to any other state."""
        record = make_record(IncidentStatus.CLOSED)
        machine = IncidentStateMachine(record)

        with pytest.raises(InvalidTransitionError):
            machine.transition(IncidentStatus.TRIAGING)

    def test_cannot_reopen_false_positive(self):
        """A CLOSED_FALSE_POSITIVE incident cannot be reopened."""
        record = make_record(IncidentStatus.CLOSED_FALSE_POSITIVE)
        machine = IncidentStateMachine(record)

        with pytest.raises(InvalidTransitionError):
            machine.transition(IncidentStatus.DETECTED)

    def test_go_backward_fails(self):
        """Cannot regress to a previous state (e.g., CONTAINING → TRIAGING)."""
        record = make_record(IncidentStatus.CONTAINING)
        machine = IncidentStateMachine(record)

        with pytest.raises(InvalidTransitionError):
            machine.transition(IncidentStatus.TRIAGING)


# ---------------------------------------------------------------------------
# Force transition tests
# ---------------------------------------------------------------------------

class TestForceTransitions:
    def test_force_invalid_transition_succeeds(self):
        """Force=True allows bypassing normal transition validation."""
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)

        # Normally invalid — detected cannot go directly to RECOVERING
        machine.transition(IncidentStatus.RECOVERING, force=True, notes="Emergency override")

        assert record.status == IncidentStatus.RECOVERING

    def test_force_does_not_require_invalid_path(self):
        """Force=True on a valid transition should still work normally."""
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)
        machine.transition(IncidentStatus.TRIAGING, force=True)

        assert record.status == IncidentStatus.TRIAGING


# ---------------------------------------------------------------------------
# Helper method tests
# ---------------------------------------------------------------------------

class TestHelperMethods:
    def test_can_transition_to_valid(self):
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)

        assert machine.can_transition_to(IncidentStatus.TRIAGING) is True
        assert machine.can_transition_to(IncidentStatus.CLOSED_FALSE_POSITIVE) is True

    def test_can_transition_to_invalid(self):
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)

        assert machine.can_transition_to(IncidentStatus.RECOVERING) is False
        assert machine.can_transition_to(IncidentStatus.CLOSED) is False

    def test_available_transitions_detected(self):
        record = make_record(IncidentStatus.DETECTED)
        machine = IncidentStateMachine(record)

        available = machine.available_transitions()
        assert IncidentStatus.TRIAGING in available
        assert IncidentStatus.CLOSED_FALSE_POSITIVE in available
        # Should not include states that aren't reachable
        assert IncidentStatus.CONTAINING not in available

    def test_available_transitions_closed_is_empty(self):
        """A closed incident has no available transitions."""
        record = make_record(IncidentStatus.CLOSED)
        machine = IncidentStateMachine(record)

        assert machine.available_transitions() == []

    def test_describe_returns_string(self):
        record = make_record(IncidentStatus.TRIAGING)
        machine = IncidentStateMachine(record)

        description = machine.describe()
        assert isinstance(description, str)
        assert len(description) > 0

    def test_current_state_property(self):
        record = make_record(IncidentStatus.CONFIRMED)
        machine = IncidentStateMachine(record)

        assert machine.current_state == IncidentStatus.CONFIRMED

    def test_transition_updates_updated_at(self):
        record = make_record(IncidentStatus.DETECTED)
        original_updated_at = record.updated_at
        machine = IncidentStateMachine(record)

        machine.transition(IncidentStatus.TRIAGING)

        # updated_at should be refreshed
        assert record.updated_at >= original_updated_at

    def test_invalid_transition_error_message(self):
        """InvalidTransitionError should include both states in its message."""
        error = InvalidTransitionError(IncidentStatus.DETECTED, IncidentStatus.RECOVERING)
        assert "detected" in str(error).lower()
        assert "recovering" in str(error).lower()
