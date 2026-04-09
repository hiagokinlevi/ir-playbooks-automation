"""
Tests for incident data schemas (Pydantic models).

These tests validate:
  - IncidentRecord construction and field defaults
  - EvidenceItem construction and hash validation
  - TimelineEvent construction and UTC enforcement
  - IncidentRecord helper methods (add_timeline_event, add_evidence, is_open, dwell_time_hours)
  - SeverityLevel, IncidentType, IncidentStatus enum values
  - Field validation (pattern, min/max length, ge)
"""

from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError

from schemas.incident import (
    EvidenceItem,
    EvidenceType,
    IncidentRecord,
    IncidentStatus,
    IncidentType,
    SeverityLevel,
    TimelineEvent,
    TimelineEventActor,
)


# ---------------------------------------------------------------------------
# IncidentRecord tests
# ---------------------------------------------------------------------------

class TestIncidentRecord:
    def test_minimal_construction(self):
        """IncidentRecord can be created with only required fields."""
        record = IncidentRecord(
            incident_id="INC-20250101-001",
            title="Test incident",
        )
        assert record.incident_id == "INC-20250101-001"
        assert record.title == "Test incident"
        assert record.status == IncidentStatus.DETECTED
        assert record.severity is None
        assert record.incident_type == IncidentType.GENERIC
        assert record.timeline == []
        assert record.evidence == []

    def test_invalid_incident_id_format(self):
        """Incident ID must match INC-YYYYMMDD-NNN pattern."""
        with pytest.raises(ValidationError):
            IncidentRecord(incident_id="INVALID-001", title="Test")

    def test_invalid_incident_id_short(self):
        """Incident ID must have the correct date format."""
        with pytest.raises(ValidationError):
            IncidentRecord(incident_id="INC-2025-001", title="Test")

    def test_title_too_short(self):
        """Title must be at least 5 characters."""
        with pytest.raises(ValidationError):
            IncidentRecord(incident_id="INC-20250101-001", title="Hi")

    def test_title_too_long(self):
        """Title must not exceed 200 characters."""
        with pytest.raises(ValidationError):
            IncidentRecord(
                incident_id="INC-20250101-001",
                title="X" * 201,
            )

    def test_full_construction(self):
        """IncidentRecord accepts all optional fields."""
        now = datetime.now(timezone.utc)
        record = IncidentRecord(
            incident_id="INC-20250101-001",
            title="Compromised service account in production",
            status=IncidentStatus.TRIAGING,
            severity=SeverityLevel.CRITICAL,
            incident_type=IncidentType.CREDENTIAL_COMPROMISE,
            owner="analyst_01",
            affected_assets=["svc-deploy@company.com", "aws-prod"],
            detected_at=now,
            summary="A service account was compromised via leaked credentials.",
            tags=["credential_compromise", "aws"],
        )
        assert record.severity == SeverityLevel.CRITICAL
        assert record.incident_type == IncidentType.CREDENTIAL_COMPROMISE
        assert "aws-prod" in record.affected_assets

    def test_is_open_true_for_active_states(self):
        """is_open returns True for non-terminal states."""
        for status in [
            IncidentStatus.DETECTED,
            IncidentStatus.TRIAGING,
            IncidentStatus.CONFIRMED,
            IncidentStatus.CONTAINING,
            IncidentStatus.ERADICATING,
            IncidentStatus.RECOVERING,
            IncidentStatus.POST_INCIDENT_REVIEW,
        ]:
            record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
            record.status = status
            assert record.is_open is True

    def test_is_open_false_for_closed(self):
        """is_open returns False for terminal states."""
        for status in [IncidentStatus.CLOSED, IncidentStatus.CLOSED_FALSE_POSITIVE]:
            record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
            record.status = status
            assert record.is_open is False

    def test_add_timeline_event(self):
        """add_timeline_event appends and sorts events by observed_at."""
        record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
        now = datetime.now(timezone.utc)

        event_2 = TimelineEvent(
            observed_at=now + timedelta(minutes=10),
            phase="Triage",
            description="Second event",
        )
        event_1 = TimelineEvent(
            observed_at=now,
            phase="Detection",
            description="First event",
        )

        record.add_timeline_event(event_2)  # Add later event first
        record.add_timeline_event(event_1)  # Add earlier event second

        # Should be sorted chronologically
        assert record.timeline[0].description == "First event"
        assert record.timeline[1].description == "Second event"
        assert len(record.timeline) == 2

    def test_add_evidence(self):
        """add_evidence appends an evidence item."""
        record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
        item = EvidenceItem(
            evidence_type=EvidenceType.LOG_EXPORT,
            description="Authentication log export",
        )
        record.add_evidence(item)

        assert len(record.evidence) == 1
        assert record.evidence[0].description == "Authentication log export"

    def test_dwell_time_hours_with_data(self):
        """dwell_time_hours calculates correctly when data is available."""
        now = datetime.now(timezone.utc)
        record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
        record.contained_at = now + timedelta(hours=5)

        attacker_event = TimelineEvent(
            observed_at=now,
            phase="Initial Access",
            description="Initial access",
            actor=TimelineEventActor.ATTACKER,
        )
        record.add_timeline_event(attacker_event)

        assert record.dwell_time_hours == 5.0

    def test_dwell_time_hours_no_attacker_events(self):
        """dwell_time_hours returns None when no attacker events exist."""
        record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")
        record.contained_at = datetime.now(timezone.utc)

        assert record.dwell_time_hours is None

    def test_dwell_time_hours_no_contained_at(self):
        """dwell_time_hours returns None when contained_at is not set."""
        record = IncidentRecord(incident_id="INC-20250101-001", title="Test incident")

        event = TimelineEvent(
            observed_at=datetime.now(timezone.utc),
            phase="Initial Access",
            description="Attack started",
            actor=TimelineEventActor.ATTACKER,
        )
        record.add_timeline_event(event)

        assert record.dwell_time_hours is None


# ---------------------------------------------------------------------------
# EvidenceItem tests
# ---------------------------------------------------------------------------

class TestEvidenceItem:
    def test_auto_generated_evidence_id(self):
        """EvidenceItem auto-generates a unique ID."""
        item1 = EvidenceItem(evidence_type=EvidenceType.LOG_EXPORT, description="Log 1")
        item2 = EvidenceItem(evidence_type=EvidenceType.LOG_EXPORT, description="Log 2")

        assert item1.evidence_id != item2.evidence_id
        assert item1.evidence_id.startswith("E-")

    def test_valid_sha256(self):
        """EvidenceItem accepts a valid lowercase hex SHA-256."""
        item = EvidenceItem(
            evidence_type=EvidenceType.LOG_EXPORT,
            description="Test log",
            sha256="a" * 64,  # 64 hex chars
        )
        assert item.sha256 == "a" * 64

    def test_invalid_sha256_wrong_length(self):
        """EvidenceItem rejects a SHA-256 with wrong length."""
        with pytest.raises(ValidationError):
            EvidenceItem(
                evidence_type=EvidenceType.LOG_EXPORT,
                description="Test log",
                sha256="abc123",  # Too short
            )

    def test_invalid_sha256_uppercase(self):
        """EvidenceItem rejects uppercase hex in SHA-256."""
        with pytest.raises(ValidationError):
            EvidenceItem(
                evidence_type=EvidenceType.LOG_EXPORT,
                description="Test log",
                sha256="A" * 64,  # Uppercase not allowed
            )

    def test_size_bytes_non_negative(self):
        """EvidenceItem rejects negative size_bytes."""
        with pytest.raises(ValidationError):
            EvidenceItem(
                evidence_type=EvidenceType.LOG_EXPORT,
                description="Test",
                size_bytes=-1,
            )

    def test_collected_at_auto_set(self):
        """collected_at is automatically set to current UTC time."""
        before = datetime.now(timezone.utc)
        item = EvidenceItem(evidence_type=EvidenceType.SCREENSHOT, description="Screenshot")
        after = datetime.now(timezone.utc)

        assert before <= item.collected_at <= after


# ---------------------------------------------------------------------------
# TimelineEvent tests
# ---------------------------------------------------------------------------

class TestTimelineEvent:
    def test_valid_construction(self):
        """TimelineEvent can be constructed with minimal fields."""
        event = TimelineEvent(
            observed_at=datetime.now(timezone.utc),
            phase="Detection",
            description="Alert fired",
        )
        assert event.actor == TimelineEventActor.UNKNOWN
        assert event.confidence == "medium"

    def test_auto_generated_event_id(self):
        """TimelineEvent auto-generates a unique ID."""
        e1 = TimelineEvent(
            observed_at=datetime.now(timezone.utc),
            phase="Detection",
            description="Event 1",
        )
        e2 = TimelineEvent(
            observed_at=datetime.now(timezone.utc),
            phase="Detection",
            description="Event 2",
        )
        assert e1.event_id != e2.event_id

    def test_valid_mitre_technique(self):
        """TimelineEvent accepts a valid ATT&CK technique ID."""
        event = TimelineEvent(
            observed_at=datetime.now(timezone.utc),
            phase="Initial Access",
            description="Valid creds used",
            mitre_attack_technique="T1078.004",
        )
        assert event.mitre_attack_technique == "T1078.004"

    def test_invalid_mitre_technique(self):
        """TimelineEvent rejects a malformed ATT&CK technique ID."""
        with pytest.raises(ValidationError):
            TimelineEvent(
                observed_at=datetime.now(timezone.utc),
                phase="Initial Access",
                description="Test",
                mitre_attack_technique="INVALID",
            )

    def test_naive_datetime_gets_utc(self):
        """Naive datetimes are converted to UTC-aware."""
        naive_dt = datetime(2025, 1, 1, 12, 0, 0)  # No timezone info
        event = TimelineEvent(
            observed_at=naive_dt,
            phase="Detection",
            description="Test event",
        )
        assert event.observed_at.tzinfo is not None

    def test_invalid_confidence(self):
        """TimelineEvent rejects non-standard confidence values."""
        with pytest.raises(ValidationError):
            TimelineEvent(
                observed_at=datetime.now(timezone.utc),
                phase="Detection",
                description="Test",
                confidence="certain",  # Not a valid choice
            )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestEnums:
    def test_severity_level_values(self):
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.LOW.value == "low"

    def test_incident_type_values(self):
        assert IncidentType.CREDENTIAL_COMPROMISE.value == "credential_compromise"
        assert IncidentType.PHISHING.value == "phishing"
        assert IncidentType.CLOUD_EXPOSURE.value == "cloud_exposure"

    def test_incident_status_lifecycle_values(self):
        """All expected status values are present."""
        expected = {
            "detected", "triaging", "confirmed", "containing",
            "eradicating", "recovering", "post_incident_review",
            "closed", "closed_false_positive",
        }
        actual = {s.value for s in IncidentStatus}
        assert expected == actual
