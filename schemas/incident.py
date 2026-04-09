"""
Incident Data Schemas
======================
Pydantic models for all core incident response data structures.

These models serve as the canonical data contracts for:
  - Incident records (IncidentRecord)
  - Evidence items (EvidenceItem)
  - Timeline events (TimelineEvent)
  - Severity classification (SeverityLevel)

Usage:
    from schemas.incident import IncidentRecord, SeverityLevel, IncidentType

    record = IncidentRecord(
        incident_id="INC-20250101-001",
        title="Compromised service account in production",
        severity=SeverityLevel.HIGH,
        incident_type=IncidentType.CREDENTIAL_COMPROMISE,
    )

Design notes:
  - All timestamps are stored as UTC-aware datetime objects
  - String fields that may contain PII are marked with Field(description=...) for documentation
  - Use .model_dump(mode="json") for JSON-serializable output
  - All enum values are lowercase strings for config-file friendliness
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    """Standard severity classification aligned with NIST SP 800-61r2."""
    CRITICAL = "critical"   # Active compromise, confirmed data exposure, production system
    HIGH = "high"           # Likely compromise, privileged account involved
    MEDIUM = "medium"       # Suspicious activity, limited scope, no confirmed impact
    LOW = "low"             # Anomaly, informational, no current evidence of harm


class IncidentType(str, Enum):
    """Supported incident type classifications."""
    CREDENTIAL_COMPROMISE = "credential_compromise"
    MALWARE = "malware"
    DATA_EXPOSURE = "data_exposure"
    API_ABUSE = "api_abuse"
    PHISHING = "phishing"
    CLOUD_EXPOSURE = "cloud_exposure"
    SECRET_LEAKAGE = "secret_leakage"
    GENERIC = "generic"


class IncidentStatus(str, Enum):
    """
    Valid incident lifecycle states.
    Transitions are enforced by the state machine in workflows/state_machine.py.
    """
    DETECTED = "detected"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    POST_INCIDENT_REVIEW = "post_incident_review"
    CLOSED = "closed"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"


class EvidenceType(str, Enum):
    """Types of evidence that can be collected during an incident."""
    LOG_EXPORT = "log_export"           # Raw log file or export
    MEMORY_IMAGE = "memory_image"       # Memory dump
    DISK_IMAGE = "disk_image"           # Disk or partition image
    NETWORK_CAPTURE = "network_capture" # PCAP or flow data
    SCREENSHOT = "screenshot"           # Visual evidence
    CONFIGURATION = "configuration"     # Resource configuration snapshot
    ARTIFACT = "artifact"               # Malicious file or sample
    INTERVIEW_NOTES = "interview_notes" # Notes from analyst interviews
    OTHER = "other"


class TimelineEventActor(str, Enum):
    """Actor type for timeline events — distinguishes attacker from defender actions."""
    ATTACKER = "attacker"
    DEFENDER = "defender"
    UNKNOWN = "unknown"
    SYSTEM = "system"   # Automated system action (alert, automation script)


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

class EvidenceItem(BaseModel):
    """
    A single piece of evidence collected during an incident.

    Evidence items should be created by the evidence packager script
    (automations/evidence_packaging/packager.py) to ensure hashes are recorded.
    """
    evidence_id: str = Field(
        default_factory=lambda: f"E-{uuid4().hex[:8].upper()}",
        description="Auto-generated evidence identifier (e.g., E-3F7A2B1C)"
    )
    evidence_type: EvidenceType = Field(
        description="Classification of evidence type"
    )
    description: str = Field(
        description="Human-readable description of what this evidence item is"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Path within the evidence package (relative to EVIDENCE_DIR/incident_id/)"
    )
    sha256: Optional[str] = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",   # Enforce lowercase hex SHA-256 format
        description="SHA-256 hash of the evidence file for integrity verification"
    )
    size_bytes: Optional[int] = Field(
        default=None,
        ge=0,
        description="File size in bytes"
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this evidence was collected"
    )
    collected_by: Optional[str] = Field(
        default=None,
        description="Analyst or automation that collected this evidence"
    )
    notes: Optional[str] = Field(
        default=None,
        description="Additional context or chain-of-custody notes"
    )


class TimelineEvent(BaseModel):
    """
    A single event in the incident timeline.

    Timeline events should be recorded as they are discovered, not reconstructed later.
    Include both the time the event occurred (observed_at) and when it was discovered (discovered_at).
    """
    event_id: str = Field(
        default_factory=lambda: f"TL-{uuid4().hex[:8].upper()}",
        description="Auto-generated event identifier"
    )
    observed_at: datetime = Field(
        description="UTC timestamp when the event actually occurred (from logs or evidence)"
    )
    discovered_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when this event was discovered by an analyst (may differ from observed_at)"
    )
    actor: TimelineEventActor = Field(
        default=TimelineEventActor.UNKNOWN,
        description="Who performed this action"
    )
    phase: str = Field(
        description="Incident phase this event belongs to (e.g., 'Initial Access', 'Containment')"
    )
    description: str = Field(
        description="Plain-language description of the event"
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="List of evidence_id values that support this event"
    )
    confidence: str = Field(
        default="medium",
        pattern=r"^(high|medium|low)$",
        description="Confidence level that this event occurred as described"
    )
    mitre_attack_technique: Optional[str] = Field(
        default=None,
        pattern=r"^T\d{4}(\.\d{3})?$",  # Enforce ATT&CK technique format (e.g., T1078 or T1078.004)
        description="MITRE ATT&CK technique ID if applicable (e.g., T1078.004)"
    )

    @field_validator("observed_at", "discovered_at", mode="before")
    @classmethod
    def ensure_utc(cls, v: datetime | None) -> datetime | None:
        """Ensure all timestamps are UTC-aware."""
        if v is None:
            return v
        if isinstance(v, datetime) and v.tzinfo is None:
            # Treat naive datetimes as UTC — warn the caller
            return v.replace(tzinfo=timezone.utc)
        return v


class IncidentRecord(BaseModel):
    """
    The canonical incident record — the single source of truth for an incident.

    One IncidentRecord should exist per incident, stored in the incident management system
    and updated throughout the lifecycle. Use the CLI commands to update fields:

        k1n-ir set-severity --incident-id INC-20250101-001 --severity critical
    """
    incident_id: str = Field(
        description="Unique incident identifier in format INC-YYYYMMDD-NNN",
        pattern=r"^INC-\d{8}-\d{3}$"
    )
    title: str = Field(
        min_length=5,
        max_length=200,
        description="Concise, descriptive title. No jargon. Avoid abbreviations."
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.DETECTED,
        description="Current lifecycle state — managed by the state machine"
    )
    severity: Optional[SeverityLevel] = Field(
        default=None,
        description="Severity level — must be assigned during triage"
    )
    incident_type: IncidentType = Field(
        default=IncidentType.GENERIC,
        description="Incident classification type"
    )

    # Ownership
    owner: Optional[str] = Field(
        default=None,
        description="Primary analyst or IR lead responsible for this incident"
    )
    assigned_to: Optional[str] = Field(
        default=None,
        description="Currently assigned analyst"
    )

    # Affected scope
    affected_assets: list[str] = Field(
        default_factory=list,
        description="List of affected hostnames, service names, account names, or resource IDs"
    )

    # Timestamps — all UTC
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the incident was first detected (alert time or user report time)"
    )
    triaged_at: Optional[datetime] = Field(
        default=None,
        description="When triage was completed and severity was confirmed"
    )
    contained_at: Optional[datetime] = Field(
        default=None,
        description="When containment was confirmed complete"
    )
    eradicated_at: Optional[datetime] = Field(
        default=None,
        description="When eradication was confirmed complete"
    )
    recovered_at: Optional[datetime] = Field(
        default=None,
        description="When service was restored"
    )
    closed_at: Optional[datetime] = Field(
        default=None,
        description="When the incident was formally closed"
    )

    # Content
    summary: Optional[str] = Field(
        default=None,
        description="Executive-level summary (2–4 sentences)"
    )
    timeline: list[TimelineEvent] = Field(
        default_factory=list,
        description="Ordered list of timeline events"
    )
    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="Evidence items collected for this incident"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Searchable tags for filtering and reporting"
    )

    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this record was created"
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this record was last updated"
    )

    def add_timeline_event(self, event: TimelineEvent) -> None:
        """
        Add a timeline event and keep the list sorted by observed_at.

        Modifies the record in place and updates updated_at.
        """
        self.timeline.append(event)
        self.timeline.sort(key=lambda e: e.observed_at)
        self.updated_at = datetime.now(timezone.utc)

    def add_evidence(self, item: EvidenceItem) -> None:
        """
        Add an evidence item to this incident record.

        Modifies the record in place and updates updated_at.
        """
        self.evidence.append(item)
        self.updated_at = datetime.now(timezone.utc)

    @property
    def is_open(self) -> bool:
        """Returns True if the incident is in an active (non-closed) state."""
        return self.status not in {IncidentStatus.CLOSED, IncidentStatus.CLOSED_FALSE_POSITIVE}

    @property
    def dwell_time_hours(self) -> Optional[float]:
        """
        Estimated attacker dwell time in hours.

        Calculated as the time between the first attacker timeline event and containment.
        Returns None if insufficient data is available.
        """
        attacker_events = [
            e for e in self.timeline
            if e.actor == TimelineEventActor.ATTACKER
        ]
        if not attacker_events or self.contained_at is None:
            return None

        first_attacker_action = min(e.observed_at for e in attacker_events)
        delta = self.contained_at - first_attacker_action
        return round(delta.total_seconds() / 3600, 2)
