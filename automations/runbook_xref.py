"""
IR Runbook Cross-Reference Engine
===================================
Maps incident types and lifecycle phases to the relevant playbooks in the
playbooks/ directory, returning prioritised, phase-ordered references for
incident commanders and analysts.

The engine answers three core questions:
  1. "Which playbooks apply to this incident type?"
  2. "What should we do right now, given our current lifecycle phase?"
  3. "Which incident types does a given playbook cover?"

Key concepts:
  - PlaybookRef:       A lightweight pointer to one playbook document.
  - PlaybookPhase:     Which lifecycle phase the playbook covers
                       (TRIAGE, CONTAINMENT, ERADICATION, RECOVERY).
  - RUNBOOK_REGISTRY:  The authoritative list of all registered playbooks.
  - RunbookXrefReport: Structured result returned by xref_incident(), grouping
                       applicable playbooks by phase in execution order.

Usage:
    from schemas.incident import IncidentRecord, IncidentType, SeverityLevel
    from automations.runbook_xref import (
        lookup_playbooks,
        xref_incident,
        PlaybookPhase,
        PlaybookRef,
    )

    # All playbooks for a phishing incident
    refs = lookup_playbooks(IncidentType.PHISHING)
    for ref in refs:
        print(ref.phase.value, "→", ref.path)

    # Full phase-ordered report for an active incident
    report = xref_incident(incident_record)
    for phase, books in report.by_phase.items():
        print(phase.value.upper())
        for b in books:
            print("  •", b.title)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from schemas.incident import IncidentRecord, IncidentStatus, IncidentType


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PlaybookPhase(str, Enum):
    """IR lifecycle phase a playbook primarily covers."""
    TRIAGE      = "triage"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY    = "recovery"


# Execution order for phases — used when sorting the xref report
_PHASE_ORDER: dict[PlaybookPhase, int] = {
    PlaybookPhase.TRIAGE:      0,
    PlaybookPhase.CONTAINMENT: 1,
    PlaybookPhase.ERADICATION: 2,
    PlaybookPhase.RECOVERY:    3,
}

# Map incident status → most relevant phase (for xref_incident priority sorting)
_STATUS_TO_PHASE: dict[IncidentStatus, PlaybookPhase] = {
    IncidentStatus.DETECTED:             PlaybookPhase.TRIAGE,
    IncidentStatus.TRIAGING:             PlaybookPhase.TRIAGE,
    IncidentStatus.CONFIRMED:            PlaybookPhase.CONTAINMENT,
    IncidentStatus.CONTAINING:           PlaybookPhase.CONTAINMENT,
    IncidentStatus.ERADICATING:          PlaybookPhase.ERADICATION,
    IncidentStatus.RECOVERING:           PlaybookPhase.RECOVERY,
    IncidentStatus.POST_INCIDENT_REVIEW: PlaybookPhase.RECOVERY,
    IncidentStatus.CLOSED:               PlaybookPhase.RECOVERY,
    IncidentStatus.CLOSED_FALSE_POSITIVE: PlaybookPhase.TRIAGE,
}


# ---------------------------------------------------------------------------
# PlaybookRef — one entry in the registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlaybookRef:
    """
    A lightweight, immutable pointer to a single playbook document.

    Attributes:
        path:           Relative path from the repo root (e.g.,
                        'playbooks/triage/initial_triage.md').
        title:          Human-readable playbook title.
        phase:          Lifecycle phase this playbook primarily covers.
        incident_types: Set of IncidentType values this playbook applies to.
                        An empty set means it applies to ALL incident types.
        description:    One-sentence description of what the playbook covers.
        automation_ref: Optional module path of a companion automation script
                        (e.g., 'automations.cloud.isolate_aws_instance').
    """
    path:           str
    title:          str
    phase:          PlaybookPhase
    incident_types: frozenset[IncidentType]
    description:    str
    automation_ref: Optional[str] = None

    @property
    def is_universal(self) -> bool:
        """True when the playbook applies to every incident type."""
        return len(self.incident_types) == 0

    def applies_to(self, incident_type: IncidentType) -> bool:
        """Return True if this playbook applies to the given incident type."""
        return self.is_universal or incident_type in self.incident_types


# ---------------------------------------------------------------------------
# Runbook registry
# ---------------------------------------------------------------------------

#: All registered playbooks. Add new entries here when new playbooks are created.
RUNBOOK_REGISTRY: list[PlaybookRef] = [
    # ── Triage ────────────────────────────────────────────────────────────
    PlaybookRef(
        path="playbooks/triage/initial_triage.md",
        title="Initial Triage Checklist",
        phase=PlaybookPhase.TRIAGE,
        incident_types=frozenset(),     # universal — applies to all types
        description=(
            "Severity classification, stakeholder notification, and evidence "
            "preservation checklist for the first 30 minutes of any incident."
        ),
    ),

    # ── Containment ───────────────────────────────────────────────────────
    PlaybookRef(
        path="playbooks/containment/compromised_credentials.md",
        title="Containment: Compromised Credentials",
        phase=PlaybookPhase.CONTAINMENT,
        incident_types=frozenset({
            IncidentType.CREDENTIAL_COMPROMISE,
            IncidentType.PHISHING,
        }),
        description=(
            "Revoke active sessions, rotate credentials, and isolate affected "
            "accounts to stop lateral movement from compromised identities."
        ),
        automation_ref="automations.identity.revoke_azure_sessions",
    ),
    PlaybookRef(
        path="playbooks/containment/cloud_exposure.md",
        title="Containment: Cloud Resource Exposure",
        phase=PlaybookPhase.CONTAINMENT,
        incident_types=frozenset({
            IncidentType.CLOUD_EXPOSURE,
            IncidentType.SECRET_LEAKAGE,
            IncidentType.DATA_EXPOSURE,
        }),
        description=(
            "Isolate exposed cloud resources (EC2, Azure VM), tighten security "
            "groups/NSGs, and prevent further data exfiltration from misconfigured "
            "or compromised cloud infrastructure."
        ),
        automation_ref="automations.cloud.isolate_aws_instance",
    ),

    # ── Eradication ───────────────────────────────────────────────────────
    PlaybookRef(
        path="playbooks/eradication/remove_persistence.md",
        title="Eradication: Remove Persistence Mechanisms",
        phase=PlaybookPhase.ERADICATION,
        incident_types=frozenset({
            IncidentType.MALWARE,
            IncidentType.CREDENTIAL_COMPROMISE,
            IncidentType.CLOUD_EXPOSURE,
        }),
        description=(
            "Identify and eliminate backdoors, scheduled tasks, unauthorised "
            "IAM roles, and other attacker persistence mechanisms before recovery."
        ),
    ),

    # ── Recovery ──────────────────────────────────────────────────────────
    PlaybookRef(
        path="playbooks/recovery/controlled_return.md",
        title="Recovery: Controlled Service Return",
        phase=PlaybookPhase.RECOVERY,
        incident_types=frozenset(),     # universal
        description=(
            "Phased service restoration with monitoring gates to confirm that "
            "eradication was complete before returning systems to production."
        ),
    ),

    # ── Incident-type–specific ────────────────────────────────────────────
    PlaybookRef(
        path="playbooks/incident-types/phishing.md",
        title="Incident Type Guide: Phishing",
        phase=PlaybookPhase.TRIAGE,
        incident_types=frozenset({IncidentType.PHISHING}),
        description=(
            "Phishing-specific indicators, email header analysis, and user "
            "communication templates for phishing incidents."
        ),
    ),
    PlaybookRef(
        path="playbooks/incident-types/api_abuse.md",
        title="Incident Type Guide: API Abuse",
        phase=PlaybookPhase.TRIAGE,
        incident_types=frozenset({IncidentType.API_ABUSE}),
        description=(
            "API abuse triage: rate-limit enforcement, token revocation, "
            "access-log analysis, and WAF tuning guidance."
        ),
    ),
    PlaybookRef(
        path="playbooks/incident-types/secret_leakage.md",
        title="Incident Type Guide: Secret Leakage",
        phase=PlaybookPhase.TRIAGE,
        incident_types=frozenset({
            IncidentType.SECRET_LEAKAGE,
            IncidentType.DATA_EXPOSURE,
        }),
        description=(
            "Secret leakage response: credential rotation priority matrix, "
            "git history scrubbing guidance, and breach notification checklist."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def lookup_playbooks(
    incident_type: IncidentType,
    phase: Optional[PlaybookPhase] = None,
) -> list[PlaybookRef]:
    """
    Return all playbooks that apply to an incident type, optionally filtered
    by lifecycle phase.  Results are sorted by phase execution order.

    Args:
        incident_type: The IncidentType to look up.
        phase:         Optional filter — return only playbooks for this phase.

    Returns:
        List of PlaybookRef, sorted by phase (TRIAGE → CONTAINMENT →
        ERADICATION → RECOVERY), then alphabetically by title within each phase.
    """
    results = [
        ref for ref in RUNBOOK_REGISTRY
        if ref.applies_to(incident_type)
        and (phase is None or ref.phase == phase)
    ]
    results.sort(key=lambda r: (_PHASE_ORDER[r.phase], r.title))
    return results


def lookup_by_phase(phase: PlaybookPhase) -> list[PlaybookRef]:
    """
    Return all playbooks that cover a specific lifecycle phase, regardless
    of incident type.  Results are sorted alphabetically by title.

    Args:
        phase: The PlaybookPhase to look up.

    Returns:
        List of PlaybookRef sorted by title.
    """
    return sorted(
        [ref for ref in RUNBOOK_REGISTRY if ref.phase == phase],
        key=lambda r: r.title,
    )


def reverse_lookup(playbook_path: str) -> Optional[PlaybookRef]:
    """
    Find a PlaybookRef by its relative file path.

    Args:
        playbook_path: Path relative to the repo root
                       (e.g., 'playbooks/triage/initial_triage.md').

    Returns:
        The matching PlaybookRef, or None if not found.
    """
    for ref in RUNBOOK_REGISTRY:
        if ref.path == playbook_path:
            return ref
    return None


def playbooks_with_automation() -> list[PlaybookRef]:
    """
    Return all playbooks that have a companion automation script registered.
    Results are sorted by phase then title.
    """
    results = [ref for ref in RUNBOOK_REGISTRY if ref.automation_ref is not None]
    results.sort(key=lambda r: (_PHASE_ORDER[r.phase], r.title))
    return results


# ---------------------------------------------------------------------------
# RunbookXrefReport — structured output for xref_incident()
# ---------------------------------------------------------------------------

@dataclass
class RunbookXrefReport:
    """
    Phase-ordered cross-reference report for a specific incident.

    Attributes:
        incident_id:      The incident this report was generated for.
        incident_type:    The IncidentType used for the lookup.
        current_phase:    The lifecycle phase derived from the incident's status.
        by_phase:         Dict mapping PlaybookPhase → list of PlaybookRef
                          (only phases that have ≥1 applicable playbook are present).
        current_phase_refs: Shortcut — playbooks for the current phase only.
        all_refs:         Flat list of all applicable playbooks in phase order.
        has_automations:  True if any applicable playbook has an automation_ref.
    """
    incident_id:        str
    incident_type:      IncidentType
    current_phase:      PlaybookPhase
    by_phase:           dict[PlaybookPhase, list[PlaybookRef]] = field(
                            default_factory=dict)
    current_phase_refs: list[PlaybookRef]                      = field(
                            default_factory=list)
    all_refs:           list[PlaybookRef]                      = field(
                            default_factory=list)

    @property
    def has_automations(self) -> bool:
        return any(ref.automation_ref for ref in self.all_refs)

    def summary(self) -> str:
        """
        Return a human-readable summary of the cross-reference report.

        Example output::

            Incident INC-20260101-001 | Type: phishing | Phase: CONTAINMENT
            ─────────────────────────────────────────────────────────────────
            [TRIAGE] Initial Triage Checklist
                     playbooks/triage/initial_triage.md
            [TRIAGE] Incident Type Guide: Phishing
                     playbooks/incident-types/phishing.md
            [CONTAINMENT] ★ Containment: Compromised Credentials
                          playbooks/containment/compromised_credentials.md
                          automation: automations.identity.revoke_azure_sessions
        """
        lines: list[str] = [
            f"Incident {self.incident_id} | "
            f"Type: {self.incident_type.value} | "
            f"Phase: {self.current_phase.value.upper()}",
            "─" * 65,
        ]
        for ref in self.all_refs:
            phase_label = f"[{ref.phase.value.upper()}]"
            current_marker = " ★" if ref.phase == self.current_phase else ""
            lines.append(f"{phase_label}{current_marker} {ref.title}")
            lines.append(f"         {ref.path}")
            if ref.automation_ref:
                lines.append(f"         automation: {ref.automation_ref}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main cross-reference function
# ---------------------------------------------------------------------------

def xref_incident(incident: IncidentRecord) -> RunbookXrefReport:
    """
    Generate a phase-ordered runbook cross-reference report for an incident.

    The function:
      1. Derives the current lifecycle phase from the incident's status.
      2. Looks up all playbooks applicable to the incident type.
      3. Groups them by phase.
      4. Returns a RunbookXrefReport with convenient accessors.

    Args:
        incident: An IncidentRecord from schemas.incident.

    Returns:
        RunbookXrefReport with by_phase dict, current_phase_refs shortcut,
        and flat all_refs list (phase order: TRIAGE → CONTAINMENT →
        ERADICATION → RECOVERY).
    """
    current_phase = _STATUS_TO_PHASE.get(incident.status, PlaybookPhase.TRIAGE)
    all_refs      = lookup_playbooks(incident.incident_type)

    # Group by phase
    by_phase: dict[PlaybookPhase, list[PlaybookRef]] = {}
    for ref in all_refs:
        by_phase.setdefault(ref.phase, []).append(ref)

    current_phase_refs = by_phase.get(current_phase, [])

    return RunbookXrefReport(
        incident_id=incident.incident_id,
        incident_type=incident.incident_type,
        current_phase=current_phase,
        by_phase=by_phase,
        current_phase_refs=current_phase_refs,
        all_refs=all_refs,
    )
