# incident_correlation_engine.py
# Cyber Port Portfolio — IR Playbooks Automation
#
# CC BY 4.0 License
# Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
#
# You are free to share and adapt this material for any purpose, provided
# you give appropriate credit, provide a link to the license, and indicate
# if changes were made.
#
# Author: Cyber Port (github.com/hiagokinlevi)

"""
incident_correlation_engine.py
------------------------------
Correlate multiple security incidents to identify patterns:
  - Repeated attackers (same source IP across incidents)
  - Shared vulnerability identifiers (same CVE across incidents)
  - Critical unowned assets affected by incidents
  - Historical IOC matches against known-bad lists
  - Coordinated attack detection via overlapping time windows
  - Lack of containment action after threshold time
  - High fan-out incidents with many child/linked incidents

Check IDs:
  ICOR-001  Same source IP in >1 incident within 24 h window          HIGH      w=25
  ICOR-002  Same CVE referenced in >1 incident                         HIGH      w=25
  ICOR-003  Critical asset with no owner affected by incident          HIGH      w=25
  ICOR-004  IOC matches known historical bad IOC list                  CRITICAL  w=45
  ICOR-005  Overlapping time windows suggesting coordinated attack     HIGH      w=25
  ICOR-006  No containment action >4 h after detection                 HIGH      w=25
  ICOR-007  Incident has >5 child/linked incidents                     HIGH      w=20
"""

import time
from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Check weight registry — single source of truth for IDs, severities, titles
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, Dict] = {
    "ICOR-001": {
        "severity": "HIGH",
        "weight": 25,
        "title": "Repeated Source IP Across Incidents Within 24-Hour Window",
    },
    "ICOR-002": {
        "severity": "HIGH",
        "weight": 25,
        "title": "Same CVE Referenced in Multiple Incidents",
    },
    "ICOR-003": {
        "severity": "HIGH",
        "weight": 25,
        "title": "Critical Asset With No Owner Affected by Incident",
    },
    "ICOR-004": {
        "severity": "CRITICAL",
        "weight": 45,
        "title": "Incident IOC Matches Known Historical Bad IOC",
    },
    "ICOR-005": {
        "severity": "HIGH",
        "weight": 25,
        "title": "Overlapping Incident Time Windows Suggest Coordinated Attack",
    },
    "ICOR-006": {
        "severity": "HIGH",
        "weight": 25,
        "title": "No Containment Action Recorded More Than 4 Hours After Detection",
    },
    "ICOR-007": {
        "severity": "HIGH",
        "weight": 20,
        "title": "Incident Has More Than 5 Child or Linked Incidents",
    },
}

# Millisecond constants used in check logic
_MS_24H: int = 86_400_000       # 24 hours in milliseconds
_MS_4H: int = 14_400_000        # 4 hours in milliseconds
_MS_2H: int = 7_200_000         # 2 hours in milliseconds


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IncidentAsset:
    """Represents an asset affected by or relevant to a security incident."""

    asset_id: str
    asset_name: str
    criticality: str        # "critical", "high", "medium", "low"
    owner: Optional[str]    # None if the asset has no assigned owner


@dataclass
class Incident:
    """A single security incident record."""

    incident_id: str
    title: str
    detected_at_ms: int                 # Unix timestamp in milliseconds
    resolved_at_ms: Optional[int]       # None if not yet resolved
    source_ips: List[str]               # IP addresses of attack sources
    cve_ids: List[str]                  # CVE identifiers, e.g. "CVE-2024-12345"
    iocs: List[str]                     # IOC values: IPs, file hashes, domains
    affected_assets: List[IncidentAsset]
    containment_actions: List[str]      # Descriptions of containment steps taken
    child_incident_ids: List[str]       # IDs of related or child incidents
    severity: str                       # "CRITICAL", "HIGH", "MEDIUM", "LOW"


@dataclass
class ICORFinding:
    """A single correlation finding produced by a check."""

    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    incident_ids: List[str]     # Which incident IDs are involved in this finding


@dataclass
class ICORResult:
    """Aggregated result from correlating a set of incidents."""

    findings: List[ICORFinding]
    risk_score: int             # min(100, sum of weights for unique fired check IDs)
    correlation_summary: str    # Brief human-readable one-line summary

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise the result to a plain dictionary (JSON-safe types only)."""
        return {
            "risk_score": self.risk_score,
            "correlation_summary": self.correlation_summary,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "incident_ids": list(f.incident_ids),
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return the human-readable correlation summary string."""
        return self.correlation_summary

    def by_severity(self) -> Dict[str, List[ICORFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[ICORFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_finding(check_id: str, detail: str, incident_ids: List[str]) -> ICORFinding:
    """Construct an ICORFinding using the central _CHECK_WEIGHTS registry."""
    meta = _CHECK_WEIGHTS[check_id]
    return ICORFinding(
        check_id=check_id,
        severity=meta["severity"],
        title=meta["title"],
        detail=detail,
        weight=meta["weight"],
        incident_ids=incident_ids,
    )


def _compute_risk_score(findings: List[ICORFinding]) -> int:
    """
    Risk score = min(100, sum of weights for *unique* check IDs that fired.
    Multiple findings for the same check_id only count the weight once.
    """
    fired_ids: Set[str] = {f.check_id for f in findings}
    total = sum(_CHECK_WEIGHTS[cid]["weight"] for cid in fired_ids)
    return min(100, total)


def _build_summary(findings: List[ICORFinding], risk_score: int, incidents: List[Incident]) -> str:
    """Build the one-line correlation_summary string."""
    n_findings = len(findings)
    # Collect unique incident IDs involved across all findings
    involved: Set[str] = set()
    for f in findings:
        involved.update(f.incident_ids)
    n_incidents = len(involved)
    return (
        f"{n_findings} finding{'s' if n_findings != 1 else ''} "
        f"across {n_incidents} incident{'s' if n_incidents != 1 else ''} "
        f"— risk score {risk_score}"
    )


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _check_icor001(incidents: List[Incident]) -> List[ICORFinding]:
    """
    ICOR-001: Same source IP appears in >1 incident within a 24-hour window.
    For each source IP that appears in multiple incidents, verify whether any
    two of those incidents have detected_at_ms values within 86,400,000 ms
    (24 hours) of each other.  Fire one finding per qualifying IP.
    """
    findings: List[ICORFinding] = []

    # Build ip -> list of incidents map
    ip_map: Dict[str, List[Incident]] = {}
    for inc in incidents:
        for ip in inc.source_ips:
            ip_map.setdefault(ip, []).append(inc)

    for ip, inc_list in ip_map.items():
        if len(inc_list) < 2:
            continue
        # Sort by detection time; check all pairs for 24-h proximity
        sorted_incs = sorted(inc_list, key=lambda x: x.detected_at_ms)
        involved_ids: List[str] = []
        for i, j in combinations(sorted_incs, 2):
            delta = abs(j.detected_at_ms - i.detected_at_ms)
            if delta <= _MS_24H:
                # Record both; use a set to avoid duplicates within this IP
                for iid in (i.incident_id, j.incident_id):
                    if iid not in involved_ids:
                        involved_ids.append(iid)
        if involved_ids:
            detail = (
                f"Source IP {ip!r} appeared in {len(involved_ids)} incident(s) "
                f"within a 24-hour window: {', '.join(involved_ids)}"
            )
            findings.append(_make_finding("ICOR-001", detail, involved_ids))

    return findings


def _check_icor002(incidents: List[Incident]) -> List[ICORFinding]:
    """
    ICOR-002: Same CVE identifier referenced in >1 incident.
    Fire one finding per CVE that appears in multiple distinct incidents.
    """
    findings: List[ICORFinding] = []

    cve_map: Dict[str, List[Incident]] = {}
    for inc in incidents:
        seen_cves: Set[str] = set()
        for cve in inc.cve_ids:
            normalised = cve.upper().strip()
            if normalised not in seen_cves:
                cve_map.setdefault(normalised, []).append(inc)
                seen_cves.add(normalised)

    for cve, inc_list in cve_map.items():
        if len(inc_list) < 2:
            continue
        involved_ids = [i.incident_id for i in inc_list]
        detail = (
            f"CVE {cve!r} was referenced in {len(inc_list)} incident(s): "
            f"{', '.join(involved_ids)}"
        )
        findings.append(_make_finding("ICOR-002", detail, involved_ids))

    return findings


def _check_icor003(incidents: List[Incident]) -> List[ICORFinding]:
    """
    ICOR-003: Critical asset with no assigned owner affected by an incident.
    Fire one finding per (incident, asset) pair where criticality=='critical'
    and owner is None.  The check weight is counted only once in risk_score
    regardless of how many findings this check produces.
    """
    findings: List[ICORFinding] = []

    for inc in incidents:
        for asset in inc.affected_assets:
            if asset.criticality == "critical" and asset.owner is None:
                detail = (
                    f"Incident {inc.incident_id!r} affects critical asset "
                    f"{asset.asset_name!r} (id={asset.asset_id!r}) with no owner assigned."
                )
                findings.append(_make_finding("ICOR-003", detail, [inc.incident_id]))

    return findings


def _check_icor004(
    incidents: List[Incident],
    known_bad_set: Set[str],
) -> List[ICORFinding]:
    """
    ICOR-004: An IOC in the incident matches a known historical bad IOC list.
    Comparison is case-insensitive.  Fire one finding per (incident, IOC) pair.
    """
    findings: List[ICORFinding] = []

    for inc in incidents:
        for ioc in inc.iocs:
            if ioc.lower() in known_bad_set:
                detail = (
                    f"Incident {inc.incident_id!r} contains IOC {ioc!r} "
                    f"which matches a known historical bad indicator."
                )
                findings.append(_make_finding("ICOR-004", detail, [inc.incident_id]))

    return findings


def _check_icor005(incidents: List[Incident]) -> List[ICORFinding]:
    """
    ICOR-005: Two or more incidents have overlapping time windows, suggesting
    a coordinated attack.

    Overlap rules (checked for every ordered pair (i, j) where i != j):
      1. If i has a resolved_at_ms:
            i.detected_at_ms <= j.detected_at_ms <= i.resolved_at_ms
      2. If neither i nor j has a resolved_at_ms (both ongoing):
            |i.detected_at_ms - j.detected_at_ms| <= 2 hours

    Fire one finding per unordered overlapping pair.
    """
    findings: List[ICORFinding] = []

    for i, j in combinations(incidents, 2):
        overlaps = False

        # Rule 1a: j starts within i's resolved window
        if i.resolved_at_ms is not None:
            if i.detected_at_ms <= j.detected_at_ms <= i.resolved_at_ms:
                overlaps = True

        # Rule 1b: i starts within j's resolved window
        if not overlaps and j.resolved_at_ms is not None:
            if j.detected_at_ms <= i.detected_at_ms <= j.resolved_at_ms:
                overlaps = True

        # Rule 2: Both unresolved and started within 2 hours of each other
        if not overlaps and i.resolved_at_ms is None and j.resolved_at_ms is None:
            delta = abs(i.detected_at_ms - j.detected_at_ms)
            if delta <= _MS_2H:
                overlaps = True

        if overlaps:
            detail = (
                f"Incidents {i.incident_id!r} and {j.incident_id!r} have "
                f"overlapping time windows, suggesting a coordinated attack."
            )
            findings.append(
                _make_finding("ICOR-005", detail, [i.incident_id, j.incident_id])
            )

    return findings


def _check_icor006(
    incidents: List[Incident],
    reference_time_ms: int,
) -> List[ICORFinding]:
    """
    ICOR-006: No containment action recorded more than 4 hours after detection.
    Collect all qualifying incidents into a single consolidated finding.
    """
    uncontained: List[Incident] = []

    for inc in incidents:
        if len(inc.containment_actions) == 0:
            elapsed = reference_time_ms - inc.detected_at_ms
            if elapsed > _MS_4H:
                uncontained.append(inc)

    if not uncontained:
        return []

    involved_ids = [inc.incident_id for inc in uncontained]
    detail = (
        f"{len(uncontained)} incident(s) have no containment actions recorded "
        f"more than 4 hours after detection: {', '.join(involved_ids)}"
    )
    return [_make_finding("ICOR-006", detail, involved_ids)]


def _check_icor007(incidents: List[Incident]) -> List[ICORFinding]:
    """
    ICOR-007: Incident has more than 5 child or linked incidents.
    Fire one finding per incident where len(child_incident_ids) > 5.
    """
    findings: List[ICORFinding] = []

    for inc in incidents:
        count = len(inc.child_incident_ids)
        if count > 5:
            detail = (
                f"Incident {inc.incident_id!r} has {count} child/linked incidents, "
                f"exceeding the threshold of 5."
            )
            findings.append(_make_finding("ICOR-007", detail, [inc.incident_id]))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate(
    incidents: List[Incident],
    known_bad_iocs: Optional[List[str]] = None,
    reference_time_ms: Optional[int] = None,
) -> ICORResult:
    """
    Correlate a list of incidents and produce correlation findings.

    Parameters
    ----------
    incidents : List[Incident]
        The incidents to analyse.
    known_bad_iocs : Optional[List[str]]
        A list of known-bad IOC values used for ICOR-004 matching.
        Comparison is case-insensitive.  Pass None or empty list to skip.
    reference_time_ms : Optional[int]
        Reference timestamp in Unix milliseconds used as "now" for ICOR-006.
        Defaults to the current wall-clock time when not provided.

    Returns
    -------
    ICORResult
        Aggregated findings, risk score, and correlation summary.
    """
    if reference_time_ms is None:
        reference_time_ms = int(time.time() * 1000)

    # Normalise known_bad_iocs to a lowercase set for O(1) lookup
    known_bad_set: Set[str] = set()
    if known_bad_iocs:
        known_bad_set = {ioc.lower() for ioc in known_bad_iocs}

    # Run all checks and collect findings
    findings: List[ICORFinding] = []
    findings.extend(_check_icor001(incidents))
    findings.extend(_check_icor002(incidents))
    findings.extend(_check_icor003(incidents))
    findings.extend(_check_icor004(incidents, known_bad_set))
    findings.extend(_check_icor005(incidents))
    findings.extend(_check_icor006(incidents, reference_time_ms))
    findings.extend(_check_icor007(incidents))

    risk_score = _compute_risk_score(findings)
    correlation_summary = _build_summary(findings, risk_score, incidents)

    return ICORResult(
        findings=findings,
        risk_score=risk_score,
        correlation_summary=correlation_summary,
    )


def correlate_incremental(
    new_incidents: List[Incident],
    historical_incidents: List[Incident],
    known_bad_iocs: Optional[List[str]] = None,
    reference_time_ms: Optional[int] = None,
) -> ICORResult:
    """
    Correlate new incidents against a historical baseline.

    The combined pool of new + historical incidents is fed through the same
    correlation engine, but only findings that involve at least one incident
    from `new_incidents` are returned.  This lets callers surface only the
    actionable, net-new correlations while still benefiting from historical
    context (e.g. a source IP that appeared in old incidents but is now
    appearing again in a new incident will still trigger ICOR-001).

    Parameters
    ----------
    new_incidents : List[Incident]
        Freshly ingested incidents to evaluate.
    historical_incidents : List[Incident]
        Previously analysed incidents used for baseline context.
    known_bad_iocs : Optional[List[str]]
        Known-bad IOC list forwarded to the core correlator.
    reference_time_ms : Optional[int]
        Reference time forwarded to the core correlator.

    Returns
    -------
    ICORResult
        Findings relevant to the new incidents, with risk score and summary
        computed over those filtered findings only.
    """
    all_incidents = list(new_incidents) + list(historical_incidents)
    new_ids: Set[str] = {inc.incident_id for inc in new_incidents}

    # Run full correlation on the combined pool
    full_result = correlate(
        incidents=all_incidents,
        known_bad_iocs=known_bad_iocs,
        reference_time_ms=reference_time_ms,
    )

    # Keep only findings that reference at least one new incident
    filtered_findings = [
        f for f in full_result.findings
        if any(iid in new_ids for iid in f.incident_ids)
    ]

    risk_score = _compute_risk_score(filtered_findings)
    correlation_summary = _build_summary(filtered_findings, risk_score, new_incidents)

    return ICORResult(
        findings=filtered_findings,
        risk_score=risk_score,
        correlation_summary=correlation_summary,
    )
