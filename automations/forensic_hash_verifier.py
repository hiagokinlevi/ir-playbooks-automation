# forensic_hash_verifier.py
# Forensic artifact hash verification and chain-of-custody validator for incident response.
# Works offline on artifact metadata — no file I/O.
#
# Copyright (c) 2024 Cyber Port — hiagokinlevi
# Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
#
# SPDX-License-Identifier: CC-BY-4.0
#
# Checks implemented (FHV-001 through FHV-007):
#   FHV-001  Weak hash algorithm used               HIGH     weight=25
#   FHV-002  Hash mismatch (chain of custody broken) CRITICAL weight=45
#   FHV-003  Artifact collected too long after incident HIGH  weight=20
#   FHV-004  No chain-of-custody record              HIGH     weight=20
#   FHV-005  Artifact missing initial hash           HIGH     weight=20
#   FHV-006  Missing collector metadata              MEDIUM   weight=15
#   FHV-007  Chain of custody hash inconsistency     CRITICAL weight=40

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Check weights — drives risk_score calculation
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "FHV-001": 25,  # Weak hash algorithm
    "FHV-002": 45,  # Hash mismatch
    "FHV-003": 20,  # Collection delay too long
    "FHV-004": 20,  # No chain of custody
    "FHV-005": 20,  # Missing initial hash
    "FHV-006": 15,  # Missing collector metadata
    "FHV-007": 40,  # Custody hash inconsistency
}

# Default set of hash algorithms considered cryptographically weak for forensics
_DEFAULT_WEAK_HASH_ALGOS: List[str] = ["md5", "sha1", "crc32"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ChainOfCustodyEntry:
    """A single link in the forensic chain of custody."""
    custodian: str                        # Name/ID of who handled the evidence
    action: str                           # "collected" | "transferred" | "analyzed" | "stored"
    timestamp: float                      # Unix timestamp of the custody event
    hash_at_time: Optional[str] = None    # Hash value recorded at this custody step
    hash_algo: Optional[str] = None       # Algorithm used for hash_at_time

    def to_dict(self) -> dict:
        """Serialise the entry to a plain dictionary."""
        return {
            "custodian": self.custodian,
            "action": self.action,
            "timestamp": self.timestamp,
            "hash_at_time": self.hash_at_time,
            "hash_algo": self.hash_algo,
        }


@dataclass
class ForensicArtifact:
    """Metadata descriptor for a single forensic artifact."""
    artifact_id: str                                      # Unique artifact identifier
    name: str                                             # Human-readable artifact name
    artifact_type: str                                    # "memory-dump" | "disk-image" | "log-file" |
                                                          # "network-capture" | "process-dump" | "file"
    collection_timestamp: Optional[float] = None          # Unix ts when the artifact was collected
    incident_timestamp: Optional[float] = None            # Unix ts when the incident occurred
    original_hash: Optional[str] = None                  # Hash value at time of collection
    current_hash: Optional[str] = None                   # Hash value at time of verification
    hash_algo: Optional[str] = None                      # Algorithm used for original/current hash
    chain_of_custody: List[ChainOfCustodyEntry] = field(default_factory=list)
    collector_id: Optional[str] = None                   # Who collected the artifact
    is_compressed: bool = False
    is_encrypted: bool = False

    def to_dict(self) -> dict:
        """Serialise the artifact to a plain dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "collection_timestamp": self.collection_timestamp,
            "incident_timestamp": self.incident_timestamp,
            "original_hash": self.original_hash,
            "current_hash": self.current_hash,
            "hash_algo": self.hash_algo,
            "chain_of_custody": [e.to_dict() for e in self.chain_of_custody],
            "collector_id": self.collector_id,
            "is_compressed": self.is_compressed,
            "is_encrypted": self.is_encrypted,
        }


@dataclass
class HashVerifyFinding:
    """A single finding produced by a verification check."""
    check_id: str            # e.g. "FHV-001"
    severity: str            # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    artifact_id: str
    artifact_name: str
    message: str             # Human-readable description of the issue
    recommendation: str      # Remediation guidance

    def to_dict(self) -> dict:
        """Serialise the finding to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class HashVerifyResult:
    """Aggregated verification result for a single ForensicArtifact."""
    artifact_id: str
    artifact_name: str
    findings: List[HashVerifyFinding] = field(default_factory=list)
    risk_score: int = 0        # 0–100; higher = more risk
    integrity_score: int = 100 # 0–100; 100 - risk_score (inverse)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a single-line human-readable summary including both scores."""
        total = len(self.findings)
        severities = ", ".join(
            f"{sev}={count}"
            for sev, count in sorted(self.by_severity().items())
            if count > 0
        ) or "none"
        return (
            f"Artifact '{self.artifact_name}' ({self.artifact_id}): "
            f"{total} finding(s) [{severities}] — "
            f"risk_score={self.risk_score}/100, integrity_score={self.integrity_score}/100"
        )

    def by_severity(self) -> Dict[str, int]:
        """Return finding counts grouped by severity label."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        """Serialise the full result to a plain dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "integrity_score": self.integrity_score,
            "summary": self.summary(),
            "by_severity": self.by_severity(),
        }


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class ForensicHashVerifier:
    """
    Runs forensic hash-integrity and chain-of-custody checks against
    ForensicArtifact metadata entirely offline (no file I/O).

    Parameters
    ----------
    max_collection_delay_hours:
        Maximum acceptable gap (hours) between incident and collection.
        Defaults to 24 hours.
    weak_hash_algos:
        List of algorithm names (lowercase) considered weak for forensics.
        Defaults to ["md5", "sha1", "crc32"].
    """

    def __init__(
        self,
        max_collection_delay_hours: int = 24,
        weak_hash_algos: Optional[List[str]] = None,
    ) -> None:
        self._max_collection_delay_hours = max_collection_delay_hours
        # Normalise to lower-case for comparison
        self._weak_hash_algos: List[str] = (
            [a.lower() for a in weak_hash_algos]
            if weak_hash_algos is not None
            else list(_DEFAULT_WEAK_HASH_ALGOS)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, artifact: ForensicArtifact) -> HashVerifyResult:
        """
        Run all checks against a single ForensicArtifact and return a
        HashVerifyResult.  Findings are deduplicated by check_id so each
        check fires at most once per artifact.
        """
        findings: List[HashVerifyFinding] = []

        # Each check appends to findings if the condition is met.
        # Deduplication happens in _add_finding() — subsequent calls for
        # the same check_id on the same result are silently ignored.
        self._check_fhv001(artifact, findings)
        self._check_fhv002(artifact, findings)
        self._check_fhv003(artifact, findings)
        self._check_fhv004(artifact, findings)
        self._check_fhv005(artifact, findings)
        self._check_fhv006(artifact, findings)
        self._check_fhv007(artifact, findings)

        # Compute scores from unique fired check IDs
        fired_ids = {f.check_id for f in findings}
        raw_risk = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        risk_score = min(100, raw_risk)
        integrity_score = max(0, 100 - risk_score)

        return HashVerifyResult(
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            findings=findings,
            risk_score=risk_score,
            integrity_score=integrity_score,
        )

    def verify_many(self, artifacts: List[ForensicArtifact]) -> List[HashVerifyResult]:
        """Run verify() against each artifact in the list and return all results."""
        return [self.verify(a) for a in artifacts]

    # ------------------------------------------------------------------
    # Internal check helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _add_finding(
        findings: List[HashVerifyFinding],
        finding: HashVerifyFinding,
    ) -> None:
        """Append a finding, deduplicating by check_id (first one wins)."""
        existing_ids = {f.check_id for f in findings}
        if finding.check_id not in existing_ids:
            findings.append(finding)

    def _check_fhv001(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-001 — Weak hash algorithm detected (artifact-level or in custody chain)."""
        triggered = False

        # Check the primary artifact hash algorithm
        if artifact.hash_algo is not None:
            if artifact.hash_algo.lower() in self._weak_hash_algos:
                triggered = True

        # Check all custody-chain entries even if artifact-level already triggered
        if not triggered:
            for entry in artifact.chain_of_custody:
                if entry.hash_algo is not None and entry.hash_algo.lower() in self._weak_hash_algos:
                    triggered = True
                    break

        if triggered:
            self._add_finding(
                findings,
                HashVerifyFinding(
                    check_id="FHV-001",
                    severity="HIGH",
                    artifact_id=artifact.artifact_id,
                    artifact_name=artifact.name,
                    message=(
                        f"Weak hash algorithm detected for artifact '{artifact.name}'. "
                        f"Algorithms in use may include: {artifact.hash_algo or 'see custody chain'}."
                    ),
                    recommendation=(
                        "Replace weak algorithms (MD5, SHA-1, CRC32) with SHA-256 or stronger. "
                        "Re-hash the artifact with a cryptographically strong algorithm and update "
                        "all chain-of-custody records."
                    ),
                ),
            )

    def _check_fhv002(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-002 — Hash mismatch between original_hash and current_hash."""
        orig = artifact.original_hash
        curr = artifact.current_hash

        # Both must be non-empty strings for a meaningful comparison
        if orig and curr:
            if orig.lower().strip() != curr.lower().strip():
                self._add_finding(
                    findings,
                    HashVerifyFinding(
                        check_id="FHV-002",
                        severity="CRITICAL",
                        artifact_id=artifact.artifact_id,
                        artifact_name=artifact.name,
                        message=(
                            f"Hash mismatch for artifact '{artifact.name}': "
                            f"original_hash and current_hash differ, indicating possible tampering."
                        ),
                        recommendation=(
                            "Immediately quarantine the artifact. Investigate all custody-chain "
                            "transitions for unauthorised access or modification. Compare against "
                            "any backup copies to determine when the change occurred."
                        ),
                    ),
                )

    def _check_fhv003(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-003 — Collection occurred too long after the incident."""
        if artifact.collection_timestamp is None or artifact.incident_timestamp is None:
            return  # Cannot evaluate without both timestamps

        delay_seconds = artifact.collection_timestamp - artifact.incident_timestamp
        max_delay_seconds = self._max_collection_delay_hours * 3600

        if delay_seconds > max_delay_seconds:
            delay_hours = delay_seconds / 3600
            self._add_finding(
                findings,
                HashVerifyFinding(
                    check_id="FHV-003",
                    severity="HIGH",
                    artifact_id=artifact.artifact_id,
                    artifact_name=artifact.name,
                    message=(
                        f"Artifact '{artifact.name}' was collected {delay_hours:.1f} hours after "
                        f"the incident (max acceptable: {self._max_collection_delay_hours}h). "
                        f"Volatile evidence may have been lost or overwritten."
                    ),
                    recommendation=(
                        "Establish incident-response procedures that mandate evidence collection "
                        "within the acceptable window. Document reasons for any collection delay "
                        "and assess whether volatile evidence (RAM, swap) can still be recovered."
                    ),
                ),
            )

    def _check_fhv004(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-004 — No chain-of-custody record present."""
        if len(artifact.chain_of_custody) == 0:
            self._add_finding(
                findings,
                HashVerifyFinding(
                    check_id="FHV-004",
                    severity="HIGH",
                    artifact_id=artifact.artifact_id,
                    artifact_name=artifact.name,
                    message=(
                        f"Artifact '{artifact.name}' has no chain-of-custody entries. "
                        f"Evidence without custody tracking is typically inadmissible."
                    ),
                    recommendation=(
                        "Immediately create a retrospective custody record capturing collection "
                        "details, custodian IDs, timestamps, and hash values. Implement a mandatory "
                        "custody-logging workflow for all future evidence collection activities."
                    ),
                ),
            )

    def _check_fhv005(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-005 — Artifact is missing its initial (baseline) hash."""
        if not artifact.original_hash:  # Covers None and ""
            self._add_finding(
                findings,
                HashVerifyFinding(
                    check_id="FHV-005",
                    severity="HIGH",
                    artifact_id=artifact.artifact_id,
                    artifact_name=artifact.name,
                    message=(
                        f"Artifact '{artifact.name}' has no original (collection-time) hash. "
                        f"Without a baseline hash it is impossible to verify integrity."
                    ),
                    recommendation=(
                        "Hash the artifact immediately using SHA-256 or stronger, and record the "
                        "value as the baseline. If the artifact has already been processed, document "
                        "the absence of a baseline hash in all case notes."
                    ),
                ),
            )

    def _check_fhv006(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-006 — Collector identity or collection timestamp is missing."""
        missing_collector = not artifact.collector_id  # Covers None and ""
        missing_timestamp = artifact.collection_timestamp is None

        if missing_collector or missing_timestamp:
            details: List[str] = []
            if missing_collector:
                details.append("collector_id is missing")
            if missing_timestamp:
                details.append("collection_timestamp is missing")

            self._add_finding(
                findings,
                HashVerifyFinding(
                    check_id="FHV-006",
                    severity="MEDIUM",
                    artifact_id=artifact.artifact_id,
                    artifact_name=artifact.name,
                    message=(
                        f"Artifact '{artifact.name}' is missing collector metadata: "
                        f"{'; '.join(details)}."
                    ),
                    recommendation=(
                        "Record the identity of the collector and the exact collection timestamp "
                        "for every artifact. Use automated tooling (e.g., EDR, SIEM export) to "
                        "capture this metadata at acquisition time."
                    ),
                ),
            )

    def _check_fhv007(
        self,
        artifact: ForensicArtifact,
        findings: List[HashVerifyFinding],
    ) -> None:
        """FHV-007 — Consecutive custody entries disagree on the artifact hash."""
        custody = artifact.chain_of_custody

        # Need at least two entries to compare consecutive pairs
        if len(custody) < 2:
            return

        # Iterate pairs; fire (at most once) on the first inconsistency found
        for i in range(len(custody) - 1):
            entry_a = custody[i]
            entry_b = custody[i + 1]

            # Both entries must carry a hash for a meaningful comparison
            if entry_a.hash_at_time and entry_b.hash_at_time:
                if entry_a.hash_at_time.lower().strip() != entry_b.hash_at_time.lower().strip():
                    self._add_finding(
                        findings,
                        HashVerifyFinding(
                            check_id="FHV-007",
                            severity="CRITICAL",
                            artifact_id=artifact.artifact_id,
                            artifact_name=artifact.name,
                            message=(
                                f"Chain-of-custody hash inconsistency detected in artifact "
                                f"'{artifact.name}': entry {i} (custodian='{entry_a.custodian}', "
                                f"action='{entry_a.action}') and entry {i+1} "
                                f"(custodian='{entry_b.custodian}', action='{entry_b.action}') "
                                f"record different hashes."
                            ),
                            recommendation=(
                                "Immediately investigate both custody transitions to determine "
                                "whether the artifact was tampered with, corrupted, or incorrectly "
                                "hashed. Preserve all original custody records and escalate to the "
                                "incident commander for legal review."
                            ),
                        ),
                    )
                    return  # Deduplicate: only one FHV-007 finding per artifact
