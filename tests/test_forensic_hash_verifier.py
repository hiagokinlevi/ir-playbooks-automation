# test_forensic_hash_verifier.py
# Test suite for ForensicHashVerifier — 90+ tests covering all checks,
# edge-cases, scoring, serialisation, and convenience methods.
#
# Copyright (c) 2024 Cyber Port — hiagokinlevi
# Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
#
# Run:  python3 -m pytest tests/test_forensic_hash_verifier.py --override-ini="addopts=" -q

from __future__ import annotations

import sys
import os
import time

import pytest

# ---------------------------------------------------------------------------
# Path setup — allows running from repo root or tests/ directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "automations"))

from forensic_hash_verifier import (
    ChainOfCustodyEntry,
    ForensicArtifact,
    ForensicHashVerifier,
    HashVerifyFinding,
    HashVerifyResult,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

NOW = 1_700_000_000.0          # Arbitrary fixed epoch for determinism
INCIDENT_TS = NOW - 3600.0     # 1 hour before "now"
COLLECTION_TS = NOW             # Collected exactly at NOW (1 h after incident)


def _clean_entry(custodian: str = "analyst-01", action: str = "collected") -> ChainOfCustodyEntry:
    """Return a single custody entry with a strong hash — no issues."""
    return ChainOfCustodyEntry(
        custodian=custodian,
        action=action,
        timestamp=COLLECTION_TS,
        hash_at_time="abc123deadbeef" * 4,
        hash_algo="sha256",
    )


def _pristine_artifact(**overrides) -> ForensicArtifact:
    """
    Build a fully-populated, clean artifact.  All fields are set, hashes
    match, collection is within 24 h of the incident, and there is one
    custody entry.  Pass keyword overrides to mutate specific fields.
    """
    base = dict(
        artifact_id="art-001",
        name="memory.dmp",
        artifact_type="memory-dump",
        collection_timestamp=COLLECTION_TS,
        incident_timestamp=INCIDENT_TS,
        original_hash="aabbccdd" * 8,
        current_hash="aabbccdd" * 8,
        hash_algo="sha256",
        chain_of_custody=[_clean_entry()],
        collector_id="analyst-01",
        is_compressed=False,
        is_encrypted=False,
    )
    base.update(overrides)
    # chain_of_custody needs to remain a list — convert if caller passes a list
    return ForensicArtifact(**base)


def _verifier(**kwargs) -> ForensicHashVerifier:
    return ForensicHashVerifier(**kwargs)


def _check_ids(result: HashVerifyResult):
    return {f.check_id for f in result.findings}


# ===========================================================================
# 1. Pristine artifact — expect zero findings
# ===========================================================================

class TestPristineArtifact:
    def test_no_findings(self):
        result = _verifier().verify(_pristine_artifact())
        assert result.findings == []

    def test_integrity_score_100(self):
        result = _verifier().verify(_pristine_artifact())
        assert result.integrity_score == 100

    def test_risk_score_0(self):
        result = _verifier().verify(_pristine_artifact())
        assert result.risk_score == 0


# ===========================================================================
# 2. FHV-001 — Weak hash algorithm
# ===========================================================================

class TestFHV001WeakHashAlgorithm:
    def test_md5_triggers(self):
        art = _pristine_artifact(hash_algo="md5")
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_sha1_triggers(self):
        art = _pristine_artifact(hash_algo="sha1")
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_crc32_triggers(self):
        art = _pristine_artifact(hash_algo="crc32")
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_sha256_does_not_trigger(self):
        art = _pristine_artifact(hash_algo="sha256")
        assert "FHV-001" not in _check_ids(_verifier().verify(art))

    def test_sha512_does_not_trigger(self):
        art = _pristine_artifact(hash_algo="sha512")
        assert "FHV-001" not in _check_ids(_verifier().verify(art))

    def test_none_algo_does_not_trigger(self):
        # hash_algo=None means algorithm not recorded; FHV-001 must not fire
        art = _pristine_artifact(hash_algo=None)
        assert "FHV-001" not in _check_ids(_verifier().verify(art))

    def test_weak_algo_in_custody_entry_triggers(self):
        entry = ChainOfCustodyEntry(
            custodian="analyst-01", action="collected",
            timestamp=COLLECTION_TS, hash_at_time="deadbeef", hash_algo="md5"
        )
        art = _pristine_artifact(hash_algo="sha256", chain_of_custody=[entry])
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_sha1_in_custody_entry_triggers(self):
        entry = ChainOfCustodyEntry(
            custodian="analyst-01", action="transferred",
            timestamp=COLLECTION_TS, hash_at_time="aabbcc", hash_algo="sha1"
        )
        art = _pristine_artifact(hash_algo="sha256", chain_of_custody=[entry])
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_strong_algo_in_custody_entry_does_not_trigger(self):
        entry = ChainOfCustodyEntry(
            custodian="analyst-01", action="collected",
            timestamp=COLLECTION_TS, hash_at_time="deadbeef", hash_algo="sha256"
        )
        art = _pristine_artifact(hash_algo="sha256", chain_of_custody=[entry])
        assert "FHV-001" not in _check_ids(_verifier().verify(art))

    def test_custom_weak_hash_algos_triggers(self):
        # whirlpool added as custom weak algo
        art = _pristine_artifact(hash_algo="whirlpool")
        result = _verifier(weak_hash_algos=["whirlpool"]).verify(art)
        assert "FHV-001" in _check_ids(result)

    def test_custom_weak_hash_algos_excludes_md5(self):
        # If custom list does not include md5, md5 should NOT trigger FHV-001
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier(weak_hash_algos=["crc32"]).verify(art)
        assert "FHV-001" not in _check_ids(result)

    def test_case_insensitive_algo_match(self):
        art = _pristine_artifact(hash_algo="MD5")
        assert "FHV-001" in _check_ids(_verifier().verify(art))

    def test_severity_is_high(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-001")
        assert finding.severity == "HIGH"


# ===========================================================================
# 3. FHV-002 — Hash mismatch
# ===========================================================================

class TestFHV002HashMismatch:
    def test_different_hashes_triggers(self):
        art = _pristine_artifact(original_hash="aaa", current_hash="bbb")
        assert "FHV-002" in _check_ids(_verifier().verify(art))

    def test_same_hashes_do_not_trigger(self):
        h = "aabbccdd" * 8
        art = _pristine_artifact(original_hash=h, current_hash=h)
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_case_normalisation(self):
        # Uppercase vs lowercase of same value — should NOT trigger
        h = "AABBCCDD"
        art = _pristine_artifact(original_hash=h.upper(), current_hash=h.lower())
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_whitespace_normalisation(self):
        h = "aabbccdd"
        art = _pristine_artifact(original_hash=f"  {h}  ", current_hash=h)
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_one_none_does_not_trigger(self):
        art = _pristine_artifact(original_hash="aabbccdd", current_hash=None)
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_both_none_does_not_trigger(self):
        art = _pristine_artifact(original_hash=None, current_hash=None)
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_empty_original_does_not_trigger(self):
        art = _pristine_artifact(original_hash="", current_hash="aabbccdd")
        assert "FHV-002" not in _check_ids(_verifier().verify(art))

    def test_severity_is_critical(self):
        art = _pristine_artifact(original_hash="aaa", current_hash="bbb")
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-002")
        assert finding.severity == "CRITICAL"


# ===========================================================================
# 4. FHV-003 — Collection delay too long
# ===========================================================================

class TestFHV003CollectionDelay:
    def test_exceeds_delay_triggers(self):
        # Incident at 0, collected 25 h later (default max=24 h)
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=25 * 3600.0,
        )
        assert "FHV-003" in _check_ids(_verifier().verify(art))

    def test_within_delay_does_not_trigger(self):
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=23 * 3600.0,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))

    def test_exactly_at_limit_does_not_trigger(self):
        # Exactly 24 h — not strictly greater than, so should NOT trigger
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=24 * 3600.0,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))

    def test_collection_timestamp_none_does_not_trigger(self):
        art = _pristine_artifact(
            collection_timestamp=None,
            incident_timestamp=0.0,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))

    def test_incident_timestamp_none_does_not_trigger(self):
        art = _pristine_artifact(
            collection_timestamp=25 * 3600.0,
            incident_timestamp=None,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))

    def test_both_timestamps_none_does_not_trigger(self):
        art = _pristine_artifact(
            collection_timestamp=None,
            incident_timestamp=None,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))

    def test_custom_max_delay_triggers(self):
        # Max delay set to 1 h; collected 2 h after incident
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=2 * 3600.0,
        )
        result = _verifier(max_collection_delay_hours=1).verify(art)
        assert "FHV-003" in _check_ids(result)

    def test_custom_max_delay_does_not_trigger(self):
        # Max delay set to 48 h; collected 25 h after incident
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=25 * 3600.0,
        )
        result = _verifier(max_collection_delay_hours=48).verify(art)
        assert "FHV-003" not in _check_ids(result)

    def test_severity_is_high(self):
        art = _pristine_artifact(
            incident_timestamp=0.0,
            collection_timestamp=25 * 3600.0,
        )
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-003")
        assert finding.severity == "HIGH"


# ===========================================================================
# 5. FHV-004 — No chain of custody
# ===========================================================================

class TestFHV004NoCustodyChain:
    def test_empty_chain_triggers(self):
        art = _pristine_artifact(chain_of_custody=[])
        assert "FHV-004" in _check_ids(_verifier().verify(art))

    def test_one_entry_does_not_trigger(self):
        art = _pristine_artifact(chain_of_custody=[_clean_entry()])
        assert "FHV-004" not in _check_ids(_verifier().verify(art))

    def test_multiple_entries_does_not_trigger(self):
        art = _pristine_artifact(
            chain_of_custody=[_clean_entry("analyst-01"), _clean_entry("analyst-02")]
        )
        assert "FHV-004" not in _check_ids(_verifier().verify(art))

    def test_severity_is_high(self):
        art = _pristine_artifact(chain_of_custody=[])
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-004")
        assert finding.severity == "HIGH"


# ===========================================================================
# 6. FHV-005 — Missing initial hash
# ===========================================================================

class TestFHV005MissingInitialHash:
    def test_none_original_hash_triggers(self):
        art = _pristine_artifact(original_hash=None)
        assert "FHV-005" in _check_ids(_verifier().verify(art))

    def test_empty_string_original_hash_triggers(self):
        art = _pristine_artifact(original_hash="")
        assert "FHV-005" in _check_ids(_verifier().verify(art))

    def test_set_original_hash_does_not_trigger(self):
        art = _pristine_artifact(original_hash="aabbccdd" * 8)
        assert "FHV-005" not in _check_ids(_verifier().verify(art))

    def test_severity_is_high(self):
        art = _pristine_artifact(original_hash=None)
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-005")
        assert finding.severity == "HIGH"


# ===========================================================================
# 7. FHV-006 — Missing collector metadata
# ===========================================================================

class TestFHV006MissingCollectorMetadata:
    def test_none_collector_id_triggers(self):
        art = _pristine_artifact(collector_id=None)
        assert "FHV-006" in _check_ids(_verifier().verify(art))

    def test_empty_collector_id_triggers(self):
        art = _pristine_artifact(collector_id="")
        assert "FHV-006" in _check_ids(_verifier().verify(art))

    def test_none_collection_timestamp_triggers(self):
        art = _pristine_artifact(collection_timestamp=None)
        assert "FHV-006" in _check_ids(_verifier().verify(art))

    def test_both_set_does_not_trigger(self):
        art = _pristine_artifact(collector_id="analyst-01", collection_timestamp=COLLECTION_TS)
        assert "FHV-006" not in _check_ids(_verifier().verify(art))

    def test_severity_is_medium(self):
        art = _pristine_artifact(collector_id=None)
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-006")
        assert finding.severity == "MEDIUM"


# ===========================================================================
# 8. FHV-007 — Chain-of-custody hash inconsistency
# ===========================================================================

class TestFHV007CustodyHashInconsistency:
    def _make_entry(self, custodian: str, h: str, action: str = "transferred") -> ChainOfCustodyEntry:
        return ChainOfCustodyEntry(
            custodian=custodian,
            action=action,
            timestamp=COLLECTION_TS,
            hash_at_time=h,
            hash_algo="sha256",
        )

    def test_different_consecutive_hashes_triggers(self):
        entries = [
            self._make_entry("analyst-01", "aaaa", action="collected"),
            self._make_entry("analyst-02", "bbbb"),
        ]
        art = _pristine_artifact(chain_of_custody=entries)
        assert "FHV-007" in _check_ids(_verifier().verify(art))

    def test_same_consecutive_hashes_do_not_trigger(self):
        h = "aabbccdd" * 4
        entries = [
            self._make_entry("analyst-01", h, action="collected"),
            self._make_entry("analyst-02", h),
        ]
        art = _pristine_artifact(chain_of_custody=entries)
        assert "FHV-007" not in _check_ids(_verifier().verify(art))

    def test_only_one_entry_has_hash_does_not_trigger(self):
        entry_a = ChainOfCustodyEntry(
            custodian="analyst-01", action="collected",
            timestamp=COLLECTION_TS, hash_at_time="aaaa", hash_algo="sha256"
        )
        entry_b = ChainOfCustodyEntry(
            custodian="analyst-02", action="transferred",
            timestamp=COLLECTION_TS, hash_at_time=None, hash_algo=None
        )
        art = _pristine_artifact(chain_of_custody=[entry_a, entry_b])
        assert "FHV-007" not in _check_ids(_verifier().verify(art))

    def test_single_entry_does_not_trigger(self):
        entry = self._make_entry("analyst-01", "aaaa", action="collected")
        art = _pristine_artifact(chain_of_custody=[entry])
        assert "FHV-007" not in _check_ids(_verifier().verify(art))

    def test_fires_only_once_per_artifact(self):
        # Three entries with two hash mismatches — should still produce only one finding
        entries = [
            self._make_entry("a1", "aaaa", action="collected"),
            self._make_entry("a2", "bbbb"),
            self._make_entry("a3", "cccc"),
        ]
        art = _pristine_artifact(chain_of_custody=entries)
        result = _verifier().verify(art)
        fhv007_findings = [f for f in result.findings if f.check_id == "FHV-007"]
        assert len(fhv007_findings) == 1

    def test_severity_is_critical(self):
        entries = [
            self._make_entry("analyst-01", "aaaa", action="collected"),
            self._make_entry("analyst-02", "bbbb"),
        ]
        art = _pristine_artifact(chain_of_custody=entries)
        result = _verifier().verify(art)
        finding = next(f for f in result.findings if f.check_id == "FHV-007")
        assert finding.severity == "CRITICAL"

    def test_case_insensitive_hash_comparison(self):
        # AAAA and aaaa are the same hash — must NOT trigger
        h_upper = "AABBCCDD"
        h_lower = "aabbccdd"
        entries = [
            self._make_entry("analyst-01", h_upper, action="collected"),
            self._make_entry("analyst-02", h_lower),
        ]
        art = _pristine_artifact(chain_of_custody=entries)
        assert "FHV-007" not in _check_ids(_verifier().verify(art))


# ===========================================================================
# 9. Scoring mechanics
# ===========================================================================

class TestScoringMechanics:
    def test_integrity_score_is_inverse_of_risk(self):
        art = _pristine_artifact(hash_algo="md5")  # FHV-001 weight=25
        result = _verifier().verify(art)
        assert result.integrity_score == 100 - result.risk_score

    def test_integrity_score_never_below_zero(self):
        # Fire every possible check at once
        entries = [
            ChainOfCustodyEntry("a1", "collected", 0.0, "aaaa", "md5"),
            ChainOfCustodyEntry("a2", "transferred", 1.0, "bbbb", "sha1"),
        ]
        art = ForensicArtifact(
            artifact_id="art-max",
            name="max-risk.dmp",
            artifact_type="memory-dump",
            collection_timestamp=50 * 3600.0,   # FHV-003
            incident_timestamp=0.0,
            original_hash="aaa",
            current_hash="bbb",                  # FHV-002
            hash_algo="md5",                     # FHV-001
            chain_of_custody=entries,            # FHV-007
            collector_id=None,                   # FHV-006
        )
        # FHV-005 not triggered (original_hash is set); FHV-004 not triggered (has entries)
        result = _verifier().verify(art)
        assert result.integrity_score >= 0

    def test_risk_score_capped_at_100(self):
        # Trigger all 7 checks; sum of weights > 100
        total = sum(_CHECK_WEIGHTS.values())
        assert total > 100, "pre-condition: weights must sum to > 100"
        entries = [
            ChainOfCustodyEntry("a1", "collected", 0.0, "aaaa", "md5"),
            ChainOfCustodyEntry("a2", "transferred", 1.0, "bbbb", "sha1"),
        ]
        art = ForensicArtifact(
            artifact_id="art-cap",
            name="cap.dmp",
            artifact_type="memory-dump",
            collection_timestamp=50 * 3600.0,
            incident_timestamp=0.0,
            original_hash=None,                  # FHV-005
            current_hash=None,
            hash_algo="md5",                     # FHV-001
            chain_of_custody=entries,            # FHV-001 (chain), FHV-007
            collector_id=None,                   # FHV-006
        )
        result = _verifier().verify(art)
        assert result.risk_score <= 100

    def test_multiple_distinct_checks_accumulate_weight(self):
        # FHV-001 (25) + FHV-005 (20) should produce risk_score >= 45 (if no cap)
        art = _pristine_artifact(hash_algo="md5", original_hash=None)
        result = _verifier().verify(art)
        fired = _check_ids(result)
        expected = sum(_CHECK_WEIGHTS[c] for c in fired)
        assert result.risk_score == min(100, expected)

    def test_check_weights_dict_has_all_seven_checks(self):
        assert set(_CHECK_WEIGHTS.keys()) == {
            "FHV-001", "FHV-002", "FHV-003", "FHV-004",
            "FHV-005", "FHV-006", "FHV-007",
        }

    def test_zero_findings_gives_risk_zero_integrity_hundred(self):
        result = _verifier().verify(_pristine_artifact())
        assert result.risk_score == 0
        assert result.integrity_score == 100


# ===========================================================================
# 10. by_severity() method
# ===========================================================================

class TestBySeverity:
    def test_empty_findings_returns_empty_dict(self):
        result = _verifier().verify(_pristine_artifact())
        assert result.by_severity() == {}

    def test_high_finding_counted(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        by_sev = result.by_severity()
        assert by_sev.get("HIGH", 0) >= 1

    def test_critical_finding_counted(self):
        art = _pristine_artifact(original_hash="aaa", current_hash="bbb")
        result = _verifier().verify(art)
        by_sev = result.by_severity()
        assert by_sev.get("CRITICAL", 0) >= 1

    def test_mixed_severities(self):
        # FHV-002 (CRITICAL) + FHV-006 (MEDIUM)
        art = _pristine_artifact(
            original_hash="aaa",
            current_hash="bbb",
            collector_id=None,
        )
        result = _verifier().verify(art)
        by_sev = result.by_severity()
        assert by_sev.get("CRITICAL", 0) >= 1
        assert by_sev.get("MEDIUM", 0) >= 1

    def test_returns_dict_type(self):
        result = _verifier().verify(_pristine_artifact(hash_algo="md5"))
        assert isinstance(result.by_severity(), dict)

    def test_counts_sum_to_total_findings(self):
        art = _pristine_artifact(
            hash_algo="md5",
            original_hash="aaa",
            current_hash="bbb",
            collector_id=None,
        )
        result = _verifier().verify(art)
        assert sum(result.by_severity().values()) == len(result.findings)


# ===========================================================================
# 11. summary() method
# ===========================================================================

class TestSummaryMethod:
    def test_contains_risk_score(self):
        result = _verifier().verify(_pristine_artifact())
        assert "risk_score=0" in result.summary()

    def test_contains_integrity_score(self):
        result = _verifier().verify(_pristine_artifact())
        assert "integrity_score=100" in result.summary()

    def test_contains_artifact_name(self):
        result = _verifier().verify(_pristine_artifact())
        assert "memory.dmp" in result.summary()

    def test_contains_artifact_id(self):
        result = _verifier().verify(_pristine_artifact())
        assert "art-001" in result.summary()

    def test_nonzero_scores_reflected(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        summary = result.summary()
        assert f"risk_score={result.risk_score}" in summary
        assert f"integrity_score={result.integrity_score}" in summary

    def test_returns_str(self):
        result = _verifier().verify(_pristine_artifact())
        assert isinstance(result.summary(), str)


# ===========================================================================
# 12. verify_many()
# ===========================================================================

class TestVerifyMany:
    def test_returns_list(self):
        arts = [_pristine_artifact(), _pristine_artifact(artifact_id="art-002", name="disk.img")]
        results = _verifier().verify_many(arts)
        assert isinstance(results, list)

    def test_length_matches_input(self):
        arts = [
            _pristine_artifact(artifact_id=f"art-{i}", name=f"art-{i}.dmp")
            for i in range(5)
        ]
        results = _verifier().verify_many(arts)
        assert len(results) == 5

    def test_empty_list_returns_empty_list(self):
        assert _verifier().verify_many([]) == []

    def test_results_are_hash_verify_result_instances(self):
        arts = [_pristine_artifact()]
        results = _verifier().verify_many(arts)
        assert all(isinstance(r, HashVerifyResult) for r in results)

    def test_each_result_maps_to_correct_artifact(self):
        arts = [
            _pristine_artifact(artifact_id="a1", name="first.dmp"),
            _pristine_artifact(artifact_id="a2", name="second.dmp"),
        ]
        results = _verifier().verify_many(arts)
        assert results[0].artifact_id == "a1"
        assert results[1].artifact_id == "a2"


# ===========================================================================
# 13. to_dict() serialisation
# ===========================================================================

class TestToDictMethods:
    # -- ChainOfCustodyEntry --
    def test_custody_entry_to_dict_keys(self):
        entry = _clean_entry()
        d = entry.to_dict()
        assert set(d.keys()) == {"custodian", "action", "timestamp", "hash_at_time", "hash_algo"}

    def test_custody_entry_to_dict_values(self):
        entry = ChainOfCustodyEntry(
            custodian="alice", action="collected", timestamp=1.0,
            hash_at_time="abc", hash_algo="sha256"
        )
        d = entry.to_dict()
        assert d["custodian"] == "alice"
        assert d["hash_algo"] == "sha256"

    # -- ForensicArtifact --
    def test_artifact_to_dict_keys(self):
        art = _pristine_artifact()
        d = art.to_dict()
        expected_keys = {
            "artifact_id", "name", "artifact_type", "collection_timestamp",
            "incident_timestamp", "original_hash", "current_hash", "hash_algo",
            "chain_of_custody", "collector_id", "is_compressed", "is_encrypted",
        }
        assert set(d.keys()) == expected_keys

    def test_artifact_to_dict_chain_is_list_of_dicts(self):
        art = _pristine_artifact()
        d = art.to_dict()
        assert isinstance(d["chain_of_custody"], list)
        assert all(isinstance(e, dict) for e in d["chain_of_custody"])

    # -- HashVerifyFinding --
    def test_finding_to_dict_keys(self):
        finding = HashVerifyFinding(
            check_id="FHV-001", severity="HIGH",
            artifact_id="art-001", artifact_name="memory.dmp",
            message="Test message", recommendation="Test recommendation",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "artifact_id", "artifact_name",
            "message", "recommendation",
        }

    def test_finding_to_dict_values(self):
        finding = HashVerifyFinding(
            check_id="FHV-002", severity="CRITICAL",
            artifact_id="art-002", artifact_name="disk.img",
            message="msg", recommendation="rec",
        )
        d = finding.to_dict()
        assert d["check_id"] == "FHV-002"
        assert d["severity"] == "CRITICAL"

    # -- HashVerifyResult --
    def test_result_to_dict_keys(self):
        result = _verifier().verify(_pristine_artifact())
        d = result.to_dict()
        assert set(d.keys()) == {
            "artifact_id", "artifact_name", "findings",
            "risk_score", "integrity_score", "summary", "by_severity",
        }

    def test_result_to_dict_findings_is_list(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_result_to_dict_findings_are_dicts(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_result_to_dict_summary_is_str(self):
        result = _verifier().verify(_pristine_artifact())
        d = result.to_dict()
        assert isinstance(d["summary"], str)

    def test_result_to_dict_by_severity_is_dict(self):
        result = _verifier().verify(_pristine_artifact(hash_algo="md5"))
        d = result.to_dict()
        assert isinstance(d["by_severity"], dict)

    def test_result_to_dict_scores_are_ints(self):
        result = _verifier().verify(_pristine_artifact())
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)
        assert isinstance(d["integrity_score"], int)


# ===========================================================================
# 14. Finding metadata correctness
# ===========================================================================

class TestFindingMetadata:
    def test_finding_carries_correct_artifact_id(self):
        art = _pristine_artifact(artifact_id="art-xyz", hash_algo="md5")
        result = _verifier().verify(art)
        for f in result.findings:
            assert f.artifact_id == "art-xyz"

    def test_finding_carries_correct_artifact_name(self):
        art = _pristine_artifact(name="my-artifact.raw", hash_algo="md5")
        result = _verifier().verify(art)
        for f in result.findings:
            assert f.artifact_name == "my-artifact.raw"

    def test_each_finding_has_non_empty_message(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        for f in result.findings:
            assert len(f.message.strip()) > 0

    def test_each_finding_has_non_empty_recommendation(self):
        art = _pristine_artifact(hash_algo="md5")
        result = _verifier().verify(art)
        for f in result.findings:
            assert len(f.recommendation.strip()) > 0


# ===========================================================================
# 15. Edge cases / boundary conditions
# ===========================================================================

class TestEdgeCases:
    def test_artifact_with_no_optional_fields_at_all(self):
        """Minimal artifact — only required fields."""
        art = ForensicArtifact(
            artifact_id="min-001",
            name="minimal",
            artifact_type="file",
        )
        result = _verifier().verify(art)
        # FHV-004, FHV-005, FHV-006 should fire; no crash
        fired = _check_ids(result)
        assert "FHV-004" in fired
        assert "FHV-005" in fired
        assert "FHV-006" in fired

    def test_deduplication_check_id_fires_at_most_once(self):
        """Even if both artifact-level AND chain-entry have weak algo, FHV-001 fires once."""
        entry = ChainOfCustodyEntry(
            custodian="analyst", action="collected",
            timestamp=COLLECTION_TS, hash_at_time="abc", hash_algo="md5"
        )
        art = _pristine_artifact(hash_algo="md5", chain_of_custody=[entry])
        result = _verifier().verify(art)
        fhv001_count = sum(1 for f in result.findings if f.check_id == "FHV-001")
        assert fhv001_count == 1

    def test_verify_returns_hash_verify_result_type(self):
        result = _verifier().verify(_pristine_artifact())
        assert isinstance(result, HashVerifyResult)

    def test_compressed_artifact_does_not_affect_checks(self):
        art = _pristine_artifact(is_compressed=True)
        result = _verifier().verify(art)
        assert result.findings == []

    def test_encrypted_artifact_does_not_affect_checks(self):
        art = _pristine_artifact(is_encrypted=True)
        result = _verifier().verify(art)
        assert result.findings == []

    def test_collection_before_incident_does_not_trigger_fhv003(self):
        # Negative delay (collection before incident) should not trigger FHV-003
        art = _pristine_artifact(
            incident_timestamp=100 * 3600.0,
            collection_timestamp=50 * 3600.0,
        )
        assert "FHV-003" not in _check_ids(_verifier().verify(art))
