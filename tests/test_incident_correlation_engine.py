# test_incident_correlation_engine.py
# Cyber Port Portfolio — IR Playbooks Automation
#
# CC BY 4.0 License
# Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
#
# Test suite for incident_correlation_engine.py
# Run with: python -m pytest tests/test_incident_correlation_engine.py -q

"""
Test suite for incident_correlation_engine.py
Covers all 7 ICOR checks, edge cases, data-model helpers, and incremental
correlation.  Uses fixed base timestamp to make timing assertions deterministic.

base_ms = 1_000_000_000_000  (approximately 2001-09-09 01:46:40 UTC)
"""

import sys
import os

# Allow imports from sibling automations/ package without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from automations.incident_correlation_engine import (
    ICORFinding,
    ICORResult,
    Incident,
    IncidentAsset,
    _CHECK_WEIGHTS,
    _compute_risk_score,
    correlate,
    correlate_incremental,
)

# ---------------------------------------------------------------------------
# Fixed base timestamp — all test timestamps are derived from this
# ---------------------------------------------------------------------------
base_ms: int = 1_000_000_000_000   # ~2001-09-09

# Millisecond shorthands
MS_1H: int = 3_600_000
MS_2H: int = 7_200_000
MS_4H: int = 14_400_000
MS_24H: int = 86_400_000
MS_25H: int = 90_000_000

# ---------------------------------------------------------------------------
# Factory helpers — keep tests concise and self-documenting
# ---------------------------------------------------------------------------

def make_asset(
    asset_id: str = "ast-1",
    asset_name: str = "Web Server",
    criticality: str = "high",
    owner: str = "alice",
) -> IncidentAsset:
    return IncidentAsset(
        asset_id=asset_id,
        asset_name=asset_name,
        criticality=criticality,
        owner=owner,
    )


_SENTINEL_ACTIONS = ["contained"]  # default prevents accidental ICOR-006 triggers


def make_incident(
    incident_id: str = "INC-001",
    title: str = "Test Incident",
    detected_at_ms: int = base_ms,
    resolved_at_ms: int = base_ms + MS_1H,
    source_ips: list = None,
    cve_ids: list = None,
    iocs: list = None,
    affected_assets: list = None,
    containment_actions: list = None,
    child_incident_ids: list = None,
    severity: str = "HIGH",
) -> Incident:
    # Default containment_actions to a non-empty list so tests that do not
    # explicitly set this field do not accidentally trigger ICOR-006.
    if containment_actions is None:
        containment_actions = list(_SENTINEL_ACTIONS)
    return Incident(
        incident_id=incident_id,
        title=title,
        detected_at_ms=detected_at_ms,
        resolved_at_ms=resolved_at_ms,
        source_ips=source_ips if source_ips is not None else [],
        cve_ids=cve_ids if cve_ids is not None else [],
        iocs=iocs if iocs is not None else [],
        affected_assets=affected_assets if affected_assets is not None else [],
        containment_actions=containment_actions,
        child_incident_ids=child_incident_ids if child_incident_ids is not None else [],
        severity=severity,
    )


# ===========================================================================
# _CHECK_WEIGHTS registry integrity
# ===========================================================================

class TestCheckWeightsRegistry:
    def test_all_seven_check_ids_present(self):
        expected = {"ICOR-001", "ICOR-002", "ICOR-003", "ICOR-004", "ICOR-005", "ICOR-006", "ICOR-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected

    def test_icor001_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-001"]["weight"] == 25
        assert _CHECK_WEIGHTS["ICOR-001"]["severity"] == "HIGH"

    def test_icor002_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-002"]["weight"] == 25
        assert _CHECK_WEIGHTS["ICOR-002"]["severity"] == "HIGH"

    def test_icor003_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-003"]["weight"] == 25
        assert _CHECK_WEIGHTS["ICOR-003"]["severity"] == "HIGH"

    def test_icor004_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-004"]["weight"] == 45
        assert _CHECK_WEIGHTS["ICOR-004"]["severity"] == "CRITICAL"

    def test_icor005_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-005"]["weight"] == 25
        assert _CHECK_WEIGHTS["ICOR-005"]["severity"] == "HIGH"

    def test_icor006_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-006"]["weight"] == 25
        assert _CHECK_WEIGHTS["ICOR-006"]["severity"] == "HIGH"

    def test_icor007_weight_and_severity(self):
        assert _CHECK_WEIGHTS["ICOR-007"]["weight"] == 20
        assert _CHECK_WEIGHTS["ICOR-007"]["severity"] == "HIGH"

    def test_all_entries_have_title(self):
        for cid, meta in _CHECK_WEIGHTS.items():
            assert "title" in meta, f"{cid} missing title"
            assert isinstance(meta["title"], str)
            assert len(meta["title"]) > 0


# ===========================================================================
# _compute_risk_score helper
# ===========================================================================

class TestComputeRiskScore:
    def test_empty_findings_gives_zero(self):
        assert _compute_risk_score([]) == 0

    def test_single_finding_returns_its_weight(self):
        f = ICORFinding("ICOR-001", "HIGH", "t", "d", 25, ["INC-1"])
        assert _compute_risk_score([f]) == 25

    def test_two_different_checks_sum_weights(self):
        f1 = ICORFinding("ICOR-001", "HIGH", "t", "d", 25, ["INC-1"])
        f2 = ICORFinding("ICOR-002", "HIGH", "t", "d", 25, ["INC-2"])
        assert _compute_risk_score([f1, f2]) == 50

    def test_duplicate_check_ids_count_once(self):
        # Two ICOR-001 findings: weight should only be counted once
        f1 = ICORFinding("ICOR-001", "HIGH", "t", "d1", 25, ["INC-1"])
        f2 = ICORFinding("ICOR-001", "HIGH", "t", "d2", 25, ["INC-2"])
        assert _compute_risk_score([f1, f2]) == 25

    def test_capped_at_100(self):
        # All 7 checks: 25+25+25+45+25+25+20 = 190 -> capped at 100
        findings = []
        for cid in _CHECK_WEIGHTS:
            meta = _CHECK_WEIGHTS[cid]
            findings.append(ICORFinding(cid, meta["severity"], "t", "d", meta["weight"], []))
        assert _compute_risk_score(findings) == 100

    def test_icor004_alone_gives_45(self):
        f = ICORFinding("ICOR-004", "CRITICAL", "t", "d", 45, ["INC-1"])
        assert _compute_risk_score([f]) == 45

    def test_three_checks_not_exceeding_100(self):
        # ICOR-001(25) + ICOR-002(25) + ICOR-003(25) = 75
        findings = []
        for cid in ["ICOR-001", "ICOR-002", "ICOR-003"]:
            meta = _CHECK_WEIGHTS[cid]
            findings.append(ICORFinding(cid, meta["severity"], "t", "d", meta["weight"], []))
        assert _compute_risk_score(findings) == 75


# ===========================================================================
# ICOR-001: Same source IP within 24-hour window
# ===========================================================================

class TestICOR001:
    def test_no_incidents_no_finding(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_single_incident_no_finding(self):
        inc = make_incident("INC-001", source_ips=["1.2.3.4"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_two_incidents_same_ip_within_24h_fires(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["1.2.3.4"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, source_ips=["1.2.3.4"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" in ids

    def test_two_incidents_same_ip_within_24h_finding_contains_both_ids(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["1.2.3.4"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, source_ips=["1.2.3.4"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        findings = [f for f in result.findings if f.check_id == "ICOR-001"]
        assert len(findings) == 1
        assert "INC-001" in findings[0].incident_ids
        assert "INC-002" in findings[0].incident_ids

    def test_same_ip_different_24h_windows_no_finding(self):
        # 25 hours apart — outside 24h window
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["1.2.3.4"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_25H, source_ips=["1.2.3.4"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_25H + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_different_ips_no_finding(self):
        inc1 = make_incident("INC-001", source_ips=["1.2.3.4"])
        inc2 = make_incident("INC-002", source_ips=["5.6.7.8"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_exactly_24h_apart_fires(self):
        # Exactly at the boundary (delta == 86_400_000) should still fire
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["10.0.0.1"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_24H, source_ips=["10.0.0.1"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" in ids

    def test_one_ms_over_24h_no_finding(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["10.0.0.1"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_24H + 1, source_ips=["10.0.0.1"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2 + 1)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_multiple_ips_each_fires_separate_finding(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["1.1.1.1", "2.2.2.2"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, source_ips=["1.1.1.1", "2.2.2.2"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        ip_findings = [f for f in result.findings if f.check_id == "ICOR-001"]
        assert len(ip_findings) == 2

    def test_three_incidents_same_ip_within_window_fires_one_finding(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["9.9.9.9"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, source_ips=["9.9.9.9"])
        inc3 = make_incident("INC-003", detected_at_ms=base_ms + MS_2H, source_ips=["9.9.9.9"])
        result = correlate([inc1, inc2, inc3], reference_time_ms=base_ms + MS_24H * 2)
        ip_findings = [f for f in result.findings if f.check_id == "ICOR-001"]
        assert len(ip_findings) == 1
        # All three incident IDs should be in the finding
        assert set(ip_findings[0].incident_ids) == {"INC-001", "INC-002", "INC-003"}

    def test_icor001_severity_is_high(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, source_ips=["3.3.3.3"])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, source_ips=["3.3.3.3"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        findings = [f for f in result.findings if f.check_id == "ICOR-001"]
        assert findings[0].severity == "HIGH"

    def test_incident_with_no_source_ips_no_finding(self):
        inc1 = make_incident("INC-001", source_ips=[])
        inc2 = make_incident("INC-002", source_ips=[])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H * 2)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids


# ===========================================================================
# ICOR-002: Same CVE in multiple incidents
# ===========================================================================

class TestICOR002:
    def test_no_incidents_no_finding(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" not in ids

    def test_single_incident_single_cve_no_finding(self):
        inc = make_incident("INC-001", cve_ids=["CVE-2024-12345"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" not in ids

    def test_two_incidents_same_cve_fires(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-12345"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-12345"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" in ids

    def test_two_incidents_different_cves_no_finding(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-00001"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-00002"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" not in ids

    def test_cve_case_insensitive_matching(self):
        inc1 = make_incident("INC-001", cve_ids=["cve-2024-99999"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-99999"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" in ids

    def test_finding_references_both_incident_ids(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-12345"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-12345"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-002"]
        assert "INC-001" in findings[0].incident_ids
        assert "INC-002" in findings[0].incident_ids

    def test_two_cves_shared_fires_two_findings(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-00001", "CVE-2024-00002"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-00001", "CVE-2024-00002"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        cve_findings = [f for f in result.findings if f.check_id == "ICOR-002"]
        assert len(cve_findings) == 2

    def test_three_incidents_share_cve_single_finding(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-77777"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-77777"])
        inc3 = make_incident("INC-003", cve_ids=["CVE-2024-77777"])
        result = correlate([inc1, inc2, inc3], reference_time_ms=base_ms + MS_24H)
        cve_findings = [f for f in result.findings if f.check_id == "ICOR-002"]
        assert len(cve_findings) == 1
        assert len(cve_findings[0].incident_ids) == 3

    def test_cve_in_single_incident_does_not_fire(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-11111"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-22222"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        cve_findings = [f for f in result.findings if f.check_id == "ICOR-002"]
        assert len(cve_findings) == 0

    def test_icor002_severity_is_high(self):
        inc1 = make_incident("INC-001", cve_ids=["CVE-2024-12345"])
        inc2 = make_incident("INC-002", cve_ids=["CVE-2024-12345"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-002"]
        assert findings[0].severity == "HIGH"

    def test_no_cve_ids_no_finding(self):
        inc1 = make_incident("INC-001", cve_ids=[])
        inc2 = make_incident("INC-002", cve_ids=[])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-002" not in ids


# ===========================================================================
# ICOR-003: Critical asset with no owner
# ===========================================================================

class TestICOR003:
    def test_critical_asset_no_owner_fires(self):
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" in ids

    def test_critical_asset_with_owner_no_finding(self):
        asset = make_asset(criticality="critical", owner="alice")
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" not in ids

    def test_high_criticality_no_owner_no_finding(self):
        # Only "critical" criticality level triggers ICOR-003
        asset = make_asset(criticality="high", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" not in ids

    def test_medium_criticality_no_owner_no_finding(self):
        asset = make_asset(criticality="medium", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" not in ids

    def test_low_criticality_no_owner_no_finding(self):
        asset = make_asset(criticality="low", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" not in ids

    def test_two_critical_unowned_assets_two_findings(self):
        asset1 = make_asset(asset_id="a1", criticality="critical", owner=None)
        asset2 = make_asset(asset_id="a2", asset_name="DB Server", criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset1, asset2])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-003"]
        assert len(findings) == 2

    def test_one_critical_owned_one_unowned_one_finding(self):
        asset_owned = make_asset(asset_id="a1", criticality="critical", owner="bob")
        asset_unowned = make_asset(asset_id="a2", asset_name="Firewall", criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset_owned, asset_unowned])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-003"]
        assert len(findings) == 1

    def test_no_assets_no_finding(self):
        inc = make_incident("INC-001", affected_assets=[])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-003" not in ids

    def test_weight_counted_once_even_with_multiple_findings(self):
        asset1 = make_asset(asset_id="a1", criticality="critical", owner=None)
        asset2 = make_asset(asset_id="a2", asset_name="DB", criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset1, asset2])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        # Two ICOR-003 findings but weight should only count once: 25
        assert result.risk_score == 25

    def test_finding_incident_id_is_correct(self):
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-SPECIAL", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-003"]
        assert findings[0].incident_ids == ["INC-SPECIAL"]

    def test_icor003_severity_is_high(self):
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-003"]
        assert findings[0].severity == "HIGH"


# ===========================================================================
# ICOR-004: IOC matches known bad IOC list
# ===========================================================================

class TestICOR004:
    def test_no_known_bad_iocs_no_finding(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=None, reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" not in ids

    def test_empty_known_bad_iocs_no_finding(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=[], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" not in ids

    def test_ioc_matches_known_bad_fires(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" in ids

    def test_ioc_no_match_no_finding(self):
        inc = make_incident("INC-001", iocs=["good.com"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" not in ids

    def test_case_insensitive_ioc_match(self):
        inc = make_incident("INC-001", iocs=["EVIL.COM"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" in ids

    def test_case_insensitive_ioc_list_match(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=["EVIL.COM"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" in ids

    def test_ip_hash_ioc_matches(self):
        inc = make_incident("INC-001", iocs=["d41d8cd98f00b204e9800998ecf8427e"])
        result = correlate([inc], known_bad_iocs=["d41d8cd98f00b204e9800998ecf8427e"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" in ids

    def test_two_matching_iocs_in_one_incident_fires_two_findings(self):
        inc = make_incident("INC-001", iocs=["evil.com", "bad.net"])
        result = correlate([inc], known_bad_iocs=["evil.com", "bad.net"], reference_time_ms=base_ms + MS_24H)
        ioc_findings = [f for f in result.findings if f.check_id == "ICOR-004"]
        assert len(ioc_findings) == 2

    def test_two_incidents_each_with_matching_ioc(self):
        inc1 = make_incident("INC-001", iocs=["evil.com"])
        inc2 = make_incident("INC-002", iocs=["evil.com"])
        result = correlate([inc1, inc2], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        ioc_findings = [f for f in result.findings if f.check_id == "ICOR-004"]
        assert len(ioc_findings) == 2

    def test_weight_counted_once_for_multiple_icor004_findings(self):
        inc1 = make_incident("INC-001", iocs=["evil.com", "bad.net"])
        result = correlate([inc1], known_bad_iocs=["evil.com", "bad.net"], reference_time_ms=base_ms + MS_24H)
        # Multiple ICOR-004 findings but weight counted once: 45
        assert result.risk_score == 45

    def test_icor004_severity_is_critical(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-004"]
        assert findings[0].severity == "CRITICAL"

    def test_incident_with_no_iocs_no_finding(self):
        inc = make_incident("INC-001", iocs=[])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" not in ids


# ===========================================================================
# ICOR-005: Overlapping time windows suggesting coordinated attack
# ===========================================================================

class TestICOR005:
    def test_no_incidents_no_finding(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" not in ids

    def test_single_incident_no_finding(self):
        inc = make_incident("INC-001")
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" not in ids

    def test_j_starts_within_i_resolved_window_fires(self):
        # i: base_ms to base_ms+4h; j starts at base_ms+2h (within i's window)
        inc_i = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_4H)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms + MS_2H, resolved_at_ms=base_ms + MS_4H + MS_1H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" in ids

    def test_non_overlapping_resolved_incidents_no_finding(self):
        # i ends at base_ms+1h; j starts at base_ms+2h — no overlap
        inc_i = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_1H)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms + MS_2H, resolved_at_ms=base_ms + MS_4H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" not in ids

    def test_both_unresolved_within_2h_fires(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=None)
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, resolved_at_ms=None)
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" in ids

    def test_both_unresolved_beyond_2h_no_finding(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=None)
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_2H + 1, resolved_at_ms=None)
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" not in ids

    def test_i_unresolved_j_resolved_overlap_rule1b(self):
        # j resolved window contains i's start
        inc_i = make_incident("INC-001", detected_at_ms=base_ms + MS_1H, resolved_at_ms=None)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_4H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" in ids

    def test_finding_contains_both_incident_ids(self):
        inc_i = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_4H)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms + MS_2H, resolved_at_ms=base_ms + MS_4H + MS_1H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-005"]
        assert "INC-001" in findings[0].incident_ids
        assert "INC-002" in findings[0].incident_ids

    def test_three_overlapping_pairs_fires_three_findings(self):
        # All three overlap with each other
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_4H)
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, resolved_at_ms=base_ms + MS_4H)
        inc3 = make_incident("INC-003", detected_at_ms=base_ms + MS_2H, resolved_at_ms=base_ms + MS_4H)
        result = correlate([inc1, inc2, inc3], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-005"]
        assert len(findings) == 3

    def test_exactly_at_resolved_boundary_fires(self):
        # j.detected_at_ms == i.resolved_at_ms — boundary case should fire
        inc_i = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_2H)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms + MS_2H, resolved_at_ms=base_ms + MS_4H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" in ids

    def test_icor005_severity_is_high(self):
        inc_i = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=base_ms + MS_4H)
        inc_j = make_incident("INC-002", detected_at_ms=base_ms + MS_1H, resolved_at_ms=base_ms + MS_4H)
        result = correlate([inc_i, inc_j], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-005"]
        assert findings[0].severity == "HIGH"

    def test_both_unresolved_exactly_2h_apart_fires(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, resolved_at_ms=None)
        inc2 = make_incident("INC-002", detected_at_ms=base_ms + MS_2H, resolved_at_ms=None)
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-005" in ids


# ===========================================================================
# ICOR-006: No containment action > 4 hours after detection
# ===========================================================================

class TestICOR006:
    def test_no_containment_beyond_4h_fires(self):
        inc = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            containment_actions=[],
        )
        ref = base_ms + MS_4H + 1  # just over 4 hours
        result = correlate([inc], reference_time_ms=ref)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" in ids

    def test_containment_action_present_no_finding(self):
        inc = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            containment_actions=["Isolated host from network"],
        )
        ref = base_ms + MS_4H + 1
        result = correlate([inc], reference_time_ms=ref)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" not in ids

    def test_no_containment_within_4h_no_finding(self):
        inc = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            containment_actions=[],
        )
        ref = base_ms + MS_4H - 1  # just under 4 hours
        result = correlate([inc], reference_time_ms=ref)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" not in ids

    def test_exactly_4h_no_finding(self):
        # elapsed == 14_400_000 is NOT > 4h (must be strictly greater)
        inc = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            containment_actions=[],
        )
        ref = base_ms + MS_4H
        result = correlate([inc], reference_time_ms=ref)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" not in ids

    def test_two_uncontained_incidents_single_finding(self):
        inc1 = make_incident("INC-001", detected_at_ms=base_ms, containment_actions=[])
        inc2 = make_incident("INC-002", detected_at_ms=base_ms, containment_actions=[])
        ref = base_ms + MS_4H + 1
        result = correlate([inc1, inc2], reference_time_ms=ref)
        findings = [f for f in result.findings if f.check_id == "ICOR-006"]
        # Both incidents are consolidated into a single finding
        assert len(findings) == 1
        assert "INC-001" in findings[0].incident_ids
        assert "INC-002" in findings[0].incident_ids

    def test_one_uncontained_one_contained_single_finding(self):
        inc_bad = make_incident("INC-001", detected_at_ms=base_ms, containment_actions=[])
        inc_ok = make_incident("INC-002", detected_at_ms=base_ms, containment_actions=["Blocked IP"])
        ref = base_ms + MS_4H + 1
        result = correlate([inc_bad, inc_ok], reference_time_ms=ref)
        findings = [f for f in result.findings if f.check_id == "ICOR-006"]
        assert len(findings) == 1
        assert "INC-001" in findings[0].incident_ids
        assert "INC-002" not in findings[0].incident_ids

    def test_icor006_default_reference_time_used_when_none(self):
        # This incident was detected a very long time ago — should fire with real time
        very_old_ms = 1_000_000  # 1970-01-01 — well over 4h ago
        inc = make_incident("INC-001", detected_at_ms=very_old_ms, containment_actions=[])
        result = correlate([inc])  # reference_time_ms defaults to current wall clock
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" in ids

    def test_icor006_severity_is_high(self):
        inc = make_incident("INC-001", detected_at_ms=base_ms, containment_actions=[])
        ref = base_ms + MS_4H + 1
        result = correlate([inc], reference_time_ms=ref)
        findings = [f for f in result.findings if f.check_id == "ICOR-006"]
        assert findings[0].severity == "HIGH"

    def test_weight_counted_once_for_multiple_uncontained_incidents(self):
        # Place incidents 25 hours apart so they do NOT overlap (ICOR-005 stays silent)
        # and are NOT within the same 24-h IP window (ICOR-001 stays silent).
        # Each has no containment actions, and ref is more than 4 h after both.
        inc1 = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            resolved_at_ms=base_ms + MS_1H,
            containment_actions=[],
        )
        inc2 = make_incident(
            "INC-002",
            detected_at_ms=base_ms + MS_25H,
            resolved_at_ms=base_ms + MS_25H + MS_1H,
            containment_actions=[],
        )
        ref = base_ms + MS_25H + MS_4H + 1
        result = correlate([inc1, inc2], reference_time_ms=ref)
        # Both consolidated into one ICOR-006 finding; weight counted once = 25
        findings_006 = [f for f in result.findings if f.check_id == "ICOR-006"]
        assert len(findings_006) == 1
        assert result.risk_score == 25


# ===========================================================================
# ICOR-007: Incident has more than 5 child incidents
# ===========================================================================

class TestICOR007:
    def test_zero_children_no_finding(self):
        inc = make_incident("INC-001", child_incident_ids=[])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-007" not in ids

    def test_exactly_five_children_no_finding(self):
        inc = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-007" not in ids

    def test_six_children_fires(self):
        inc = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5", "C6"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-007" in ids

    def test_ten_children_fires(self):
        children = [f"C{i}" for i in range(10)]
        inc = make_incident("INC-001", child_incident_ids=children)
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-007" in ids

    def test_finding_references_correct_incident_id(self):
        children = [f"C{i}" for i in range(6)]
        inc = make_incident("INC-FANOUT", child_incident_ids=children)
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-007"]
        assert findings[0].incident_ids == ["INC-FANOUT"]

    def test_two_incidents_both_exceeding_threshold_two_findings(self):
        inc1 = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5", "C6"])
        inc2 = make_incident("INC-002", child_incident_ids=["D1", "D2", "D3", "D4", "D5", "D6"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-007"]
        assert len(findings) == 2

    def test_one_exceeds_one_does_not_one_finding(self):
        inc1 = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5", "C6"])
        inc2 = make_incident("INC-002", child_incident_ids=["D1", "D2"])
        result = correlate([inc1, inc2], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-007"]
        assert len(findings) == 1

    def test_icor007_severity_is_high(self):
        inc = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5", "C6"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-007"]
        assert findings[0].severity == "HIGH"

    def test_icor007_weight_is_20(self):
        inc = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4", "C5", "C6"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        findings = [f for f in result.findings if f.check_id == "ICOR-007"]
        assert findings[0].weight == 20

    def test_four_children_no_finding(self):
        inc = make_incident("INC-001", child_incident_ids=["C1", "C2", "C3", "C4"])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        ids = [f.check_id for f in result.findings]
        assert "ICOR-007" not in ids


# ===========================================================================
# ICORResult helpers: to_dict, summary, by_severity
# ===========================================================================

class TestICORResultHelpers:
    def _get_result_with_findings(self) -> ICORResult:
        # INC-001: critical unowned asset (ICOR-003)
        # IOC match (ICOR-004)
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", iocs=["evil.com"], affected_assets=[asset])
        return correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)

    def test_to_dict_has_required_keys(self):
        result = self._get_result_with_findings()
        d = result.to_dict()
        assert "risk_score" in d
        assert "correlation_summary" in d
        assert "findings" in d

    def test_to_dict_risk_score_correct(self):
        result = self._get_result_with_findings()
        d = result.to_dict()
        assert d["risk_score"] == result.risk_score

    def test_to_dict_findings_is_list(self):
        result = self._get_result_with_findings()
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_has_all_keys(self):
        result = self._get_result_with_findings()
        d = result.to_dict()
        for f in d["findings"]:
            for key in ("check_id", "severity", "title", "detail", "weight", "incident_ids"):
                assert key in f, f"Missing key {key} in finding dict"

    def test_summary_returns_string(self):
        result = self._get_result_with_findings()
        assert isinstance(result.summary(), str)

    def test_summary_contains_risk_score(self):
        result = self._get_result_with_findings()
        assert str(result.risk_score) in result.summary()

    def test_summary_equals_correlation_summary(self):
        result = self._get_result_with_findings()
        assert result.summary() == result.correlation_summary

    def test_by_severity_returns_dict(self):
        result = self._get_result_with_findings()
        grouped = result.by_severity()
        assert isinstance(grouped, dict)

    def test_by_severity_groups_correctly(self):
        result = self._get_result_with_findings()
        grouped = result.by_severity()
        for severity, findings in grouped.items():
            for f in findings:
                assert f.severity == severity

    def test_by_severity_all_findings_accounted(self):
        result = self._get_result_with_findings()
        grouped = result.by_severity()
        total = sum(len(v) for v in grouped.values())
        assert total == len(result.findings)

    def test_empty_result_to_dict(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        d = result.to_dict()
        assert d["risk_score"] == 0
        assert d["findings"] == []


# ===========================================================================
# Risk score and correlation summary
# ===========================================================================

class TestRiskScoreAndSummary:
    def test_no_incidents_risk_score_zero(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        assert result.risk_score == 0

    def test_risk_score_capped_at_100(self):
        # Trigger as many checks as possible
        asset = make_asset(criticality="critical", owner=None)
        children = [f"C{i}" for i in range(6)]
        inc1 = make_incident(
            "INC-001",
            detected_at_ms=base_ms,
            resolved_at_ms=base_ms + MS_4H,
            source_ips=["1.1.1.1"],
            cve_ids=["CVE-2024-00001"],
            iocs=["evil.com"],
            affected_assets=[asset],
            containment_actions=[],
            child_incident_ids=children,
        )
        inc2 = make_incident(
            "INC-002",
            detected_at_ms=base_ms + MS_1H,
            resolved_at_ms=base_ms + MS_4H,
            source_ips=["1.1.1.1"],
            cve_ids=["CVE-2024-00001"],
            iocs=["evil.com"],
            affected_assets=[],
            containment_actions=[],
            child_incident_ids=[],
        )
        ref = base_ms + MS_4H + 1
        result = correlate([inc1, inc2], known_bad_iocs=["evil.com"], reference_time_ms=ref)
        assert result.risk_score <= 100

    def test_correlation_summary_format(self):
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        # Should contain "finding" and "incident" and "risk score"
        summary = result.correlation_summary
        assert "finding" in summary.lower()
        assert "incident" in summary.lower()
        assert "risk score" in summary.lower()

    def test_zero_findings_summary_format(self):
        inc = make_incident("INC-001")
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        assert "0 findings" in result.correlation_summary
        assert "risk score 0" in result.correlation_summary

    def test_risk_score_icor004_alone_is_45(self):
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        assert result.risk_score == 45

    def test_single_finding_summary_grammar(self):
        # "1 finding" (not "1 findings")
        inc = make_incident("INC-001", iocs=["evil.com"])
        result = correlate([inc], known_bad_iocs=["evil.com"], reference_time_ms=base_ms + MS_24H)
        # Should say "finding" not "findings" for count of 1
        assert "1 finding" in result.correlation_summary
        assert "1 findings" not in result.correlation_summary


# ===========================================================================
# correlate_incremental
# ===========================================================================

class TestCorrelateIncremental:
    def test_basic_incremental_returns_icor_result(self):
        new_inc = make_incident("INC-NEW", source_ips=["2.2.2.2"])
        hist_inc = make_incident("INC-OLD", source_ips=["2.2.2.2"])
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[hist_inc],
            reference_time_ms=base_ms + MS_24H,
        )
        assert isinstance(result, ICORResult)

    def test_incremental_detects_repeated_ip_across_new_and_historical(self):
        new_inc = make_incident(
            "INC-NEW", detected_at_ms=base_ms + MS_1H, source_ips=["6.6.6.6"]
        )
        hist_inc = make_incident(
            "INC-OLD", detected_at_ms=base_ms, source_ips=["6.6.6.6"]
        )
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[hist_inc],
            reference_time_ms=base_ms + MS_24H,
        )
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" in ids

    def test_incremental_no_connection_no_finding(self):
        new_inc = make_incident("INC-NEW", source_ips=["7.7.7.7"])
        hist_inc = make_incident("INC-OLD", source_ips=["8.8.8.8"])
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[hist_inc],
            reference_time_ms=base_ms + MS_24H,
        )
        ids = [f.check_id for f in result.findings]
        assert "ICOR-001" not in ids

    def test_incremental_filters_historical_only_findings(self):
        # Two historical incidents share an IP — should NOT appear in incremental results
        new_inc = make_incident("INC-NEW", source_ips=["9.9.9.9"])
        hist_inc1 = make_incident("INC-OLD1", detected_at_ms=base_ms, source_ips=["4.4.4.4"])
        hist_inc2 = make_incident("INC-OLD2", detected_at_ms=base_ms + MS_1H, source_ips=["4.4.4.4"])
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[hist_inc1, hist_inc2],
            reference_time_ms=base_ms + MS_24H,
        )
        # The ICOR-001 finding would only reference hist incident IDs
        for f in result.findings:
            if f.check_id == "ICOR-001":
                # Must involve the new incident
                assert "INC-NEW" in f.incident_ids

    def test_incremental_risk_score_correct_type(self):
        new_inc = make_incident("INC-NEW")
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[],
            reference_time_ms=base_ms + MS_24H,
        )
        assert isinstance(result.risk_score, int)

    def test_incremental_empty_new_incidents(self):
        hist_inc = make_incident("INC-OLD", source_ips=["1.1.1.1"])
        result = correlate_incremental(
            new_incidents=[],
            historical_incidents=[hist_inc],
            reference_time_ms=base_ms + MS_24H,
        )
        assert result.risk_score == 0
        assert result.findings == []

    def test_incremental_known_bad_iocs_passed_through(self):
        new_inc = make_incident("INC-NEW", iocs=["evil.com"])
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[],
            known_bad_iocs=["evil.com"],
            reference_time_ms=base_ms + MS_24H,
        )
        ids = [f.check_id for f in result.findings]
        assert "ICOR-004" in ids

    def test_incremental_reference_time_passed_through(self):
        new_inc = make_incident("INC-NEW", detected_at_ms=base_ms, containment_actions=[])
        ref = base_ms + MS_4H + 1
        result = correlate_incremental(
            new_incidents=[new_inc],
            historical_incidents=[],
            reference_time_ms=ref,
        )
        ids = [f.check_id for f in result.findings]
        assert "ICOR-006" in ids


# ===========================================================================
# Full correlate() — integration / multi-check scenarios
# ===========================================================================

class TestCorrelateIntegration:
    def test_correlate_returns_icor_result_type(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        assert isinstance(result, ICORResult)

    def test_no_incidents_returns_zero_risk(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        assert result.risk_score == 0

    def test_no_incidents_empty_findings(self):
        result = correlate([], reference_time_ms=base_ms + MS_24H)
        assert result.findings == []

    def test_all_checks_fire_risk_capped(self):
        asset = make_asset(criticality="critical", owner=None)
        children = [f"C{i}" for i in range(7)]
        inc1 = make_incident(
            "INC-A",
            detected_at_ms=base_ms,
            resolved_at_ms=base_ms + MS_4H,
            source_ips=["5.5.5.5"],
            cve_ids=["CVE-2024-55555"],
            iocs=["badactor.io"],
            affected_assets=[asset],
            containment_actions=[],
            child_incident_ids=children,
        )
        inc2 = make_incident(
            "INC-B",
            detected_at_ms=base_ms + MS_2H,
            resolved_at_ms=base_ms + MS_4H + MS_1H,
            source_ips=["5.5.5.5"],
            cve_ids=["CVE-2024-55555"],
            iocs=["badactor.io"],
            affected_assets=[],
            containment_actions=[],
            child_incident_ids=[],
        )
        ref = base_ms + MS_4H + 1
        result = correlate([inc1, inc2], known_bad_iocs=["badactor.io"], reference_time_ms=ref)
        assert result.risk_score == 100  # Total well exceeds 100

    def test_findings_list_contains_icorfinding_instances(self):
        inc = make_incident("INC-001", iocs=["x.com"])
        result = correlate([inc], known_bad_iocs=["x.com"], reference_time_ms=base_ms + MS_24H)
        for f in result.findings:
            assert isinstance(f, ICORFinding)

    def test_check_ids_in_findings_are_all_known(self):
        known_ids = set(_CHECK_WEIGHTS.keys())
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", iocs=["x.com"], affected_assets=[asset])
        result = correlate([inc], known_bad_iocs=["x.com"], reference_time_ms=base_ms + MS_24H)
        for f in result.findings:
            assert f.check_id in known_ids

    def test_finding_weight_matches_registry(self):
        inc = make_incident("INC-001", iocs=["x.com"])
        result = correlate([inc], known_bad_iocs=["x.com"], reference_time_ms=base_ms + MS_24H)
        for f in result.findings:
            assert f.weight == _CHECK_WEIGHTS[f.check_id]["weight"]

    def test_finding_severity_matches_registry(self):
        asset = make_asset(criticality="critical", owner=None)
        inc = make_incident("INC-001", affected_assets=[asset])
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        for f in result.findings:
            assert f.severity == _CHECK_WEIGHTS[f.check_id]["severity"]

    def test_incident_with_all_empty_fields_no_findings(self):
        inc = make_incident(
            "INC-CLEAN",
            source_ips=[],
            cve_ids=[],
            iocs=[],
            affected_assets=[],
            containment_actions=["Completed"],
            child_incident_ids=[],
        )
        result = correlate([inc], reference_time_ms=base_ms + MS_24H)
        assert result.findings == []
        assert result.risk_score == 0

    def test_correlation_summary_in_to_dict(self):
        inc = make_incident("INC-001", iocs=["e.com"])
        result = correlate([inc], known_bad_iocs=["e.com"], reference_time_ms=base_ms + MS_24H)
        d = result.to_dict()
        assert d["correlation_summary"] == result.correlation_summary
