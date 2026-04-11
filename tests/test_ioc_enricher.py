# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Cyber Port — hiagokinlevi
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# Full license: https://creativecommons.org/licenses/by/4.0/
"""
Tests for automations.ioc_enricher
===================================
90+ deterministic, offline tests for the IOC enrichment and correlation engine.
No network access is required; all fixtures are self-contained.
"""
from __future__ import annotations

import sys
import os

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from any working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from automations.ioc_enricher import (
    IOCEnricher,
    IOCEnrichResult,
    IOCMatch,
    IOCType,
    ThreatIOC,
    _extract_strings,
    _TYPE_WEIGHTS,
)


# ===========================================================================
# Fixtures & helpers
# ===========================================================================

def make_ioc(
    ioc_type: IOCType,
    value: str,
    severity: str = "HIGH",
    confidence: float = 1.0,
    source: str = "test-feed",
    tags: list | None = None,
) -> ThreatIOC:
    """Convenience factory for ThreatIOC objects."""
    return ThreatIOC(
        ioc_type=ioc_type,
        value=value,
        severity=severity,
        confidence=confidence,
        source=source,
        tags=tags or [],
    )


enricher = IOCEnricher()


# ===========================================================================
# 1. Empty-input edge cases
# ===========================================================================

class TestEmptyInputs:
    def test_empty_iocs_no_matches(self):
        result = enricher.match([], [{"src_ip": "1.2.3.4"}])
        assert result.matches == []

    def test_empty_iocs_risk_score_zero(self):
        result = enricher.match([], [{"src_ip": "1.2.3.4"}])
        assert result.risk_score == 0

    def test_empty_iocs_ioc_coverage_zero(self):
        result = enricher.match([], [{"src_ip": "1.2.3.4"}])
        assert result.ioc_coverage == 0.0

    def test_empty_iocs_matched_ioc_count_zero(self):
        result = enricher.match([], [{"src_ip": "1.2.3.4"}])
        assert result.matched_ioc_count == 0

    def test_empty_events_no_matches(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")
        result = enricher.match([ioc], [])
        assert result.matches == []

    def test_empty_events_risk_score_zero(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")
        result = enricher.match([ioc], [])
        assert result.risk_score == 0

    def test_empty_events_ioc_coverage_zero(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")
        result = enricher.match([ioc], [])
        assert result.ioc_coverage == 0.0

    def test_both_empty(self):
        result = enricher.match([], [])
        assert result.matches == []
        assert result.risk_score == 0
        assert result.matched_ioc_count == 0
        assert result.ioc_coverage == 0.0


# ===========================================================================
# 2. IP_ADDRESS matching
# ===========================================================================

class TestIPAddress:
    def test_ip_exact_match(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "192.168.1.100")
        events = [{"src_ip": "192.168.1.100"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_ip_exact_match_event_index(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "192.168.1.100")
        events = [{"src_ip": "192.168.1.100"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].event_index == 0

    def test_ip_case_insensitive(self):
        # IPv6 hex digits may vary in case
        ioc = make_ioc(IOCType.IP_ADDRESS, "FE80::1")
        events = [{"src_ip": "fe80::1"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_ip_no_match_different_ip(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")
        events = [{"src_ip": "10.0.0.2"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_ip_no_partial_match(self):
        # "10.0.0.1" must NOT match "10.0.0.10"
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")
        events = [{"src_ip": "10.0.0.10"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_ip_second_event_matches(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"src_ip": "8.8.8.8"}, {"dst_ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].event_index == 1

    def test_ip_field_name_recorded(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.2.3.4")
        events = [{"remote_addr": "1.2.3.4"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].field_name == "remote_addr"

    def test_ip_matched_value_recorded(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.2.3.4")
        events = [{"remote_addr": "1.2.3.4"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].matched_value == "1.2.3.4"


# ===========================================================================
# 3. DOMAIN matching
# ===========================================================================

class TestDomain:
    def test_domain_exact_match(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"dns_query": "evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_domain_subdomain_match(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"dns_query": "sub.evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_domain_deep_subdomain_match(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"host": "a.b.evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_domain_case_insensitive_exact(self):
        ioc = make_ioc(IOCType.DOMAIN, "EVIL.COM")
        events = [{"dns_query": "evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_domain_case_insensitive_subdomain(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"host": "SUB.EVIL.COM"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_domain_no_match_different_domain(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"dns_query": "notevil.com"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_domain_no_match_suffix_overlap(self):
        # "evilexample.com" must NOT match ioc "evil.com" — no dot separator
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"host": "notevil.com"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_domain_ioc_is_subdomain_of_event(self):
        # IOC "sub.evil.com" must NOT match event "evil.com"
        ioc = make_ioc(IOCType.DOMAIN, "sub.evil.com")
        events = [{"host": "evil.com"}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 4. FILE_HASH matching
# ===========================================================================

class TestFileHash:
    _md5 = "d41d8cd98f00b204e9800998ecf8427e"
    _sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    _sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_md5_exact_match(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._md5)
        events = [{"file_hash": self._md5}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_md5_case_insensitive_upper_event(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._md5)
        events = [{"file_hash": self._md5.upper()}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_md5_case_insensitive_upper_ioc(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._md5.upper())
        events = [{"file_hash": self._md5}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_sha256_match(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._sha256)
        events = [{"hash": self._sha256}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_sha1_match(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._sha1)
        events = [{"sha1": self._sha1}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_hash_no_match_wrong_hash(self):
        ioc = make_ioc(IOCType.FILE_HASH, self._md5)
        events = [{"file_hash": "aabbccdd"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_hash_no_partial_match(self):
        # Substring of a hash must not match
        ioc = make_ioc(IOCType.FILE_HASH, self._md5[:16])
        events = [{"file_hash": self._md5}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 5. URL matching
# ===========================================================================

class TestURL:
    def test_url_substring_match(self):
        ioc = make_ioc(IOCType.URL, "evil.com/malware")
        events = [{"url": "http://evil.com/malware/payload.exe"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_url_exact_match(self):
        ioc = make_ioc(IOCType.URL, "http://evil.com/drop")
        events = [{"url": "http://evil.com/drop"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_url_case_insensitive(self):
        ioc = make_ioc(IOCType.URL, "EVIL.COM/path")
        events = [{"url": "http://evil.com/path/file"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_url_match_strips_surrounding_whitespace(self):
        ioc = make_ioc(IOCType.URL, "  evil.com/path  ")
        events = [{"url": "  http://evil.com/path/file  "}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_url_no_match_unrelated(self):
        ioc = make_ioc(IOCType.URL, "evil.com/malware")
        events = [{"url": "https://safe.example.com/page"}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 6. EMAIL matching
# ===========================================================================

class TestEmail:
    def test_email_exact_match(self):
        ioc = make_ioc(IOCType.EMAIL, "attacker@evil.com")
        events = [{"from": "attacker@evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_email_case_insensitive(self):
        ioc = make_ioc(IOCType.EMAIL, "ATTACKER@EVIL.COM")
        events = [{"from": "attacker@evil.com"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_email_no_match_different_email(self):
        ioc = make_ioc(IOCType.EMAIL, "attacker@evil.com")
        events = [{"from": "legit@safe.com"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_email_no_partial_match(self):
        ioc = make_ioc(IOCType.EMAIL, "attacker@evil.com")
        events = [{"from": "someone+attacker@evil.com"}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 7. REGISTRY_KEY matching
# ===========================================================================

class TestRegistryKey:
    _key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

    def test_registry_exact_match(self):
        ioc = make_ioc(IOCType.REGISTRY_KEY, self._key)
        events = [{"registry": self._key}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_registry_case_insensitive(self):
        ioc = make_ioc(IOCType.REGISTRY_KEY, self._key.upper())
        events = [{"registry": self._key.lower()}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_registry_no_match_different_key(self):
        ioc = make_ioc(IOCType.REGISTRY_KEY, self._key)
        events = [{"registry": r"HKLM\Software\OtherKey"}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 8. PROCESS_NAME matching
# ===========================================================================

class TestProcessName:
    def test_process_exact_filename(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz.exe")
        events = [{"process": "mimikatz.exe"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_full_windows_path(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz.exe")
        events = [{"process_path": r"C:\Windows\Temp\mimikatz.exe"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_unix_path(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "malware.sh")
        events = [{"cmd": "/tmp/malware.sh"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_case_insensitive_exact(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "MIMIKATZ.EXE")
        events = [{"process": "mimikatz.exe"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_case_insensitive_path(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz.exe")
        events = [{"process_path": r"C:\WINDOWS\TEMP\MIMIKATZ.EXE"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_no_match_different_process(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz.exe")
        events = [{"process": "notepad.exe"}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_process_no_match_partial_name(self):
        # "mimikatz" must NOT match "mimikatz.exe"
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz")
        events = [{"process": "mimikatz.exe"}]
        result = enricher.match([ioc], events)
        assert result.matches == []


# ===========================================================================
# 9. Nested event dict
# ===========================================================================

class TestNestedEvents:
    def test_nested_dict_ip_match(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.5")
        events = [{"network": {"connection": {"src": "10.0.0.5"}}}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_nested_dict_field_path(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "10.0.0.5")
        events = [{"network": {"connection": {"src": "10.0.0.5"}}}]
        result = enricher.match([ioc], events)
        assert result.matches[0].field_name == "network.connection.src"

    def test_list_in_event(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"queries": ["safe.com", "evil.com", "other.net"]}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_list_of_dicts_in_event(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.2.3.4")
        events = [{"connections": [{"dst": "9.9.9.9"}, {"dst": "1.2.3.4"}]}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_deeply_nested_hash(self):
        _hash = "aabbccddeeff00112233445566778899"
        ioc = make_ioc(IOCType.FILE_HASH, _hash)
        events = [{"alert": {"file": {"metadata": {"md5": _hash}}}}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_extract_strings_simple(self):
        pairs = _extract_strings({"a": "hello", "b": "world"})
        values = {v for _, v in pairs}
        assert values == {"hello", "world"}

    def test_extract_strings_nested_dict(self):
        pairs = _extract_strings({"outer": {"inner": "deep_value"}})
        assert any(v == "deep_value" for _, v in pairs)

    def test_extract_strings_nested_list(self):
        pairs = _extract_strings({"items": ["x", "y", "z"]})
        values = {v for _, v in pairs}
        assert {"x", "y", "z"}.issubset(values)

    def test_extract_strings_skips_integers(self):
        pairs = _extract_strings({"count": 42, "label": "ok"})
        values = {v for _, v in pairs}
        assert values == {"ok"}

    def test_extract_strings_skips_none(self):
        pairs = _extract_strings({"key": None, "label": "ok"})
        values = {v for _, v in pairs}
        assert values == {"ok"}

    def test_extract_strings_mixed_list(self):
        pairs = _extract_strings({"items": ["text", 99, None, {"sub": "val"}]})
        values = {v for _, v in pairs}
        assert "text" in values
        assert "val" in values


# ===========================================================================
# 10. Multiple IOCs on the same event
# ===========================================================================

class TestMultipleIOCsSameEvent:
    def test_two_iocs_same_event(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "10.0.0.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"src_ip": "10.0.0.1", "dns": "evil.com"}]
        result = enricher.match(iocs, events)
        assert len(result.matches) == 2

    def test_two_iocs_matched_ioc_count(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "10.0.0.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"src_ip": "10.0.0.1", "dns": "evil.com"}]
        result = enricher.match(iocs, events)
        assert result.matched_ioc_count == 2

    def test_three_iocs_one_event_one_unmatched(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "10.0.0.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
            make_ioc(IOCType.EMAIL, "unused@noop.io"),
        ]
        events = [{"src_ip": "10.0.0.1", "dns": "evil.com"}]
        result = enricher.match(iocs, events)
        assert result.matched_ioc_count == 2
        assert len(result.matches) == 2


# ===========================================================================
# 11. Deduplication
# ===========================================================================

class TestDeduplication:
    def test_same_ioc_two_events_two_matches(self):
        # Same IOC, two separate events — TWO matches expected
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 2

    def test_same_ioc_same_event_two_fields_two_matches(self):
        # Same value in two different fields of the same event — TWO matches
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"src": "1.1.1.1", "dst": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 2

    def test_duplicate_ioc_objects_same_value_deduped(self):
        # Two IOC objects with the same value+type in the same event+field
        # should NOT produce two matches for the same (value, event, field)
        ioc1 = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        ioc2 = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc1, ioc2], events)
        assert len(result.matches) == 1

    def test_dedup_only_counts_one_matched_ioc(self):
        ioc1 = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        ioc2 = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc1, ioc2], events)
        assert result.matched_ioc_count == 1


# ===========================================================================
# 12. Coverage metric
# ===========================================================================

class TestCoverage:
    def test_full_coverage(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"src": "1.1.1.1", "host": "evil.com"}]
        result = enricher.match(iocs, events)
        assert result.ioc_coverage == pytest.approx(1.0)

    def test_half_coverage(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"src": "1.1.1.1"}]  # only IP matches
        result = enricher.match(iocs, events)
        assert result.ioc_coverage == pytest.approx(0.5)

    def test_zero_coverage(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "9.9.9.9"),
            make_ioc(IOCType.DOMAIN, "gone.com"),
        ]
        events = [{"src": "1.1.1.1"}]
        result = enricher.match(iocs, events)
        assert result.ioc_coverage == pytest.approx(0.0)

    def test_quarter_coverage(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
            make_ioc(IOCType.EMAIL, "x@y.z"),
            make_ioc(IOCType.FILE_HASH, "aabb1122"),
        ]
        events = [{"src": "1.1.1.1"}]
        result = enricher.match(iocs, events)
        assert result.ioc_coverage == pytest.approx(0.25)


# ===========================================================================
# 13. Risk score
# ===========================================================================

class TestRiskScore:
    def test_risk_score_single_ip(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert result.risk_score == _TYPE_WEIGHTS["ip_address"]  # 30

    def test_risk_score_single_file_hash(self):
        ioc = make_ioc(IOCType.FILE_HASH, "abc123")
        events = [{"hash": "abc123"}]
        result = enricher.match([ioc], events)
        assert result.risk_score == _TYPE_WEIGHTS["file_hash"]  # 35

    def test_risk_score_ip_plus_domain(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"ip": "1.1.1.1", "host": "evil.com"}]
        result = enricher.match(iocs, events)
        expected = _TYPE_WEIGHTS["ip_address"] + _TYPE_WEIGHTS["domain"]  # 55
        assert result.risk_score == expected

    def test_risk_score_capped_at_100(self):
        # File-hash (35) + IP (30) + Domain (25) + Email (15) = 105 → capped 100
        iocs = [
            make_ioc(IOCType.FILE_HASH, "aabbcc"),
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
            make_ioc(IOCType.EMAIL, "x@evil.com"),
        ]
        events = [
            {
                "hash": "aabbcc",
                "ip": "1.1.1.1",
                "host": "evil.com",
                "from": "x@evil.com",
            }
        ]
        result = enricher.match(iocs, events)
        assert result.risk_score == 100

    def test_risk_score_no_double_count_same_ioc_multiple_events(self):
        # Same IOC fires in two events — but score should only count weight ONCE
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}, {"src": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert result.risk_score == _TYPE_WEIGHTS["ip_address"]  # 30, not 60

    def test_risk_score_zero_no_matches(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "9.9.9.9")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert result.risk_score == 0

    def test_risk_score_url_and_process(self):
        iocs = [
            make_ioc(IOCType.URL, "evil.com/drop"),
            make_ioc(IOCType.PROCESS_NAME, "evil.exe"),
        ]
        events = [{"url": "http://evil.com/drop/x", "proc": "evil.exe"}]
        result = enricher.match(iocs, events)
        expected = _TYPE_WEIGHTS["url"] + _TYPE_WEIGHTS["process_name"]  # 45
        assert result.risk_score == expected

    def test_risk_score_registry_key(self):
        ioc = make_ioc(IOCType.REGISTRY_KEY, r"HKLM\Run\BadApp")
        events = [{"reg": r"HKLM\Run\BadApp"}]
        result = enricher.match([ioc], events)
        assert result.risk_score == _TYPE_WEIGHTS["registry_key"]  # 20


# ===========================================================================
# 14. by_type()
# ===========================================================================

class TestByType:
    def test_by_type_keys_are_ioc_type_strings(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"ip": "1.1.1.1", "host": "evil.com"}]
        result = enricher.match(iocs, events)
        bt = result.by_type()
        assert "ip_address" in bt
        assert "domain" in bt

    def test_by_type_values_are_ioc_match_lists(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        bt = result.by_type()
        assert all(isinstance(m, IOCMatch) for m in bt["ip_address"])

    def test_by_type_only_matched_types(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.EMAIL, "x@y.z"),  # does not match
        ]
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match(iocs, events)
        bt = result.by_type()
        assert "ip_address" in bt
        assert "email" not in bt

    def test_by_type_count(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com")
        events = [{"a": "evil.com", "b": "sub.evil.com"}]
        result = enricher.match([ioc], events)
        bt = result.by_type()
        assert len(bt["domain"]) == 2


# ===========================================================================
# 15. summary()
# ===========================================================================

class TestSummary:
    def test_summary_format_non_empty(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        s = result.summary()
        assert s.startswith("IOCEnrichResult:")
        assert "risk_score=" in s
        assert "coverage=" in s

    def test_summary_format_empty(self):
        result = enricher.match([], [{"ip": "1.2.3.4"}])
        s = result.summary()
        assert "0 matches" in s
        assert "risk_score=0" in s

    def test_summary_match_count(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"ip": "1.1.1.1", "host": "evil.com"}]
        result = enricher.match(iocs, events)
        s = result.summary()
        assert "2 matches" in s

    def test_summary_coverage_two_decimal_places(self):
        iocs = [make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")]
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match(iocs, events)
        assert "coverage=1.00" in result.summary()

    def test_summary_half_coverage(self):
        iocs = [
            make_ioc(IOCType.IP_ADDRESS, "1.1.1.1"),
            make_ioc(IOCType.DOMAIN, "evil.com"),
        ]
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match(iocs, events)
        assert "coverage=0.50" in result.summary()


# ===========================================================================
# 16. match_many()
# ===========================================================================

class TestMatchMany:
    def test_match_many_returns_correct_length(self):
        ioc_a = [make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")]
        ioc_b = [make_ioc(IOCType.DOMAIN, "evil.com")]
        ev_a = [{"ip": "1.1.1.1"}]
        ev_b = [{"host": "evil.com"}]
        results = enricher.match_many([ioc_a, ioc_b], [ev_a, ev_b])
        assert len(results) == 2

    def test_match_many_each_result_is_ioc_enrich_result(self):
        ioc_a = [make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")]
        ev_a = [{"ip": "1.1.1.1"}]
        results = enricher.match_many([ioc_a], [ev_a])
        assert all(isinstance(r, IOCEnrichResult) for r in results)

    def test_match_many_first_has_match(self):
        ioc_a = [make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")]
        ev_a = [{"ip": "1.1.1.1"}]
        ev_b: list[dict] = []
        results = enricher.match_many([ioc_a, ioc_a], [ev_a, ev_b])
        assert len(results[0].matches) == 1
        assert len(results[1].matches) == 0

    def test_match_many_empty_lists(self):
        results = enricher.match_many([], [])
        assert results == []

    def test_match_many_raises_on_length_mismatch(self):
        with pytest.raises(ValueError):
            enricher.match_many([[]], [[], []])

    def test_match_many_three_batches(self):
        ioc_list = [make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")]
        events = [{"ip": "10.0.0.1"}]
        results = enricher.match_many([ioc_list, ioc_list, ioc_list], [events, events, events])
        assert len(results) == 3

    def test_match_many_three_batches_all_match(self):
        ioc = [make_ioc(IOCType.IP_ADDRESS, "10.0.0.1")]
        events = [{"ip": "10.0.0.1"}]
        results = enricher.match_many([ioc, ioc, ioc], [events, events, events])
        assert all(len(r.matches) == 1 for r in results)


# ===========================================================================
# 17. to_dict() serialisation
# ===========================================================================

class TestToDict:
    def test_threat_ioc_to_dict_keys(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1", tags=["apt"])
        d = ioc.to_dict()
        assert set(d.keys()) == {"ioc_type", "value", "severity", "confidence", "source", "tags"}

    def test_threat_ioc_to_dict_values(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com", severity="CRITICAL", confidence=0.8)
        d = ioc.to_dict()
        assert d["ioc_type"] == "domain"
        assert d["value"] == "evil.com"
        assert d["severity"] == "CRITICAL"
        assert d["confidence"] == pytest.approx(0.8)

    def test_threat_ioc_to_dict_tags(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.2.3.4", tags=["c2", "botnet"])
        d = ioc.to_dict()
        assert d["tags"] == ["c2", "botnet"]

    def test_ioc_match_to_dict_keys(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        match = IOCMatch(ioc=ioc, event_index=0, field_name="ip",
                         matched_value="1.1.1.1", match_confidence=1.0)
        d = match.to_dict()
        assert set(d.keys()) == {"ioc", "event_index", "field_name", "matched_value", "match_confidence"}

    def test_ioc_match_to_dict_nested_ioc(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        match = IOCMatch(ioc=ioc, event_index=2, field_name="src_ip",
                         matched_value="1.1.1.1", match_confidence=0.95)
        d = match.to_dict()
        assert isinstance(d["ioc"], dict)
        assert d["ioc"]["ioc_type"] == "ip_address"

    def test_ioc_enrich_result_to_dict_keys(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        d = result.to_dict()
        assert set(d.keys()) == {
            "matches", "risk_score", "matched_ioc_count",
            "ioc_coverage", "summary", "by_type"
        }

    def test_ioc_enrich_result_to_dict_matches_is_list(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        d = result.to_dict()
        assert isinstance(d["matches"], list)

    def test_ioc_enrich_result_to_dict_by_type_is_dict(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        d = result.to_dict()
        assert isinstance(d["by_type"], dict)

    def test_ioc_type_to_dict(self):
        d = IOCType.FILE_HASH.to_dict()
        assert d == {"name": "FILE_HASH", "value": "file_hash"}


# ===========================================================================
# 18. match_confidence propagation
# ===========================================================================

class TestMatchConfidence:
    def test_match_confidence_equals_ioc_confidence(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1", confidence=0.75)
        events = [{"ip": "1.1.1.1"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].match_confidence == pytest.approx(0.75)

    def test_match_confidence_full(self):
        ioc = make_ioc(IOCType.DOMAIN, "evil.com", confidence=1.0)
        events = [{"host": "evil.com"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].match_confidence == pytest.approx(1.0)


# ===========================================================================
# 19. Miscellaneous / regression tests
# ===========================================================================

class TestMiscellaneous:
    def test_ioc_value_in_list_field(self):
        ioc = make_ioc(IOCType.EMAIL, "hacker@dark.net")
        events = [{"recipients": ["alice@corp.com", "hacker@dark.net"]}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_multiple_events_only_second_matches(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "5.5.5.5")
        events = [{"ip": "1.2.3.4"}, {"ip": "5.5.5.5"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].event_index == 1

    def test_no_match_non_string_value_in_event(self):
        ioc = make_ioc(IOCType.IP_ADDRESS, "1.1.1.1")
        events = [{"count": 42, "flag": True, "ip": None}]
        result = enricher.match([ioc], events)
        assert result.matches == []

    def test_ioc_with_tags_serialised(self):
        ioc = ThreatIOC(
            ioc_type=IOCType.DOMAIN,
            value="evil.com",
            severity="HIGH",
            confidence=0.9,
            source="threat-intel",
            tags=["ransomware", "c2"],
        )
        d = ioc.to_dict()
        assert "ransomware" in d["tags"]

    def test_default_source_unknown(self):
        ioc = ThreatIOC(
            ioc_type=IOCType.EMAIL,
            value="x@y.z",
            severity="LOW",
            confidence=0.5,
        )
        assert ioc.source == "unknown"

    def test_blank_source_normalized_to_unknown(self):
        ioc = ThreatIOC(
            ioc_type=IOCType.EMAIL,
            value="x@y.z",
            severity="low",
            confidence=0.5,
            source="   ",
        )
        assert ioc.source == "unknown"

    def test_default_tags_empty(self):
        ioc = ThreatIOC(
            ioc_type=IOCType.EMAIL,
            value="x@y.z",
            severity="LOW",
            confidence=0.5,
        )
        assert ioc.tags == []

    def test_tags_are_trimmed_and_deduplicated(self):
        ioc = ThreatIOC(
            ioc_type=IOCType.EMAIL,
            value="x@y.z",
            severity="low",
            confidence=0.5,
            tags=[" phishing ", "phishing", "", " c2 "],
        )
        assert ioc.tags == ["phishing", "c2"]

    @pytest.mark.parametrize("value", ["", "   "])
    def test_blank_ioc_value_rejected(self, value: str):
        with pytest.raises(ValueError, match="IOC value must contain non-whitespace characters"):
            ThreatIOC(
                ioc_type=IOCType.URL,
                value=value,
                severity="HIGH",
                confidence=0.5,
            )

    @pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -0.1, 1.1])
    def test_out_of_range_or_non_finite_confidence_rejected(self, confidence: float):
        with pytest.raises(ValueError, match="IOC confidence must be a finite number between 0.0 and 1.0"):
            ThreatIOC(
                ioc_type=IOCType.URL,
                value="evil.com",
                severity="HIGH",
                confidence=confidence,
            )

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError, match="IOC severity must be one of"):
            ThreatIOC(
                ioc_type=IOCType.URL,
                value="evil.com",
                severity="urgent",
                confidence=0.5,
            )

    def test_type_weights_all_types_present(self):
        for t in IOCType:
            assert t.value in _TYPE_WEIGHTS, f"Missing weight for {t}"

    def test_type_weights_values_positive(self):
        for k, v in _TYPE_WEIGHTS.items():
            assert v > 0, f"Weight for {k} must be positive"

    def test_url_ioc_matches_prefix(self):
        ioc = make_ioc(IOCType.URL, "evil.com")
        events = [{"url": "http://evil.com/path"}]
        result = enricher.match([ioc], events)
        assert len(result.matches) == 1

    def test_process_name_match_confidence_propagated(self):
        ioc = make_ioc(IOCType.PROCESS_NAME, "mimikatz.exe", confidence=0.88)
        events = [{"proc": "mimikatz.exe"}]
        result = enricher.match([ioc], events)
        assert result.matches[0].match_confidence == pytest.approx(0.88)
