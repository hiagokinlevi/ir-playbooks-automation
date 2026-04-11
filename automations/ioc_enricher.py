# SPDX-License-Identifier: CC-BY-4.0
# Copyright (c) 2026 Cyber Port — hiagokinlevi
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# You are free to share and adapt this material for any purpose, even
# commercially, as long as you give appropriate credit. Full license text:
# https://creativecommons.org/licenses/by/4.0/
"""
IOC Enricher — Indicator of Compromise Enrichment and Correlation Engine
========================================================================
Matches threat intelligence IOCs against structured event data **offline**;
no live API calls are made. Suitable for air-gapped SOC environments and
deterministic unit-test coverage.

Core concepts
-------------
- ``ThreatIOC``     — a single threat intelligence indicator with metadata.
- ``IOCMatch``      — one confirmed hit: an IOC matched a specific field in a
                      specific event.
- ``IOCEnrichResult``— aggregated result for a batch (iocs × events): list of
                      matches plus derived risk score and coverage metrics.
- ``IOCEnricher``   — stateless engine that drives matching and scoring.

Quick-start
-----------
::

    from automations.ioc_enricher import IOCEnricher, ThreatIOC, IOCType

    iocs = [
        ThreatIOC(ioc_type=IOCType.IP_ADDRESS, value="10.0.0.1",
                  severity="HIGH", confidence=0.9),
        ThreatIOC(ioc_type=IOCType.DOMAIN, value="evil.com",
                  severity="CRITICAL", confidence=1.0),
    ]
    events = [
        {"src_ip": "10.0.0.1", "dns_query": "sub.evil.com"},
    ]

    result = IOCEnricher().match(iocs, events)
    print(result.summary())
    # IOCEnrichResult: 2 matches (2 unique IOCs), risk_score=55, coverage=1.00
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# IOCType
# ---------------------------------------------------------------------------

class IOCType(str, Enum):
    """Supported indicator-of-compromise types.

    Inherits from ``str`` so instances compare equal to their string values,
    which simplifies serialisation and dict-key lookups.
    """

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"       # MD5 / SHA-1 / SHA-256
    URL = "url"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation of this enum member."""
        return {"name": self.name, "value": self.value}


# ---------------------------------------------------------------------------
# Per-type base weights used in risk scoring
# ---------------------------------------------------------------------------

_TYPE_WEIGHTS: Dict[str, int] = {
    IOCType.IP_ADDRESS.value:    30,
    IOCType.DOMAIN.value:        25,
    IOCType.FILE_HASH.value:     35,
    IOCType.URL.value:           20,
    IOCType.EMAIL.value:         15,
    IOCType.REGISTRY_KEY.value:  20,
    IOCType.PROCESS_NAME.value:  25,
}

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# ThreatIOC
# ---------------------------------------------------------------------------

@dataclass
class ThreatIOC:
    """A single threat intelligence indicator.

    Attributes
    ----------
    ioc_type:
        Category of the indicator (see :class:`IOCType`).
    value:
        The raw indicator string, e.g. ``"192.0.2.1"``, ``"evil.com"``,
        ``"d41d8cd98f00b204e9800998ecf8427e"``.
    severity:
        One of ``"CRITICAL"`` / ``"HIGH"`` / ``"MEDIUM"`` / ``"LOW"``.
    confidence:
        Analyst confidence in the indicator, ``0.0`` – ``1.0``.
    source:
        Origin feed or analyst identifier; defaults to ``"unknown"``.
    tags:
        Free-form labels for grouping (e.g. ``["APT29", "phishing"]``).
    """

    ioc_type: IOCType
    value: str
    severity: str
    confidence: float
    source: str = "unknown"
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Normalize basic IOC fields before they participate in matching."""
        self.value = _normalize_required_text(self.value, field_name="IOC value")
        self.severity = _normalize_severity(self.severity)
        self.confidence = _normalize_confidence(self.confidence)
        self.source = _normalize_optional_text(self.source, default="unknown")
        self.tags = _normalize_tags(self.tags)

    def to_dict(self) -> dict:
        """Serialise to a plain ``dict`` suitable for JSON encoding."""
        return {
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "tags": list(self.tags),
        }


# ---------------------------------------------------------------------------
# IOCMatch
# ---------------------------------------------------------------------------

@dataclass
class IOCMatch:
    """Records a confirmed hit between one IOC and one event field.

    Attributes
    ----------
    ioc:
        The :class:`ThreatIOC` that triggered this match.
    event_index:
        Zero-based index of the matching event in the supplied events list.
    field_name:
        Dot-separated path to the field that matched, e.g. ``"dns.query"``.
    matched_value:
        The actual string extracted from the event that satisfied the match
        condition.
    match_confidence:
        Confidence value propagated from ``ioc.confidence``; may be adjusted
        downward for partial / heuristic matches in future extensions.
    """

    ioc: ThreatIOC
    event_index: int
    field_name: str
    matched_value: str
    match_confidence: float

    def to_dict(self) -> dict:
        """Serialise to a plain ``dict`` suitable for JSON encoding."""
        return {
            "ioc": self.ioc.to_dict(),
            "event_index": self.event_index,
            "field_name": self.field_name,
            "matched_value": self.matched_value,
            "match_confidence": self.match_confidence,
        }


# ---------------------------------------------------------------------------
# IOCEnrichResult
# ---------------------------------------------------------------------------

@dataclass
class IOCEnrichResult:
    """Aggregated enrichment result for one (iocs, events) batch.

    Attributes
    ----------
    matches:
        All confirmed :class:`IOCMatch` objects (deduplicated).
    risk_score:
        Integer 0–100 derived from the type weights of every unique IOC value
        that fired at least one match.
    matched_ioc_count:
        Number of *unique* IOC values that had at least one match.
    ioc_coverage:
        ``matched_ioc_count / total_iocs_provided``; ``0.0`` when no IOCs were
        supplied.
    """

    matches: List[IOCMatch]
    risk_score: int
    matched_ioc_count: int
    ioc_coverage: float

    # ------------------------------------------------------------------
    # Derived accessors
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a single-line human-readable description of the result.

        Example::

            "IOCEnrichResult: 3 matches (2 unique IOCs), risk_score=55, coverage=0.67"
        """
        return (
            f"IOCEnrichResult: {len(self.matches)} matches "
            f"({self.matched_ioc_count} unique IOCs), "
            f"risk_score={self.risk_score}, "
            f"coverage={self.ioc_coverage:.2f}"
        )

    def by_type(self) -> Dict[str, List[IOCMatch]]:
        """Group matches by IOC type string.

        Returns
        -------
        dict
            Keys are :attr:`IOCType.value` strings; values are lists of
            :class:`IOCMatch` objects of that type.  Only types that have at
            least one match appear as keys.
        """
        result: Dict[str, List[IOCMatch]] = {}
        for m in self.matches:
            key = m.ioc.ioc_type.value
            result.setdefault(key, []).append(m)
        return result

    def to_dict(self) -> dict:
        """Serialise to a plain ``dict`` suitable for JSON encoding."""
        return {
            "matches": [m.to_dict() for m in self.matches],
            "risk_score": self.risk_score,
            "matched_ioc_count": self.matched_ioc_count,
            "ioc_coverage": self.ioc_coverage,
            "summary": self.summary(),
            "by_type": {
                k: [m.to_dict() for m in v]
                for k, v in self.by_type().items()
            },
        }


# ---------------------------------------------------------------------------
# IOCEnricher — matching engine
# ---------------------------------------------------------------------------

class IOCEnricher:
    """Stateless engine for offline IOC enrichment and correlation.

    All matching logic is deterministic and requires no external network
    access, making it suitable for unit tests and air-gapped deployments.

    Example
    -------
    ::

        enricher = IOCEnricher()
        result = enricher.match(iocs, events)
        results = enricher.match_many([iocs_a, iocs_b], [events_a, events_b])
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(
        self,
        iocs: List[ThreatIOC],
        events: List[dict],
    ) -> IOCEnrichResult:
        """Match a list of IOCs against a list of event dicts.

        Parameters
        ----------
        iocs:
            Threat intelligence indicators to search for.
        events:
            Structured event records (arbitrary nested dicts/lists of strings).

        Returns
        -------
        IOCEnrichResult
            Populated with all confirmed matches, risk score, and coverage.
        """
        if not iocs or not events:
            # No input — return an empty, zero-score result immediately.
            return IOCEnrichResult(
                matches=[],
                risk_score=0,
                matched_ioc_count=0,
                ioc_coverage=0.0,
            )

        # Pre-extract string fields from every event once so we do not repeat
        # the extraction for every IOC.
        extracted: List[List[Tuple[str, str]]] = [
            _extract_strings(ev) for ev in events
        ]

        raw_matches: List[IOCMatch] = []
        # Deduplication key: (ioc_value_lower, event_index, field_name_lower)
        seen: set = set()

        for ioc in iocs:
            for event_index, field_pairs in enumerate(extracted):
                for field_name, field_value in field_pairs:
                    if _ioc_matches(ioc, field_value):
                        # Build dedup key — normalise case for robustness.
                        dedup_key = (
                            ioc.value.lower(),
                            event_index,
                            field_name.lower(),
                        )
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        raw_matches.append(
                            IOCMatch(
                                ioc=ioc,
                                event_index=event_index,
                                field_name=field_name,
                                matched_value=field_value,
                                match_confidence=ioc.confidence,
                            )
                        )

        # --- risk score: sum weights of unique IOC *values* that fired ------
        fired_values: set = set()
        for m in raw_matches:
            fired_values.add(m.ioc.value.lower())

        # Map each fired value back to its IOC to get the type weight.
        # We need: for each unique fired value, the corresponding IOC type.
        # Build a lookup from normalised value → ioc_type (first seen wins;
        # values are unique per IOC in well-formed intel feeds).
        value_to_type: Dict[str, str] = {}
        for ioc in iocs:
            key = ioc.value.lower()
            if key not in value_to_type:
                value_to_type[key] = ioc.ioc_type.value

        raw_score = sum(
            _TYPE_WEIGHTS.get(value_to_type[v], 0) for v in fired_values
        )
        risk_score = min(100, raw_score)

        matched_ioc_count = len(fired_values)
        ioc_coverage = matched_ioc_count / len(iocs) if iocs else 0.0

        return IOCEnrichResult(
            matches=raw_matches,
            risk_score=risk_score,
            matched_ioc_count=matched_ioc_count,
            ioc_coverage=ioc_coverage,
        )

    def match_many(
        self,
        ioc_lists: List[List[ThreatIOC]],
        event_lists: List[List[dict]],
    ) -> List[IOCEnrichResult]:
        """Run :meth:`match` for each corresponding pair of (iocs, events).

        Parameters
        ----------
        ioc_lists:
            Parallel list of IOC lists.
        event_lists:
            Parallel list of event lists.  Must be the same length as
            ``ioc_lists``.

        Returns
        -------
        list of IOCEnrichResult
            One result per (iocs, events) pair, in the same order.

        Raises
        ------
        ValueError
            If ``ioc_lists`` and ``event_lists`` differ in length.
        """
        if len(ioc_lists) != len(event_lists):
            raise ValueError(
                f"ioc_lists length ({len(ioc_lists)}) must equal "
                f"event_lists length ({len(event_lists)})"
            )
        return [
            self.match(iocs, events)
            for iocs, events in zip(ioc_lists, event_lists)
        ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_required_text(value: object, *, field_name: str) -> str:
    """Return stripped text and reject blank or non-string values."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must contain non-whitespace characters")
    return normalized


def _normalize_optional_text(value: object, *, default: str) -> str:
    """Return stripped text, or a default when omitted or blank."""
    if value is None:
        return default
    if not isinstance(value, str):
        raise TypeError("IOC source must be a string")

    normalized = value.strip()
    return normalized or default


def _normalize_severity(value: object) -> str:
    """Return a canonical uppercase severity string."""
    normalized = _normalize_required_text(value, field_name="IOC severity").upper()
    if normalized not in _VALID_SEVERITIES:
        allowed = ", ".join(sorted(_VALID_SEVERITIES))
        raise ValueError(f"IOC severity must be one of: {allowed}")
    return normalized


def _normalize_confidence(value: object) -> float:
    """Coerce confidence to float and reject non-finite or out-of-range values."""
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise TypeError("IOC confidence must be a number") from exc

    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise ValueError("IOC confidence must be a finite number between 0.0 and 1.0")
    return normalized


def _normalize_tags(tags: object) -> List[str]:
    """Keep non-empty tag strings and trim surrounding whitespace."""
    if tags is None:
        return []
    if not isinstance(tags, list):
        raise TypeError("IOC tags must be a list of strings")

    normalized_tags: List[str] = []
    seen: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            raise TypeError("IOC tags must be a list of strings")

        normalized = tag.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        normalized_tags.append(normalized)

    return normalized_tags

def _extract_strings(event: dict) -> List[Tuple[str, str]]:
    """Recursively extract all (field_path, string_value) pairs from an event.

    Handles arbitrary nesting of dicts and lists.  Non-string leaf values are
    skipped.  List items receive a path suffix like ``"alerts[0]"``.

    Parameters
    ----------
    event:
        A structured event record.

    Returns
    -------
    list of (str, str) tuples
        Each tuple is ``(dot_separated_path, string_value)``.
    """
    results: List[Tuple[str, str]] = []
    _recurse(event, prefix="", results=results)
    return results


def _recurse(
    node: object,
    prefix: str,
    results: List[Tuple[str, str]],
) -> None:
    """Depth-first traversal helper for :func:`_extract_strings`."""
    if isinstance(node, str):
        # Leaf: record the (path, value) pair.
        results.append((prefix, node))
    elif isinstance(node, dict):
        for key, value in node.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            _recurse(value, child_prefix, results)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            child_prefix = f"{prefix}[{idx}]"
            _recurse(item, child_prefix, results)
    # All other types (int, float, bool, None) are ignored.


def _ioc_matches(ioc: ThreatIOC, value: str) -> bool:
    """Determine whether *value* satisfies the match condition for *ioc*.

    Matching rules per type
    -----------------------
    - **IP_ADDRESS** — exact case-insensitive string match.
    - **DOMAIN** — case-insensitive: value equals ``ioc.value`` OR value ends
      with ``".{ioc.value}"`` (covers subdomains).
    - **FILE_HASH** — exact case-insensitive match (handles mixed-case hex).
    - **URL** — case-insensitive substring: ``ioc.value in value``.
    - **EMAIL** — exact case-insensitive match.
    - **REGISTRY_KEY** — exact case-insensitive match.
    - **PROCESS_NAME** — case-insensitive match of ``os.path.basename(value)``
      against ``ioc.value``, OR full-path exact match.

    Parameters
    ----------
    ioc:
        The threat indicator to test.
    value:
        A string extracted from an event field.

    Returns
    -------
    bool
        ``True`` if the value matches the IOC according to the type rules.
    """
    ioc_val_lower = ioc.value.lower()
    val_lower = value.strip().lower()
    if not val_lower:
        return False

    if ioc.ioc_type == IOCType.IP_ADDRESS:
        # Exact match only — avoid false positives on partial IP strings.
        return val_lower == ioc_val_lower

    if ioc.ioc_type == IOCType.DOMAIN:
        # Matches "evil.com" and "sub.evil.com" but NOT "notevil.com".
        return val_lower == ioc_val_lower or val_lower.endswith(f".{ioc_val_lower}")

    if ioc.ioc_type == IOCType.FILE_HASH:
        # Hash comparison is case-insensitive (hex string may be upper/lower).
        return val_lower == ioc_val_lower

    if ioc.ioc_type == IOCType.URL:
        # Substring match: the IOC URL may be a prefix or embedded path.
        return ioc_val_lower in val_lower

    if ioc.ioc_type == IOCType.EMAIL:
        # Email addresses are case-insensitive per RFC 5321 local-part
        # convention (though technically the local part is case-sensitive,
        # in practice all major providers treat it as case-insensitive).
        return val_lower == ioc_val_lower

    if ioc.ioc_type == IOCType.REGISTRY_KEY:
        # Registry keys are case-insensitive on Windows.
        return val_lower == ioc_val_lower

    if ioc.ioc_type == IOCType.PROCESS_NAME:
        # Match on basename OR full path equals IOC value.
        # os.path.basename only splits on the OS separator; on POSIX that is
        # "/" only, so Windows paths with "\" must be handled explicitly.
        # We split on both "/" and "\" to cover all platforms.
        basename_lower = val_lower.replace("\\", "/").split("/")[-1]
        return basename_lower == ioc_val_lower or val_lower == ioc_val_lower

    # Unknown type — no match.  This branch is unreachable with the current
    # enum definition but satisfies exhaustive type checking.
    return False  # pragma: no cover
