"""
MITRE ATT&CK Auto-Tagger for IR Incidents
==========================================
Automatically tags incident records with MITRE ATT&CK technique IDs based
on incident type, indicators of compromise (IoCs), and free-text fields.

The tagger enriches IncidentRecord objects (or plain dicts) with:
  - tactic names   (e.g. "Initial Access", "Credential Access")
  - technique IDs  (e.g. "T1078", "T1110")
  - sub-technique IDs where applicable (e.g. "T1078.004")

Mapping Strategy:
  1. IncidentType → primary technique(s): deterministic, always applied
  2. Keyword scan of title + description: pattern matching for additional TTPs
  3. IoC type hints: if the incident has cloud-resource or credential IoCs,
     extra cloud-specific techniques are added

Usage:
    from automations.mitre_attack_tagger import (
        tag_incident,
        AttackTag,
        AttackTaggingResult,
    )
    from schemas.incident import IncidentRecord, IncidentType, SeverityLevel

    record = IncidentRecord(
        incident_id="INC-2026-042",
        title="Compromised service account — unusual API calls detected",
        severity=SeverityLevel.HIGH,
        incident_type=IncidentType.CREDENTIAL_COMPROMISE,
    )

    result = tag_incident(record)
    for tag in result.tags:
        print(f"[{tag.tactic}] {tag.technique_id} — {tag.technique_name}")

    # Enriched dict ready for SIEM or ticketing system
    enriched = result.to_dict()
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackTag:
    """A single MITRE ATT&CK technique tag."""
    technique_id:   str         # e.g. "T1078" or "T1078.004"
    technique_name: str         # human-readable name
    tactic:         str         # parent tactic (e.g. "Credential Access")
    source:         str         # "incident_type" | "keyword" | "ioc_hint"
    confidence:     str = "medium"  # "high" | "medium" | "low"

    def __str__(self) -> str:
        return f"[{self.tactic}] {self.technique_id} {self.technique_name} (conf={self.confidence})"


@dataclass
class AttackTaggingResult:
    """Result of tagging an incident with MITRE ATT&CK techniques."""
    incident_id:  str
    tags:         list[AttackTag] = field(default_factory=list)
    tactics:      list[str]       = field(default_factory=list)
    technique_ids: list[str]      = field(default_factory=list)

    def __post_init__(self) -> None:
        # Derive convenience fields from tags
        self.tactics = sorted({t.tactic for t in self.tags})
        self.technique_ids = sorted({t.technique_id for t in self.tags})

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict for SIEM ingestion or ticket enrichment."""
        return {
            "incident_id":    self.incident_id,
            "mitre_tactics":  self.tactics,
            "mitre_techniques": self.technique_ids,
            "mitre_tags": [
                {
                    "technique_id":   t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic":         t.tactic,
                    "source":         t.source,
                    "confidence":     t.confidence,
                }
                for t in self.tags
            ],
        }

    def summary(self) -> str:
        if not self.tags:
            return f"[{self.incident_id}] No ATT&CK tags generated"
        return (
            f"[{self.incident_id}] {len(self.tags)} tag(s) across "
            f"{len(self.tactics)} tactic(s): {', '.join(self.tactics)}"
        )


# ---------------------------------------------------------------------------
# ATT&CK technique catalog (subset — most relevant to IR scenarios)
# ---------------------------------------------------------------------------

# Format: (technique_id, technique_name, tactic, confidence)
_T = tuple[str, str, str, str]


def _tag(tid: str, name: str, tactic: str, conf: str = "high", source: str = "incident_type") -> AttackTag:
    return AttackTag(technique_id=tid, technique_name=name, tactic=tactic, source=source, confidence=conf)


# ---------------------------------------------------------------------------
# IncidentType → primary MITRE techniques (deterministic)
# ---------------------------------------------------------------------------

_INCIDENT_TYPE_TAGS: dict[str, list[AttackTag]] = {
    "credential_compromise": [
        _tag("T1078",     "Valid Accounts",                    "Defense Evasion"),
        _tag("T1078",     "Valid Accounts",                    "Initial Access"),
        _tag("T1078.004", "Valid Accounts: Cloud Accounts",    "Defense Evasion"),
        _tag("T1552",     "Unsecured Credentials",             "Credential Access"),
    ],
    "malware": [
        _tag("T1059",     "Command and Scripting Interpreter", "Execution"),
        _tag("T1055",     "Process Injection",                 "Defense Evasion"),
        _tag("T1070",     "Indicator Removal",                 "Defense Evasion"),
        _tag("T1027",     "Obfuscated Files or Information",   "Defense Evasion"),
    ],
    "data_exposure": [
        _tag("T1530",     "Data from Cloud Storage",           "Collection"),
        _tag("T1537",     "Transfer Data to Cloud Account",    "Exfiltration"),
        _tag("T1567",     "Exfiltration Over Web Service",     "Exfiltration"),
    ],
    "api_abuse": [
        _tag("T1190",     "Exploit Public-Facing Application", "Initial Access"),
        _tag("T1059",     "Command and Scripting Interpreter", "Execution"),
        _tag("T1106",     "Native API",                        "Execution"),
    ],
    "phishing": [
        _tag("T1566",     "Phishing",                          "Initial Access"),
        _tag("T1566.001", "Phishing: Spearphishing Attachment","Initial Access"),
        _tag("T1566.002", "Phishing: Spearphishing Link",      "Initial Access"),
        _tag("T1598",     "Phishing for Information",          "Reconnaissance"),
    ],
    "cloud_exposure": [
        _tag("T1580",     "Cloud Infrastructure Discovery",    "Discovery"),
        _tag("T1526",     "Cloud Service Discovery",           "Discovery"),
        _tag("T1530",     "Data from Cloud Storage",           "Collection"),
        _tag("T1562.008", "Impair Defenses: Disable Cloud Logs","Defense Evasion"),
    ],
    "secret_leakage": [
        _tag("T1552",     "Unsecured Credentials",             "Credential Access"),
        _tag("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access"),
        _tag("T1213",     "Data from Information Repositories","Collection"),
    ],
    "generic": [
        _tag("T1078",     "Valid Accounts",                    "Initial Access", conf="low"),
    ],
}


# ---------------------------------------------------------------------------
# Keyword → additional MITRE techniques (pattern matching)
# ---------------------------------------------------------------------------

@dataclass
class _KeywordRule:
    pattern: re.Pattern
    tag:     AttackTag


def _krule(pattern: str, tid: str, name: str, tactic: str, conf: str = "medium") -> _KeywordRule:
    return _KeywordRule(
        pattern=re.compile(pattern, re.IGNORECASE),
        tag=AttackTag(
            technique_id=tid, technique_name=name, tactic=tactic,
            source="keyword", confidence=conf,
        ),
    )


_KEYWORD_RULES: list[_KeywordRule] = [
    # Credential attacks
    _krule(r"\bbrute.?force\b",              "T1110",     "Brute Force",                       "Credential Access"),
    _krule(r"\bpassword.?spray",             "T1110.003", "Brute Force: Password Spraying",     "Credential Access"),
    _krule(r"\bcredential.?stuff",           "T1110.004", "Brute Force: Credential Stuffing",   "Credential Access"),
    _krule(r"\bmfa.{0,20}bypass\b",          "T1111",     "Multi-Factor Authentication Interception", "Credential Access"),
    _krule(r"\btoken.{0,20}(theft|stolen|hijack)", "T1528", "Steal Application Access Token",  "Credential Access"),
    _krule(r"\bservice.?account.{0,20}(compromised|misuse)", "T1078.004", "Valid Accounts: Cloud Accounts", "Credential Access"),
    # Privilege escalation
    _krule(r"\bprivilege.?escal",            "T1068",     "Exploitation for Privilege Escalation", "Privilege Escalation"),
    _krule(r"\bcluster.?admin\b",            "T1078.004", "Valid Accounts: Cloud Accounts",    "Privilege Escalation"),
    _krule(r"\brbac.{0,20}(abuse|misconfig)", "T1078",    "Valid Accounts",                    "Privilege Escalation"),
    # Discovery
    _krule(r"\bport.?scan\b",                "T1046",     "Network Service Discovery",         "Discovery"),
    _krule(r"\brecon\b",                     "T1595",     "Active Scanning",                   "Reconnaissance"),
    _krule(r"\biam.{0,20}(enum|list|discover)", "T1069.003", "Permission Groups Discovery: Cloud Groups", "Discovery"),
    _krule(r"\bsecret.{0,20}(access|read|dump)", "T1552", "Unsecured Credentials",             "Credential Access"),
    # Execution
    _krule(r"\bremote.?code.?exec\b",        "T1210",     "Exploitation of Remote Services",  "Lateral Movement"),
    _krule(r"\bsupply.?chain\b",             "T1195",     "Supply Chain Compromise",           "Initial Access"),
    _krule(r"\bci.?cd\b",                    "T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain", "Initial Access"),
    # Persistence
    _krule(r"\bbackdoor\b",                  "T1505",     "Server Software Component",         "Persistence"),
    _krule(r"\bwebshell\b",                  "T1505.003", "Server Software Component: Web Shell","Persistence"),
    _krule(r"\bcron.?job\b",                 "T1053.003", "Scheduled Task/Job: Cron",          "Persistence"),
    # Exfiltration
    _krule(r"\bdata.{0,20}exfil",            "T1020",     "Automated Exfiltration",            "Exfiltration"),
    _krule(r"\bs3.{0,20}(public|exposed|dump)", "T1530",  "Data from Cloud Storage",           "Collection"),
    # Containers / K8s
    _krule(r"\bcontainer.{0,20}(escape|breakout)", "T1611", "Escape to Host",                  "Privilege Escalation"),
    _krule(r"\bprivileged.{0,20}container",  "T1611",     "Escape to Host",                    "Privilege Escalation"),
    _krule(r"\bkubernetes\b.*\bexec\b",      "T1609",     "Container Administration Command",  "Execution"),
    _krule(r"\bcrypto.{0,20}min",            "T1496",     "Resource Hijacking",                "Impact"),
    # Impact
    _krule(r"\bransom",                      "T1486",     "Data Encrypted for Impact",         "Impact"),
    _krule(r"\bdos\b|\bdenial.of.service\b", "T1498",     "Network Denial of Service",         "Impact"),
]


# ---------------------------------------------------------------------------
# IoC-based hints (if incident has structured IoC data)
# ---------------------------------------------------------------------------

_IOC_HINTS: dict[str, list[AttackTag]] = {
    # If IoC type strings contain these keywords, add these tags
    "api_key": [
        _tag("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", source="ioc_hint"),
    ],
    "aws_access_key": [
        _tag("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access", source="ioc_hint"),
    ],
    "jwt": [
        _tag("T1528",     "Steal Application Access Token",   "Credential Access", source="ioc_hint"),
    ],
    "ip": [
        _tag("T1071",     "Application Layer Protocol",       "Command and Control", conf="low", source="ioc_hint"),
    ],
    "domain": [
        _tag("T1568",     "Dynamic Resolution",               "Command and Control", conf="low", source="ioc_hint"),
    ],
    "hash": [
        _tag("T1027",     "Obfuscated Files or Information",  "Defense Evasion", conf="low", source="ioc_hint"),
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def tag_incident(
    incident: Any,
    include_keyword_scan: bool = True,
    include_ioc_hints: bool = True,
) -> AttackTaggingResult:
    """
    Tag an incident record with MITRE ATT&CK techniques.

    Accepts either an IncidentRecord (from schemas.incident) or a plain dict
    with keys: incident_id, incident_type, title, description, iocs.

    Args:
        incident:              IncidentRecord or dict.
        include_keyword_scan:  If True, scan title+description for extra TTPs.
        include_ioc_hints:     If True, check IoC types for cloud-specific TTPs.

    Returns:
        AttackTaggingResult with deduplicated tags sorted by tactic.
    """
    # Normalize input to dict
    if hasattr(incident, "model_dump"):
        data = incident.model_dump(mode="json")
    elif hasattr(incident, "__dict__"):
        data = vars(incident)
    elif isinstance(incident, dict):
        data = incident
    else:
        data = {}

    incident_id = str(data.get("incident_id", "<unknown>"))
    incident_type = str(data.get("incident_type", "generic")).lower()
    title = str(data.get("title", ""))
    description = str(data.get("description", "") or "")
    iocs = data.get("iocs") or []  # list of EvidenceItem or dicts

    seen: set[str] = set()   # (technique_id, tactic) dedup key
    tags: list[AttackTag] = []

    def _add(t: AttackTag) -> None:
        key = f"{t.technique_id}:{t.tactic}"
        if key not in seen:
            seen.add(key)
            tags.append(t)

    # Step 1: Incident-type primary tags
    primary_tags = _INCIDENT_TYPE_TAGS.get(incident_type, _INCIDENT_TYPE_TAGS["generic"])
    for t in primary_tags:
        _add(t)

    # Step 2: Keyword scan
    if include_keyword_scan:
        text = f"{title} {description}"
        for rule in _KEYWORD_RULES:
            if rule.pattern.search(text):
                _add(rule.tag)

    # Step 3: IoC hints
    if include_ioc_hints and iocs:
        for ioc in iocs:
            ioc_type = ""
            if isinstance(ioc, dict):
                ioc_type = str(ioc.get("evidence_type", "") or ioc.get("ioc_type", "")).lower()
            elif hasattr(ioc, "evidence_type"):
                ioc_type = str(ioc.evidence_type).lower()
            for hint_key, hint_tags in _IOC_HINTS.items():
                if hint_key in ioc_type:
                    for t in hint_tags:
                        _add(t)

    # Sort by tactic then technique_id for stable output
    tags.sort(key=lambda t: (t.tactic, t.technique_id))

    result = AttackTaggingResult(incident_id=incident_id, tags=tags)
    return result


def enrich_incident_dict(
    incident_dict: dict[str, Any],
    include_keyword_scan: bool = True,
    include_ioc_hints: bool = True,
) -> dict[str, Any]:
    """
    Return a copy of incident_dict enriched with MITRE ATT&CK fields.

    Adds keys: mitre_tactics, mitre_techniques, mitre_tags.

    Args:
        incident_dict:         Plain dict representation of an incident.
        include_keyword_scan:  Enable keyword-based TTP detection.
        include_ioc_hints:     Enable IoC-type-based TTP hints.

    Returns:
        Enriched dict (original is not mutated).
    """
    result = tag_incident(
        incident_dict,
        include_keyword_scan=include_keyword_scan,
        include_ioc_hints=include_ioc_hints,
    )
    enriched = dict(incident_dict)
    enriched.update(result.to_dict())
    return enriched
