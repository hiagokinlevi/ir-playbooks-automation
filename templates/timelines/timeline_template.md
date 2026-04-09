# Attack Timeline Template
<!--
  Instructions:
  - All timestamps must be in UTC (ISO 8601)
  - Add events as they are discovered — do not wait until after the incident
  - Distinguish between "observed at" (when the event happened) and "discovered at" (when the analyst found it)
  - Events marked [ATTACKER] represent attacker actions; [DEFENDER] represent response actions
  - Use [UNKNOWN] when the event time cannot be precisely determined
-->

**Incident ID:** `INC-<YYYYMMDD>-<NNN>`
**Timeline Author:** `<analyst name>`
**Last Updated:** `<UTC timestamp>`

---

## Pre-Incident Context

> _Optional: include relevant context that existed before the incident, such as known vulnerabilities, recent changes, or threat intelligence._

---

## Timeline

### `<YYYY-MM-DD>` — Day 1

| Time (UTC) | Phase | Actor | Event | Evidence | Confidence |
|---|---|---|---|---|---|
| `HH:MM:SSZ` | `Initial Access` | `[ATTACKER]` | `<what happened>` | `<log ref / evidence ID>` | `High/Med/Low` |
| `HH:MM:SSZ` | `Discovery` | `[DEFENDER]` | `Alert triggered: <rule name>` | `SIEM alert ID: <id>` | `High` |

### `<YYYY-MM-DD>` — Day 2

| Time (UTC) | Phase | Actor | Event | Evidence | Confidence |
|---|---|---|---|---|---|
| `HH:MM:SSZ` | `Triage` | `[DEFENDER]` | `Incident INC-<ID> opened; severity <SEV> assigned` | Incident record | `High` |
| `HH:MM:SSZ` | `Persistence` | `[ATTACKER]` | `<what attacker did to maintain access>` | `<evidence>` | `Medium` |
| `HH:MM:SSZ` | `Containment` | `[DEFENDER]` | `<containment action taken>` | Automation log | `High` |

> _Continue adding rows. Group by day for readability._

---

## Timeline Summary

| Phase | Start (UTC) | End (UTC) | Duration |
|---|---|---|---|
| Attack active (pre-detection) | `<time>` | `<time>` | `<Xh Ym>` |
| Detection to triage | `<time>` | `<time>` | `<Xh Ym>` |
| Triage to containment start | `<time>` | `<time>` | `<Xh Ym>` |
| Containment to eradication complete | `<time>` | `<time>` | `<Xh Ym>` |
| Eradication to service restoration | `<time>` | `<time>` | `<Xh Ym>` |
| **Total incident duration** | `<time>` | `<time>` | `<Xh Ym>` |

---

## Key Metrics

| Metric | Value |
|---|---|
| **Mean Time to Detect (MTTD)** | `<duration from first attacker action to first alert>` |
| **Mean Time to Respond (MTTR)** | `<duration from alert to containment complete>` |
| **Dwell Time** | `<duration attacker had active access>` |
| **Time to Closure** | `<duration from open to closed>` |

---

## Timeline Gaps

> _Document any time periods where attacker activity may have occurred but is unverified due to missing logs or telemetry._

| Gap Period | Missing Telemetry | Impact on Investigation |
|---|---|---|
| `<start> to <end>` | `<e.g., CloudTrail logging was disabled>` | `<e.g., Cannot confirm attacker did not access S3>` |
