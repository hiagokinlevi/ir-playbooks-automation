from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def _write_incident(tmp_path: Path) -> Path:
    incident = {
        "id": "IR-2026-0042",
        "title": "Suspicious OAuth App",
        "severity": "high",
        "state": "triage",
        "owner": "alice",
        "created_at": "2026-04-30T12:00:00Z",
        "updated_at": "2026-04-30T12:05:00Z",
    }
    path = tmp_path / "incident.json"
    path.write_text(json.dumps(incident), encoding="utf-8")
    return path


def test_incident_summary_default_line(tmp_path: Path) -> None:
    runner = CliRunner()
    incident_path = _write_incident(tmp_path)

    result = runner.invoke(cli, ["incident-summary", str(incident_path)])

    assert result.exit_code == 0
    assert (
        "IR-2026-0042 severity=high state=triage owner=alice" in result.output.strip()
    )


def test_incident_summary_custom_format(tmp_path: Path) -> None:
    runner = CliRunner()
    incident_path = _write_incident(tmp_path)

    result = runner.invoke(
        cli,
        [
            "incident-summary",
            str(incident_path),
            "--format",
            "{id} {severity} {state} {owner}",
        ],
    )

    assert result.exit_code == 0
    assert result.output.strip() == "IR-2026-0042 high triage alice"


def test_incident_summary_unknown_placeholder_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    incident_path = _write_incident(tmp_path)

    result = runner.invoke(
        cli,
        ["incident-summary", str(incident_path), "--format", "{id} {bogus}"],
    )

    assert result.exit_code != 0
    assert "Unknown placeholder(s): bogus" in result.output
    assert "Allowed placeholders:" in result.output
