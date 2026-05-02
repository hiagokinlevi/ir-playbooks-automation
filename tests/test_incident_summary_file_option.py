from __future__ import annotations

import json

from click.testing import CliRunner

from cli import cli


def test_incident_summary_reads_explicit_file_json_output(tmp_path):
    incident_file = tmp_path / "incident.json"
    incident_file.write_text(
        json.dumps(
            {
                "incident_id": "IR-2026-0001",
                "title": "Suspicious OAuth app",
                "severity": "high",
                "status": "triage",
                "summary": "Analyst investigating suspicious consent grant",
                "created_at": "2026-01-10T10:00:00Z"
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["incident-summary", "--file", str(incident_file), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["incident_id"] == "IR-2026-0001"


def test_incident_summary_file_not_found_returns_nonzero():
    runner = CliRunner()
    result = runner.invoke(cli, ["incident-summary", "--file", "does-not-exist.json"])

    assert result.exit_code != 0
    assert "Incident record file not found" in result.output
