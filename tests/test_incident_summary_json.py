import json

from click.testing import CliRunner

import ir_playbooks_automation_cli as app


def test_incident_summary_json_output(tmp_path, monkeypatch):
    db_path = tmp_path / ".incidents.json"
    db_path.write_text(
        json.dumps(
            {
                "IR-2026-001": {
                    "current_state": "triage",
                    "severity": "high",
                    "opened_at": "2026-01-01T00:00:00Z",
                    "updated_at": "2026-01-01T01:00:00Z",
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "INCIDENT_DB", db_path)

    runner = CliRunner()
    result = runner.invoke(app.cli, ["incident-summary", "IR-2026-001", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload == {
        "incident_id": "IR-2026-001",
        "current_state": "triage",
        "severity": "high",
        "opened_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T01:00:00Z",
    }
