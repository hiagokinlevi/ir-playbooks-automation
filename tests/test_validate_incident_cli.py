import json

from click.testing import CliRunner

from cli.commands import cli


def test_validate_incident_success(tmp_path):
    # Minimal valid structure expected by IncidentRecord schema in this project
    incident = {
        "incident_id": "IR-2026-0001",
        "title": "Suspicious login activity",
        "severity": "medium",
        "status": "triage",
        "summary": "Multiple failed logins followed by success",
        "created_at": "2026-01-01T10:00:00Z",
        "updated_at": "2026-01-01T10:05:00Z",
        "artifacts": [],
        "timeline": [],
        "owners": [],
        "tags": [],
    }
    f = tmp_path / "incident.json"
    f.write_text(json.dumps(incident), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["validate-incident", "--file", str(f)])

    assert result.exit_code == 0
    assert "Incident record is valid." in result.output


def test_validate_incident_failure(tmp_path):
    invalid_incident = {
        "incident_id": "IR-2026-0002",
        "title": "Bad incident",
        # severity intentionally invalid/missing required fields to trigger schema errors
        "severity": "not-a-severity",
    }
    f = tmp_path / "incident.json"
    f.write_text(json.dumps(invalid_incident), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["validate-incident", "--file", str(f)])

    assert result.exit_code != 0
    assert "Validation failed:" in result.output
    assert "- " in result.output
