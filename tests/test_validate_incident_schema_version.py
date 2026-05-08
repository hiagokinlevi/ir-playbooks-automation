import json

from click.testing import CliRunner

from cli.main import cli


def test_validate_incident_fails_on_schema_version_mismatch(tmp_path):
    incident = {
        "schema_version": "1.0",
        "incident_id": "IR-2026-0001",
        "title": "Test incident",
        "severity": "medium",
        "status": "triage",
        "summary": "Validation test",
        "timeline": [],
        "artifacts": [],
        "owner": "soc@example.com",
    }

    incident_file = tmp_path / "incident.json"
    incident_file.write_text(json.dumps(incident), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "validate-incident",
            str(incident_file),
            "--schema-version",
            "2.0",
        ],
    )

    assert result.exit_code != 0
    assert "Schema version mismatch" in result.output
    assert "expected '2.0'" in result.output
    assert "detected '1.0'" in result.output
