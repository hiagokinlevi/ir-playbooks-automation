import json

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_validate_incident_record_valid_and_invalid(tmp_path):
    runner = CliRunner()

    valid_record = {
        "incident_id": "IR-2026-0001",
        "title": "Credential compromise investigation",
        "severity": "high",
        "status": "triage",
        "summary": "Suspicious login from unusual geolocation",
    }
    valid_path = tmp_path / "valid_incident.json"
    valid_path.write_text(json.dumps(valid_record), encoding="utf-8")

    valid_result = runner.invoke(cli, ["validate-incident-record", str(valid_path)])
    assert valid_result.exit_code == 0
    assert "VALID" in valid_result.output

    invalid_record = {
        "incident_id": "IR-2026-0002",
        "title": "Malformed record",
        "severity": "criticality-9000",
    }
    invalid_path = tmp_path / "invalid_incident.yaml"
    invalid_path.write_text(
        "incident_id: IR-2026-0002\n"
        "title: Malformed record\n"
        "severity: criticality-9000\n",
        encoding="utf-8",
    )

    invalid_result = runner.invoke(cli, ["validate-incident-record", str(invalid_path)])
    assert invalid_result.exit_code != 0
    assert "INVALID" in invalid_result.output
    assert "field=" in invalid_result.output
