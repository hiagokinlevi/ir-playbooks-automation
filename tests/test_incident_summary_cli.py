import json

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_incident_summary_text_from_json(tmp_path):
    incident = {
        "incident_id": "IR-2026-0042",
        "current_state": "containment",
        "severity": "high",
        "owner": "alice",
        "last_updated": "2026-04-25T10:30:00Z",
    }
    p = tmp_path / "incident.json"
    p.write_text(json.dumps(incident), encoding="utf-8")

    result = CliRunner().invoke(cli, ["incident-summary", str(p)])

    assert result.exit_code == 0
    assert (
        result.output.strip()
        == "incident_id=IR-2026-0042 current_state=containment severity=high owner=alice last_updated=2026-04-25T10:30:00Z"
    )


def test_incident_summary_text_from_yaml_without_owner(tmp_path):
    p = tmp_path / "incident.yaml"
    p.write_text(
        """
incident_id: IR-2026-0099
current_state: triage
severity: medium
last_updated: 2026-04-25T11:00:00Z
""".strip(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["incident-summary", str(p)])

    assert result.exit_code == 0
    assert result.output.strip() == (
        "incident_id=IR-2026-0099 current_state=triage severity=medium "
        "last_updated=2026-04-25T11:00:00Z"
    )
    assert "owner=" not in result.output


def test_incident_summary_json_flag(tmp_path):
    incident = {
        "incident_id": "IR-2026-0100",
        "current_state": "eradication",
        "severity": "critical",
        "owner": "soc-oncall",
        "last_updated": "2026-04-25T12:00:00Z",
    }
    p = tmp_path / "incident.json"
    p.write_text(json.dumps(incident), encoding="utf-8")

    result = CliRunner().invoke(cli, ["incident-summary", str(p), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload == incident
