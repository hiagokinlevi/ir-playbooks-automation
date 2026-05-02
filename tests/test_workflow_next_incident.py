import json

from click.testing import CliRunner

from cli.main import ir


def test_workflow_next_uses_incident_state(tmp_path):
    p = tmp_path / "incident.json"
    p.write_text(json.dumps({"state": "triage"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(ir, ["workflow-next", "--incident", str(p), "--json"])

    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["from"] == "triage"
    assert "contained" in body["next"]


def test_workflow_next_from_precedence_over_incident(tmp_path):
    p = tmp_path / "incident.yaml"
    p.write_text("state: triage\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        ir,
        ["workflow-next", "--incident", str(p), "--from", "contained", "--json"],
    )

    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["from"] == "contained"


def test_workflow_next_incident_missing_state(tmp_path):
    p = tmp_path / "incident.json"
    p.write_text(json.dumps({"id": "IR-1"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(ir, ["workflow-next", "--incident", str(p)])

    assert result.exit_code != 0
    assert "does not contain a valid workflow state" in result.output


def test_workflow_next_incident_parse_error(tmp_path):
    p = tmp_path / "incident.json"
    p.write_text("{bad json", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(ir, ["workflow-next", "--incident", str(p)])

    assert result.exit_code != 0
    assert "Failed to parse incident record" in result.output
