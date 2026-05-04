import json

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_workflow_next_json_valid_transition():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["workflow-next", "--from-state", "triage", "--to-state", "containment", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["from_state"] == "triage"
    assert payload["to_state"] == "containment"
    assert payload["valid"] is True
    assert "allowed_next_states" in payload
    assert "reason" not in payload


def test_workflow_next_json_invalid_transition():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["workflow-next", "--from-state", "triage", "--to-state", "recovery", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["from_state"] == "triage"
    assert payload["to_state"] == "recovery"
    assert payload["valid"] is False
    assert "allowed_next_states" in payload
    assert "reason" in payload


def test_workflow_next_json_without_to_state_returns_allowed_states():
    runner = CliRunner()
    result = runner.invoke(cli, ["workflow-next", "--from-state", "triage", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["from_state"] == "triage"
    assert "allowed_next_states" in payload
    assert "to_state" not in payload
    assert "valid" not in payload
