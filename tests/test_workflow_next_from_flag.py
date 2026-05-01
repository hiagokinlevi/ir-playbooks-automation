import json

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_workflow_next_from_flag_valid_and_invalid_state() -> None:
    runner = CliRunner()

    valid_result = runner.invoke(cli, ["workflow-next", "--from", "triage", "--json"])
    assert valid_result.exit_code == 0
    payload = json.loads(valid_result.output)
    assert payload["from"] == "triage"
    assert isinstance(payload["next"], list)

    invalid_result = runner.invoke(cli, ["workflow-next", "--from", "not-a-state"])
    assert invalid_result.exit_code != 0
    assert "Invalid state 'not-a-state'" in invalid_result.output
