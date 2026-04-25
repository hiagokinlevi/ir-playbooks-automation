import json

from click.testing import CliRunner

from cli.main import cli


def test_workflow_next_json_shape() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["workflow-next", "--state", "triage", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert set(payload.keys()) == {"current_state", "allowed_next_states", "valid"}
    assert payload["current_state"] == "triage"
    assert isinstance(payload["allowed_next_states"], list)
    assert payload["valid"] is True
