import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def _write_workflow(tmp_path: Path):
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "incident_state_machine.json").write_text(
        json.dumps(
            {
                "transitions": {
                    "triage": ["containment", "closed"],
                    "containment": ["eradication"],
                }
            }
        ),
        encoding="utf-8",
    )


def test_workflow_next_to_valid(monkeypatch, tmp_path):
    _write_workflow(tmp_path)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["workflow-next", "--from", "triage", "--to", "containment"])

    assert result.exit_code == 0
    assert "valid transition" in result.output


def test_workflow_next_to_invalid(monkeypatch, tmp_path):
    _write_workflow(tmp_path)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["workflow-next", "--from", "triage", "--to", "eradication"])

    assert result.exit_code != 0
    assert "invalid transition" in result.output


def test_workflow_next_to_json_valid(monkeypatch, tmp_path):
    _write_workflow(tmp_path)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["workflow-next", "--from", "triage", "--to", "containment", "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["from"] == "triage"
    assert payload["to"] == "containment"
    assert payload["valid"] is True


def test_workflow_next_to_json_invalid(monkeypatch, tmp_path):
    _write_workflow(tmp_path)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["workflow-next", "--from", "triage", "--to", "eradication", "--json"],
    )

    assert result.exit_code != 0
    payload = json.loads(result.output)
    assert payload["from"] == "triage"
    assert payload["to"] == "eradication"
    assert payload["valid"] is False
