from __future__ import annotations

from click.testing import CliRunner

from cli.main import cli


def test_start_playbook_renders_bundled_playbook() -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "start-playbook",
            "--playbook",
            "triage/initial_triage",
            "--incident-id",
            "INC-2026-074",
        ],
    )

    assert result.exit_code == 0
    assert "Initial Triage Playbook" in result.output
    assert "INC-2026-074" in result.output


def test_start_playbook_rejects_path_traversal() -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "start-playbook",
            "--playbook",
            "../../README",
        ],
    )

    assert result.exit_code != 0
    assert "must stay within playbooks" in result.output
    assert "# ir-playbooks-automation" not in result.output
