from __future__ import annotations

from pathlib import Path

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


def test_start_playbook_rejects_absolute_paths() -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "start-playbook",
            "--playbook",
            str((Path(__file__).resolve().parents[1] / "README.md")),
        ],
    )

    assert result.exit_code != 0
    assert "must be relative to playbooks/" in result.output
