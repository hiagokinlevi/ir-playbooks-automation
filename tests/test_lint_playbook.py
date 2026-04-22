from pathlib import Path

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_lint_playbook_success(tmp_path: Path) -> None:
    playbook = tmp_path / "valid_playbook.md"
    playbook.write_text(
        """---
incident_type: credential_compromise
severity: high
owner: soc-team
last_reviewed: 2026-01-15
---

# Credential Compromise Playbook
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["lint-playbook", str(playbook)])

    assert result.exit_code == 0
    assert "front-matter is valid" in result.output


def test_lint_playbook_missing_required_keys(tmp_path: Path) -> None:
    playbook = tmp_path / "invalid_playbook.md"
    playbook.write_text(
        """---
incident_type: malware
owner: soc-team
---

# Malware Playbook
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["lint-playbook", str(playbook)])

    assert result.exit_code != 0
    assert "Missing required front-matter keys" in result.output
    assert "severity" in result.output
    assert "last_reviewed" in result.output
