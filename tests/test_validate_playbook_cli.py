from pathlib import Path

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


REQUIRED_FIELDS = ["id", "title", "version", "phase", "owner"]


def _write_playbook(path: Path, front_matter: str, body: str = "# Steps\n\n- test") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\n{front_matter}\n---\n\n{body}\n", encoding="utf-8")


def test_validate_playbook_success(tmp_path, monkeypatch):
    playbooks_dir = tmp_path / "playbooks"
    playbook_path = playbooks_dir / "triage" / "valid-playbook.md"

    _write_playbook(
        playbook_path,
        "\n".join(
            [
                "id: pb-triage-001",
                "title: Initial Alert Triage",
                "version: 1.0.0",
                "phase: triage",
                "owner: soc-team",
            ]
        ),
    )

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["validate-playbook", "triage/valid-playbook.md"])

    assert result.exit_code == 0, result.output
    assert "valid" in result.output.lower()


def test_validate_playbook_missing_required_field(tmp_path, monkeypatch):
    playbooks_dir = tmp_path / "playbooks"
    playbook_path = playbooks_dir / "containment" / "invalid-playbook.md"

    _write_playbook(
        playbook_path,
        "\n".join(
            [
                "id: pb-contain-001",
                "title: Endpoint Containment",
                "version: 1.0.0",
                "phase: containment",
                # owner missing
            ]
        ),
    )

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["validate-playbook", "containment/invalid-playbook.md"])

    assert result.exit_code != 0
    lower_output = result.output.lower()
    assert "validation" in lower_output or "error" in lower_output
    assert "owner" in lower_output


def test_validate_playbook_not_found(tmp_path, monkeypatch):
    (tmp_path / "playbooks").mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli, ["validate-playbook", "triage/does-not-exist.md"])

    assert result.exit_code != 0
    assert "not found" in result.output.lower()
