from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def _write_input(tmp_path: Path) -> Path:
    input_path = tmp_path / "incident.json"
    input_path.write_text(
        json.dumps({"title": "Test Incident", "summary": "Summary content"}),
        encoding="utf-8",
    )
    return input_path


def test_report_html_default_does_not_open_browser(monkeypatch, tmp_path: Path) -> None:
    calls = []

    def fake_open(url: str, new: int = 0):
        calls.append((url, new))
        return True

    monkeypatch.setattr("ir_playbooks_automation_cli.webbrowser.open", fake_open)

    runner = CliRunner()
    input_path = _write_input(tmp_path)
    output_path = tmp_path / "report.html"

    result = runner.invoke(
        cli,
        [
            "report-html",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert calls == []


def test_report_html_open_flag_attempts_browser_but_is_fail_safe(monkeypatch, tmp_path: Path) -> None:
    calls = []

    def fake_open(url: str, new: int = 0):
        calls.append((url, new))
        raise RuntimeError("browser unavailable")

    monkeypatch.setattr("ir_playbooks_automation_cli.webbrowser.open", fake_open)

    runner = CliRunner()
    input_path = _write_input(tmp_path)
    output_path = tmp_path / "report.html"

    result = runner.invoke(
        cli,
        [
            "report-html",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--open",
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert len(calls) == 1
    assert calls[0][0].startswith("file://")
    assert "Warning: failed to open browser" in result.output
