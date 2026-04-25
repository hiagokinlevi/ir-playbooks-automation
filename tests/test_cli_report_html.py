from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_report_html_open_flag_triggers_browser_open(monkeypatch, tmp_path: Path) -> None:
    incident_path = tmp_path / "incident.json"
    output_path = tmp_path / "report.html"

    incident_path.write_text(
        json.dumps(
            {
                "incident_id": "IR-2026-0001",
                "title": "Suspicious login activity",
                "severity": "high",
                "status": "triage",
            }
        ),
        encoding="utf-8",
    )

    opened: list[str] = []

    def fake_open(url: str, *_args, **_kwargs):
        opened.append(url)
        return True

    monkeypatch.setattr("cli.main.webbrowser.open", fake_open)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "ir",
            "report-html",
            "--incident",
            str(incident_path),
            "--output",
            str(output_path),
            "--open",
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8").strip() != ""
    assert opened == [output_path.resolve().as_uri()]
