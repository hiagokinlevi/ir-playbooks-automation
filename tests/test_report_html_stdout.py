from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_report_html_stdout_deterministic(tmp_path: Path) -> None:
    incident = {
        "id": "INC-2026-0001",
        "title": "Credential compromise",
        "severity": "high",
        "status": "triage",
        "summary": "User reported suspicious MFA prompts.",
    }
    incident_file = tmp_path / "incident.json"
    incident_file.write_text(json.dumps(incident), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["report-html", str(incident_file), "--stdout"])

    assert result.exit_code == 0
    # deterministic HTML payload in stdout
    assert "<html" in result.output.lower()
    assert "INC-2026-0001" in result.output
    assert "Credential compromise" in result.output
    # ensure default output file path is not written when --stdout is set
    assert not (Path.cwd() / "incident-report.html").exists()
