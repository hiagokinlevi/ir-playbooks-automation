from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_report_html_uses_custom_title(tmp_path: Path) -> None:
    incident_file = tmp_path / "incident.json"
    output_file = tmp_path / "report.html"

    incident_file.write_text(
        json.dumps(
            {
                "id": "IR-49-001",
                "title": "Default Incident Title",
                "severity": "high",
            }
        ),
        encoding="utf-8",
    )

    templates_dir = tmp_path / "templates" / "reports"
    templates_dir.mkdir(parents=True)
    (templates_dir / "incident_report.html.j2").write_text("<h1>{{ title }}</h1>", encoding="utf-8")

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(
            cli,
            [
                "report-html",
                str(incident_file),
                "--output",
                str(output_file),
                "--title",
                "Executive Summary Heading",
            ],
        )

    assert result.exit_code == 0, result.output
    rendered = output_file.read_text(encoding="utf-8")
    assert "Executive Summary Heading" in rendered
