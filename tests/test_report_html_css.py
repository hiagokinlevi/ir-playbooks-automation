from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def _write_template(repo_tmp: Path) -> None:
    tpl_dir = repo_tmp / "templates" / "reports"
    tpl_dir.mkdir(parents=True, exist_ok=True)
    (tpl_dir / "incident_report.html.j2").write_text(
        "<html><head><style>{{ custom_css }}</style></head><body>{{ incident.id }}</body></html>",
        encoding="utf-8",
    )


def test_report_html_css_injection_success(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_template(tmp_path)

    incident_path = tmp_path / "incident.json"
    incident_path.write_text(json.dumps({"id": "INC-001"}), encoding="utf-8")

    css_path = tmp_path / "custom.css"
    css_path.write_text("body{background:#111;}", encoding="utf-8")

    out_path = tmp_path / "report.html"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report-html",
            "--input",
            str(incident_path),
            "--output",
            str(out_path),
            "--css",
            str(css_path),
        ],
    )

    assert result.exit_code == 0, result.output
    content = out_path.read_text(encoding="utf-8")
    assert "body{background:#111;}" in content
    assert "INC-001" in content


def test_report_html_css_invalid_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_template(tmp_path)

    incident_path = tmp_path / "incident.json"
    incident_path.write_text(json.dumps({"id": "INC-002"}), encoding="utf-8")

    out_path = tmp_path / "report.html"
    bad_css = tmp_path / "missing.css"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report-html",
            "--input",
            str(incident_path),
            "--output",
            str(out_path),
            "--css",
            str(bad_css),
        ],
    )

    assert result.exit_code != 0
    assert "CSS file not found" in result.output
