from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_report_html_writes_to_explicit_output_path(tmp_path: Path) -> None:
    incident_path = tmp_path / "incident.json"
    template_path = tmp_path / "report.html"
    output_path = tmp_path / "reports" / "incident-123.html"

    incident_path.write_text('{"id":"incident-123","severity":"high"}', encoding="utf-8")
    template_path.write_text(
        "<html><body><h1>{{ incident.id }}</h1><p>{{ incident.severity }}</p></body></html>",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "report-html",
            "--incident",
            str(incident_path),
            "--template",
            str(template_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "incident-123" in content
    assert "high" in content
