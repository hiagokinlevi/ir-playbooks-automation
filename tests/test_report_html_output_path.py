from pathlib import Path

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_report_html_explicit_output_path_creates_parent_and_writes_file() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        output_path = Path("nested/reports/custom-report.html")

        result = runner.invoke(
            cli,
            [
                "report-html",
                "--incident-id",
                "IR-2026-0042",
                "--output",
                str(output_path),
            ],
        )

        assert result.exit_code == 0, result.output
        assert output_path.exists()
        assert "HTML report written:" in result.output
        assert str(output_path) in result.output
