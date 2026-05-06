import json
from pathlib import Path

from click.testing import CliRunner

from cli.main import cli


def test_report_html_metadata_output_fields(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "report.html"

    result = runner.invoke(
        cli,
        [
            "ir",
            "report-html",
            "--incident",
            "IR-56",
            "--template",
            "technical",
            "--output",
            str(out),
            "--metadata",
        ],
    )

    assert result.exit_code == 0
    assert out.exists()

    lines = [line for line in result.output.strip().splitlines() if line.strip()]
    assert len(lines) >= 2

    metadata = json.loads(lines[-1])
    assert metadata["report_path"] == str(out)
    assert metadata["incident_id"] == "IR-56"
    assert metadata["template"] == "technical"
    assert metadata["success"] is True
    assert "generated_at" in metadata and isinstance(metadata["generated_at"], str)
