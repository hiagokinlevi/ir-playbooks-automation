from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from cli.ir_cli import ir


def test_report_html_loads_incident_context_and_explicit_flags_override(tmp_path: Path) -> None:
    templates_dir = tmp_path / "templates" / "reports"
    templates_dir.mkdir(parents=True)
    (templates_dir / "report.html").write_text(
        "{{ incident_id }}|{{ severity }}|{{ status }}|{{ owner }}",
        encoding="utf-8",
    )

    incident = {
        "id": "IR-1001",
        "severity": "high",
        "status": "open",
        "owner": "alice",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T01:00:00Z",
        "closed_at": None,
    }
    incident_path = tmp_path / "incident.json"
    incident_path.write_text(json.dumps(incident), encoding="utf-8")

    output_path = tmp_path / "out.html"

    runner = CliRunner()
    result = runner.invoke(
        ir,
        [
            "report-html",
            "--template",
            "report.html",
            "--output",
            str(output_path),
            "--incident",
            str(incident_path),
            "--severity",
            "critical",
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0
    assert output_path.read_text(encoding="utf-8") == "IR-1001|critical|open|alice"
