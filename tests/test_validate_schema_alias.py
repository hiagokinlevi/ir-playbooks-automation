from __future__ import annotations

import json

from click.testing import CliRunner

from ir_playbooks_automation_cli import cli


def test_validate_schema_alias_parity(tmp_path):
    runner = CliRunner()
    record = {
        "incident_id": "INC-001",
        "title": "Suspicious login",
        "severity": "high",
        "status": "triage",
    }
    record_file = tmp_path / "incident.json"
    record_file.write_text(json.dumps(record), encoding="utf-8")

    primary = runner.invoke(cli, ["validate-record", str(record_file)])
    alias = runner.invoke(cli, ["validate-schema", str(record_file)])

    assert primary.exit_code == alias.exit_code
    assert primary.output == alias.output
