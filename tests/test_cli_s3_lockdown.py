from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_lockdown_s3_bucket_dry_run_outputs_actions() -> None:
    output_path = "s3-lockdown.json"
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "lockdown-s3-bucket",
                "--bucket-name",
                "prod-exposure",
                "--incident-id",
                "INC-2026-060",
                "--output",
                output_path,
            ],
        )

        assert result.exit_code == 0
        assert "[DRY RUN]" in result.output
        payload = json.loads(open(output_path, encoding="utf-8").read())

    assert payload["dry_run"] is True
    assert payload["success"] is True
    assert payload["lockdown_state"]["rollback_command"].startswith("restore_s3_bucket")


def test_lockdown_s3_bucket_writes_json_output(tmp_path) -> None:
    output_path = tmp_path / "s3-lockdown.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "lockdown-s3-bucket",
            "--bucket-name",
            "prod-exposure",
            "--incident-id",
            "INC-2026-060",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["bucket_name"] == "prod-exposure"
    assert any("Public Access Block" in action for action in payload["actions_taken"])
