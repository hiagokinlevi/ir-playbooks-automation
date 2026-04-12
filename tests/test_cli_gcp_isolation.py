from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_isolate_gcp_instance_dry_run_outputs_actions() -> None:
    output_path = "gcp-isolation.json"
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "isolate-gcp-instance",
                "--project-id",
                "prod-project",
                "--zone",
                "us-central1-a",
                "--instance-name",
                "web-01",
                "--incident-id",
                "INC-2026-067",
                "--output",
                output_path,
            ],
        )

        assert result.exit_code == 0
        assert "[DRY RUN]" in result.output
        payload = json.loads(open(output_path, encoding="utf-8").read())
    assert payload["dry_run"] is True
    assert payload["success"] is True
    assert payload["saved_state"]["isolation_tag"] == "k1n-ir-isolated-inc-2026-067"


def test_isolate_gcp_instance_writes_json_output(tmp_path) -> None:
    output_path = tmp_path / "gcp-isolation.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "isolate-gcp-instance",
            "--project-id",
            "prod-project",
            "--zone",
            "us-central1-a",
            "--instance-name",
            "web-01",
            "--incident-id",
            "INC-2026-067",
            "--stop-instance",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["saved_state"]["stop_instance"] is True
    assert any("stop instance" in action.lower() for action in payload["actions_taken"])


def test_isolate_gcp_instance_rejects_path_like_instance_name() -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "isolate-gcp-instance",
            "--project-id",
            "prod-project",
            "--zone",
            "us-central1-a",
            "--instance-name",
            "../web-01",
            "--incident-id",
            "INC-2026-067",
        ],
    )

    assert result.exit_code != 0
    assert "Instance name must not contain path separators" in result.output
