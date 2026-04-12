from __future__ import annotations

import json

from click.testing import CliRunner

from cli.main import cli


def test_isolate_azure_vm_dry_run_outputs_actions() -> None:
    output_path = "azure-isolation.json"
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "isolate-azure-vm",
                "--subscription-id",
                "00000000-0000-0000-0000-000000000000",
                "--resource-group",
                "rg-prod",
                "--vm-name",
                "web-01",
                "--incident-id",
                "INC-2026-061",
                "--output",
                output_path,
            ],
        )

        assert result.exit_code == 0
        assert "[DRY RUN]" in result.output
        payload = json.loads(open(output_path, encoding="utf-8").read())

    assert payload["dry_run"] is True
    assert payload["success"] is True
    assert payload["saved_state"]["rollback_command"].startswith("restore_azure_vm")


def test_isolate_azure_vm_writes_json_output(tmp_path) -> None:
    output_path = tmp_path / "azure-isolation.json"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "isolate-azure-vm",
            "--subscription-id",
            "00000000-0000-0000-0000-000000000000",
            "--resource-group",
            "rg-prod",
            "--vm-name",
            "web-01",
            "--incident-id",
            "INC-2026-061",
            "--deallocate-vm",
            "--location",
            "westus2",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["resource_group"] == "rg-prod"
    assert any("deallocate" in action.lower() for action in payload["actions_taken"])
    assert any("westus2" in action for action in payload["actions_taken"])


def test_isolate_azure_vm_rejects_path_like_vm_name() -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "isolate-azure-vm",
            "--subscription-id",
            "00000000-0000-0000-0000-000000000000",
            "--resource-group",
            "rg-prod",
            "--vm-name",
            "../web-01",
            "--incident-id",
            "INC-2026-061",
        ],
    )

    assert result.exit_code != 0
    assert "VM name must not contain path separators" in result.output
