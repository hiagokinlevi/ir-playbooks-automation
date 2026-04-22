from click.testing import CliRunner

from cli.commands import cli


def test_aws_isolate_ec2_dry_run_outputs_and_skips_execution(monkeypatch):
    called = {"value": False}

    def _fake_isolate_instance(*args, **kwargs):
        called["value"] = True

    monkeypatch.setattr(
        "cli.commands.aws_isolate_instance",
        _fake_isolate_instance,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "containment",
            "aws-isolate-ec2",
            "--instance-id",
            "i-1234567890abcdef0",
            "--region",
            "us-east-1",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "[DRY-RUN] Would isolate AWS EC2 instance 'i-1234567890abcdef0' in region 'us-east-1'." in result.output
    assert called["value"] is False
