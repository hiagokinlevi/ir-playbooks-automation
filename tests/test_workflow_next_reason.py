from click.testing import CliRunner

from cli.workflow import workflow_next


class _FakeTransitions:
    @staticmethod
    def allowed_with_reason(*_, **__):
        return [
            {"state": "containment", "reason": "Allowed after triage is complete."},
            {"state": "closed", "reason": "Allowed for low severity after validation."},
        ]

    @staticmethod
    def denied_with_reason(*_, **__):
        return []


def test_workflow_next_default_output_without_reason(monkeypatch):
    monkeypatch.setattr("cli.workflow.get_next_states", _FakeTransitions.allowed_with_reason)
    runner = CliRunner()

    result = runner.invoke(workflow_next, ["triage"])

    assert result.exit_code == 0
    assert "containment" in result.output
    assert "Allowed after triage is complete." not in result.output


def test_workflow_next_with_reason_outputs_explanation(monkeypatch):
    monkeypatch.setattr("cli.workflow.get_next_states", _FakeTransitions.allowed_with_reason)
    runner = CliRunner()

    result = runner.invoke(workflow_next, ["triage", "--reason"])

    assert result.exit_code == 0
    assert "containment: Allowed after triage is complete." in result.output
    assert "closed: Allowed for low severity after validation." in result.output


def test_workflow_next_denied_transition_message(monkeypatch):
    monkeypatch.setattr("cli.workflow.get_next_states", _FakeTransitions.denied_with_reason)
    runner = CliRunner()

    result = runner.invoke(workflow_next, ["eradication", "--reason"])

    assert result.exit_code == 0
    assert "No valid next states." in result.output
