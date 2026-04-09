# Contributing to ir-playbooks-automation

Thank you for your interest in contributing. This project is maintained by practitioners for practitioners — contributions that improve real-world SOC utility are especially welcome.

## Ways to Contribute

- **New playbooks:** Add playbooks for incident types not yet covered
- **Automation scripts:** New cloud, identity, or endpoint containment automations
- **Bug fixes:** Fixes for incorrect logic, typos, or broken CLI commands
- **Documentation:** Improvements to docs, tutorials, or training labs
- **Tests:** Additional unit or integration test coverage

## Development Setup

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/ir-playbooks-automation.git
cd ir-playbooks-automation

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Copy environment template
cp .env.example .env
```

## Coding Standards

- **Python:** Follow PEP 8. Use type hints on all function signatures. Use `structlog` for logging — never `print()`.
- **Docstrings:** Every public function and class must have a docstring explaining purpose, parameters, and return value.
- **Inline comments:** Config files (YAML, TOML) must have inline comments explaining each key.
- **Safety first:** Automation scripts must default to `dry_run=True`. Destructive operations must log a warning before executing.
- **No hardcoded credentials:** Never commit tokens, passwords, or secrets. Use `.env` and `python-dotenv`.
- **Masking:** Any output that might contain PII or sensitive data must be masked when `MASKING_MODE=true`.

## Playbook Standards

New playbooks must follow the structure of `playbooks/triage/initial_triage.md`:

- Clear objective statement
- Prerequisites list
- Numbered steps with decision gates
- Documentation checkpoints
- Severity/scope classification table where applicable

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/my-new-playbook`
2. Write your changes with tests
3. Run tests: `pytest tests/`
4. Ensure no regressions: `pytest --tb=short`
5. Open a pull request with a clear description of what changed and why
6. Reference any related issues with `Closes #NNN`

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add phishing playbook with O365 containment steps
fix: correct severity mapping in state_machine.py
docs: expand AWS isolation runbook with rollback steps
test: add unit tests for IncidentRecord schema
```

## Code of Conduct

By contributing, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
