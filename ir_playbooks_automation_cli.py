"""Repository-unique console entrypoint for the k1n-ir CLI."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_CLI_PATH = Path(__file__).resolve().parent / "cli" / "main.py"
_SPEC = importlib.util.spec_from_file_location("ir_playbooks_automation_local_cli", _CLI_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load local CLI module from {_CLI_PATH}")

_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
cli = _MODULE.cli


__all__ = ["cli"]
