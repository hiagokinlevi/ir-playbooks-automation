from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.evidence_packaging import packager


def test_create_evidence_package_skips_symlinked_files(tmp_path, monkeypatch) -> None:
    evidence_dir = tmp_path / "evidence"
    source_dir = tmp_path / "source"
    external_dir = tmp_path / "external"
    source_dir.mkdir()
    external_dir.mkdir()

    collected = source_dir / "collected.txt"
    collected.write_text("host telemetry", encoding="utf-8")

    external = external_dir / "outside.txt"
    external.write_text("should not be packaged", encoding="utf-8")

    (source_dir / "outside-link.txt").symlink_to(external)

    monkeypatch.setattr(packager, "EVIDENCE_DIR", evidence_dir)

    package_dir = packager.create_evidence_package(
        incident_id="INC-20260411-001",
        source_path=source_dir,
        analyst="analyst-01",
    )

    manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["file_count"] == 1
    assert manifest["files"][0]["package_path"] == "collected.txt"
    assert (package_dir / "files" / "collected.txt").read_text(encoding="utf-8") == "host telemetry"
    assert not (package_dir / "files" / "outside-link.txt").exists()


def test_create_evidence_package_rejects_symlink_source(tmp_path, monkeypatch) -> None:
    evidence_dir = tmp_path / "evidence"
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    target_file = source_dir / "target.txt"
    target_file.write_text("artifact", encoding="utf-8")
    symlink_source = tmp_path / "target-link.txt"
    symlink_source.symlink_to(target_file)

    monkeypatch.setattr(packager, "EVIDENCE_DIR", evidence_dir)

    with pytest.raises(ValueError, match="Symlinked source paths are not allowed"):
        packager.create_evidence_package(
            incident_id="INC-20260411-002",
            source_path=symlink_source,
            analyst="analyst-01",
        )
