import json
import time
from pathlib import Path

from automations.evidence_packaging.package_evidence import generate_manifest


def test_manifest_deterministic_for_identical_inputs(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    (evidence_dir / "b.txt").write_text("second", encoding="utf-8")
    (evidence_dir / "a.txt").write_text("first", encoding="utf-8")

    fixed_mtime = 1_700_000_000
    for p in [evidence_dir / "a.txt", evidence_dir / "b.txt"]:
        p.touch()
        import os

        os.utime(p, (fixed_mtime, fixed_mtime))

    manifest_1_path = tmp_path / "manifest1.json"
    manifest_2_path = tmp_path / "manifest2.json"

    generate_manifest(evidence_dir, manifest_1_path)
    time.sleep(1)
    generate_manifest(evidence_dir, manifest_2_path)

    manifest_1 = json.loads(manifest_1_path.read_text(encoding="utf-8"))
    manifest_2 = json.loads(manifest_2_path.read_text(encoding="utf-8"))

    assert [f["path"] for f in manifest_1["files"]] == ["a.txt", "b.txt"]
    assert [f["path"] for f in manifest_1["files"]] == [f["path"] for f in manifest_2["files"]]

    for f1, f2 in zip(manifest_1["files"], manifest_2["files"]):
        assert f1["sha256"] == f2["sha256"]
        assert f1["size_bytes"] == f2["size_bytes"]
        assert f1["modified_utc"].endswith("Z")
        assert f2["modified_utc"].endswith("Z")

    assert manifest_1["algorithm"] == "sha256"
    assert manifest_2["algorithm"] == "sha256"
