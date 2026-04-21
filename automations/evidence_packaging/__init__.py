from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List


def sha256_file(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return SHA-256 hex digest for a file path."""
    digest = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest(package_dir: str | Path, manifest_filename: str = "sha256_manifest.json") -> Dict[str, List[str]]:
    """Verify evidence files in a package against a SHA-256 manifest.

    Expected manifest formats:
    - {"files": [{"path": "relative/path", "sha256": "..."}, ...]}
    - {"relative/path": "sha256", ...}
    """
    base = Path(package_dir)
    manifest_path = base / manifest_filename
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))

    entries: List[tuple[str, str]] = []
    if isinstance(data, dict) and "files" in data and isinstance(data["files"], list):
        for item in data["files"]:
            if not isinstance(item, dict):
                continue
            rel = item.get("path") or item.get("file")
            expected = item.get("sha256")
            if rel and expected:
                entries.append((str(rel), str(expected).lower()))
    elif isinstance(data, dict):
        for rel, expected in data.items():
            if isinstance(expected, str):
                entries.append((str(rel), expected.lower()))

    missing: List[str] = []
    mismatched: List[str] = []
    verified: List[str] = []

    for rel_path, expected_hash in entries:
        file_path = base / rel_path
        if not file_path.exists() or not file_path.is_file():
            missing.append(rel_path)
            continue

        actual_hash = sha256_file(file_path)
        if actual_hash != expected_hash:
            mismatched.append(rel_path)
        else:
            verified.append(rel_path)

    return {
        "missing": missing,
        "mismatched": mismatched,
        "verified": verified,
        "manifest": str(manifest_path),
    }
