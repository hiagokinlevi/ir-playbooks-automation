from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_iso8601(dt: datetime | None = None) -> str:
    current = dt or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iter_files(evidence_dir: Path) -> Iterable[Path]:
    for p in evidence_dir.rglob("*"):
        if p.is_file():
            yield p


def _stable_relpath(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def generate_manifest(evidence_dir: Path, output_manifest: Path) -> dict:
    evidence_dir = evidence_dir.resolve()
    files = sorted(_iter_files(evidence_dir), key=lambda p: _stable_relpath(p, evidence_dir))

    entries = []
    for fp in files:
        stat = fp.stat()
        entries.append(
            {
                "path": _stable_relpath(fp, evidence_dir),
                "size_bytes": stat.st_size,
                "sha256": _sha256_file(fp),
                "modified_utc": _utc_iso8601(datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)),
            }
        )

    manifest = {
        "generated_utc": _utc_iso8601(),
        "algorithm": "sha256",
        "evidence_root": evidence_dir.as_posix(),
        "files": entries,
    }

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    output_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate evidence manifest with SHA-256 hashes")
    parser.add_argument("evidence_dir", type=Path, help="Directory containing evidence files")
    parser.add_argument("--output", type=Path, default=Path("manifest.json"), help="Output manifest path")
    args = parser.parse_args()

    generate_manifest(args.evidence_dir, args.output)


if __name__ == "__main__":
    main()
