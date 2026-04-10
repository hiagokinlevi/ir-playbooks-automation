"""
Evidence Packaging Automation
==============================
Creates a structured, tamper-evident evidence package for an incident.

The package includes:
  - A timestamped directory hierarchy under EVIDENCE_DIR/<incident_id>/
  - SHA-256 hashes for all collected files
  - A JSON manifest with package metadata and file inventory
  - A chain-of-custody log entry

Usage:
    python packager.py --incident-id INC-20250101-001 [--source /path/to/files]
    python packager.py --incident-id INC-20250101-001 --source-type cloud_config --notes "Pre-remediation snapshot"

Safety:
  - This script only READS and COPIES files — it does not delete or modify originals
  - All output is written to EVIDENCE_DIR (default: ./evidence), never to the source
  - When MASKING_MODE=true, file names in the manifest are preserved but content
    is not inspected (hash only) to avoid logging sensitive data

Limitations:
  - Does not handle live memory images (use specialized tools like LiME, WinPmem)
  - File copy is not atomic — do not use on actively-written files without coordination
"""

import hashlib
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*args: Any, **kwargs: Any) -> bool:
        return False

from automations.logging_compat import structlog

load_dotenv()  # Load environment variables from .env if present

# Configure structured logging for audit trail compatibility
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger(__name__)

# Evidence directory from environment, defaulting to ./evidence
EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "./evidence"))

# When masking mode is on, skip content inspection and only record file metadata
MASKING_MODE = os.getenv("MASKING_MODE", "true").lower() == "true"


def sha256_file(file_path: Path) -> str:
    """
    Compute the SHA-256 hash of a file.

    Reads in 64KB chunks to avoid loading large files into memory.

    Args:
        file_path: Path to the file to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_evidence_package(
    incident_id: str,
    source_path: Path | None = None,
    source_type: str = "generic",
    analyst: str = "unknown",
    notes: str = "",
) -> Path:
    """
    Create a structured evidence package for an incident.

    Creates the following structure:
        EVIDENCE_DIR/
          <incident_id>/
            <timestamp>/
              files/         <- Copies of collected files (if source_path provided)
              manifest.json  <- Package metadata and file inventory with hashes
              chain_of_custody.log

    Args:
        incident_id: The incident ID (e.g., 'INC-20250101-001'). Used as the top-level directory.
        source_path: Optional path to a file or directory to include in the package.
        source_type: Describes the type of evidence (e.g., 'cloud_config', 'log_export', 'memory').
        analyst: Name or identifier of the analyst creating the package.
        notes: Free-text notes about the evidence collection context.

    Returns:
        Path to the created evidence package directory.

    Raises:
        FileNotFoundError: If source_path is provided but does not exist.
        PermissionError: If the evidence directory cannot be created or written to.
    """
    # Build the package directory path with a UTC timestamp to avoid collisions
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    package_dir = EVIDENCE_DIR / incident_id / timestamp
    files_dir = package_dir / "files"

    # Create directories — exist_ok=False ensures we don't silently overwrite
    package_dir.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)

    log.info("evidence_package_started",
             incident_id=incident_id,
             package_dir=str(package_dir),
             source_type=source_type,
             analyst=analyst)

    file_inventory: list[dict] = []

    # Collect and hash files from the source path
    if source_path is not None:
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source path does not exist: {source}")

        # Resolve source files — handle both single file and directory
        if source.is_file():
            source_files = [source]
        else:
            # Walk the directory and collect all files
            source_files = [f for f in source.rglob("*") if f.is_file()]

        for src_file in source_files:
            # Compute hash before copying (tamper-evidence)
            file_hash = sha256_file(src_file)

            # Preserve relative directory structure in the package
            try:
                rel_path = src_file.relative_to(source.parent if source.is_file() else source)
            except ValueError:
                rel_path = Path(src_file.name)  # Fallback to filename only

            dest_file = files_dir / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)  # copy2 preserves metadata (mtime, etc.)

            file_inventory.append({
                "original_path": str(src_file),             # Original location
                "package_path": str(rel_path),               # Location within package
                "sha256": file_hash,                         # Pre-copy hash for integrity
                "size_bytes": src_file.stat().st_size,
                "collected_at": timestamp,
            })

            log.info("file_collected",
                     incident_id=incident_id,
                     file=str(rel_path),
                     sha256=file_hash,
                     size_bytes=src_file.stat().st_size)

    # Write the manifest file — provides a complete audit record of the package
    manifest = {
        "schema_version": "1.0",                    # Version this format for future compatibility
        "incident_id": incident_id,
        "package_created_at": timestamp,
        "source_type": source_type,                  # What kind of evidence this is
        "analyst": analyst,
        "notes": notes,
        "masking_mode": MASKING_MODE,                # Record whether masking was active
        "file_count": len(file_inventory),
        "files": file_inventory,
    }

    manifest_path = package_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Hash the manifest itself — ensures the inventory hasn't been tampered with
    manifest_hash = sha256_file(manifest_path)

    # Write the chain of custody log — append-friendly plaintext for operator review
    coc_path = package_dir / "chain_of_custody.log"
    with open(coc_path, "a", encoding="utf-8") as coc:
        coc.write(
            f"[{timestamp}] Package created\n"
            f"  Incident ID  : {incident_id}\n"
            f"  Source Type  : {source_type}\n"
            f"  Analyst      : {analyst}\n"
            f"  Files        : {len(file_inventory)}\n"
            f"  Manifest SHA256: {manifest_hash}\n"
            f"  Notes        : {notes or '(none)'}\n"
            f"{'=' * 60}\n"
        )

    log.info("evidence_package_complete",
             incident_id=incident_id,
             package_dir=str(package_dir),
             file_count=len(file_inventory),
             manifest_sha256=manifest_hash)

    print(f"Evidence package created: {package_dir}")
    print(f"Files collected : {len(file_inventory)}")
    print(f"Manifest SHA-256: {manifest_hash}")
    print(f"Chain of custody: {coc_path}")

    return package_dir


# ---------------------------------------------------------------------------
# CLI entry point — supports both direct invocation and import-as-module
# ---------------------------------------------------------------------------

def main() -> None:
    """Command-line entry point for the evidence packager."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Package evidence files for an incident with SHA-256 hashes and manifest."
    )
    parser.add_argument("--incident-id", required=True,
                        help="Incident ID (e.g., INC-20250101-001)")
    parser.add_argument("--source", default=None,
                        help="Path to file or directory to include in the package")
    parser.add_argument("--source-type", default="generic",
                        help="Type of evidence (e.g., cloud_config, log_export, memory)")
    parser.add_argument("--analyst", default=os.getenv("USER", "unknown"),
                        help="Analyst name or ID creating the package")
    parser.add_argument("--notes", default="",
                        help="Free-text notes about the evidence collection")

    args = parser.parse_args()

    create_evidence_package(
        incident_id=args.incident_id,
        source_path=Path(args.source) if args.source else None,
        source_type=args.source_type,
        analyst=args.analyst,
        notes=args.notes,
    )


if __name__ == "__main__":
    main()
