"""
PCAP Evidence Capture Trigger
==============================
Automates network capture for forensic evidence collection during incident
response. Wraps tcpdump / tshark in a controlled, time-bounded subprocess
with structured metadata, safe defaults, and dry_run mode.

Design principles:
 - dry_run=True (default) never spawns a capture process; logs what would run
 - All captures are bounded by a max_seconds / max_packets limit
 - Output files are timestamped and placed in an IR evidence directory
 - Structured CaptureResult dataclass feeds into the broader IR pipeline
 - No root escalation; caller is responsible for privilege setup

Usage::

    from automations.pcap_trigger import PcapTrigger, CaptureResult, CaptureBackend

    trigger = PcapTrigger(
        output_dir="/evidence/captures",
        dry_run=True,       # set False only on live IR systems with privileges
    )
    result = trigger.capture(
        interface="eth0",
        bpf_filter="host 192.168.1.100 and tcp",
        max_seconds=60,
        max_packets=5000,
        label="suspected_c2_traffic",
    )
    print(result.to_dict())
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CaptureBackend(str, Enum):
    TCPDUMP = "tcpdump"
    TSHARK  = "tshark"
    AUTO    = "auto"  # auto-detect whichever is available


class CaptureStatus(str, Enum):
    SUCCESS    = "SUCCESS"
    DRY_RUN    = "DRY_RUN"
    FAILED     = "FAILED"
    TIMEOUT    = "TIMEOUT"
    BACKEND_MISSING = "BACKEND_MISSING"


# ---------------------------------------------------------------------------
# CaptureResult
# ---------------------------------------------------------------------------

@dataclass
class CaptureResult:
    """
    Structured result from a PCAP capture attempt.

    Attributes:
        status:        Outcome of the capture attempt.
        backend:       Backend used (tcpdump/tshark).
        interface:     Network interface captured.
        bpf_filter:    BPF filter expression applied.
        output_file:   Absolute path to the .pcap file (empty on failure).
        command:       Full command that was (or would have been) run.
        label:         Human label for this capture.
        started_at:    Unix timestamp of capture start.
        duration_s:    Actual capture duration in seconds.
        packets_count: Estimated packet count (from backend output), or -1.
        error:         Error message if status is FAILED.
        dry_run:       Whether this was a dry run.
    """
    status:        CaptureStatus
    backend:       str
    interface:     str
    bpf_filter:    str        = ""
    output_file:   str        = ""
    command:       list[str]  = field(default_factory=list)
    label:         str        = ""
    started_at:    float      = field(default_factory=time.time)
    duration_s:    float      = 0.0
    packets_count: int        = -1
    error:         str        = ""
    dry_run:       bool       = False

    def to_dict(self) -> dict:
        return {
            "status":        self.status.value,
            "backend":       self.backend,
            "interface":     self.interface,
            "bpf_filter":    self.bpf_filter,
            "output_file":   self.output_file,
            "command":       " ".join(self.command),
            "label":         self.label,
            "started_at":    self.started_at,
            "duration_s":    self.duration_s,
            "packets_count": self.packets_count,
            "error":         self.error,
            "dry_run":       self.dry_run,
        }

    def summary(self) -> str:
        if self.dry_run:
            return (
                f"[DRY RUN] Would capture on {self.interface} "
                f"filter='{self.bpf_filter}' "
                f"cmd='{' '.join(self.command)}'"
            )
        if self.status == CaptureStatus.SUCCESS:
            return (
                f"Capture OK: {self.output_file} "
                f"({self.duration_s:.1f}s, "
                f"{self.packets_count} packets)"
            )
        return f"Capture {self.status.value}: {self.error}"


# ---------------------------------------------------------------------------
# PcapTrigger
# ---------------------------------------------------------------------------

class PcapTrigger:
    """
    Network capture trigger for IR evidence collection.

    Args:
        output_dir:    Directory to write .pcap files into.
                       Created if it does not exist (unless dry_run).
        dry_run:       If True, build and log commands but never execute them.
        backend:       Which capture backend to use (AUTO detects tcpdump first,
                       then tshark).
        max_seconds:   Default capture duration limit (seconds).
        max_packets:   Default packet count limit.
    """

    def __init__(
        self,
        output_dir: str = "/tmp/ir_captures",
        dry_run: bool = True,
        backend: CaptureBackend = CaptureBackend.AUTO,
        max_seconds: int = 120,
        max_packets: int = 10_000,
    ) -> None:
        self._output_dir  = Path(output_dir)
        self._dry_run     = dry_run
        self._backend_pref = backend
        self._max_seconds = max_seconds
        self._max_packets = max_packets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(
        self,
        interface: str,
        bpf_filter: str = "",
        max_seconds: Optional[int] = None,
        max_packets: Optional[int] = None,
        label: str = "",
    ) -> CaptureResult:
        """
        Run (or simulate) a bounded network capture.

        Args:
            interface:   Network interface (e.g. "eth0", "any").
            bpf_filter:  BPF filter expression (e.g. "host 10.0.0.1 and tcp").
            max_seconds: Override instance max_seconds for this capture.
            max_packets: Override instance max_packets for this capture.
            label:       Human-readable label embedded in the output filename.

        Returns:
            CaptureResult with status, output path, and metadata.
        """
        max_sec = max_seconds if max_seconds is not None else self._max_seconds
        max_pkt = max_packets if max_packets is not None else self._max_packets
        started = time.time()

        backend_bin = self._resolve_backend()
        if backend_bin is None:
            return CaptureResult(
                status=CaptureStatus.BACKEND_MISSING,
                backend="",
                interface=interface,
                bpf_filter=bpf_filter,
                label=label,
                started_at=started,
                error="Neither tcpdump nor tshark found in PATH",
                dry_run=self._dry_run,
            )

        output_path = self._output_path(interface, label, started)
        cmd = self._build_command(
            backend_bin, interface, bpf_filter,
            max_sec, max_pkt, output_path,
        )

        if self._dry_run:
            return CaptureResult(
                status=CaptureStatus.DRY_RUN,
                backend=backend_bin,
                interface=interface,
                bpf_filter=bpf_filter,
                output_file=str(output_path),
                command=cmd,
                label=label,
                started_at=started,
                dry_run=True,
            )

        return self._run_capture(
            cmd, backend_bin, interface, bpf_filter,
            output_path, label, started, max_sec,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_backend(self) -> Optional[str]:
        """Return the binary name for the selected backend, or None."""
        if self._backend_pref == CaptureBackend.TCPDUMP:
            return "tcpdump" if shutil.which("tcpdump") else None
        if self._backend_pref == CaptureBackend.TSHARK:
            return "tshark" if shutil.which("tshark") else None
        # AUTO: try tcpdump first, then tshark
        if shutil.which("tcpdump"):
            return "tcpdump"
        if shutil.which("tshark"):
            return "tshark"
        return None

    def _output_path(self, interface: str, label: str, ts: float) -> Path:
        """Build a timestamped output file path."""
        ts_str = time.strftime("%Y%m%dT%H%M%S", time.gmtime(ts))
        safe_iface = interface.replace("/", "_").replace(":", "_")
        safe_label = label.replace(" ", "_").replace("/", "_")[:32] if label else "capture"
        filename = f"{ts_str}_{safe_iface}_{safe_label}.pcap"
        return self._output_dir / filename

    def _build_command(
        self,
        backend: str,
        interface: str,
        bpf_filter: str,
        max_seconds: int,
        max_packets: int,
        output_path: Path,
    ) -> list[str]:
        """Build the tcpdump or tshark command list."""
        if backend == "tcpdump":
            cmd = [
                "tcpdump",
                "-i", interface,
                "-w", str(output_path),
                "-G", str(max_seconds),   # rotate every N seconds (also sets duration)
                "-W", "1",                # only one file (combined with -G)
                "-c", str(max_packets),   # stop after N packets
                "-Z", "root",             # drop privileges after open (if available)
                "--immediate-mode",
            ]
            if bpf_filter:
                cmd.append(bpf_filter)
            return cmd

        # tshark
        cmd = [
            "tshark",
            "-i", interface,
            "-w", str(output_path),
            "-a", f"duration:{max_seconds}",
            "-c", str(max_packets),
        ]
        if bpf_filter:
            cmd += ["-f", bpf_filter]
        return cmd

    def _run_capture(
        self,
        cmd: list[str],
        backend: str,
        interface: str,
        bpf_filter: str,
        output_path: Path,
        label: str,
        started: float,
        max_seconds: int,
    ) -> CaptureResult:
        """Execute the capture subprocess with a timeout guard."""
        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=max_seconds + 5,   # +5 s grace period
                text=True,
            )
            duration = time.time() - started
            packets = _parse_packet_count(proc.stderr or proc.stdout, backend)

            if proc.returncode == 0:
                return CaptureResult(
                    status=CaptureStatus.SUCCESS,
                    backend=backend,
                    interface=interface,
                    bpf_filter=bpf_filter,
                    output_file=str(output_path),
                    command=cmd,
                    label=label,
                    started_at=started,
                    duration_s=duration,
                    packets_count=packets,
                    dry_run=False,
                )
            return CaptureResult(
                status=CaptureStatus.FAILED,
                backend=backend,
                interface=interface,
                bpf_filter=bpf_filter,
                output_file=str(output_path),
                command=cmd,
                label=label,
                started_at=started,
                duration_s=duration,
                packets_count=packets,
                error=proc.stderr[:256] if proc.stderr else "",
                dry_run=False,
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - started
            return CaptureResult(
                status=CaptureStatus.TIMEOUT,
                backend=backend,
                interface=interface,
                bpf_filter=bpf_filter,
                output_file=str(output_path),
                command=cmd,
                label=label,
                started_at=started,
                duration_s=duration,
                error=f"Capture exceeded {max_seconds + 5}s timeout",
                dry_run=False,
            )

        except (OSError, FileNotFoundError) as exc:
            return CaptureResult(
                status=CaptureStatus.FAILED,
                backend=backend,
                interface=interface,
                bpf_filter=bpf_filter,
                command=cmd,
                label=label,
                started_at=started,
                error=str(exc),
                dry_run=False,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_packet_count(output: str, backend: str) -> int:
    """
    Parse packet count from tcpdump/tshark summary output.
    Returns -1 if the count cannot be extracted.
    """
    if not output:
        return -1
    import re
    if backend == "tcpdump":
        # tcpdump: "42 packets captured"
        m = re.search(r"(\d+)\s+packets?\s+captured", output)
        if m:
            return int(m.group(1))
    else:
        # tshark: "42 packets captured"  or just a number on last line
        m = re.search(r"(\d+)\s+packets?\s+captured", output)
        if m:
            return int(m.group(1))
    return -1
