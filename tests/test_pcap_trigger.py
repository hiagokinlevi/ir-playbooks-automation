"""
Tests for automations/pcap_trigger.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from automations.pcap_trigger import (
    CaptureBackend,
    CaptureResult,
    CaptureStatus,
    PcapTrigger,
    _parse_packet_count,
)


# ===========================================================================
# CaptureResult
# ===========================================================================

class TestCaptureResult:
    def _result(self, status=CaptureStatus.SUCCESS, dry_run=False) -> CaptureResult:
        return CaptureResult(
            status=status,
            backend="tcpdump",
            interface="eth0",
            bpf_filter="host 10.0.0.1",
            output_file="/evidence/cap.pcap",
            command=["tcpdump", "-i", "eth0", "-w", "/evidence/cap.pcap"],
            label="test",
            started_at=1_700_000_000.0,
            duration_s=12.5,
            packets_count=42,
            dry_run=dry_run,
        )

    def test_to_dict_keys(self):
        d = self._result().to_dict()
        for k in ("status", "backend", "interface", "bpf_filter",
                  "output_file", "command", "label", "started_at",
                  "duration_s", "packets_count", "error", "dry_run"):
            assert k in d

    def test_status_serialized_as_string(self):
        assert self._result().to_dict()["status"] == "SUCCESS"

    def test_command_serialized_as_string(self):
        d = self._result().to_dict()
        assert isinstance(d["command"], str)
        assert "tcpdump" in d["command"]

    def test_summary_success_contains_file(self):
        assert "/evidence/cap.pcap" in self._result().summary()

    def test_summary_success_contains_duration(self):
        assert "12.5" in self._result().summary()

    def test_summary_dry_run_prefix(self):
        assert "[DRY RUN]" in self._result(dry_run=True).summary()

    def test_summary_failure_contains_status(self):
        r = self._result(status=CaptureStatus.FAILED)
        r.error = "permission denied"
        assert "FAILED" in r.summary()


# ===========================================================================
# _parse_packet_count
# ===========================================================================

class TestParsePacketCount:
    def test_tcpdump_standard(self):
        assert _parse_packet_count("42 packets captured", "tcpdump") == 42

    def test_tcpdump_singular(self):
        assert _parse_packet_count("1 packet captured", "tcpdump") == 1

    def test_tshark_standard(self):
        assert _parse_packet_count("100 packets captured", "tshark") == 100

    def test_empty_string_returns_minus_one(self):
        assert _parse_packet_count("", "tcpdump") == -1

    def test_no_match_returns_minus_one(self):
        assert _parse_packet_count("no useful output here", "tcpdump") == -1


# ===========================================================================
# PcapTrigger — backend resolution
# ===========================================================================

class TestBackendResolution:
    def test_auto_returns_tcpdump_when_available(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.AUTO)
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/tcpdump" if x == "tcpdump" else None):
            result = trigger.capture(interface="eth0")
        assert result.backend == "tcpdump"

    def test_auto_falls_back_to_tshark(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.AUTO)
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/tshark" if x == "tshark" else None):
            result = trigger.capture(interface="eth0")
        assert result.backend == "tshark"

    def test_auto_returns_backend_missing_when_neither_found(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.AUTO)
        with patch("shutil.which", return_value=None):
            result = trigger.capture(interface="eth0")
        assert result.status == CaptureStatus.BACKEND_MISSING

    def test_tcpdump_explicit_missing(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.TCPDUMP)
        with patch("shutil.which", return_value=None):
            result = trigger.capture(interface="eth0")
        assert result.status == CaptureStatus.BACKEND_MISSING

    def test_tshark_explicit_found(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.TSHARK)
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            result = trigger.capture(interface="eth0")
        assert result.backend == "tshark"


# ===========================================================================
# PcapTrigger — dry run
# ===========================================================================

class TestDryRun:
    def _trigger(self, **kwargs) -> PcapTrigger:
        return PcapTrigger(dry_run=True, **kwargs)

    def _run(self, trigger=None, interface="eth0", **kwargs) -> CaptureResult:
        t = trigger or self._trigger()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"):
            return t.capture(interface=interface, **kwargs)

    def test_status_is_dry_run(self):
        assert self._run().status == CaptureStatus.DRY_RUN

    def test_dry_run_flag_set(self):
        assert self._run().dry_run is True

    def test_command_is_populated(self):
        result = self._run()
        assert len(result.command) > 0

    def test_interface_in_command(self):
        result = self._run(interface="eth1")
        assert "eth1" in result.command

    def test_bpf_filter_in_command_for_tcpdump(self):
        result = self._run(bpf_filter="host 1.2.3.4 and tcp")
        assert "host 1.2.3.4 and tcp" in result.command

    def test_bpf_filter_in_tshark_command(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.TSHARK)
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            result = trigger.capture(interface="eth0", bpf_filter="tcp port 80")
        assert "tcp port 80" in result.command

    def test_output_file_contains_interface(self):
        result = self._run(interface="eth0")
        assert "eth0" in result.output_file

    def test_output_file_ends_with_pcap(self):
        assert self._run().output_file.endswith(".pcap")

    def test_label_in_output_file(self):
        result = self._run(label="malware_traffic")
        assert "malware_traffic" in result.output_file

    def test_no_subprocess_called(self):
        with patch("subprocess.run") as mock_run:
            self._run()
            mock_run.assert_not_called()

    def test_summary_contains_dry_run(self):
        assert "[DRY RUN]" in self._run().summary()

    def test_max_seconds_in_tcpdump_command(self):
        result = self._run(max_seconds=30)
        assert "30" in result.command

    def test_max_packets_in_command(self):
        result = self._run(max_packets=500)
        assert "500" in result.command

    def test_interface_default(self):
        result = self._run(interface="lo")
        assert result.interface == "lo"

    def test_empty_filter_not_appended_for_tcpdump(self):
        result = self._run(bpf_filter="")
        # No empty string at end of command
        assert result.command[-1] != ""

    def test_empty_filter_not_added_for_tshark(self):
        trigger = PcapTrigger(dry_run=True, backend=CaptureBackend.TSHARK)
        with patch("shutil.which", return_value="/usr/bin/tshark"):
            result = trigger.capture(interface="eth0", bpf_filter="")
        assert "-f" not in result.command


# ===========================================================================
# PcapTrigger — output path
# ===========================================================================

class TestOutputPath:
    def test_timestamp_in_filename(self):
        trigger = PcapTrigger(output_dir="/tmp/ir", dry_run=True)
        with patch("shutil.which", return_value="/usr/bin/tcpdump"):
            result = trigger.capture(interface="eth0")
        filename = Path(result.output_file).name
        # ISO-ish timestamp in name: YYYYMMDD
        import re
        assert re.search(r"\d{8}T\d{6}", filename)

    def test_label_sanitized_in_filename(self):
        trigger = PcapTrigger(output_dir="/tmp/ir", dry_run=True)
        with patch("shutil.which", return_value="/usr/bin/tcpdump"):
            result = trigger.capture(interface="eth0", label="bad/label name")
        assert "/" not in Path(result.output_file).name

    def test_long_label_truncated(self):
        trigger = PcapTrigger(output_dir="/tmp/ir", dry_run=True)
        with patch("shutil.which", return_value="/usr/bin/tcpdump"):
            result = trigger.capture(interface="eth0", label="a" * 100)
        # label portion should be at most 32 chars
        filename = Path(result.output_file).name
        parts = filename.split("_")
        label_part = "_".join(parts[2:]).replace(".pcap", "")
        assert len(label_part) <= 32


# ===========================================================================
# PcapTrigger — live run (mocked subprocess)
# ===========================================================================

class TestLiveCapture:
    def _trigger_live(self, **kwargs) -> PcapTrigger:
        return PcapTrigger(
            output_dir="/tmp/test_ir_captures",
            dry_run=False,
            **kwargs,
        )

    def _mock_proc(self, returncode=0, stderr="42 packets captured") -> MagicMock:
        proc = MagicMock()
        proc.returncode = returncode
        proc.stderr = stderr
        proc.stdout = ""
        return proc

    def test_success_result(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", return_value=self._mock_proc(0)), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        assert result.status == CaptureStatus.SUCCESS

    def test_success_parses_packet_count(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", return_value=self._mock_proc(0, "42 packets captured")), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        assert result.packets_count == 42

    def test_failed_nonzero_returncode(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", return_value=self._mock_proc(1, "pcap: eth0: No such device")), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth99")
        assert result.status == CaptureStatus.FAILED
        assert "No such device" in result.error

    def test_timeout_result(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=10)), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        assert result.status == CaptureStatus.TIMEOUT

    def test_oserror_returns_failed(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", side_effect=FileNotFoundError("tcpdump not found")), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        assert result.status == CaptureStatus.FAILED

    def test_dry_run_false_flag_in_result(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", return_value=self._mock_proc(0)), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        assert result.dry_run is False

    def test_result_to_dict_round_trip(self):
        trigger = self._trigger_live()
        with patch("shutil.which", return_value="/usr/bin/tcpdump"), \
             patch("subprocess.run", return_value=self._mock_proc(0)), \
             patch("pathlib.Path.mkdir"):
            result = trigger.capture(interface="eth0")
        d = result.to_dict()
        assert d["status"] == "SUCCESS"
        assert d["dry_run"] is False
