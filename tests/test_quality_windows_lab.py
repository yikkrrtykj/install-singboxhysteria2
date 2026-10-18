"""Frozen-acceptance provenance and independent upload observations."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
from quality_windows_lab import TrackedReceiver

spec = importlib.util.spec_from_file_location("frozen_acceptance_contract", ROOT / "tests/quality-windows-exe-lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
HEAD = "1" * 40


class SourceGuardTests(unittest.TestCase):
    def test_old_receipt_refused_before_network_or_exe_even_with_matching_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "build.json"
            receipt.write_text(json.dumps({"source_commit": "0" * 40, "configuration_embedded": False,
                "bundled_data_sha256": {name: lab.digest(ROOT / "tools" / name) for name in (
                    "mihomo-multi-vps-merge.py", "mihomo-quality-failover.py")}}), encoding="utf-8")
            with patch.object(lab.subprocess, "check_output", return_value=HEAD + "\n"), patch.object(lab, "receiver_init") as receiver:
                with self.assertRaisesRegex(ValueError, "source_commit"):
                    lab.accept(Path(directory) / "must-not-run.exe", receipt)
                receiver.assert_not_called()

    def test_dirty_checkout_refused(self):
        with patch.object(lab.subprocess, "check_output", side_effect=[HEAD, " M tools/quality_failover/desktop.py\n"]):
            with self.assertRaisesRegex(ValueError, "clean tracked"):
                lab.verify_checkout(HEAD)

    def test_clean_matching_checkout_accepted(self):
        with patch.object(lab.subprocess, "check_output", side_effect=[HEAD, ""]):
            lab.verify_checkout(HEAD)


class UploadObservationTests(unittest.TestCase):
    def setUp(self):
        self.sink = TrackedReceiver()
        self.addCleanup(self.sink.server_close)

    def test_readiness_without_upload_does_not_confirm_quality(self):
        self.assertFalse(self.sink.confirmed("Reality", 0))

    def test_other_protocol_and_stale_receipts_do_not_confirm_recovery(self):
        self.sink.completed_uploads = [
            {"node": "Reality", "at": 1, "mbps": 20},
            {"node": "Hysteria2", "at": 3, "mbps": 20}]
        self.assertFalse(self.sink.confirmed("Reality", 2))
        self.assertTrue(self.sink.confirmed("Hysteria2", 2))

    def test_recovery_requires_consecutive_recent_good_uploads(self):
        self.sink.completed_uploads = [
            {"node": "Reality", "at": 1, "mbps": 20},
            {"node": "Reality", "at": 2, "mbps": 2},
            {"node": "Reality", "at": 3, "mbps": 20},
            {"node": "Reality", "at": 4, "mbps": 20}]
        self.assertFalse(self.sink.confirmed("Reality", 0, count=3))
        self.sink.completed_uploads.append({"node": "Reality", "at": 5, "mbps": 20})
        self.assertTrue(self.sink.confirmed("Reality", 0, count=3))


if __name__ == "__main__":
    unittest.main()
