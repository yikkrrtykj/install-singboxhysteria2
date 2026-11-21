#!/usr/bin/env python3
"""Isolated contract tests for the GUI-facing HA-04 delivery filename adapter.

The real HA chain preflight lives in HA-02/03/04 suites; these tests deliberately
mock that boundary and verify the public filename cannot misstate the A/B role.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1] / "tools" / (
    "mihomo-competition-ha-friendly-export.py")
spec = importlib.util.spec_from_file_location("friendly_export_under_test", MODULE)
friendly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(friendly)


class FakeBatch:
    def check_directory(self, _path, _role):
        return None

    def check_private_path(self, _path, _role):
        return None

    def check_local_boundary(self, _path, _role):
        return None

    def load_merge_tool(self):
        return object()


class FakeFast:
    def __init__(self, source: bytes, group: str = "A-first"):
        self.group = group
        self.checked = False
        self.fail_preflight = False
        self.entries = [{
            "name": "event-ob01",
            "group": group,
            "primary_vps": "A" if group == "A-first" else "B",
            "backup_vps": "B" if group == "A-first" else "A",
            "output": "event-ob01-ha4f.yaml",
            "output_bytes": len(source),
            "output_sha256": hashlib.sha256(source).hexdigest(),
        }]

    def batch_tool(self):
        return FakeBatch()

    def check(self, *_args):
        self.checked = True
        if self.fail_preflight:
            raise friendly.ExportError("E_SOURCE_HASH")

    def load_variant_delivery(self, _variant):
        return {}, "manifest.json", self.entries, []

    def validate_manifest_entries(self, entries, _merge):
        return entries


class FriendlyExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for item in ("ha04", "ha03", "ha02", "download"):
            (self.root / item).mkdir()
        (self.root / "pins.json").write_text("{}", encoding="utf-8")
        self.payload = b"private profile bytes - no secret output"
        (self.root / "ha04" / "event-ob01-ha4f.yaml").write_bytes(self.payload)
        self.fast = FakeFast(self.payload)

    def run_export(self, group="A-first"):
        return friendly.export_one(
            str(self.root / "ha04"), str(self.root / "ha03"),
            str(self.root / "ha02"), str(self.root / "pins.json"),
            "event-ob01", group, str(self.root / "download"),
            fast=self.fast)

    def test_friendly_name_and_byte_identity(self):
        name, digest = self.run_export()
        self.assertTrue(self.fast.checked)
        self.assertEqual(name, "event-ob01-A-first.yaml")
        self.assertEqual(digest, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual((self.root / "download" / name).read_bytes(), self.payload)

    def test_b_first_published_only_from_b_first_manifest(self):
        self.fast = FakeFast(self.payload, "B-first")
        self.assertEqual(self.run_export("B-first")[0],
                         "event-ob01-B-first.yaml")
        with self.assertRaisesRegex(friendly.ExportError, "E_ROLE_MISMATCH"):
            self.run_export("A-first")

    def test_name_refusal_and_role_spoof(self):
        for name in ("../../bad", "-bad", "", "bad/name"):
            with self.assertRaisesRegex(friendly.ExportError, "E_NAME"):
                friendly.output_name(name, "A-first")
        with self.assertRaisesRegex(friendly.ExportError, "E_ROLE_MISMATCH"):
            self.run_export("B-first")
        self.assertEqual(list((self.root / "download").iterdir()), [])

    def test_no_overwrite(self):
        self.run_export()
        with self.assertRaisesRegex(friendly.ExportError, "E_OUTPUT_EXISTS"):
            self.run_export()
        self.assertEqual((self.root / "download" /
                          "event-ob01-A-first.yaml").read_bytes(), self.payload)

    def test_tamper_or_failed_preflight_leaves_no_delivery(self):
        self.fast.entries[0]["output_sha256"] = "0" * 64
        with self.assertRaisesRegex(friendly.ExportError, "E_SOURCE_HASH"):
            self.run_export()
        self.fast = FakeFast(self.payload)
        self.fast.fail_preflight = True
        with self.assertRaisesRegex(friendly.ExportError, "E_SOURCE_HASH"):
            self.run_export()
        self.assertEqual(list((self.root / "download").iterdir()), [])

    def test_cannot_publish_inside_source(self):
        with self.assertRaisesRegex(friendly.ExportError, "E_PATH_CONFLICT"):
            friendly.export_one(
                str(self.root / "ha04"), str(self.root / "ha03"),
                str(self.root / "ha02"), str(self.root / "pins.json"),
                "event-ob01", "A-first", str(self.root / "ha04"),
                fast=self.fast)


if __name__ == "__main__":
    unittest.main()
