"""Recipient pairing and explicit-start GUI contracts; no real controller contact."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover import desktop, desktop_ui
spec = importlib.util.spec_from_file_location("desktop_fixtures", ROOT / "tests/test_quality_failover.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def inputs(root):
    yaml = root / "colleague-mihomo.yaml"
    fixture.export(yaml)
    ca = root / "receiver-ca.pem"
    ca.write_bytes(b"synthetic-ca-no-network")
    info = root / "receiver-info.json"
    info.write_text(json.dumps({"v": 1, "endpoint": "https://127.0.0.1:19443", "token": "x" * 32,
                               "certificate_sha256": hashlib.sha256(ca.read_bytes()).hexdigest()}), encoding="utf-8")
    manifest = {"v": 1, "client": "colleague", "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (yaml, ca, info)}}
    (root / "quality-package.json").write_text(json.dumps(manifest), encoding="utf-8")
    for p in root.iterdir():
        p.chmod(0o600)
    return manifest


class RecipientTests(unittest.TestCase):
    def test_move_to_other_unicode_directory_preserves_identity(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary, patch("quality_failover.pilot.ssl.create_default_context"):
            root = Path(temporary)
            a = root / "first"; a.mkdir()
            inputs(a)
            first = desktop.package_inputs(a)
            b = root / "同事电脑 解压目录"; shutil.copytree(a, b)
            second = desktop.package_inputs(b)
            self.assertEqual(first[2], second[2])
            self.assertEqual(second[0].parent, b)

    def test_yaml_edit_refused_before_receiver_validation(self):
        with tempfile.TemporaryDirectory() as directory, patch("quality_failover.desktop.receiver_info") as receiver:
            root = Path(directory); inputs(root)
            (root / "colleague-mihomo.yaml").write_bytes(b"changed")
            with self.assertRaises(ValueError): desktop.package_inputs(root)
            receiver.assert_not_called()

    def test_extra_or_traversing_file_refused(self):
        for name in ("../private.pem", "extra-file"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); manifest = inputs(root)
                manifest["files"][name] = "0" * 64
                (root / "quality-package.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(ValueError): desktop.package_inputs(root)

    def test_duplicate_descriptor_key_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); inputs(root)
            (root / "quality-package.json").write_text('{"v":1,"v":1}', encoding="utf-8")
            with self.assertRaises(ValueError): desktop.package_inputs(root)

    def test_foreign_ca_even_with_updated_outer_digest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); manifest = inputs(root)
            ca = root / "receiver-ca.pem"; ca.write_bytes(b"another CA")
            manifest["files"][ca.name] = hashlib.sha256(ca.read_bytes()).hexdigest()
            (root / "quality-package.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "certificate_digest"): desktop.package_inputs(root)

    def test_changed_receiver_token_has_independent_workspace_identity(self):
        with tempfile.TemporaryDirectory() as directory, patch("quality_failover.pilot.ssl.create_default_context"):
            root = Path(directory); manifest = inputs(root)
            first = desktop.package_inputs(root)[2]
            path = root / "receiver-info.json"; info = json.loads(path.read_text())
            info["token"] = "y" * 32; path.write_text(json.dumps(info), encoding="utf-8")
            manifest["files"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "quality-package.json").write_text(json.dumps(manifest), encoding="utf-8")
            self.assertNotEqual(first, desktop.package_inputs(root)[2])

    def test_oversized_and_symlink_inputs_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "file"; path.write_bytes(b"x" * 100)
            with self.assertRaises(ValueError): desktop.checked_bytes(path, 10)

    def test_recipient_zip_uses_only_adjacent_files_and_generic_exe(self):
        import zipfile
        spec = importlib.util.spec_from_file_location("desktop_packager", ROOT / "tools/package-quality-windows.py")
        packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
        with tempfile.TemporaryDirectory() as directory, patch("quality_failover.pilot.ssl.create_default_context"):
            root = Path(directory); inputs(root)
            exe = root / desktop.EXE_NAME; exe.write_bytes(b"MZ" + b"x" * 1024)
            with patch.object(packager, "check_signature") as signature:
                output = root / "recipient.zip"
                packager.package(exe, root / "colleague-mihomo.yaml", root / "receiver-info.json", output)
                signature.assert_called_once_with(exe)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), {desktop.EXE_NAME, "colleague-mihomo.yaml", "receiver-info.json",
                                                         "receiver-ca.pem", "quality-package.json", "先看这里.txt", "第三方许可.txt"})
                self.assertEqual(archive.read(desktop.EXE_NAME), exe.read_bytes())
                self.assertNotIn(str(root), archive.read("quality-package.json").decode())

    def test_invalid_signature_never_emits_recipient_zip(self):
        spec = importlib.util.spec_from_file_location("desktop_packager_refusal", ROOT / "tools/package-quality-windows.py")
        packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); inputs(root)
            exe = root / desktop.EXE_NAME; exe.write_bytes(b"MZ" + b"x" * 1024)
            output = root / "recipient.zip"
            with patch.object(packager, "check_signature", side_effect=ValueError("signature")):
                with self.assertRaises(ValueError):
                    packager.package(exe, root / "colleague-mihomo.yaml", root / "receiver-info.json", output)
            self.assertFalse(output.exists())


@unittest.skipUnless(os.name == "nt", "native Tk acceptance runs on Windows")
class GuiTests(unittest.TestCase):
    def exercise(self, ready):
        import tkinter as tk
        from tkinter import ttk
        instances = []
        class FakeSession:
            def __init__(self, *args):
                instances.append(self); self.stop_event = threading.Event(); self.enables = 0
            def start(self, **kwargs): pass
            def loop(self, emit):
                emit({"action": "observe", "mode": "observe", "paths": {
                    n: {"state": "UP", "reason": "upload_confirmed_good" if ready else "reachable_only"}
                    for n in ("Reality", "Hysteria2")}})
                self.stop_event.wait(3)
                emit({"action": "stopped", "restore_confirmed": True})
            def enable(self): self.enables += 1
            def stop(self): self.stop_event.set()
            def confirm(self): pass
        def widgets(root):
            for child in root.winfo_children():
                yield child
                yield from widgets(child)
        def acceptance(root, *args):
            root.withdraw(); root.update_idletasks()
            self.assertEqual(instances, [])
            self.assertFalse(any(isinstance(w, ttk.Entry) for w in widgets(root)))
            start = next(w for w in widgets(root) if isinstance(w, ttk.Button) and w.cget("text") == "开启质量切换")
            start.invoke()
            deadline = time.monotonic() + .6
            while time.monotonic() < deadline: root.update(); time.sleep(.01)
            self.assertEqual(instances[0].enables, 1 if ready else 0)
            stop = next(w for w in widgets(root) if isinstance(w, ttk.Button) and w.cget("text") == "停止")
            stop.invoke()
            deadline = time.monotonic() + .4
            while time.monotonic() < deadline: root.update(); time.sleep(.01)
            self.assertTrue(instances[0].stop_event.is_set())
            for scheduled in root.tk.call("after", "info"):
                root.after_cancel(scheduled)
            root.destroy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "bundle-test").mkdir(); (root / "bundle-test/bundle.json").write_text("{}")
            with patch.object(tk.Tk, "mainloop", acceptance), patch.object(desktop_ui, "load_bundle", return_value=({}, {})), patch.object(desktop_ui, "Session", FakeSession):
                desktop_ui.show(root, root, root / "colleague-mihomo.yaml", root / "receiver-info.json")

    def test_user_click_and_both_upload_confirmations_required(self): self.exercise(True)
    def test_reachability_alone_does_not_enable(self): self.exercise(False)


if __name__ == "__main__":
    unittest.main()
