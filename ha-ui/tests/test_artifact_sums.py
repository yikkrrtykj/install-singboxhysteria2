"""Regression tests for the Windows build SHA256SUMS handoff.

The regression this guards: on Windows, ``Path.write_text`` translates LF to
CRLF, while an in-memory hash of the LF payload does not describe the file that
is actually delivered. The build now writes bytes and hashes the files on disk;
the verifier recomputes every hash from disk bytes.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = APP_ROOT / "scripts" / "build_windows.py"
VERIFIER = APP_ROOT / "ci" / "verify_artifact_sums.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def build():
    return load_module(BUILD_SCRIPT, "ha_ui_build_windows_sums")


@pytest.fixture()
def verifier():
    return load_module(VERIFIER, "ha_ui_verify_artifact_sums")


def make_dist(tmp_path: Path, build) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    exe = dist / "ha-ui.exe"
    exe.write_bytes(b"fake-exe-bytes-for-sums")
    receipt = {
        "schema": "ha-ui/windows-exe-receipt/1",
        "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "signed": False,
        "configuration_embedded": False,
    }
    build.write_receipt(dist / "receipt.json", receipt)
    return dist


def test_write_receipt_hashes_actual_bytes_and_emits_lf(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    receipt_bytes = (dist / "receipt.json").read_bytes()
    sums_bytes = (dist / "SHA256SUMS.txt").read_bytes()
    assert b"\r\n" not in receipt_bytes
    assert b"\r\n" not in sums_bytes
    lines = sums_bytes.decode("utf-8").splitlines()
    assert len(lines) == 2
    assert lines[0] == "%s  ha-ui.exe" % hashlib.sha256(
        (dist / "ha-ui.exe").read_bytes()).hexdigest()
    assert lines[1] == "%s  receipt.json" % hashlib.sha256(
        receipt_bytes).hexdigest()
    assert verifier.verify(dist) == []


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_verifier_accepts_lf_and_crlf_sums(tmp_path, build, verifier, newline):
    dist = make_dist(tmp_path, build)
    sums = dist / "SHA256SUMS.txt"
    text = sums.read_text(encoding="utf-8")
    sums.write_bytes(text.replace("\n", newline).encode("utf-8"))
    assert verifier.verify(dist) == []


def test_verifier_rejects_wrong_hash(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    sums = dist / "SHA256SUMS.txt"
    lines = sums.read_text(encoding="utf-8").splitlines()
    name = lines[0].rsplit("  ", 1)[1]
    lines[0] = "0" * 64 + "  " + name
    sums.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    problems = verifier.verify(dist)
    assert any(p.startswith("hash mismatch: ") for p in problems)


def test_verifier_rejects_missing_file(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    (dist / "ha-ui.exe").unlink()
    problems = verifier.verify(dist)
    assert any(p.startswith("missing file: ") for p in problems)


def test_verifier_rejects_tampered_file(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    with (dist / "ha-ui.exe").open("ab") as handle:
        handle.write(b"tamper")
    problems = verifier.verify(dist)
    assert any(p.startswith("hash mismatch: ") for p in problems)


def test_verifier_rejects_unlisted_extra_file(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    (dist / "unexpected.log").write_text("x", encoding="utf-8")
    problems = verifier.verify(dist)
    assert "unlisted file: unexpected.log" in problems


def test_verifier_rejects_duplicate_and_malformed_entries(tmp_path, build, verifier):
    dist = make_dist(tmp_path, build)
    sums = dist / "SHA256SUMS.txt"
    text = sums.read_text(encoding="utf-8")
    sums.write_text(text + "not-a-hash  receipt.json\n", encoding="utf-8")
    problems = verifier.verify(dist)
    assert any("bad hash" in p for p in problems)

    # A duplicated but syntactically valid entry must also fail closed.
    first = text.splitlines()[0]
    sums.write_text(text + first + "\n", encoding="utf-8")
    problems = verifier.verify(dist)
    assert any("duplicate" in p for p in problems)


def test_old_crlf_receipt_hash_bug_is_rejected(tmp_path, build, verifier):
    """Reproduce the pre-fix artifact: hash of LF payload, CRLF delivered file."""
    dist = make_dist(tmp_path, build)
    receipt = dist / "receipt.json"
    payload = receipt.read_bytes()
    assert b"\r\n" not in payload
    # Simulate the old build writing CRLF but hashing the pre-write LF payload.
    receipt.write_bytes(payload.replace(b"\n", b"\r\n"))
    problems = verifier.verify(dist)
    assert "hash mismatch: receipt.json" in problems
