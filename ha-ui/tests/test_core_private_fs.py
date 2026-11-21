"""Tests for :mod:`ha_ui.core.private_fs` (requirement C).

These tests use the real filesystem and the real NTFS ACL gate:

* private directories/files are created with ``ensure_private_dir`` /
  ``secure_write_new`` and verified through the reviewed
  ``mihomo-competition-ha-batch.py`` ACL checks;
* the ACL negative test grants ``BUILTIN\\Users`` (SID ``S-1-5-32-545``) read
  access with ``icacls`` and proves the gate refuses the path, then re-hardens;
* path ambiguity (``..``, separators, colon, NUL), workspace escape, reparse
  points (junction/symlink), oversize reads and deletion boundaries are tested.

The repository worktree's ``.scratch`` area is used for every fixture path; no
system temp directory is required.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from ha_ui.core import errors, private_fs
from ha_ui.core.errors import HaUiError

WINDOWS = private_fs.is_windows()
requires_windows = pytest.mark.skipif(
    not WINDOWS, reason="requires real Windows NTFS ACL semantics")


def _assert_error(exc_info: "pytest.ExceptionInfo[HaUiError]", code: str,
                  detail: str | None = None) -> None:
    err = exc_info.value
    assert isinstance(err, HaUiError), "expected HaUiError, got %r" % (err,)
    assert err.code == code, (
        "expected error code %r, got %r (detail=%r)" % (code, err.code, err.detail))
    if detail is not None:
        assert err.detail == detail, (
            "expected detail %r, got %r" % (detail, err.detail))


def _make_junction(link: Path, target: Path) -> bool:
    """Create an NTFS junction (no admin privilege needed) if possible."""
    if not WINDOWS or not target.is_dir():
        return False
    try:
        proc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and os.path.lexists(link)


def _remove_junction(link: Path) -> None:
    try:
        os.rmdir(link)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# ensure_private_dir
# --------------------------------------------------------------------------- #
def test_ensure_private_dir_creates_and_verifies(private_workspace) -> None:
    target = private_workspace / "nested" / "deeper"
    created = private_fs.ensure_private_dir(target, workspace=private_workspace)
    assert created == target
    assert target.is_dir()
    private_fs.verify_private_dir(target)
    # Newly created intermediate components are hardened immediately.
    private_fs.verify_private_dir(private_workspace / "nested")


def test_ensure_private_dir_is_idempotent(private_workspace) -> None:
    target = private_workspace / "reused"
    private_fs.ensure_private_dir(target, workspace=private_workspace)
    payload = b"existing"
    private_fs.secure_write_new(target / "f.bin", payload,
                                workspace=private_workspace)
    private_fs.ensure_private_dir(target, workspace=private_workspace)
    private_fs.verify_private_dir(target)
    assert (target / "f.bin").read_bytes() == payload, (
        "re-hardening an existing private directory must not destroy content")
    runtime_root = private_fs.ensure_private_dir(private_workspace,
                                                 workspace=private_workspace)
    assert runtime_root == private_workspace


def test_ensure_private_dir_refuses_outside_workspace(private_workspace) -> None:
    escape = private_workspace.parent / ("outside-%s" % uuid.uuid4().hex)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.ensure_private_dir(escape, workspace=private_workspace)
    _assert_error(excinfo, errors.E_PATH, "outside-workspace")
    assert not escape.exists(), "refused directory must not be created"


def test_ensure_private_dir_refuses_regular_file(private_workspace) -> None:
    file_path = private_workspace / "already-a-file.bin"
    private_fs.secure_write_new(file_path, b"data",
                                workspace=private_workspace)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.ensure_private_dir(file_path, workspace=private_workspace)
    _assert_error(excinfo, errors.E_PATH, "not-directory")


# --------------------------------------------------------------------------- #
# secure_write_new / secure_write_replace
# --------------------------------------------------------------------------- #
def test_secure_write_new_writes_private_file_with_sha(private_workspace) -> None:
    payload = b"line-1\nline-2\ncredential-free\n"
    target = private_workspace / "runs" / "delivery.yaml"
    digest = private_fs.secure_write_new(target, payload,
                                         workspace=private_workspace)
    expected = hashlib.sha256(payload).hexdigest()
    assert digest == expected
    assert target.read_bytes() == payload
    assert private_fs.file_sha256(target) == expected
    private_fs.verify_private_file(target)
    private_fs.verify_private_dir(target.parent)
    leftovers = [p.name for p in target.parent.iterdir()
                 if p.name.startswith(".ha-ui-")]
    assert leftovers == [], "temp file not cleaned up: %r" % leftovers


def test_secure_write_new_is_no_clobber(private_workspace) -> None:
    target = private_workspace / "no-clobber.bin"
    first = b"first payload"
    digest = private_fs.secure_write_new(target, first,
                                         workspace=private_workspace)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.secure_write_new(target, b"second payload",
                                    workspace=private_workspace)
    _assert_error(excinfo, errors.E_OUTPUT_EXISTS, "target")
    assert target.read_bytes() == first
    assert private_fs.file_sha256(target) == digest


def test_secure_write_new_refuses_path_escape(private_workspace) -> None:
    escape = private_workspace.parent / ("escape-%s.bin" % uuid.uuid4().hex)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.secure_write_new(escape, b"payload")
    assert excinfo.value.code in (errors.E_PATH, errors.E_ACL), (
        "path escape must be refused, got %r" % excinfo.value.code)
    assert not escape.exists()


def test_secure_write_replace_updates_existing_private_file(
        private_workspace) -> None:
    target = private_workspace / "servers-copy.json"
    private_fs.secure_write_replace(target, b'{"v": 1}')
    assert target.read_bytes() == b'{"v": 1}'
    private_fs.verify_private_file(target)

    private_fs.secure_write_replace(target, b'{"v": 2}')
    assert target.read_bytes() == b'{"v": 2}'
    private_fs.verify_private_file(target)
    leftovers = [p.name for p in private_workspace.iterdir()
                 if p.name.startswith(".ha-ui-")]
    assert leftovers == [], "atomic replace must not leave temp files: %r" % leftovers


def test_secure_write_replace_creates_new_file(private_workspace) -> None:
    target = private_workspace / "created-by-replace.json"
    private_fs.secure_write_replace(target, b"{}")
    assert target.read_bytes() == b"{}"
    private_fs.verify_private_file(target)


# --------------------------------------------------------------------------- #
# read_private_file
# --------------------------------------------------------------------------- #
def test_read_private_file_roundtrip_and_size_limit(private_workspace) -> None:
    payload = b"0123456789"
    target = private_workspace / "read.bin"
    private_fs.secure_write_new(target, payload, workspace=private_workspace)
    assert private_fs.read_private_file(target) == payload
    assert private_fs.read_private_file(target, max_bytes=len(payload)) == payload
    with pytest.raises(HaUiError) as excinfo:
        private_fs.read_private_file(target, max_bytes=len(payload) - 1)
    _assert_error(excinfo, errors.E_PATH, "too-large")


def test_read_private_file_rejects_missing_and_directory(
        private_workspace) -> None:
    with pytest.raises(HaUiError) as excinfo:
        private_fs.read_private_file(private_workspace / "absent.bin")
    _assert_error(excinfo, errors.E_PATH, "missing")

    directory = private_workspace / "a-directory"
    private_fs.ensure_private_dir(directory, workspace=private_workspace)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.read_private_file(directory)
    _assert_error(excinfo, errors.E_PATH, "not-file")


def test_read_private_file_rejects_non_private_path_outside_workspace(
        private_workspace) -> None:
    outside = private_workspace.parent / ("plain-%s.bin" % uuid.uuid4().hex)
    outside.write_bytes(b"plain data")
    try:
        with pytest.raises(HaUiError) as excinfo:
            private_fs.read_private_file(outside)
        assert excinfo.value.code in (errors.E_ACL, errors.E_PATH), (
            "a non-private path outside the workspace must be rejected, got %r"
            % excinfo.value.code)
    finally:
        outside.unlink(missing_ok=True)


def test_read_private_file_rejects_reparse_symlink(private_workspace) -> None:
    target = private_workspace / "real-file.bin"
    private_fs.secure_write_new(target, b"secret-free",
                                workspace=private_workspace)
    link = private_workspace / "symlink-file.bin"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("cannot create a symlink on this host (%s)" % exc)
    try:
        with pytest.raises(HaUiError) as excinfo:
            private_fs.read_private_file(link)
        _assert_error(excinfo, errors.E_PATH, "reparse")
    finally:
        try:
            link.unlink()
        except OSError:
            pass


def test_read_private_file_rejects_reparse_junction(private_workspace) -> None:
    real_dir = private_workspace / "real-dir"
    private_fs.ensure_private_dir(real_dir, workspace=private_workspace)
    link = private_workspace / "junction-dir"
    if not _make_junction(link, real_dir):
        pytest.skip("cannot create an NTFS junction on this host")
    try:
        assert private_fs._is_reparse(link.lstat()), (
            "the fixture must be a real reparse point")
        with pytest.raises(HaUiError) as excinfo:
            private_fs.verify_private_dir(link)
        _assert_error(excinfo, errors.E_PATH, "reparse")
        with pytest.raises(HaUiError) as excinfo:
            private_fs.read_private_file(link)
        _assert_error(excinfo, errors.E_PATH, "reparse")
    finally:
        _remove_junction(link)


# --------------------------------------------------------------------------- #
# safe_child / is_within
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["file.txt", "报告.yaml", "a-b_c.1",
                                  "manifest-20240101T000000Z.json"])
def test_safe_child_accepts_plain_names(private_workspace,
                                        name: str) -> None:
    child = private_fs.safe_child(private_workspace, name)
    assert child == private_workspace / name
    assert child.parent == private_workspace


@pytest.mark.parametrize("name", [
    "", ".", "..", "a/b", "a\\b", "C:evil", "a:b", "a\x00b", "../x",
    "..\\x", "/absolute", "\\absolute", None,
])
def test_safe_child_rejects_ambiguous_names(private_workspace, name) -> None:
    with pytest.raises(HaUiError) as excinfo:
        private_fs.safe_child(private_workspace, name)
    _assert_error(excinfo, errors.E_PATH, "name")


def test_is_within_accepts_contained_paths(private_workspace) -> None:
    assert private_fs.is_within(private_workspace, private_workspace) is True
    assert private_fs.is_within(private_workspace,
                                private_workspace / "a") is True
    assert private_fs.is_within(private_workspace,
                                private_workspace / "a" / "b") is True


def test_is_within_rejects_escapes(private_workspace) -> None:
    assert private_fs.is_within(private_workspace,
                                private_workspace.parent) is False
    assert private_fs.is_within(private_workspace,
                                private_workspace / ".." / "sibling") is False
    sibling = private_workspace.parent / (private_workspace.name + "-sibling")
    sibling.mkdir()
    try:
        assert private_fs.is_within(private_workspace,
                                    sibling / "child") is False, (
            "a sibling whose name shares the root prefix is not contained")
    finally:
        shutil.rmtree(sibling, ignore_errors=True)


# --------------------------------------------------------------------------- #
# delete_tree_under / run_dir / output_dir
# --------------------------------------------------------------------------- #
def test_delete_tree_under_refuses_root_outside_and_files(
        private_workspace) -> None:
    with pytest.raises(HaUiError) as excinfo:
        private_fs.delete_tree_under(private_workspace, private_workspace)
    _assert_error(excinfo, errors.E_PATH, "outside-workspace")

    with pytest.raises(HaUiError) as excinfo:
        private_fs.delete_tree_under(private_workspace,
                                     private_workspace / "..")
    _assert_error(excinfo, errors.E_PATH, "outside-workspace")

    file_path = private_workspace / "keep-me.bin"
    private_fs.secure_write_new(file_path, b"data",
                                workspace=private_workspace)
    with pytest.raises(HaUiError) as excinfo:
        private_fs.delete_tree_under(private_workspace, file_path)
    _assert_error(excinfo, errors.E_PATH, "not-directory")
    assert file_path.exists(), "refused deletion must not remove the file"

    sibling = private_workspace.parent / ("outside-tree-%s"
                                          % uuid.uuid4().hex)
    sibling.mkdir()
    try:
        with pytest.raises(HaUiError) as excinfo:
            private_fs.delete_tree_under(private_workspace, sibling)
        _assert_error(excinfo, errors.E_PATH, "outside-workspace")
        assert sibling.is_dir(), "refused deletion must not remove outside trees"
    finally:
        shutil.rmtree(sibling, ignore_errors=True)


def test_delete_tree_under_removes_private_subtree(private_workspace) -> None:
    target = private_workspace / "runs" / "run-to-delete"
    private_fs.ensure_private_dir(target, workspace=private_workspace)
    private_fs.secure_write_new(target / "artifact.bin", b"artifact",
                                workspace=private_workspace)
    private_fs.delete_tree_under(private_workspace, target)
    assert not target.exists()
    assert private_workspace.is_dir(), "only the requested subtree is removed"


def test_run_dir_and_output_dir_layout(private_workspace) -> None:
    run = private_fs.run_dir(private_workspace, "run-2024.01.01_a")
    assert run == private_workspace / "runs" / "run-2024.01.01_a"
    assert run.is_dir()
    private_fs.verify_private_dir(run)

    output = private_fs.output_dir(private_workspace)
    assert output == private_workspace / "output"
    assert output.is_dir()
    private_fs.verify_private_dir(output)


@pytest.mark.parametrize("run_id", [
    "", ".", "..", "../escape", "a/b", "a\\b", "-leading", ".hidden",
    "a" * 65, "a b", "a\x00b",
])
def test_run_dir_rejects_invalid_run_id(private_workspace,
                                        run_id: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        private_fs.run_dir(private_workspace, run_id)
    _assert_error(excinfo, errors.E_PATH, "run-id")


# --------------------------------------------------------------------------- #
# Real Windows ACL negative test
# --------------------------------------------------------------------------- #
@requires_windows
@pytest.mark.windows_only
def test_workspace_acl_grant_for_builtin_users_is_rejected(
        private_workspace) -> None:
    icacls = shutil.which("icacls")
    assert icacls is not None, "icacls must exist on a supported Windows host"

    target = private_workspace / "acl-negative"
    private_fs.ensure_private_dir(target, workspace=private_workspace)
    private_fs.verify_private_dir(target)

    grant = subprocess.run(
        [icacls, str(target), "/grant", "*S-1-5-32-545:(OI)(CI)R"],
        capture_output=True, text=True, timeout=60)
    granted = grant.returncode == 0
    try:
        assert granted, "icacls grant failed: %r" % (grant.stderr.strip()[:200])
        # BUILTIN\Users must make the reviewed ACL gate refuse the directory.
        with pytest.raises(HaUiError) as excinfo:
            private_fs.verify_private_dir(target)
        err = excinfo.value
        assert err.code == errors.E_ACL, (
            "expected E_ACL after granting BUILTIN\\Users, got %r" % err.code)
        assert "S-1-5-32-545" in (err.detail or ""), (
            "ACL error detail should name the offending principal: %r"
            % err.detail)
    finally:
        if granted:
            removed = subprocess.run(
                [icacls, str(target), "/remove:g", "*S-1-5-32-545"],
                capture_output=True, text=True, timeout=60)
            assert removed.returncode == 0, (
                "could not remove the test grant: %r"
                % removed.stderr.strip()[:200])
            # Re-harden and prove the path is private again.
            private_fs.ensure_private_dir(target, workspace=private_workspace)
            private_fs.verify_private_dir(target)
