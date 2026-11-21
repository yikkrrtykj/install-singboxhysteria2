"""Tests for :mod:`ha_ui.core.ha_tools` (requirement E).

The loader/wrapper is exercised against the real reviewed tools bundled in the
repository ``tools/`` directory, but only through deterministic, credential-free
code paths (a bad ``--config-version`` fails before any file is read).
"""

from __future__ import annotations

import hashlib
import re
import sys

import pytest

from ha_ui.core import errors, ha_tools
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import ToolResult

TOOL_FILES = {
    "batch": "mihomo-competition-ha-batch.py",
    "merge": "mihomo-multi-vps-merge.py",
    "profile": "mihomo-competition-ha-profile.py",
    "fastprobe": "mihomo-competition-ha4-fastprobe.py",
    "friendly": "mihomo-competition-ha-friendly-export.py",
}
PRESENT_TOOLS = ("batch", "merge", "profile", "fastprobe")
SHA256_HEX_RE = re.compile(r"\A[0-9a-f]{64}\Z")
BATCH_FAILURE_ARGV = [
    "--inventory", "x", "--exports", "y", "--output-dir", "z",
    "--config-version", "bad/version",
]


def _assert_error(exc_info: "pytest.ExceptionInfo[HaUiError]", code: str,
                  detail: str | None = None) -> None:
    err = exc_info.value
    assert isinstance(err, HaUiError), "expected HaUiError, got %r" % (err,)
    assert err.code == code, (
        "expected error code %r, got %r (detail=%r)" % (code, err.code, err.detail))
    if detail is not None:
        assert err.detail == detail, (
            "expected detail %r, got %r" % (detail, err.detail))


# --------------------------------------------------------------------------- #
# Tool directory discovery
# --------------------------------------------------------------------------- #
def test_tools_dir_resolves_to_repository_tools(bundled_tools_dir) -> None:
    resolved = ha_tools.tools_dir()
    assert resolved == bundled_tools_dir
    assert (resolved / TOOL_FILES["batch"]).is_file()


def test_tools_dir_follows_env_override(monkeypatch, bundled_tools_dir) -> None:
    monkeypatch.setenv("HA_UI_TOOLS_DIR", str(bundled_tools_dir))
    assert ha_tools.tools_dir() == bundled_tools_dir


def test_tools_dir_rejects_missing_env_override(monkeypatch,
                                                workspace_tmp) -> None:
    missing = workspace_tmp / "no-such-tools-dir"
    monkeypatch.setenv("HA_UI_TOOLS_DIR", str(missing))
    with pytest.raises(HaUiError) as excinfo:
        ha_tools.tools_dir()
    _assert_error(excinfo, errors.E_TOOL_MISSING, "HA_UI_TOOLS_DIR")


# --------------------------------------------------------------------------- #
# tool_path / tool_sha256 / toolset_fingerprint
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", PRESENT_TOOLS)
def test_tool_path_returns_existing_reviewed_module(name: str) -> None:
    path = ha_tools.tool_path(name)
    assert path.is_file(), "missing reviewed tool module: %s" % path
    assert path.parent == ha_tools.tools_dir()
    assert path.name == TOOL_FILES[name]


def test_tool_path_reports_friendly_export_missing_on_this_branch() -> None:
    # The friendly-export tool is not part of this branch (PR112 not merged), so
    # the loader must report it as missing instead of silently faking it.
    assert not (ha_tools.tools_dir() / TOOL_FILES["friendly"]).is_file()
    with pytest.raises(HaUiError) as excinfo:
        ha_tools.tool_path("friendly")
    _assert_error(excinfo, errors.E_TOOL_MISSING, "friendly")


@pytest.mark.parametrize("name", ["nope", "", "BATCH", "batch ", "../batch",
                                  None])
def test_tool_path_rejects_unknown_names(name) -> None:
    with pytest.raises(HaUiError) as excinfo:
        ha_tools.tool_path(name)
    _assert_error(excinfo, errors.E_TOOL_MISSING)


@pytest.mark.parametrize("name", PRESENT_TOOLS)
def test_tool_sha256_matches_file_bytes(name: str) -> None:
    path = ha_tools.tool_path(name)
    digest = ha_tools.tool_sha256(name)
    assert SHA256_HEX_RE.fullmatch(digest), "not a hex sha256: %r" % digest
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_toolset_fingerprint_covers_every_tool_slot() -> None:
    fingerprint = ha_tools.toolset_fingerprint()
    assert set(fingerprint) == set(TOOL_FILES)
    for name in PRESENT_TOOLS:
        digest = fingerprint[name]
        assert SHA256_HEX_RE.fullmatch(digest), (
            "%s fingerprint is not a 64-hex sha256: %r" % (name, digest))
        assert digest == ha_tools.tool_sha256(name)
    assert fingerprint["friendly"] == "missing", (
        "the absent friendly-export tool must be reported as 'missing'")


# --------------------------------------------------------------------------- #
# load_tool / cache
# --------------------------------------------------------------------------- #
def test_load_batch_module_exposes_reviewed_acl_gates() -> None:
    batch = ha_tools.load_tool("batch")
    for attribute in ("check_private_path", "check_local_boundary",
                      "check_directory", "main"):
        assert callable(getattr(batch, attribute)), (
            "batch module must expose callable %r" % attribute)
    assert batch.E_INSECURE_PERMISSIONS == "E_INSECURE_PERMISSIONS"
    # The private gates really work through the wrapper.
    assert ha_tools.batch_tool() is batch


def test_load_tool_is_cached_and_clear_cache_resets() -> None:
    first = ha_tools.load_tool("batch")
    assert ha_tools.load_tool("batch") is first
    assert "ha_ui_tool_batch" in sys.modules

    ha_tools.clear_cache()
    assert "ha_ui_tool_batch" not in sys.modules
    second = ha_tools.load_tool("batch")
    assert second is not first, "clear_cache must force a fresh module load"
    assert callable(second.check_private_path)


def test_load_tool_rejects_unknown_name() -> None:
    with pytest.raises(HaUiError) as excinfo:
        ha_tools.load_tool("nope")
    _assert_error(excinfo, errors.E_TOOL_MISSING, "nope")


# --------------------------------------------------------------------------- #
# run_tool / first_failure_code
# --------------------------------------------------------------------------- #
def test_run_tool_batch_rejects_bad_config_version_deterministically() -> None:
    result = ha_tools.run_tool("batch", list(BATCH_FAILURE_ARGV))
    assert isinstance(result, ToolResult)
    assert result.exit_code == 2, (
        "expected the reviewed tool's usage exit status 2, got %d (stderr=%r)"
        % (result.exit_code, result.stderr))
    code = ha_tools.first_failure_code(result)
    assert code in ("E_USAGE", "E_CONFIG_VERSION"), (
        "expected a fixed usage/config-version failure code, got %r" % code)
    assert result.stdout == "", (
        "a failing batch run must not print a success payload: %r"
        % result.stdout)
    combined = result.stdout + result.stderr
    assert "E_USAGE" in combined or "E_CONFIG_VERSION" in combined
    for secret in ("password", "sentinel", "private_key"):
        assert secret not in combined.casefold()


def test_run_tool_batch_with_no_arguments_fails_deterministically() -> None:
    result = ha_tools.run_tool("batch", [])
    assert result.exit_code == 2
    assert ha_tools.first_failure_code(result) == "E_USAGE"


def test_run_tool_rejects_unknown_tool_name() -> None:
    with pytest.raises(HaUiError) as excinfo:
        ha_tools.run_tool("nope", [])
    _assert_error(excinfo, errors.E_TOOL_MISSING, "nope")


@pytest.mark.parametrize("result,expected", [
    (ToolResult(exit_code=1, stdout="", stderr=""), "E_TOOL_FAILED"),
    (ToolResult(exit_code=2, stdout="",
                stderr="ha-batch: FAIL E_CONFIG_VERSION\n"),
     "E_CONFIG_VERSION"),
    (ToolResult(exit_code=1, stdout="note E_CHAIN_CHECK: failed", stderr=""),
     "E_CHAIN_CHECK"),
    (ToolResult(exit_code=1, stdout="e_usage lowercase", stderr=""),
     "E_TOOL_FAILED"),
    (ToolResult(exit_code=1, stdout="E_" + "A" * 60, stderr=""),
     "E_TOOL_FAILED"),
])
def test_first_failure_code_extracts_fixed_codes(result: ToolResult,
                                                 expected: str) -> None:
    assert ha_tools.first_failure_code(result) == expected


# --------------------------------------------------------------------------- #
# Real ACL gate integration through the wrapper
# --------------------------------------------------------------------------- #
def test_wrapper_acl_gates_accept_hardened_paths(private_workspace) -> None:
    from ha_ui.core import private_fs

    ha_tools.verify_private_dir(private_workspace, "test-workspace")
    target = private_workspace / "gate-check.bin"
    private_fs.secure_write_new(target, b"not-a-credential",
                                workspace=private_workspace)
    ha_tools.verify_private_file(target, "test-file")
