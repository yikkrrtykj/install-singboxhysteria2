"""Hermetic failure-path tests for the local HA chain.

Stage execution is injected by monkeypatching ``ha_tools.run_tool`` (no VPS,
no network, no real tools failing for real); everything before and after the
stages is the real chain implementation.  The module fixture first creates one
*successful* run so every failure test can prove the previous delivery is never
clobbered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ha_ui.core import errors
from ha_ui.core.chain import GenerationPipeline
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import SelectedClient
from ha_ui.core.service import GenerationService
from tests import fakes

POLICY = fakes.TEST_POLICY
BASELINE_RUN = "failbase-run-1"
BASELINE_VERSION = "failbase-20261121-r1"


@pytest.fixture(scope="module")
def workspace():
    with fakes.workspace_environment("failures") as ws:
        yield ws


@pytest.fixture(scope="module")
def baseline(workspace):
    batch = fakes.synthetic_batch()
    result = GenerationPipeline(workspace).generate(
        run_id=BASELINE_RUN,
        config_version=BASELINE_VERSION,
        policy=POLICY,
        selected=batch.selected,
        exports=batch.exports,
        pins=batch.run_pins(),
    )
    assert result.ok is True
    return fakes.ChainRun(
        workspace=workspace,
        batch=batch,
        result=result,
        run_id=BASELINE_RUN,
        artifacts=fakes.snapshot_files(workspace / "runs" / BASELINE_RUN),
    )


def generate(baseline: fakes.ChainRun, run_id: str, **overrides):
    """Run the real pipeline for a new attempt, overriding fixture inputs."""
    arguments = dict(
        run_id=run_id,
        config_version="fail-%s-r1" % run_id,
        policy=POLICY,
        selected=baseline.batch.selected,
        exports=baseline.batch.exports,
        pins=baseline.batch.run_pins(),
    )
    arguments.update(overrides)
    return GenerationPipeline(baseline.workspace).generate(**arguments)


def assert_run_cleaned(baseline: fakes.ChainRun, run_id: str) -> None:
    assert not (baseline.workspace / "runs" / run_id).exists(), (
        "failed run directory was not cleaned up: %s" % run_id)


# --------------------------------------------------------------------------- #
# Stage exit codes map to the fixed chain error taxonomy.
# --------------------------------------------------------------------------- #
def test_stage_failure_maps_to_chain_stage_and_cleans_up(baseline, monkeypatch):
    fakes.fail_tool(monkeypatch, "batch", "ha-batch: FAIL E_INVENTORY\n")

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-stage-1")

    error = excinfo.value
    assert error.code == errors.E_CHAIN_STAGE
    assert "ha02-generate" in error.detail
    assert "E_INVENTORY" in error.detail
    assert_run_cleaned(baseline, "fail-stage-1")
    baseline.assert_artifacts_untouched()


def test_check_stage_failure_maps_to_chain_check(baseline, monkeypatch):
    fakes.fail_tool(monkeypatch, "profile",
                    "ha-profile: FAIL E_DELIVERY_HASH\n",
                    when=lambda argv: "--check" in argv)

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-check-1")

    error = excinfo.value
    assert error.code == errors.E_CHAIN_CHECK
    assert "ha03-check" in error.detail
    assert "E_DELIVERY_HASH" in error.detail
    assert_run_cleaned(baseline, "fail-check-1")
    baseline.assert_artifacts_untouched()


def test_friendly_export_failure_is_a_stage_failure_and_not_trusted(
        baseline, monkeypatch):
    fakes.fail_tool(monkeypatch, "friendly",
                    "friendly-export: FAIL E_OUTPUT_EXISTS\n")

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-friendly-1")

    error = excinfo.value
    # friendly-export is a generation stage, not a ``--check`` stage.
    assert error.code == errors.E_CHAIN_STAGE
    assert "friendly" in error.detail
    assert "E_OUTPUT_EXISTS" in error.detail
    assert_run_cleaned(baseline, "fail-friendly-1")
    # No partial delivery was trusted or published anywhere.
    assert not list((baseline.workspace / "runs").glob(
        "fail-friendly-1/download/*.yaml"))
    baseline.assert_artifacts_untouched()


def test_cleanup_failed_false_keeps_the_run_dir_but_publishes_nothing(
        baseline, monkeypatch):
    fakes.fail_tool(monkeypatch, "batch", "ha-batch: FAIL E_INVENTORY\n")

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-keep-1", cleanup_failed=False)

    assert excinfo.value.code == errors.E_CHAIN_STAGE
    run_root = baseline.workspace / "runs" / "fail-keep-1"
    assert run_root.is_dir(), "diagnostic run dir must be kept"
    # Staging/diagnostics may remain, but no delivered ``*.yaml`` is trusted.
    download = run_root / "download"
    assert not list(download.glob("*.yaml"))
    assert (run_root / "pins.json").is_file()
    baseline.assert_artifacts_untouched()


# --------------------------------------------------------------------------- #
# Cancellation: fixed E_CANCELLED, no delivery, failed run dir cleaned.
# --------------------------------------------------------------------------- #
def test_cancellation_before_any_stage(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-cancel-early", cancel=lambda: True)

    assert excinfo.value.code == errors.E_CANCELLED
    assert calls == []
    assert_run_cleaned(baseline, "fail-cancel-early")
    baseline.assert_artifacts_untouched()


def test_cancellation_before_friendly_export_publishes_nothing(baseline):
    seen: list[str] = []

    def progress(stage: str) -> None:
        seen.append(stage)

    def cancel() -> bool:
        return "stage:friendly" in seen

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-cancel-late", progress=progress,
                 cancel=cancel)

    assert excinfo.value.code == errors.E_CANCELLED
    # The HA stages ran (cancellation is honoured between stages) but no
    # A-first/B-first file exists anywhere: the whole run dir was removed.
    assert "stage:ha02" in seen and "stage:friendly" in seen
    assert_run_cleaned(baseline, "fail-cancel-late")
    baseline.assert_artifacts_untouched()


# --------------------------------------------------------------------------- #
# Pre-tool validation of tampered exports/selection/pins.
# --------------------------------------------------------------------------- #
def copy_exports(batch: fakes.SyntheticBatch):
    return {role: dict(files) for role, files in batch.exports.items()}


def test_crlf_export_bytes_are_rejected_before_any_tool(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    exports = copy_exports(baseline.batch)
    name = baseline.batch.selected[0].name
    exports["A"][name] = exports["A"][name].replace(b"\n", b"\r\n")

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-crlf-1", exports=exports)

    assert excinfo.value.code == errors.E_REMOTE_FILE
    assert excinfo.value.detail == "A"
    assert calls == []
    assert_run_cleaned(baseline, "fail-crlf-1")
    baseline.assert_artifacts_untouched()


def test_non_canonical_export_bytes_are_rejected_before_any_tool(
        baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    exports = copy_exports(baseline.batch)
    name = baseline.batch.selected[0].name
    exports["A"][name] = exports["A"][name].replace(
        b"  - name: Reality", b"  - name: Tampered")

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-canonical-1", exports=exports)

    assert excinfo.value.code == errors.E_CLIENT_INCOMPLETE
    assert excinfo.value.detail == "A"
    assert calls == []
    assert_run_cleaned(baseline, "fail-canonical-1")


def test_shared_a_b_credential_is_rejected_before_any_tool(
        baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    batch = fakes.synthetic_batch(shared_credentials=True)

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-creds-1", selected=batch.selected,
                 exports=batch.exports)

    assert excinfo.value.code == errors.E_CREDENTIAL_REUSE
    assert excinfo.value.detail == batch.selected[0].name
    assert calls == []
    assert_run_cleaned(baseline, "fail-creds-1")
    baseline.assert_artifacts_untouched()


def test_missing_export_is_rejected_before_any_tool(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    exports = copy_exports(baseline.batch)
    missing = baseline.batch.selected[1].name
    del exports["B"][missing]

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-missing-1", exports=exports)

    assert excinfo.value.code == errors.E_CLIENT_MISSING
    assert excinfo.value.detail == "B"
    assert calls == []
    assert_run_cleaned(baseline, "fail-missing-1")


def test_pipeline_refuses_reused_pins_before_any_tool(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    pinned = {"A": fakes.cert_pin(fakes.PIN_A),
              "B": fakes.cert_pin(fakes.PIN_A)}

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-pin-reuse-1", pins=pinned)

    assert excinfo.value.code == errors.E_PIN_REUSED
    assert calls == []
    assert_run_cleaned(baseline, "fail-pin-reuse-1")
    baseline.assert_artifacts_untouched()


def test_pipeline_refuses_missing_pins_before_any_tool(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    for run_id, pinned in (
            ("fail-pin-missing-1", {"A": fakes.cert_pin(fakes.PIN_A)}),
            ("fail-pin-missing-2", {})):
        with pytest.raises(HaUiError) as excinfo:
            generate(baseline, run_id, pins=pinned)
        assert excinfo.value.code == errors.E_PIN_FORMAT
        assert excinfo.value.detail == "servers"
        assert_run_cleaned(baseline, run_id)
    assert calls == []


def test_pipeline_refuses_expired_pins_before_any_tool(baseline, monkeypatch):
    calls = fakes.recording_tools(monkeypatch)
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    expired = {
        "A": fakes.cert_pin(fakes.PIN_A,
                            now - timedelta(days=30), now - timedelta(days=1)),
        "B": fakes.cert_pin(fakes.PIN_B,
                            now - timedelta(days=30), now - timedelta(days=1)),
    }

    with pytest.raises(HaUiError) as excinfo:
        generate(baseline, "fail-pin-expired-1", pins=expired)

    assert excinfo.value.code == errors.E_PIN_EXPIRED
    assert calls == []
    assert_run_cleaned(baseline, "fail-pin-expired-1")


# --------------------------------------------------------------------------- #
# Service-boundary refusals that must happen before the chain (issue #110).
# --------------------------------------------------------------------------- #
def _service_with_spy(baseline: fakes.ChainRun):
    providers = fakes.providers_for_batch(baseline.batch)
    spy = fakes.PipelineSpy()
    service = GenerationService(
        baseline.workspace,
        provider_factory=fakes.FakeProviderFactory(providers),
        pipeline=spy,
    )
    return service, providers, spy


def test_service_refuses_duplicate_selection_before_the_chain(baseline):
    service, providers, spy = _service_with_spy(baseline)
    name = baseline.batch.selected[0].name
    selected = [SelectedClient(name, "A-first"),
                SelectedClient(name, "B-first")]

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions={"A": object(), "B": object()},
                         selected=selected, policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_CONFIG
    assert excinfo.value.detail == "duplicate-client"
    assert spy.calls == []
    for role in ("A", "B"):
        assert providers[role].export_requests == []
        assert providers[role].generate_requests == []


def test_service_refuses_reused_pins_before_the_chain(baseline):
    service, providers, spy = _service_with_spy(baseline)
    providers["B"].pin = providers["A"].pin

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions={"A": object(), "B": object()},
                         selected=baseline.batch.selected, policy=POLICY,
                         allow_cli=False)

    assert excinfo.value.code == errors.E_PIN_REUSED
    assert spy.calls == []
    for role in ("A", "B"):
        assert providers[role].export_requests == []
