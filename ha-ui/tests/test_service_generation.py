"""Hermetic tests for ``GenerationService`` orchestration.

The service is the only layer that combines the two remote readers with the
local HA chain.  These tests inject a fake provider object (no SSH, no VPS) and
a real or spied :class:`GenerationPipeline`, so the assertions cover exactly
the orchestration contract: role/session wiring, pin cross-checks, stale-export
consent, selection validation, cancellation and the hand-off of the downloaded
canonical bytes into the real pipeline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ha_ui.core import errors
from ha_ui.core.chain import GenerationPipeline
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import ProbePolicy, SelectedClient
from ha_ui.core.service import GenerationService
from tests import fakes

POLICY = ProbePolicy(5, 2000)


@pytest.fixture()
def workspace(monkeypatch):
    ws = fakes.create_private_workspace("service", monkeypatch=monkeypatch)
    try:
        yield ws
    finally:
        fakes.remove_workspace(ws)


@pytest.fixture()
def batch():
    return fakes.synthetic_batch()


def make_service(workspace, providers, *, pipeline=None):
    factory = fakes.FakeProviderFactory(providers)
    service = GenerationService(workspace, provider_factory=factory,
                                pipeline=pipeline)
    return service, factory


def make_sessions():
    return {"A": object(), "B": object()}


# --------------------------------------------------------------------------- #
# Preview: both remote readers, pin cross-check and warnings.
# --------------------------------------------------------------------------- #
def test_preview_aggregates_both_servers(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    service, factory = make_service(workspace, providers)
    sessions = make_sessions()

    preview = service.preview(sessions)

    assert factory.calls == [("A", sessions["A"]), ("B", sessions["B"])]
    assert set(preview.servers) == {"A", "B"}
    assert preview.names == [item.name for item in batch.selected]
    assert preview.clients_a == providers["A"].records
    assert preview.clients_b == providers["B"].records
    assert preview.servers["A"].pins == providers["A"].pin
    assert preview.servers["B"].pins == providers["B"].pin
    assert preview.servers["A"].facts.okay is True
    assert preview.warnings == []
    for role in ("A", "B"):
        assert providers[role].calls == ["preflight", "list_clients",
                                         "read_pins"]


def test_preview_reports_near_expiry_and_single_ended_clients(workspace,
                                                              batch):
    providers = fakes.providers_for_batch(batch)
    now = datetime.now(timezone.utc)
    providers["A"].pin = fakes.cert_pin(
        fakes.PIN_A, not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=10))
    providers["B"].pin = fakes.cert_pin(
        fakes.PIN_B, not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=10))
    providers["B"].records.pop(batch.selected[1].name)
    service, _ = make_service(workspace, providers)

    preview = service.preview(make_sessions())

    assert len(preview.warnings) == 2
    assert any("HY2" in warning for warning in preview.warnings)
    assert any("客户端" in warning for warning in preview.warnings)


def test_preview_refuses_reused_pins(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    providers["B"].pin = providers["A"].pin
    service, _ = make_service(workspace, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.preview(make_sessions())
    assert excinfo.value.code == errors.E_PIN_REUSED


def test_preview_refuses_a_provider_pin_mapping_with_both_roles(workspace,
                                                                batch):
    providers = fakes.providers_for_batch(batch)
    providers["A"].pins_reply = {
        "A": providers["A"].pin, "B": providers["B"].pin}
    service, _ = make_service(workspace, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.preview(make_sessions())
    assert excinfo.value.code == errors.E_REMOTE_PIN
    assert excinfo.value.detail == "A"


def test_preview_remote_error_aborts_before_second_server(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    providers["A"].errors_by_method = {"preflight": errors.E_REMOTE_NOT_ROOT}
    service, _ = make_service(workspace, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.preview(make_sessions())
    assert excinfo.value.code == errors.E_REMOTE_NOT_ROOT
    assert providers["B"].calls == []


# --------------------------------------------------------------------------- #
# Generate: fresh download -> real local chain.
# --------------------------------------------------------------------------- #
def test_generate_fresh_exports_runs_the_real_chain(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    service, factory = make_service(
        workspace, providers, pipeline=GenerationPipeline(workspace))
    sessions = make_sessions()

    result = service.generate(sessions=sessions, selected=batch.selected,
                              policy=POLICY, allow_cli=False)

    assert result.ok is True
    assert [entry.filename for entry in result.files] == (
        batch.expected_filenames())
    assert factory.calls == [("A", sessions["A"]), ("B", sessions["B"])]
    names = [item.name for item in batch.selected]
    for role in ("A", "B"):
        # Fresh derived files: no server-side CLI run, plain reads only.
        assert providers[role].generate_requests == []
        assert providers[role].export_requests == [names]
    receipt = workspace / "runs" / result.run_id / "run.json"
    assert receipt.is_file()
    import json
    document = json.loads(receipt.read_text(encoding="utf-8"))
    assert [(entry["name"], entry["group"])
            for entry in document["clients"]] == [
                (item.name, item.group) for item in batch.selected]


# --------------------------------------------------------------------------- #
# Generate: stale exports require explicit consent and use the CLI path.
# --------------------------------------------------------------------------- #
def test_generate_stale_exports_without_consent_fails_before_any_pipeline(
        workspace, batch):
    providers = fakes.providers_for_batch(
        batch, derived={batch.selected[0].name: False})
    spy = fakes.PipelineSpy()
    service, _ = make_service(workspace, providers, pipeline=spy)

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=batch.selected,
                         policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_REMOTE_EXPORT
    assert excinfo.value.detail == "cli-consent"
    assert spy.calls == []
    assert not (workspace / "runs").exists()
    for role in ("A", "B"):
        assert providers[role].generate_requests == []
        assert providers[role].export_requests == []


def test_generate_stale_exports_with_consent_regenerates_then_delivers(
        workspace, batch):
    stale_name = batch.selected[0].name
    fresh_name = batch.selected[1].name
    providers = fakes.providers_for_batch(
        batch, derived={stale_name: False})
    service, _ = make_service(
        workspace, providers, pipeline=GenerationPipeline(workspace))

    result = service.generate(sessions=make_sessions(),
                              selected=batch.selected, policy=POLICY,
                              allow_cli=True)

    assert result.ok is True
    assert [entry.filename for entry in result.files] == (
        batch.expected_filenames())
    for role in ("A", "B"):
        assert providers[role].generate_requests == [((stale_name,), True)]
        assert providers[role].export_requests == [[fresh_name]]


# --------------------------------------------------------------------------- #
# Generate: selection / pin / session validation happens before any tool work.
# --------------------------------------------------------------------------- #
def test_generate_duplicate_selection_is_refused(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    spy = fakes.PipelineSpy()
    service, _ = make_service(workspace, providers, pipeline=spy)
    name = batch.selected[0].name
    selected = [SelectedClient(name, "A-first"),
                SelectedClient(name, "B-first")]

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=selected,
                         policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_CONFIG
    assert excinfo.value.detail == "duplicate-client"
    assert spy.calls == []
    for role in ("A", "B"):
        assert providers[role].export_requests == []


def test_generate_single_ended_client_is_refused(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    providers["B"].records.pop(batch.selected[1].name)
    service, _ = make_service(workspace, providers, pipeline=fakes.PipelineSpy())

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=batch.selected,
                         policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_CLIENT_MISSING
    assert excinfo.value.detail == "B"


def test_generate_incomplete_protocol_client_is_refused(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    name = batch.selected[1].name
    providers["B"].records[name] = fakes.client_record(
        name, reality=False, derived=True)
    service, _ = make_service(workspace, providers, pipeline=fakes.PipelineSpy())

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=batch.selected,
                         policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_CLIENT_INCOMPLETE
    assert excinfo.value.detail == "B"


def test_generate_reused_pins_are_refused_before_exports(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    providers["B"].pin = providers["A"].pin
    spy = fakes.PipelineSpy()
    service, _ = make_service(workspace, providers, pipeline=spy)

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=batch.selected,
                         policy=POLICY, allow_cli=False)

    assert excinfo.value.code == errors.E_PIN_REUSED
    assert spy.calls == []
    for role in ("A", "B"):
        assert providers[role].export_requests == []


def test_generate_requires_both_sessions(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    factory = fakes.FakeProviderFactory(providers)
    service = GenerationService(workspace, provider_factory=factory)
    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions={"A": object()}, selected=batch.selected,
                         policy=POLICY, allow_cli=False)
    assert excinfo.value.code == errors.E_CONFIG
    assert excinfo.value.detail == "sessions"
    assert factory.calls == []


def test_generate_cancelled_before_the_pipeline_starts(workspace, batch):
    providers = fakes.providers_for_batch(batch)
    spy = fakes.PipelineSpy()
    service, _ = make_service(workspace, providers, pipeline=spy)

    with pytest.raises(HaUiError) as excinfo:
        service.generate(sessions=make_sessions(), selected=batch.selected,
                         policy=POLICY, allow_cli=False,
                         cancel=lambda: True)

    assert excinfo.value.code == errors.E_CANCELLED
    assert spy.calls == []
    assert not (workspace / "runs").exists()
