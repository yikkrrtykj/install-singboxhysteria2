"""Hermetic contracts for dual-VPS client creation (HA-UI 0.2.0).

The real :class:`RemoteProvider` is driven against the scripted
:class:`~tests.fakes.FakeSession`; no SSH, VPS, credential manager or network is
used. These tests pin the properties the operator depends on:

* the write is only the reviewed installer's canonical menu 10→2 path, bounded
  to a canonical name, with the immutable installer/lib trust anchor;
* a clean exit code is never accepted as proof: the success transcript and a
  fresh live inventory are both required;
* the two servers are independent writes, so a partial result is returned
  explicitly and a successfully created side is never deleted;
* one side existing defaults to STOP; an explicitly authorised repair only
  creates the missing side and never overwrites the existing credential;
* no generated UUID/password can appear in the result, command or UI data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ha_ui.core import errors, remote
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import CreationSideResult
from ha_ui.core.service import GenerationService
from tests import fakes
from tests.fakes import ClientSpec, DerivedState, FakeSession


def provider_for(role: str = "A", **kwargs):
    session = FakeSession(role, **kwargs)
    return remote.RemoteProvider(role, session), session


# --------------------------------------------------------------------------- #
# Remote provider: canonical pinned add path + live proof
# --------------------------------------------------------------------------- #
def test_create_client_runs_the_pinned_add_menu_and_proves_live_state():
    provider, session = provider_for()
    provider.create_client("event-vmix01", confirmed=True)

    assert session.create_invoked is True
    assert any("HAUI_MENU_END" in command for command in session.commands)
    command = [c for c in session.commands if "HAUI_MENU_END" in c][0]
    assert remote.INSTALLER_REVIEWED_COMMIT in command
    assert remote.INSTALLER_SHA256 in command
    assert remote.CLIENT_MANAGEMENT_SHA256 in command
    assert "/main/" not in command
    assert "10\n2\nevent-vmix01\n0\n" in command
    assert "2) add_client_interactive" in command
    assert "FAIL=menu-drift" in command
    # The command never carries generated credentials, only the validated name.
    assert "uuid" not in command.casefold()
    assert "password" not in command.casefold()
    record = provider.list_clients()["event-vmix01"]
    assert record.complete is True
    assert record.derived_export_present is False


def test_create_client_refuses_without_explicit_confirmation():
    provider, session = provider_for()
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=False)
    assert excinfo.value.code == errors.E_USAGE
    assert excinfo.value.detail == "create-consent"
    assert session.commands == []


@pytest.mark.parametrize("name", ["legacy", "LEGACY", "../x", "bad name", ""])
def test_create_client_refuses_reserved_or_noncanonical_names(name):
    provider, session = provider_for()
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client(name, confirmed=True)
    assert excinfo.value.code == errors.E_USAGE
    assert excinfo.value.detail in ("reserved-name", "client-name")
    assert session.commands == []


def test_create_client_stops_before_write_when_name_already_exists():
    provider, session = provider_for(
        clients=[ClientSpec("event-vmix01", derived=DerivedState())])
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CLIENT_EXISTS
    assert session.create_invoked is False


def test_success_transcript_without_a_live_client_is_not_accepted():
    # The server returned the canonical success line but the live inventory does
    # not contain the client: never claim success.
    provider, session = provider_for(add_side_effect=False)
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_REMOTE_VERIFY
    assert excinfo.value.detail == "missing"
    assert session.created_credentials


def test_incomplete_live_client_after_create_is_not_accepted(monkeypatch):
    provider, session = provider_for()

    original = session._list

    def incomplete_list():
        rc, out, err = original()
        out = out.replace(
            '{"name":"event-vmix01","cred":true}', '{"name":"event-vmix01","cred":false}'
        )
        return rc, out, err

    monkeypatch.setattr(session, "_list", incomplete_list)
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_REMOTE_VERIFY


@pytest.mark.parametrize("kwargs", [
    {"add_timeout": True},
    {"add_raise_timeout": True},
])
def test_timeout_after_the_write_boundary_is_uncertain(kwargs):
    provider, _session = provider_for(**kwargs)
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CREATE_UNCERTAIN
    assert excinfo.value.detail == "timeout"


def test_lock_failure_is_a_clean_write_refusal():
    provider, _session = provider_for(add_fail="lock")
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_REMOTE_CREATE
    assert excinfo.value.detail == "lock"


def test_reload_failure_and_rollback_is_a_clean_write_refusal():
    provider, _session = provider_for(add_fail="rollback")
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_REMOTE_CREATE
    assert excinfo.value.detail == "rollback"


def test_a_racing_existing_client_is_not_overwritten():
    # Present in the menu's live view but absent from the earlier list: the
    # server-side canonical add refuses duplicates; the GUI maps that to STOP.
    provider, _session = provider_for(add_fail="exists")
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CLIENT_EXISTS


def test_tampered_installer_is_untrusted_and_never_executed():
    provider, session = provider_for(menu_fail="installer-hash")
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_INSTALLER_UNTRUSTED
    assert excinfo.value.detail == "installer-hash"
    assert session.created_credentials == {}


def test_live_read_failure_after_write_is_uncertain_not_success(monkeypatch):
    provider, _session = provider_for()

    original = provider.list_clients
    calls = {"count": 0}

    def flaky():
        calls["count"] += 1
        if calls["count"] >= 2:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="management-active")
        return original()

    monkeypatch.setattr(provider, "list_clients", flaky)
    with pytest.raises(HaUiError) as excinfo:
        provider.create_client("event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_REMOTE_VERIFY
    assert excinfo.value.detail == "live-read"


def test_add_command_requires_the_add_menu_markers_before_execution():
    command = remote._add_client_command("event-vmix01")
    for marker in remote.MENU_ADD_MARKERS:
        assert marker in command
    # The generate markers remain part of the same reviewed installer contract.
    for marker in remote.MENU_SCRIPT_MARKERS:
        assert marker in command


# --------------------------------------------------------------------------- #
# GenerationService: sequential, non-atomic per-side orchestration
# --------------------------------------------------------------------------- #
def make_service(workspace: Path, providers):
    factory = fakes.FakeProviderFactory(providers)
    return GenerationService(workspace, provider_factory=factory,
                             pipeline=fakes.PipelineSpy()), factory


def ready_providers():
    return {
        "A": fakes.FakeProvider(role="A"),
        "B": fakes.FakeProvider(role="B", pin=fakes.cert_pin(fakes.PIN_B)),
    }


def test_service_creates_both_sides_and_reports_complete(workspace_tmp):
    providers = ready_providers()
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    assert result.complete is True
    assert result.partial is False
    assert result.ok is True
    assert result.created_roles == ("A", "B")
    assert result.repaired_existing == ()
    assert [p.create_requests for p in providers.values()] == [
        [("event-vmix01", True)], [("event-vmix01", True)]]
    # The final live re-read happened on both sides.
    assert providers["A"].calls.count("list_clients") == 2
    assert providers["B"].calls.count("list_clients") == 2


def test_service_a_failure_does_not_attempt_b(workspace_tmp):
    providers = ready_providers()
    providers["A"].errors_by_method = {"create_client": errors.E_REMOTE_CREATE}
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    assert result.complete is False
    assert result.partial is False
    assert result.side("A").status == "failed"
    assert result.side("B").status == "skipped"
    assert providers["B"].create_requests == []


def test_service_a_success_b_failure_is_partial_and_never_rolls_back_a(
        workspace_tmp):
    providers = ready_providers()
    providers["B"].errors_by_method = {"create_client": errors.E_REMOTE_CREATE}
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    assert result.side("A").status == "created"
    assert result.side("B").status == "failed"
    assert result.partial is True
    assert result.ok is False
    # A remains present: no compensating delete call exists in the interface.
    assert "event-vmix01" in providers["A"].records
    assert providers["B"].create_requests == [("event-vmix01", True)]


def test_service_a_success_b_uncertain_is_partial(workspace_tmp):
    providers = ready_providers()
    providers["B"].errors_by_method = {"create_client": errors.E_SSH_TIMEOUT}
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    assert result.side("A").status == "created"
    assert result.side("B").status == "uncertain"
    assert result.partial is True


def test_service_post_write_verification_failure_is_not_success(workspace_tmp):
    providers = ready_providers()
    providers["A"].create_effect = False  # write reports success, live read misses it
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    assert result.side("A").status == "failed"
    assert result.side("A").code == errors.E_REMOTE_VERIFY
    assert result.ok is False


def test_service_both_existing_stops_before_any_write(workspace_tmp):
    providers = ready_providers()
    for role in ("A", "B"):
        providers[role].records["event-vmix01"] = fakes.client_record(
            "event-vmix01")
    service, _ = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CLIENT_EXISTS
    assert all(p.create_requests == [] for p in providers.values())


def test_service_one_side_existing_defaults_to_stop(workspace_tmp):
    providers = ready_providers()
    providers["A"].records["event-vmix01"] = fakes.client_record("event-vmix01")
    service, _ = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CLIENT_PARTIAL_EXISTS
    assert excinfo.value.detail == "A"
    assert providers["B"].create_requests == []


def test_service_explicit_repair_only_creates_the_missing_side(workspace_tmp):
    providers = ready_providers()
    providers["A"].records["event-vmix01"] = fakes.client_record("event-vmix01")
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True,
                                   allow_partial_repair=True)
    assert result.complete is True
    assert result.repaired_existing == ("A",)
    assert result.side("A").status == "existing"
    assert result.side("B").status == "created"
    assert providers["A"].create_requests == []
    assert providers["B"].create_requests == [("event-vmix01", True)]


def test_service_incomplete_existing_side_blocks_repair(workspace_tmp):
    providers = ready_providers()
    providers["A"].records["event-vmix01"] = fakes.client_record(
        "event-vmix01", hy2=False)
    service, _ = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=True,
                              allow_partial_repair=True)
    assert excinfo.value.code == errors.E_CLIENT_INCOMPLETE
    assert excinfo.value.detail == "A"
    assert providers["B"].create_requests == []


def test_service_reused_pins_block_creation(workspace_tmp):
    providers = ready_providers()
    providers["B"].pin = providers["A"].pin
    service, _ = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_PIN_REUSED
    assert all(p.create_requests == [] for p in providers.values())


def test_service_requires_confirmation_and_valid_name(workspace_tmp):
    providers = ready_providers()
    service, _ = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=False)
    assert excinfo.value.code == errors.E_USAGE
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="legacy", confirmed=True)
    assert excinfo.value.code == errors.E_USAGE
    assert excinfo.value.detail == "reserved-name"


def test_creation_result_carries_no_credential_material(workspace_tmp):
    providers = ready_providers()
    service, _ = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True)
    text = repr(result)
    assert "event-vmix01" in text
    for sentinel in (fakes.uuid_for("A", 101), fakes.password_for("A", 101),
                     fakes.uuid_for("B", 101), fakes.password_for("B", 101)):
        assert sentinel not in text


def test_creation_side_result_rejects_unknown_status():
    with pytest.raises(ValueError):
        CreationSideResult(role="A", status="maybe")


# --------------------------------------------------------------------------- #
# Real FakeSession end-to-end through GenerationService
# --------------------------------------------------------------------------- #
def test_end_to_end_creation_generates_independent_credentials(workspace_tmp):
    sessions = {"A": FakeSession("A"), "B": FakeSession("B")}

    def factory(role, session):
        return remote.RemoteProvider(role, session)

    service = GenerationService(workspace_tmp, provider_factory=factory,
                                pipeline=fakes.PipelineSpy())
    result = service.create_client(sessions=sessions, name="event-vmix01",
                                   confirmed=True)
    assert result.complete is True
    assert sessions["A"].create_invoked and sessions["B"].create_invoked
    creds_a = sessions["A"].created_credentials["event-vmix01"]
    creds_b = sessions["B"].created_credentials["event-vmix01"]
    assert creds_a[0] != creds_b[0]
    assert creds_a[1] != creds_b[1]
    rendered = repr(result)
    for sentinel in (*creds_a, *creds_b):
        assert sentinel not in rendered
