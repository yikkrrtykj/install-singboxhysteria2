"""Failure-injection regressions for the remote pointer/CLI menu generation.

The real ``miaomiao`` wrapper executes ``install.sh`` and can fail in ways that a
plain "HAUI_MENU_END" marker cannot prove: non-zero menu exits, a broken pipe,
a timeout, a renumbered menu, a partial per-client generation, or a stale
derived file that is re-read as if it were newly generated. These tests force
each of those states through the scripted SSH session and require a fail-closed
``E_REMOTE_MENU`` before any download, plus targeted hardening checks.
"""

from __future__ import annotations

import pytest

from ha_ui.core import errors, remote
from ha_ui.core.errors import HaUiError
from tests import fakes
from tests.fakes import ClientSpec, DerivedState, FakeSession


def make_provider(**kwargs):
    session = FakeSession("A", **kwargs)
    return remote.RemoteProvider("A", session), session


def stale_clients(*names):
    return [ClientSpec(name, derived=DerivedState(fresh=False)) for name in names]


def exports_for(*names):
    return {name: ("canonical-A-" + name).encode() for name in names}


def generate_stale(provider, names, **kwargs):
    return provider.generate_exports(list(names), allow_cli=True, **kwargs)


# --------------------------------------------------------------------------- #
# Pre-execution installer verification (menu version drift) and fetch failures.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("reason", ["fetch", "temp", "menu-drift"])
def test_precheck_failure_aborts_before_download(reason):
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_fail=reason)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "precheck-" + reason
    assert session.downloads == []


def test_menu_command_verifies_installer_before_executing():
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"))
    generate_stale(provider, ["stale"])
    menu_commands = [c for c in session.commands if "HAUI_MENU_END" in c]
    assert len(menu_commands) == 1
    command = menu_commands[0]
    assert "install-singboxhysteria2/main/install.sh" in command
    assert "10. 客户端管理" in command
    assert "client_management_menu" in command
    assert "3) generate_client_configuration_interactive" in command
    assert "timeout -k 10 420 bash" in command
    assert "PIPESTATUS" in command
    assert "HAUI_MENU_RC=" in command
    assert "| miaomiao" not in command
    # No unvalidated operator text is interpolated: only canonical names.
    assert "event-ob01" not in command


# --------------------------------------------------------------------------- #
# Exit statuses / timeout / pipeline failure.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kwargs, detail", [
    ({"menu_exit": 1}, "exit-status"),
    ({"menu_exit": 2}, "exit-status"),
    ({"menu_exit": 124}, "timeout"),
    ({"menu_pipe_exit": 127}, "exit-status"),
    ({"menu_printf_exit": 1}, "exit-status"),
])
def test_nonzero_menu_or_pipeline_status_aborts(kwargs, detail):
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"), **kwargs)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == detail
    assert session.downloads == []


def test_missing_end_marker_is_refused():
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_end_marker=False)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "no-end"
    assert session.downloads == []


def test_missing_exit_status_marker_is_refused():
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_rc_marker=False)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "no-exit-status"
    assert session.downloads == []


def test_ssh_level_timeout_is_mapped_to_menu_timeout(monkeypatch):
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"))

    def timeout_exec(command, **_kwargs):
        if "HAUI_MENU_END" in command:
            raise HaUiError(errors.E_SSH_TIMEOUT, detail="channel")
        return original_exec(command, **_kwargs)

    original_exec = session.exec
    monkeypatch.setattr(session, "exec", timeout_exec)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "timeout"
    assert session.downloads == []


# --------------------------------------------------------------------------- #
# Transcript / partial generation.
# --------------------------------------------------------------------------- #
def test_missing_menu_transcript_markers_is_menu_drift():
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_transcript_markers=False)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "menu-drift"
    assert session.downloads == []


def test_partial_generation_is_refused_for_the_missing_client():
    names = ["event-ob01", "event-ob02"]
    provider, session = make_provider(clients=stale_clients(*names),
                                      exports=exports_for(*names),
                                      menu_success="first")
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, names)
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "partial"
    assert session.downloads == []


def test_success_banner_without_a_rewrite_is_not_trusted():
    # The existing stale file keeps its timestamp/hash: a failed write must not
    # be mistaken for a freshly generated export even though the menu claims
    # success for it.
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_side_effect=False)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "not-regenerated"
    assert session.downloads == []


@pytest.mark.parametrize("corruption", ["mode", "uid", "size"])
def test_non_private_or_empty_derived_file_is_refused(corruption):
    provider, session = make_provider(clients=stale_clients("stale"),
                                      exports=exports_for("stale"),
                                      menu_corrupt=corruption)
    with pytest.raises(HaUiError) as excinfo:
        generate_stale(provider, ["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "provenance"
    assert session.downloads == []


def test_pre_existing_fresh_file_is_still_refused_when_menu_fails():
    # A fresh-looking file already on disk must never be treated as "generated"
    # after a non-zero menu exit. Exercise the generation boundary directly so a
    # fresh file cannot short-circuit the staleness detection.
    clients = [ClientSpec("stale", derived=DerivedState())]
    provider, session = make_provider(clients=clients,
                                      exports=exports_for("stale"),
                                      menu_exit=1)
    with pytest.raises(HaUiError) as excinfo:
        provider._run_cli_generation(["stale"])
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "exit-status"
    assert session.downloads == []


# --------------------------------------------------------------------------- #
# Preflight additions required by the verified-fetch path.
# --------------------------------------------------------------------------- #
def test_preflight_requires_curl_and_timeout():
    for field, detail in (("curl_present", "curl"),
                          ("timeout_present", "timeout")):
        facts = fakes.VpsFacts()
        setattr(facts, field, False)
        provider, _ = make_provider(facts=facts)
        with pytest.raises(HaUiError) as excinfo:
            provider.preflight()
        assert excinfo.value.code == errors.E_REMOTE_PREFLIGHT
        assert excinfo.value.detail == detail


# --------------------------------------------------------------------------- #
# Identity parser itself: malformed/absent lines fail closed later, never guess.
# --------------------------------------------------------------------------- #
def test_identity_parser_rejects_malformed_lines_and_keeps_missing_as_none():
    output = (
        "regular file|/root/sbox/clients/good/mihomo.yaml|600|0|2048|"
        "1763600001|2026-11-21 17:00:00.000000002 +0000\n"
        "not a stat line\n"
        "regular file|/root/sbox/clients/bad/mihomo.yaml|600|0|2048|oops|"
        "2026-11-21 17:00:00.000000002 +0000\n"
        "HAUI_STAT_END\n"
        "%s  /root/sbox/clients/good/mihomo.yaml\n"
        "not-a-hash  /root/sbox/clients/good/mihomo.yaml\n" % ("ab" * 32)
    )
    parsed = remote._parse_derived_identities(
        output, ["good", "bad", "missing"])
    assert parsed["good"].sha256 == "ab" * 32
    assert parsed["good"].regular is True
    assert parsed["bad"] is None
    assert parsed["missing"] is None
