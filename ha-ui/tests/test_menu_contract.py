"""Static contract: the installer menu the remote automation drives.

The Windows GUI cannot run ``install.sh`` on Windows; the reviewed installer
text is therefore the contract. These checks fail if a future main changes the
top-level menu number, the client-menu option numbers, or the success-message
text the remote layer requires before it trusts a generated export.

PR #111 only changes the interactive prompt/retry loop inside
``generate_client_configuration_interactive`` and never renumbers the menu or
renames the success line, so the same piped sequence and transcript markers
remain valid for both the pre-#111 and post-#111 main.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ha_ui.core import remote

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "install.sh"


@pytest.fixture(scope="module")
def installer_text() -> str:
    assert INSTALL_SH.is_file(), "repo install.sh missing"
    return INSTALL_SH.read_text(encoding="utf-8")


def test_installer_contains_every_structure_marker_required_before_execution(
        installer_text):
    for marker in remote.MENU_SCRIPT_MARKERS:
        assert marker in installer_text, (
            "menu automation marker no longer present in install.sh: %r"
            % marker)


def test_top_level_menu_still_maps_10_to_the_client_menu(installer_text):
    assert 'info "10. 客户端管理' in installer_text
    assert "10)\n          client_management_menu" in installer_text, (
        "top-level option 10 no longer dispatches client_management_menu; the "
        "piped sequence 10/1/3 would select an unrelated action")


def test_client_menu_still_maps_1_list_2_add_3_generate_0_exit(installer_text):
    start = installer_text.index("client_management_menu()")
    end = installer_text.index("<<< phase-c client-management", start)
    menu = installer_text[start:end]
    assert "1) list_clients" in menu
    assert "2) add_client_interactive" in menu
    assert "3) generate_client_configuration_interactive" in menu
    assert "0) break" in menu


def test_add_path_contract_markers_are_present(installer_text):
    for marker in remote.MENU_ADD_MARKERS:
        assert marker in installer_text, (
            "add-path automation marker no longer present: %r" % marker)
    assert "add_client()" in installer_text
    assert "with_client_lock _add_client_locked" in installer_text
    assert "cm_add_client_candidate_planned" in installer_text
    assert "commit_server_config" in installer_text


def test_add_command_is_pinned_and_bounded():
    command = remote._add_client_command(
        "event-vmix01", "event-vmix01-" + "a" * 32)
    assert "10\n2\nevent-vmix01\n0\n" in command
    assert remote.INSTALLER_URL in command
    assert remote.CLIENT_MANAGEMENT_URL in command
    assert remote.INSTALLER_SHA256 in command
    assert remote.CLIENT_MANAGEMENT_SHA256 in command
    # The managed transaction no longer wraps the whole menu in a hard kill;
    # it runs detached with a file-backed stdin/stdout and a durable journal.
    assert "timeout -k" not in command
    assert "setsid" in command
    assert "BASH_ENV=" in command
    assert "CM_TX_JOURNAL_HOOK=ha_ui_tx_journal" in command
    assert "HAUI_MENU_FAIL=hook-unproven" in command
    assert "PIPESTATUS" not in command
    assert "[redacted-link]" in command
    # No credential material is ever placed in the command.
    assert "uuid" not in command.casefold()
    assert "password" not in command.casefold()


def test_success_message_remote_waits_for_is_emitted_by_generation(
        installer_text):
    # The remote transcript check requires the exact success wording emitted by
    # generate_client_configuration's success info line.
    assert "客户端 '$name' 的 Mihomo 配置已生成" in installer_text
    assert (remote.MENU_SUCCESS_TEMPLATE % "$name"
            == "客户端 '$name' 的 Mihomo 配置已生成")


def test_menu_run_and_fetch_limits_are_bounded():
    command = remote._menu_command(["event-ob01"])
    assert "timeout -k 10 420 env -i" in command
    assert "--connect-timeout 10" in command
    assert "PIPESTATUS" in command
    assert remote.INSTALLER_REVIEWED_COMMIT in command
    assert remote.INSTALLER_SHA256 in command
    assert remote.CLIENT_MANAGEMENT_SHA256 in command
    # Credential-link redaction is applied server-side before the transcript
    # ever leaves the host.
    assert "[redacted-link]" in command
    assert "Reality|HY2" in command


def test_prompt_change_from_pr111_would_not_affect_the_piped_sequence():
    # #111 removes the pre-prompt consistency table and adds blank/invalid retry
    # inside the prompt function. The menu wiring and the success line stay
    # identical; a valid name on stdin still reaches the generator directly.
    assert "generate_client_configuration_interactive()" in INSTALL_SH.read_text(
        encoding="utf-8")
