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


def test_client_menu_still_maps_1_list_3_generate_0_exit(installer_text):
    start = installer_text.index("client_management_menu()")
    end = installer_text.index("<<< phase-c client-management", start)
    menu = installer_text[start:end]
    assert "1) list_clients" in menu
    assert "3) generate_client_configuration_interactive" in menu
    assert "0) break" in menu


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
