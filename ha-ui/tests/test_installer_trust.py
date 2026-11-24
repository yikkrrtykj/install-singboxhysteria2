"""Trust-anchor tests for the pinned remote installer chain.

The GUI executes only bytes fetched from an exact reviewed commit and verified
against independently embedded SHA-256 values; the installer's own embedded
client-management pin must match the separately downloaded library. These tests
bind the constants to the repository's reviewed files and exercise every
untrusted/failed-pin path, including the required fallback behaviour: automatic
generation is disabled, while already-fresh canonical exports can still be read.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from ha_ui.core import errors, remote
from ha_ui.core.errors import HaUiError
from tests import fakes
from tests.fakes import ClientSpec, DerivedState, FakeSession

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_provider(**kwargs):
    session = FakeSession("A", **kwargs)
    return remote.RemoteProvider("A", session), session


def stale(name="stale"):
    return [ClientSpec(name, derived=DerivedState(fresh=False))]


def fresh(name="fresh"):
    return [ClientSpec(name, derived=DerivedState())]


def exports(name="stale"):
    return {name: b"canonical-A"}


def test_embedded_hashes_match_the_reviewed_repository_files():
    installer = (REPO_ROOT / "install.sh").read_bytes()
    library = (REPO_ROOT / "lib" / "client-management.sh").read_bytes()
    assert hashlib.sha256(installer).hexdigest() == remote.INSTALLER_SHA256, (
        "install.sh changed: re-review the installer and update the pinned "
        "hash/commit and this test together")
    assert (hashlib.sha256(library).hexdigest()
            == remote.CLIENT_MANAGEMENT_SHA256), (
        "lib/client-management.sh changed: re-review the pinned library")
    match = re.search(
        rb'SB_CLIENT_MANAGEMENT_SHA256="([0-9a-f]{64})"', installer)
    assert match is not None
    assert match.group(1).decode() == remote.CLIENT_MANAGEMENT_SHA256
    assert re.fullmatch(r"[0-9a-f]{40}", remote.INSTALLER_REVIEWED_COMMIT)


def test_urls_are_commit_pinned_and_never_main():
    for url in (remote.INSTALLER_URL, remote.CLIENT_MANAGEMENT_URL):
        assert remote.INSTALLER_REVIEWED_COMMIT in url
        assert "/main/" not in url
        assert url.endswith(("install.sh", "client-management.sh"))
    command = remote._menu_command(["event-ob01"])
    assert "/main/" not in command
    assert remote.INSTALLER_URL in command
    assert remote.CLIENT_MANAGEMENT_URL in command


def test_add_command_uses_the_same_pinned_trust_chain():
    command = remote._add_client_command(
        "event-vmix01", "event-vmix01-" + "a" * 32)
    assert "/main/" not in command
    assert remote.INSTALLER_URL in command
    assert remote.CLIENT_MANAGEMENT_URL in command
    assert remote.INSTALLER_SHA256 in command
    assert remote.CLIENT_MANAGEMENT_SHA256 in command
    assert ('SB_CLIENT_MANAGEMENT_REF=' + remote.INSTALLER_REVIEWED_COMMIT
            in command)
    assert "2) add_client_interactive" in command


@pytest.mark.parametrize("token", ["installer-hash", "lib-hash", "lib-pin"])
def test_untrusted_installer_or_library_disables_auto_generation(token):
    provider, session = make_provider(clients=stale(), exports=exports(),
                                      menu_fail=token)
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=True)
    assert excinfo.value.code == errors.E_INSTALLER_UNTRUSTED
    assert excinfo.value.detail == token
    assert session.downloads == []


def test_fetch_failure_remains_a_retriable_menu_error_not_untrusted():
    provider, session = make_provider(clients=stale(), exports=exports(),
                                      menu_fail="fetch")
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=True)
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "precheck-fetch"
    assert session.downloads == []


def test_tampered_installer_command_cannot_claim_success():
    # A server that echoes a fake success transcript but never fetches/verifies
    # the pinned bytes must not get past the pre-execution gate. The fake
    # returns the fail marker the real script emits on a hash mismatch.
    provider, session = make_provider(clients=stale(), exports=exports(),
                                      menu_fail="installer-hash")
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=True)
    assert excinfo.value.code == errors.E_INSTALLER_UNTRUSTED
    assert session.menu_invoked is True
    assert session.downloads == []


def test_existing_fresh_export_remains_readable_when_auto_generation_disabled():
    # Requirement: if automatic menu generation cannot be trusted, the GUI may
    # still read already-fresh canonical files without executing the installer.
    provider, session = make_provider(clients=fresh(),
                                      exports=exports("fresh"),
                                      menu_fail="installer-hash")
    data = provider.generate_exports(["fresh"], allow_cli=False)
    assert data == {"fresh": b"canonical-A"}
    assert session.menu_invoked is False
    assert session.downloads == ["/root/sbox/clients/fresh/mihomo.yaml"]


def test_preflight_refuses_missing_host_deps_before_installer_execution():
    provider, session = make_provider(
        facts=fakes.VpsFacts(missing_host_deps=("qrencode", "iptables")))
    with pytest.raises(HaUiError) as excinfo:
        provider.preflight()
    assert excinfo.value.code == errors.E_REMOTE_PREFLIGHT
    assert excinfo.value.detail.startswith("host-deps:")
    assert "qrencode" in excinfo.value.detail
    assert session.menu_invoked is False


def test_preflight_host_deps_cover_the_installer_dependency_specs():
    # The installer's HOST_DEP_SPECS packages are qrencode/jq/iptables/acl/
    # util-linux; every probe must be preflight-required so install_pkgs cannot
    # reach apt to install unlocked repository code.
    for probe in ("qrencode", "jq", "iptables", "setfacl", "getfacl",
                  "runuser"):
        assert probe in remote.INSTALLER_HOST_DEPS


def test_sanitized_environment_is_used_for_the_pinned_installer():
    command = remote._menu_command(["event-ob01"])
    assert "env -i PATH=" in command
    assert "SB_CLIENT_MANAGEMENT_LIB=\"$d/client-management.sh\"" in command
    assert ("SB_CLIENT_MANAGEMENT_REF=" + remote.INSTALLER_REVIEWED_COMMIT
            in command)
    # No inherited SB_* override or caller HOME can redirect the pinned run.
    assert "HOME=/root" in command
    assert "LANG=C.UTF-8" in command
