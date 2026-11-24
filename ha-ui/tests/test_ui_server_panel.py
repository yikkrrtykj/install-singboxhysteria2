"""pytest-qt tests for the issue #110 server-management UI slice (PR-A).

Everything runs offscreen and with injected fakes: no test touches a real
Windows Credential Manager entry or opens a network connection. The workspace
is a per-test directory with ``HA_UI_HOME`` redirected to it, so the real
``%LOCALAPPDATA%\\HASingbox`` directory is never modified either.
"""

from __future__ import annotations

import json
import shutil
import threading
import uuid
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel, QLineEdit

from ha_ui import APP_NAME, APP_VERSION
from ha_ui.core import errors
from ha_ui.core.config_store import ServerConfigStore, default_servers
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import HostKeyInfo, ServerConfig
from ha_ui.core.secrets_store import InMemoryCredentialStore
from ha_ui.ui.dialogs import HostKeyDialog
from ha_ui.ui.main_window import HEADER_TITLE, HELP_TEXT, MainWindow
from ha_ui.ui.services import (
    PREFLIGHT_COMMAND,
    ServerActions,
    parse_preflight_output,
)

FINGERPRINT = "SHA256:" + "A" * 43
OTHER_FINGERPRINT = "SHA256:" + "B" * 43
PREFLIGHT_OK = "0\nLinux\nconfig=present\nmanager=present\n"
PREFLIGHT_OK_NO_MANAGER = "0\nLinux\nconfig=present\nmanager=missing\n"

# ha-ui/tests/test_ui_server_panel.py -> parents[2] is the repo worktree root.
# The test workspace lives under the repository's ignored .scratch/ tree (the
# default private-ACL store needs a writable per-test directory; the system
# TEMP directory is not always writable in restricted test environments).
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRATCH_BASE = REPO_ROOT / ".scratch" / "ui-tests"


# --------------------------------------------------------------------------- #
# Fixtures / fakes
# --------------------------------------------------------------------------- #
@pytest.fixture()
def ui_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Per-test private workspace; the real LOCALAPPDATA path is never used."""
    SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
    workspace = SCRATCH_BASE / uuid.uuid4().hex
    workspace.mkdir()
    monkeypatch.setenv("HA_UI_HOME", str(workspace))
    try:
        yield workspace
    finally:
        try:
            shutil.rmtree(workspace)
        except OSError:
            pass


def _config_text(workspace: Path) -> str:
    path = Path(workspace) / "servers.json"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _seed_config(workspace: Path, server_id: str = "A",
                 fingerprint: str | None = FINGERPRINT,
                 host: str = "203.0.113.10") -> None:
    """Write the non-secret config the UI would have saved earlier."""
    store = ServerConfigStore(Path(workspace))
    servers = default_servers()
    servers[server_id] = ServerConfig(
        server_id=server_id, alias="VPS %s" % server_id, host=host,
        port=22, username="root", host_key_fingerprint=fingerprint)
    store.save(servers)


class FakeSession:
    """Minimal ParamikoSession stand-in; records the fixed command it was given."""

    def __init__(self, stdout: str = PREFLIGHT_OK, return_code: int = 0) -> None:
        self.stdout = stdout
        self.return_code = return_code
        self.commands: list[str] = []
        self.closed = False

    def exec(self, command: str, stdin_data=None, timeout: float = 60.0):
        del stdin_data, timeout
        self.commands.append(command)
        return self.return_code, self.stdout, ""

    def close(self) -> None:
        self.closed = True


def _unexpected_probe(host: str, port: int) -> HostKeyInfo:
    raise AssertionError("test must inject a fake probe")


def _unexpected_connect(server: ServerConfig, password: str, *,
                        expected_fingerprint: str | None = None):
    raise AssertionError("test must inject a fake connect")


class UiRecorder:
    """Captures the MainWindow notifier calls instead of opening modal boxes."""

    def __init__(self) -> None:
        self.errors: list[HaUiError] = []
        self.infos: list[tuple[str, str]] = []
        self.host_key_requests: list[tuple[HostKeyInfo, str | None]] = []
        self.host_key_reply: str | None = None

    def install(self, window: MainWindow) -> None:
        window.show_error = self.errors.append  # type: ignore[method-assign]
        window.show_info = lambda title, text: self.infos.append(  # type: ignore[method-assign]
            (title, text))

        def ask_host_key(info: HostKeyInfo,
                         existing_fingerprint: str | None) -> str | None:
            self.host_key_requests.append((info, existing_fingerprint))
            return self.host_key_reply

        window.ask_host_key = ask_host_key  # type: ignore[method-assign]


def _make_window(
    qtbot,
    workspace: Path,
    *,
    credential_store: InMemoryCredentialStore | None = None,
    probe_fn=None,
    connect_fn=None,
) -> tuple[MainWindow, UiRecorder, InMemoryCredentialStore]:
    store = (credential_store if credential_store is not None
             else InMemoryCredentialStore())
    actions = ServerActions(
        Path(workspace),
        credential_store=store,
        probe_fn=probe_fn if probe_fn is not None else _unexpected_probe,
        connect_fn=connect_fn if connect_fn is not None else _unexpected_connect,
    )
    window = MainWindow(actions)
    qtbot.addWidget(window)
    window.show()
    recorder = UiRecorder()
    recorder.install(window)
    return window, recorder, store


def _fill_server(panel, *, host: str = "203.0.113.10", alias: str = "HK A",
                 port: int = 22, username: str = "root",
                 password: str = "") -> None:
    panel.alias_edit.setText(alias)
    panel.host_edit.setText(host)
    panel.port_spin.setValue(port)
    panel.username_edit.setText(username)
    panel.password_edit.setText(password)


# --------------------------------------------------------------------------- #
# Construction / layout / password widget
# --------------------------------------------------------------------------- #
def test_window_constructs_with_clear_pages_and_default_client_view(
        qtbot, ui_workspace):
    window, recorder, _store = _make_window(qtbot, ui_workspace)

    assert APP_NAME in window.windowTitle()
    assert APP_VERSION == "0.2.0"
    assert APP_VERSION in window.windowTitle()
    assert set(window.panels) == {"A", "B"}
    for server_id, panel in window.panels.items():
        assert panel.server_id == server_id
        assert panel.status_label.text() == "未连接/未配置"
        assert panel.save_button.text() == "保存配置"
        assert panel.probe_button.text() == "获取并确认指纹"
        assert panel.test_button.text() == "测试连接"
        assert panel.delete_button.text() == "删除已保存密码"
        assert panel.remember_checkbox.text() == "记住密码（Windows 凭据管理器）"

    # The 0.1.0 always-on banner was removed; help text is on demand.
    banners = [label for label in window.findChildren(QLabel)
               if label.objectName() == "safetyBanner"]
    assert banners == []
    assert window.help_button.text() == "使用说明"
    assert "两端写入不是原子事务" in HELP_TEXT
    assert "不开启 TUN" in HELP_TEXT

    titles = [label.text() for label in window.findChildren(QLabel)
              if label.objectName() == "appTitle"]
    assert titles == [HEADER_TITLE]

    assert window.tabs.count() == 3
    assert window.tabs.tabText(0) == "服务器"
    assert window.tabs.tabText(1) == "客户端"
    assert window.tabs.tabText(2) == "生成 YAML"
    assert window.tabs.isTabEnabled(0) is True
    assert window.tabs.isTabEnabled(1) is True
    assert window.tabs.isTabEnabled(2) is True
    # Daily flow starts on the client page.
    assert window.tabs.currentIndex() == 1
    assert window.client_panel is not None
    assert window.generate_panel is not None
    assert window.client_panel.create_button.text() == "＋ 新建客户端"
    assert window.client_panel.refresh_button.text() == "刷新客户端"
    assert window.client_panel.generate_yaml_button.text() == "生成 YAML"
    assert window.generate_panel.generate_button.text() == "生成 YAML"
    assert window.generate_panel.advanced_widget.isVisible() is False
    assert recorder.errors == []


def test_saved_config_populates_panel_without_password(qtbot, ui_workspace):
    _seed_config(ui_workspace)
    window, recorder, _store = _make_window(qtbot, ui_workspace)
    panel = window.panels["A"]

    assert panel.host_edit.text() == "203.0.113.10"
    assert panel.username_edit.text() == "root"
    assert panel.status_label.text() == "未连接/已配置"
    assert "已确认" in panel.fingerprint_label.text()
    assert panel.password_edit.text() == ""
    assert recorder.errors == []


def test_password_field_masked_and_toggle_changes_echo_mode(qtbot, ui_workspace):
    window, recorder, _store = _make_window(qtbot, ui_workspace)
    panel = window.panels["A"]
    assert panel.password_edit.echoMode() == QLineEdit.EchoMode.Password
    assert panel.show_password_button.text() == "显示"

    panel.password_edit.setText("S3cret-Pass")
    QTest.mouseClick(panel.show_password_button, Qt.MouseButton.LeftButton)
    assert panel.password_edit.echoMode() == QLineEdit.EchoMode.Normal
    assert panel.show_password_button.text() == "隐藏"
    assert "S3cret-Pass" not in panel.status_label.text()

    QTest.mouseClick(panel.show_password_button, Qt.MouseButton.LeftButton)
    assert panel.password_edit.echoMode() == QLineEdit.EchoMode.Password
    assert panel.show_password_button.text() == "显示"
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# Config save: no password anywhere in servers.json
# --------------------------------------------------------------------------- #
def test_save_config_never_writes_password_to_servers_json(qtbot, ui_workspace):
    window, recorder, _store = _make_window(qtbot, ui_workspace)
    panel = window.panels["A"]
    _fill_server(panel, host="203.0.113.10", alias="香港 A", port=2222,
                 username="ops", password="TopSecret-123")
    assert panel.remember_checkbox.isChecked() is False

    panel.save_button.click()

    raw = _config_text(ui_workspace)
    assert raw, "servers.json was not written"
    assert "TopSecret-123" not in raw
    assert "password" not in raw.lower()
    document = json.loads(raw)
    saved = document["servers"]["A"]
    assert saved["alias"] == "香港 A"
    assert saved["host"] == "203.0.113.10"
    assert saved["port"] == 2222
    assert saved["username"] == "ops"
    assert saved["host_key_fingerprint"] is None
    assert panel.status_label.text().startswith("配置已保存")
    # Without an explicit "记住密码" the session password stays in the field
    # (available for a test connection) but was not persisted anywhere.
    assert panel.password_edit.text() == "TopSecret-123"
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# Test connection
# --------------------------------------------------------------------------- #
def test_test_connection_refused_without_confirmed_fingerprint(qtbot, ui_workspace):
    _seed_config(ui_workspace, fingerprint=None)
    connect_calls: list[object] = []

    def connect(server, password, *, expected_fingerprint=None):
        connect_calls.append((server, password, expected_fingerprint))
        raise AssertionError("a missing fingerprint must block before SSH")

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, connect_fn=connect)
    panel = window.panels["A"]
    panel.password_edit.setText("pw")
    panel.test_button.click()

    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert recorder.errors[0].code == errors.E_HOSTKEY_MISSING
    assert connect_calls == []
    assert "连接失败" in panel.status_label.text()
    assert "E_HOSTKEY_MISSING" in panel.status_label.text()


def test_successful_test_connection_reports_preflight_facts(qtbot, ui_workspace):
    _seed_config(ui_workspace)
    session = FakeSession(PREFLIGHT_OK_NO_MANAGER)
    calls: list[dict[str, object]] = []

    def connect(server, password, *, expected_fingerprint=None):
        calls.append({"server": server, "password": password,
                      "expected_fingerprint": expected_fingerprint})
        return session

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, connect_fn=connect)
    panel = window.panels["A"]
    panel.password_edit.setText("p@ss-word")
    panel.test_button.click()

    qtbot.waitUntil(lambda: "连接正常" in panel.status_label.text(),
                    timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    status = panel.status_label.text()
    assert "root=是" in status
    assert "配置=存在" in status
    assert "管理菜单=缺失" in status
    assert "系统=Linux" in status
    assert recorder.errors == []
    assert len(calls) == 1
    assert calls[0]["password"] == "p@ss-word"
    assert calls[0]["expected_fingerprint"] == FINGERPRINT
    assert session.commands == [PREFLIGHT_COMMAND]
    assert session.closed is True
    assert "p@ss-word" not in status


def test_test_connection_uses_vault_password_when_field_is_empty(
        qtbot, ui_workspace):
    _seed_config(ui_workspace)
    store = InMemoryCredentialStore()
    store.save("A", "vault-only-pw")
    session = FakeSession(PREFLIGHT_OK)
    calls: list[str] = []

    def connect(server, password, *, expected_fingerprint=None):
        calls.append(password)
        return session

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, credential_store=store, connect_fn=connect)
    panel = window.panels["A"]
    assert panel.password_edit.text() == ""

    panel.test_button.click()

    qtbot.waitUntil(lambda: "连接正常" in panel.status_label.text(),
                    timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert calls == ["vault-only-pw"]
    assert recorder.errors == []


def test_unexpected_ssh_exception_maps_to_e_internal(qtbot, ui_workspace):
    _seed_config(ui_workspace)

    def connect(server, password, *, expected_fingerprint=None):
        raise RuntimeError("boom secret detail")

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, connect_fn=connect)
    panel = window.panels["A"]
    panel.password_edit.setText("pw")
    panel.test_button.click()

    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert recorder.errors[0].code == errors.E_INTERNAL
    assert "boom secret detail" not in recorder.errors[0].safe_text
    assert "E_INTERNAL" in panel.status_label.text()
    assert window.isVisible() is True


# --------------------------------------------------------------------------- #
# Credential vault: explicit success/failure, backend name, delete
# --------------------------------------------------------------------------- #
def test_vault_unavailable_save_is_failure_and_keeps_password_for_session(
        qtbot, ui_workspace):
    store = InMemoryCredentialStore(available=False)
    window, recorder, _store = _make_window(
        qtbot, ui_workspace, credential_store=store)
    panel = window.panels["A"]
    _fill_server(panel, password="Vault-Secret-9")
    panel.remember_checkbox.setChecked(True)
    assert "不可用" in panel.credential_hint_label.text()

    panel.save_button.click()

    # Local non-secret config is saved, but the password must be reported as a
    # failure (never "已保存") and the field is kept for the current session.
    assert "Vault-Secret-9" not in _config_text(ui_workspace)
    assert recorder.errors
    assert recorder.errors[0].code == errors.E_CREDENTIAL_UNAVAILABLE
    assert "密码未保存" in panel.status_label.text()
    assert "密码已保存" not in panel.status_label.text()
    assert panel.password_edit.text() == "Vault-Secret-9"
    assert panel.remember_checkbox.isChecked() is False


def test_remember_password_saves_to_backend_and_clears_field(
        qtbot, ui_workspace):
    window, recorder, store = _make_window(qtbot, ui_workspace)
    panel = window.panels["A"]
    _fill_server(panel, password="hunter2")
    panel.remember_checkbox.setChecked(True)
    # The hint must name the real backend once "记住密码" is ticked.
    assert "in-memory" in panel.credential_hint_label.text()

    panel.save_button.click()

    qtbot.waitUntil(lambda: panel.password_edit.text() == "", timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert "密码已保存" in panel.status_label.text()
    assert "in-memory" in panel.status_label.text()
    assert store.load("A") == "hunter2"
    assert "hunter2" not in _config_text(ui_workspace)
    assert recorder.errors == []


def test_delete_saved_credential(qtbot, ui_workspace):
    store = InMemoryCredentialStore()
    store.save("A", "stored-pw")
    window, recorder, _store = _make_window(
        qtbot, ui_workspace, credential_store=store)
    panel = window.panels["A"]
    panel.password_edit.setText("stored-pw")

    panel.delete_button.click()

    qtbot.waitUntil(lambda: "已删除" in panel.status_label.text(),
                    timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert store.load("A") is None
    assert panel.password_edit.text() == ""
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# Host-key probe -> explicit confirmation -> persisted fingerprint
# --------------------------------------------------------------------------- #
def test_probe_requires_explicit_confirmation_and_saves_fingerprint(
        qtbot, ui_workspace):
    probe_calls: list[tuple[str, int]] = []

    def probe(host: str, port: int) -> HostKeyInfo:
        probe_calls.append((host, port))
        return HostKeyInfo(algorithm="ssh-ed25519", fingerprint=FINGERPRINT)

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, probe_fn=probe)
    recorder.host_key_reply = FINGERPRINT
    panel = window.panels["A"]
    panel.host_edit.setText("203.0.113.10")
    panel.port_spin.setValue(2222)

    panel.probe_button.click()

    qtbot.waitUntil(lambda: FINGERPRINT in _config_text(ui_workspace),
                    timeout=5000)
    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert probe_calls == [("203.0.113.10", 2222)]
    assert len(recorder.host_key_requests) == 1
    info, existing = recorder.host_key_requests[0]
    assert info.algorithm == "ssh-ed25519"
    assert info.fingerprint == FINGERPRINT
    assert existing is None
    assert panel.fingerprint_label.text() == "主机指纹：已确认（连接时会校验）"
    assert "指纹已确认" in panel.status_label.text()
    assert recorder.errors == []
    saved = ServerConfigStore(ui_workspace).load()["A"]
    assert saved.host_key_fingerprint == FINGERPRINT
    assert saved.host == "203.0.113.10"
    assert saved.port == 2222


def test_probe_cancelled_by_operator_does_not_save_fingerprint(
        qtbot, ui_workspace):
    window, recorder, _store = _make_window(
        qtbot, ui_workspace,
        probe_fn=lambda host, port: HostKeyInfo("ssh-ed25519", FINGERPRINT))
    recorder.host_key_reply = None  # operator cancelled the confirmation dialog
    panel = window.panels["A"]
    panel.host_edit.setText("203.0.113.10")

    panel.probe_button.click()

    qtbot.waitUntil(lambda: not panel.busy, timeout=5000)
    assert "已取消" in panel.status_label.text()
    assert "未确认" in panel.fingerprint_label.text()
    assert _config_text(ui_workspace) == ""
    assert recorder.errors == []


def test_host_key_dialog_requires_explicit_verification(qtbot):
    dialog = HostKeyDialog(HostKeyInfo("ssh-ed25519", FINGERPRINT))
    qtbot.addWidget(dialog)
    assert dialog.algorithm_label.text() == "ssh-ed25519"
    assert dialog.fingerprint_label.text() == FINGERPRINT
    assert dialog.ok_button.isEnabled() is False
    assert dialog.verified is False

    dialog.verify_checkbox.setChecked(True)
    assert dialog.verified is True
    assert dialog.ok_button.isEnabled() is True


def test_ask_host_key_warns_before_replacing_changed_fingerprint(
        qtbot, ui_workspace, monkeypatch):
    from PySide6.QtWidgets import QDialog
    from PySide6.QtWidgets import QMessageBox as RealMessageBox

    warnings_delivered: list[tuple[str, str]] = []
    answers = [RealMessageBox.StandardButton.No,
               RealMessageBox.StandardButton.Yes]
    dialogs_created: list[dict] = []

    class _FakeMessageBox:
        StandardButton = RealMessageBox.StandardButton

        @staticmethod
        def warning(parent, title, text, buttons, default):
            del parent, buttons, default
            warnings_delivered.append((title, text))
            return answers.pop(0)

    class _FakeDialog:
        def __init__(self, info, replace_existing=False, parent=None):
            del parent
            dialogs_created.append({"info": info,
                                    "replace": replace_existing})
            self.verified = True

        def exec(self):
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr("ha_ui.ui.main_window.QMessageBox", _FakeMessageBox)
    monkeypatch.setattr("ha_ui.ui.main_window.HostKeyDialog", _FakeDialog)
    actions = ServerActions(
        Path(ui_workspace),
        credential_store=InMemoryCredentialStore(),
        probe_fn=_unexpected_probe,
        connect_fn=_unexpected_connect,
    )
    window = MainWindow(actions)
    qtbot.addWidget(window)
    info = HostKeyInfo("ssh-ed25519", FINGERPRINT)

    # A changed saved fingerprint always warns first; No aborts before dialog.
    assert window.ask_host_key(info, OTHER_FINGERPRINT) is None
    assert len(warnings_delivered) == 1
    assert "不一致" in warnings_delivered[0][1]
    assert dialogs_created == []

    # Same saved fingerprint: no warning, no replace dialog, accepted value.
    assert window.ask_host_key(info, FINGERPRINT) == FINGERPRINT
    assert len(warnings_delivered) == 1
    assert dialogs_created[-1]["replace"] is False

    # Changed fingerprint + explicit Yes: replace warning is passed to dialog.
    assert window.ask_host_key(info, OTHER_FINGERPRINT) == FINGERPRINT
    assert len(warnings_delivered) == 2
    assert dialogs_created[-1]["replace"] is True


# --------------------------------------------------------------------------- #
# Error mapping, stale results, preflight contract, self-test
# --------------------------------------------------------------------------- #
def test_show_error_renders_fixed_code_and_message_in_messagebox(
        qtbot, ui_workspace, monkeypatch):
    calls: list[tuple[str, str]] = []

    class _FakeMessageBox:
        @staticmethod
        def critical(parent, title, text):  # noqa: ANN001
            del parent
            calls.append((title, text))
            return 0

    monkeypatch.setattr("ha_ui.ui.main_window.QMessageBox", _FakeMessageBox)
    actions = ServerActions(
        Path(ui_workspace),
        credential_store=InMemoryCredentialStore(),
        probe_fn=_unexpected_probe,
        connect_fn=_unexpected_connect,
    )
    window = MainWindow(actions)
    qtbot.addWidget(window)
    # Deliberately bypass UiRecorder: this test exercises the real
    # MainWindow.show_error -> QMessageBox rendering path.
    window.show_error(HaUiError(errors.E_SSH_CONNECT, detail="refused"))

    assert len(calls) == 1
    title, text = calls[0]
    assert title == "操作失败"
    assert text.startswith(errors.E_SSH_CONNECT)
    assert "SSH 连接失败" in text


def test_results_after_window_close_are_ignored(qtbot, ui_workspace):
    _seed_config(ui_workspace)
    started = threading.Event()
    release = threading.Event()

    def connect(server, password, *, expected_fingerprint=None):
        started.set()
        release.wait(5.0)
        return FakeSession()

    window, recorder, _store = _make_window(
        qtbot, ui_workspace, connect_fn=connect)
    panel = window.panels["A"]
    panel.password_edit.setText("pw")
    panel.test_button.click()
    qtbot.waitUntil(started.is_set, timeout=5000)
    try:
        window.close()
    finally:
        release.set()
    qtbot.wait(100)
    # The window is gone: the late result must be dropped, not rendered.
    assert recorder.errors == []


def test_preflight_command_is_fixed_text_and_parser_reports_facts():
    expected = (
        "id -u; uname -s; "
        "test -f /root/sbox/sbconfig_server.json && echo config=present "
        "|| echo config=missing; "
        "command -v miaomiao >/dev/null 2>&1 && echo manager=present "
        "|| echo manager=missing; "
        "if [ -f /root/sbox/sbconfig_server.json ]; then "
        "echo cfgsha=$(sha256sum /root/sbox/sbconfig_server.json "
        "| awk '{print $1}'); "
        "else echo cfgsha=none; fi"
    )
    assert PREFLIGHT_COMMAND == expected
    # Fixed text: the only brace pair is awk's own program, and nothing here is
    # an interpolation slot for operator data.
    assert PREFLIGHT_COMMAND.replace("{print $1}", "").count("{") == 0
    assert "%s" not in PREFLIGHT_COMMAND
    assert "{0}" not in PREFLIGHT_COMMAND

    facts = parse_preflight_output(PREFLIGHT_OK_NO_MANAGER)
    assert facts.root is True
    assert facts.os_release == "Linux"
    assert facts.config_present is True
    assert facts.miaomiao_present is False
    # The config identity is real data now, not a permanently-None placeholder.
    assert facts.root_config_sha256 is None

    hashed = parse_preflight_output(
        PREFLIGHT_OK_NO_MANAGER + "cfgsha=" + "a" * 64 + "\n")
    assert hashed.root_config_sha256 == "a" * 64
    unproven = parse_preflight_output(
        PREFLIGHT_OK_NO_MANAGER + "cfgsha=NOT-A-HASH\n")
    assert unproven.root_config_sha256 is None

    non_root = parse_preflight_output("1000\nLinux\nconfig=missing\nmanager=present\n")
    assert non_root.root is False
    assert non_root.config_present is False
    assert non_root.miaomiao_present is True

    with pytest.raises(HaUiError) as excinfo:
        parse_preflight_output("unexpected output\n")
    assert excinfo.value.code == errors.E_SSH_PROTOCOL


def test_app_self_test_exits_zero(qtbot, ui_workspace, capsys):
    from ha_ui import app as app_module

    assert app_module.main(["--self-test"]) == 0
    captured = capsys.readouterr()
    assert "HA-UI self-test: OK" in captured.out
    assert captured.err == ""
