"""pytest-qt tests for the HA-UI 0.2.0 client / creation / generation pages.

Everything runs offscreen and hermetic: the SSH ``connect`` callable and the
core generation service are injected fakes, so no test touches a network, a VPS,
the Windows Credential Manager or the reviewed HA tools. The tests pin the new
operator contract:

* the default page is the client list, with A/B state, counts and a primary
  "新建客户端" action; technical diagnosis is collapsed;
* creation is impossible without the explicit confirmation checkbox, is
  double-click safe, and never claims completion when the other side failed;
* a one-sided existing client stops by default and can only be repaired after a
  second explicit confirmation;
* generation consent is shown only when a fresh export is missing;
* no password, UUID, YAML or remote output reaches any widget.
"""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from ha_ui.core import errors
from ha_ui.core.config_store import ServerConfigStore, default_servers
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import (
    CertPin,
    ClientCreationResult,
    ClientRecord,
    CreationSideResult,
    DeliveredFile,
    GenerationResult,
    ProbePolicy,
    SelectedClient,
    ServerConfig,
)
from ha_ui.core.remote import RemotePreflight
from ha_ui.core.secrets_store import InMemoryCredentialStore
from ha_ui.core.service import PreviewResult, ServerPreview
from ha_ui.ui.clients_panel import (
    COL_A,
    COL_B,
    COL_DETAIL,
    COL_GROUP,
    COL_NAME,
    COL_SELECT,
    COL_STATUS,
)
from ha_ui.ui.dialogs import ClientCreateDialog
from ha_ui.ui.generate_panel import CONSENT_TEXT
from ha_ui.ui.main_window import MainWindow
from ha_ui.ui.services import ServerActions

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRATCH_BASE = REPO_ROOT / ".scratch" / "ui-gen-tests"

FINGERPRINT_A = "SHA256:" + "A" * 43
FINGERPRINT_B = "SHA256:" + "B" * 43
HOST_A = "203.0.113.7"
HOST_B = "198.51.100.9"
PASSWORD_A = "pw-A-sentinel"
PASSWORD_B = "pw-B-sentinel"
SENTINEL_PASSWORD = "SENTINEL-PASSWORD-9f3a"
SENTINEL_YAML = "BEGIN CERTIFICATE SENTINEL-YAML-7c1d"

NOW = datetime.now(timezone.utc)
PIN_NOT_AFTER = NOW + timedelta(days=400)
PIN_WARNING = "HY2 证书剩余 24 天，低于 30 天提醒线"


# --------------------------------------------------------------------------- #
# Fixtures / fakes
# --------------------------------------------------------------------------- #
@pytest.fixture()
def ui_workspace(monkeypatch: pytest.MonkeyPatch) -> Path:
    SCRATCH_BASE.mkdir(parents=True, exist_ok=True)
    workspace = SCRATCH_BASE / uuid.uuid4().hex
    workspace.mkdir()
    monkeypatch.setenv("HA_UI_HOME", str(workspace))
    try:
        yield workspace
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _seed_config(
    workspace: Path,
    *,
    fingerprint_a: str | None = FINGERPRINT_A,
    fingerprint_b: str | None = FINGERPRINT_B,
    host_a: str = HOST_A,
    host_b: str = HOST_B,
) -> None:
    store = ServerConfigStore(workspace)
    servers = default_servers()
    servers["A"] = ServerConfig(
        server_id="A", alias="A", host=host_a, port=22, username="root",
        host_key_fingerprint=fingerprint_a)
    servers["B"] = ServerConfig(
        server_id="B", alias="B", host=host_b, port=22, username="root",
        host_key_fingerprint=fingerprint_b)
    store.save(servers)


class FakeSession:
    def __init__(self, role: str) -> None:
        self.role = role
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def exec(self, command: str, **kwargs):  # noqa: ANN003 - fail closed
        raise AssertionError("the fake generation service must not run commands")

    def download_file(self, remote_path: str, **kwargs):  # noqa: ANN003
        raise AssertionError("the fake generation service must not download")


class RecordingConnect:
    def __init__(self, fail_role: str | None = None) -> None:
        self.fail_role = fail_role
        self.calls: list[dict[str, object]] = []
        self.sessions: list[FakeSession] = []

    def __call__(self, server, password, *, expected_fingerprint=None):
        self.calls.append({
            "server_id": server.server_id,
            "password": password,
            "expected_fingerprint": expected_fingerprint,
        })
        if server.server_id == self.fail_role:
            raise HaUiError(errors.E_SSH_CONNECT, detail="refused")
        session = FakeSession(server.server_id)
        self.sessions.append(session)
        return session


def _unexpected_probe(host: str, port: int):
    raise AssertionError("the generation tabs never probe a host key")


class FakeGenerationService:
    """Duck-typed core service: preview / create_client / generate."""

    def __init__(self) -> None:
        self.preview_result: PreviewResult | None = None
        self.preview_error: HaUiError | None = None
        self.generate_result: GenerationResult | None = None
        self.generate_error: HaUiError | None = None
        self.generate_gate = None
        self.stage_tokens: list[str] = ["stage:preflight", "stage:ha02",
                                        "stage:friendly"]
        self.preview_calls = 0
        self.preview_sessions: dict[str, FakeSession] | None = None
        self.generate_sessions: dict[str, FakeSession] | None = None
        self.generate_calls: list[dict[str, object]] = []
        self.create_result: ClientCreationResult | None = None
        self.create_error: HaUiError | None = None
        self.create_gate = None
        self.create_calls: list[dict[str, object]] = []
        self.create_sessions: list[dict[str, FakeSession]] = []

    def preview(self, sessions):
        self.preview_calls += 1
        self.preview_sessions = dict(sessions)
        if self.preview_error is not None:
            raise self.preview_error
        assert self.preview_result is not None, "test forgot preview_result"
        return self.preview_result

    def create_client(self, *, sessions, name, confirmed,
                      allow_partial_repair=False, progress=None):
        self.create_sessions.append(dict(sessions))
        self.create_calls.append({
            "name": name,
            "confirmed": confirmed,
            "allow_partial_repair": allow_partial_repair,
        })
        if self.create_gate is not None:
            self.create_gate()
        if self.create_error is not None:
            error = self.create_error
            self.create_error = None
            raise error
        assert self.create_result is not None, "test forgot create_result"
        return self.create_result

    def generate(self, *, sessions, selected, policy, allow_cli,
                 run_id=None, progress=None, cancel=None,
                 cleanup_failed=True):
        self.generate_sessions = dict(sessions)
        self.generate_calls.append({
            "selected": list(selected),
            "policy": policy,
            "allow_cli": allow_cli,
            "run_id": run_id,
            "cleanup_failed": cleanup_failed,
        })
        for token in self.stage_tokens:
            if progress is not None:
                progress(token)
        if self.generate_gate is not None:
            self.generate_gate(cancel)
        if self.generate_error is not None:
            raise self.generate_error
        assert self.generate_result is not None, "test forgot generate_result"
        return self.generate_result


class UiRecorder:
    """Capture MainWindow notifier calls instead of opening modal boxes."""

    def __init__(self) -> None:
        self.errors: list[HaUiError] = []
        self.infos: list[tuple[str, str]] = []
        self.warnings: list[tuple[str, str]] = []
        self.partial_confirms: list[tuple[str, str]] = []
        self.partial_reply = False

    def install(self, window: MainWindow) -> None:
        window.show_error = self.errors.append  # type: ignore[method-assign]
        window.show_info = lambda title, text: self.infos.append(  # type: ignore[method-assign]
            (title, text))
        window.show_warning = lambda title, text: self.warnings.append(  # type: ignore[method-assign]
            (title, text))
        window.ask_host_key = lambda info, existing=None: None  # type: ignore[method-assign]

        def confirm(name: str, role: str) -> bool:
            self.partial_confirms.append((name, role))
            return self.partial_reply

        window.confirm_partial_creation = confirm  # type: ignore[method-assign]


def _make_window(
    qtbot,
    workspace: Path,
    *,
    fake: FakeGenerationService | None = None,
    connect: RecordingConnect | None = None,
    vault_passwords: bool = True,
    fingerprint_a: str | None = FINGERPRINT_A,
    fingerprint_b: str | None = FINGERPRINT_B,
    host_a: str = HOST_A,
    host_b: str = HOST_B,
    opened_folders: list[str] | None = None,
):
    _seed_config(workspace, fingerprint_a=fingerprint_a,
                 fingerprint_b=fingerprint_b, host_a=host_a, host_b=host_b)
    store = InMemoryCredentialStore()
    if vault_passwords:
        store.save("A", PASSWORD_A)
        store.save("B", PASSWORD_B)
    connector = connect if connect is not None else RecordingConnect()
    actions = ServerActions(
        Path(workspace),
        credential_store=store,
        probe_fn=_unexpected_probe,
        connect_fn=connector,
    )
    generation = fake if fake is not None else FakeGenerationService()
    folders = opened_folders if opened_folders is not None else []
    window = MainWindow(
        actions,
        generation_service=generation,
        open_folder_fn=folders.append,
    )
    qtbot.addWidget(window)
    window.show()
    recorder = UiRecorder()
    recorder.install(window)
    return window, recorder, generation, connector, folders


# --------------------------------------------------------------------------- #
# Preview data builders
# --------------------------------------------------------------------------- #
def _record(name: str, *, reality: bool = True, hy2: bool = True,
            derived: bool = True, problems: tuple[str, ...] = ()) -> ClientRecord:
    return ClientRecord(name=name, reality_ok=reality, hy2_ok=hy2,
                        derived_export_present=derived, problems=problems)


def _preview(records_a: dict[str, ClientRecord],
             records_b: dict[str, ClientRecord], *,
             warnings: list[str] | None = None) -> PreviewResult:
    facts = RemotePreflight(
        root=True, os_name="Linux", config_present=True, state_present=True,
        manager_present=True, jq_present=True, openssl_present=True,
        api_secret_present=True, management_active=False, config_mtime=0)
    server_a = ServerPreview(
        facts=facts, records=records_a,
        pins=CertPin("aa" * 32, NOW - timedelta(days=100), PIN_NOT_AFTER, "t"))
    server_b = ServerPreview(
        facts=facts, records=records_b,
        pins=CertPin("bb" * 32, NOW - timedelta(days=100), PIN_NOT_AFTER, "t"))
    return PreviewResult(servers={"A": server_a, "B": server_b},
                         warnings=list(warnings if warnings is not None
                                       else [PIN_WARNING]))


def _standard_preview() -> PreviewResult:
    """alpha=clean, beta=A-only, gamma=A HY2-incomplete, delta=stale on A."""
    records_a = {
        "alpha": _record("alpha"),
        "beta": _record("beta"),
        "gamma": _record("gamma", hy2=False,
                         problems=("no-hy2-credential",)),
        "delta": _record("delta", derived=False),
    }
    records_b = {
        "alpha": _record("alpha"),
        "gamma": _record("gamma"),
        "delta": _record("delta"),
    }
    return _preview(records_a, records_b)


def _fresh_preview() -> PreviewResult:
    records_a = {"alpha": _record("alpha")}
    records_b = {"alpha": _record("alpha")}
    return _preview(records_a, records_b, warnings=[])


def _created(name: str = "alpha") -> ClientCreationResult:
    return ClientCreationResult(name=name, sides={
        "A": CreationSideResult("A", "created"),
        "B": CreationSideResult("B", "created"),
    })


def _partial(name: str = "alpha") -> ClientCreationResult:
    return ClientCreationResult(name=name, sides={
        "A": CreationSideResult("A", "created"),
        "B": CreationSideResult("B", "failed", errors.E_REMOTE_CREATE,
                                "reload"),
    })


def _delivered(workspace: Path, client: str = "alpha",
               group: str = "A-first") -> DeliveredFile:
    filename = "%s-%s.yaml" % (client, group)
    path = workspace / "runs" / "run-20260101-000000-abcdef" / "download" / filename
    return DeliveredFile(client=client, group=group, filename=filename,
                         path=str(path), sha256="c" * 64)


def _success_result(workspace: Path, files: list[DeliveredFile]) -> GenerationResult:
    return GenerationResult(run_id="run-fake", files=list(files))


# --------------------------------------------------------------------------- #
# Table helpers
# --------------------------------------------------------------------------- #
def _row_index(table: QTableWidget, name: str) -> int:
    for row in range(table.rowCount()):
        item = table.item(row, COL_NAME)
        if item is not None and item.text() == name:
            return row
    raise AssertionError("client row %r not found" % name)


def _check_item(table: QTableWidget, name: str) -> QTableWidgetItem:
    return table.item(_row_index(table, name), COL_SELECT)


def _is_checkable(table: QTableWidget, name: str) -> bool:
    item = _check_item(table, name)
    return bool(item.flags() & Qt.ItemFlag.ItemIsUserCheckable)


def _checked_names(table: QTableWidget) -> list[str]:
    names = []
    for row in range(table.rowCount()):
        item = table.item(row, COL_SELECT)
        name_item = table.item(row, COL_NAME)
        if (item is not None and name_item is not None
                and item.checkState() == Qt.CheckState.Checked):
            names.append(name_item.text())
    return names


def _load_preview(qtbot, window: MainWindow, fake: FakeGenerationService,
                  preview: PreviewResult) -> None:
    fake.preview_result = preview
    window.client_panel.refresh_button.click()
    qtbot.waitUntil(lambda: window.client_panel.preview_result is not None,
                    timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)


def _select_only(window: MainWindow, *names: str) -> None:
    table = window.client_panel.table
    window.client_panel.clear_selection()
    for name in names:
        _check_item(table, name).setCheckState(Qt.CheckState.Checked)


def _widget_texts(window: MainWindow) -> str:
    chunks: list[str] = []
    for label in window.findChildren(QLabel):
        chunks.append(label.text())
        chunks.append(label.toolTip())
    for log in window.findChildren(QPlainTextEdit):
        chunks.append(log.toPlainText())
    for table in window.findChildren(QTableWidget):
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None:
                    chunks.append(item.text())
                    chunks.append(item.toolTip())
    for combo in window.findChildren(QComboBox):
        chunks.append(combo.currentText())
        for index in range(combo.count()):
            chunks.append(combo.itemText(index))
    for button in window.findChildren(QPushButton):
        chunks.append(button.text())
        chunks.append(button.toolTip())
    for box in window.findChildren(QCheckBox):
        chunks.append(box.text())
    return "\n".join(chunks)


# --------------------------------------------------------------------------- #
# 1. Preview: compact status, blocked rows, certificate detail
# --------------------------------------------------------------------------- #
def test_preview_union_blocks_one_sided_and_incomplete_clients(
        qtbot, ui_workspace):
    window, recorder, fake, connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel
    table = panel.table

    assert table.rowCount() == 4
    assert [table.item(row, COL_NAME).text() for row in range(4)] == [
        "alpha", "beta", "delta", "gamma"]

    beta = _row_index(table, "beta")
    assert table.item(beta, COL_A).text() == "正常"
    assert table.item(beta, COL_B).text() == "缺失"
    assert table.item(beta, COL_STATUS).text() == "缺少 B 端"
    assert _is_checkable(table, "beta") is False
    assert table.cellWidget(beta, COL_DETAIL).text() == "查看原因"

    gamma = _row_index(table, "gamma")
    assert table.item(gamma, COL_A).text() == "异常"
    assert table.item(gamma, COL_STATUS).text() == "配置异常"
    assert "HY2" in table.item(gamma, COL_STATUS).toolTip()
    assert _is_checkable(table, "gamma") is False

    alpha = _row_index(table, "alpha")
    assert table.item(alpha, COL_A).text() == "正常"
    assert table.item(alpha, COL_B).text() == "正常"
    assert table.item(alpha, COL_STATUS).text() == "可生成"
    assert _is_checkable(table, "alpha") is True
    assert table.cellWidget(alpha, COL_DETAIL) is None

    delta = _row_index(table, "delta")
    assert table.item(delta, COL_STATUS).text() == "待生成"
    assert _is_checkable(table, "delta") is True

    # Certificate warning is compact; full dates only in the details dialog.
    assert "证书提醒" in panel.cert_label.text()
    assert panel.cert_detail_button.isVisible() is True
    assert "UTC" not in panel.cert_label.text()
    assert "SHA256:" not in panel.cert_label.text()
    assert "客户端 4 个" in panel.client_count_label.text()
    assert "A：已连接" in panel.server_a_label.text()
    assert "B：已连接" in panel.server_b_label.text()

    assert [call["server_id"] for call in connect.calls] == ["A", "B"]
    assert connect.calls[0]["password"] == PASSWORD_A
    assert connect.calls[1]["password"] == PASSWORD_B
    assert connect.calls[0]["expected_fingerprint"] == FINGERPRINT_A
    assert connect.calls[1]["expected_fingerprint"] == FINGERPRINT_B
    assert fake.preview_sessions is not None
    assert all(session.closed for session in fake.preview_sessions.values())
    assert recorder.errors == []

    # The details action is a safe fixed-token explanation, no raw output.
    panel._show_reasons("gamma")
    assert recorder.infos[-1][0] == "客户端「gamma」"
    assert "HY2" in recorder.infos[-1][1]


def test_certificate_normal_state_is_short_and_no_details_button(
        qtbot, ui_workspace):
    window, _recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    panel = window.client_panel
    assert panel.cert_label.text() == "证书：A / B 正常"
    assert panel.cert_detail_button.isVisible() is False


def test_preview_uses_typed_session_password_before_vault(qtbot, ui_workspace):
    window, recorder, fake, connect, _folders = _make_window(qtbot, ui_workspace)
    window.panels["A"].password_edit.setText("typed-only-pw")
    _load_preview(qtbot, window, fake, _fresh_preview())
    assert connect.calls[0]["password"] == "typed-only-pw"
    assert connect.calls[1]["password"] == PASSWORD_B
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 2. Selection + navigation to the generate page
# --------------------------------------------------------------------------- #
def test_select_all_switches_to_generate_page_with_compact_selection(
        qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel

    panel.select_all_button.click()
    assert _checked_names(panel.table) == ["alpha", "delta"]
    assert panel.selection_label.text() == "已选 2 项"
    assert panel.generate_yaml_button.isEnabled() is True

    panel.generate_yaml_button.click()
    assert window.tabs.currentIndex() == 2
    label = window.generate_panel.selection_label.text()
    assert label == "已选 2 项：alpha、delta"
    assert "A-first" not in label  # long client→group strings moved out of top bar
    assert window.generate_panel.consent_widget.isVisible() is True
    assert recorder.errors == []


def test_group_mapping_is_visible_and_passed_to_generation(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel
    panel.select_all_button.click()
    alpha_row = _row_index(panel.table, "alpha")
    combo = panel.table.cellWidget(alpha_row, COL_GROUP)
    assert isinstance(combo, QComboBox)
    assert combo.currentData() == "A-first"
    combo.setCurrentIndex(combo.findData("B-first"))

    # delta's export is stale on A, so the explicit CLI consent is required.
    window.generate_panel.consent_checkbox.setChecked(True)
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace, "alpha", "B-first"),
                       _delivered(ui_workspace, "delta", "A-first")])
    window.generate_panel.generate_button.click()

    qtbot.waitUntil(lambda: bool(fake.generate_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.generate_panel.busy, timeout=4000)
    call = fake.generate_calls[0]
    assert [(item.name, item.group) for item in call["selected"]] == [
        ("alpha", "B-first"), ("delta", "A-first")]
    assert call["policy"] == ProbePolicy(5, 5000)
    assert call["allow_cli"] is True
    assert call["cleanup_failed"] is False
    assert fake.generate_sessions is not None
    assert all(session.closed for session in fake.generate_sessions.values())
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 3. Pre-connect identity gates
# --------------------------------------------------------------------------- #
def test_missing_fingerprint_blocks_before_any_connect(qtbot, ui_workspace):
    window, recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace, fingerprint_b=None)
    window.client_panel.refresh_button.click()

    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    assert recorder.errors[0].code == errors.E_HOSTKEY_MISSING
    assert "E_HOSTKEY_MISSING" in window.client_panel.status_label.text()
    assert connect.calls == []
    assert fake.preview_calls == 0


def test_missing_password_and_missing_config_block_before_connect(
        qtbot, ui_workspace):
    window, recorder, _fake, connect, _folders = _make_window(
        qtbot, ui_workspace, vault_passwords=False)
    window.client_panel.refresh_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    assert recorder.errors[0].code == errors.E_CREDENTIAL_MISSING
    assert connect.calls == []

    window2, recorder2, _fake2, connect2, _folders2 = _make_window(
        qtbot, ui_workspace, host_a="")
    window2.client_panel.refresh_button.click()
    qtbot.waitUntil(lambda: bool(recorder2.errors), timeout=4000)
    assert recorder2.errors[0].code == errors.E_CONFIG
    assert connect2.calls == []


def test_failed_second_connect_closes_the_first_session(qtbot, ui_workspace):
    connect = RecordingConnect(fail_role="B")
    window, recorder, _fake, _connect, _folders = _make_window(
        qtbot, ui_workspace, connect=connect)
    window.client_panel.refresh_button.click()

    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    assert recorder.errors[0].code == errors.E_SSH_CONNECT
    assert [call["server_id"] for call in connect.calls] == ["A", "B"]
    assert len(connect.sessions) == 1
    assert connect.sessions[0].closed is True


# --------------------------------------------------------------------------- #
# 4. Consent only when needed
# --------------------------------------------------------------------------- #
def test_consent_is_shown_and_required_for_a_stale_export(
        qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel
    generate = window.generate_panel
    panel.select_all_button.click()
    panel.generate_yaml_button.click()

    assert generate.consent_widget.isVisible() is True
    assert "缺少最新导出" in generate.consent_hint_label.text()
    generate.generate_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    assert recorder.errors[0].code == errors.E_USAGE
    assert fake.generate_calls == []
    assert "cli-consent" in (recorder.errors[0].detail or "")

    assert "miaomiao" in CONSENT_TEXT
    assert "sing-box" in CONSENT_TEXT and "TUN" in CONSENT_TEXT
    assert CONSENT_TEXT in generate.consent_checkbox.text()

    generate.consent_checkbox.setChecked(True)
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace, "alpha"),
                       _delivered(ui_workspace, "delta", "B-first")])
    generate.generate_button.click()
    qtbot.waitUntil(lambda: bool(fake.generate_calls), timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    assert fake.generate_calls[0]["allow_cli"] is True
    assert len(recorder.errors) == 1


def test_consent_widget_is_hidden_when_exports_are_fresh(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    panel = window.client_panel
    panel.select_all_button.click()
    panel.generate_yaml_button.click()
    generate = window.generate_panel
    assert generate.consent_widget.isVisible() is False

    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace, "alpha")])
    generate.generate_button.click()
    qtbot.waitUntil(lambda: bool(fake.generate_calls), timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    assert fake.generate_calls[0]["allow_cli"] is False
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 5. Successful generation: compact result + open folder
# --------------------------------------------------------------------------- #
def test_successful_generation_shows_count_and_open_folder(
        qtbot, ui_workspace):
    opened: list[str] = []
    window, recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace, opened_folders=opened)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    delivered = _delivered(ui_workspace)
    fake.generate_result = _success_result(ui_workspace, [delivered])

    generate = window.generate_panel
    window.client_panel.generate_yaml_button.click()
    generate.generate_button.click()
    qtbot.waitUntil(lambda: generate.results_table.rowCount() == 1,
                    timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)

    table = generate.results_table
    assert table.item(0, 0).text() == "alpha"
    assert table.item(0, 1).text() == "alpha-A-first.yaml"
    assert "SHA-256" in table.item(0, 1).toolTip()
    folder_button = table.cellWidget(0, 2)
    assert isinstance(folder_button, QPushButton)
    assert folder_button.text() == "打开目录"

    assert generate.success_label.text() == "已生成 1 个文件"
    assert generate.open_output_button.text() == "打开文件夹"
    assert generate.open_output_button.isEnabled() is True
    generate.open_output_button.click()
    expected_folder = str(Path(delivered.path).parent)
    assert opened == [expected_folder]
    folder_button.click()
    assert opened == [expected_folder, expected_folder]
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 6. Failure: safe code, previous output kept, advanced log opened
# --------------------------------------------------------------------------- #
def test_stage_failure_shows_code_and_keeps_previous_output(
        qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    generate = window.generate_panel
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace)])
    window.client_panel.generate_yaml_button.click()
    generate.generate_button.click()
    qtbot.waitUntil(lambda: generate.results_table.rowCount() == 1,
                    timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    previous_success = generate.success_label.text()

    fake.generate_error = HaUiError(errors.E_CHAIN_STAGE,
                                    detail="ha03:E_PIN_EXPIRED")
    generate.retry_button.click()
    qtbot.waitUntil(
        lambda: errors.E_CHAIN_STAGE in generate.failure_label.text(),
        timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)

    assert generate.failure_label.isVisible() is True
    assert "E_CHAIN_STAGE" in generate.failure_label.text()
    assert recorder.errors[-1].code == errors.E_CHAIN_STAGE
    assert generate.results_table.rowCount() == 1
    assert generate.success_label.text() == previous_success
    assert generate.advanced_widget.isVisible() is True
    assert len(fake.generate_calls) == 2
    assert fake.generate_calls[0]["run_id"] != fake.generate_calls[1]["run_id"]
    assert generate.delete_failed_button.isEnabled() is False


# --------------------------------------------------------------------------- #
# 7. Cancel
# --------------------------------------------------------------------------- #
def test_cancel_sets_event_and_surfaces_e_cancelled(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    entered = threading.Event()

    def gate(cancel):
        entered.set()
        deadline = time.monotonic() + 5.0
        while not cancel():
            if time.monotonic() > deadline:
                raise AssertionError("cancel event was never set")
            time.sleep(0.01)
        raise HaUiError(errors.E_CANCELLED)

    fake.generate_gate = gate
    generate = window.generate_panel
    window.client_panel.generate_yaml_button.click()
    generate.generate_button.click()
    qtbot.waitUntil(entered.is_set, timeout=4000)
    generate.advanced_toggle.setChecked(True)
    assert generate.cancel_button.isEnabled() is True
    generate.cancel_button.click()

    qtbot.waitUntil(
        lambda: "E_CANCELLED" in generate.failure_label.text(), timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    assert recorder.errors[-1].code == errors.E_CANCELLED
    assert "已请求取消" in generate.progress_log.toPlainText()


# --------------------------------------------------------------------------- #
# 8. No secrets in any rendered text
# --------------------------------------------------------------------------- #
def test_no_password_or_yaml_sentinel_in_rendered_widgets(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    fake.stage_tokens = ["stage:preflight", SENTINEL_YAML, "stage:friendly"]
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.panels["A"].password_edit.setText(SENTINEL_PASSWORD)
    window.client_panel.select_all_button.click()
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace)])
    window.client_panel.generate_yaml_button.click()
    window.generate_panel.generate_button.click()
    qtbot.waitUntil(
        lambda: window.generate_panel.results_table.rowCount() == 1,
        timeout=4000)
    qtbot.waitUntil(lambda: not window.generate_panel.busy, timeout=4000)

    rendered = _widget_texts(window)
    assert SENTINEL_PASSWORD not in rendered
    assert PASSWORD_A not in rendered
    assert SENTINEL_YAML not in rendered
    assert "uuid:" not in rendered
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 9. Late generation result after window close is ignored
# --------------------------------------------------------------------------- #
def test_generation_result_after_window_close_is_ignored(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    entered = threading.Event()
    release = threading.Event()

    def gate(cancel):
        entered.set()
        release.wait(5.0)

    fake.generate_gate = gate
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace)])
    window.client_panel.generate_yaml_button.click()
    window.generate_panel.generate_button.click()
    qtbot.waitUntil(entered.is_set, timeout=4000)
    window.close()
    release.set()
    qtbot.wait(100)
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 10. Client creation dialog and flow
# --------------------------------------------------------------------------- #
def test_create_dialog_requires_valid_name_and_explicit_write_consent(qtbot):
    dialog = ClientCreateDialog()
    qtbot.addWidget(dialog)
    assert dialog.ok_button.isEnabled() is False

    dialog.name_edit.setText("bad name")
    assert "只允许" in dialog.error_label.text()
    assert dialog.ok_button.isEnabled() is False

    dialog.name_edit.setText("legacy")
    assert "保留" in dialog.error_label.text()
    assert dialog.ok_button.isEnabled() is False

    dialog.name_edit.setText("event-vmix01")
    assert dialog.error_label.text() == ""
    assert dialog.ok_button.isEnabled() is False
    dialog.confirm_checkbox.setChecked(True)
    assert dialog.ok_button.isEnabled() is True
    assert dialog.client_name == "event-vmix01"
    assert "reload" in dialog.findChild(QLabel, "createWarning").text()


def test_create_success_refreshes_selects_and_guides_to_generate(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, connect, _folders = _make_window(qtbot, ui_workspace)
    fake.preview_result = _fresh_preview()
    fake.create_result = _created("alpha")
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(fake.create_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    qtbot.waitUntil(lambda: window.tabs.currentIndex() == 2, timeout=4000)

    call = fake.create_calls[0]
    assert call["name"] == "alpha"
    assert call["confirmed"] is True
    assert call["allow_partial_repair"] is False
    assert fake.create_sessions and all(
        session.closed for session in fake.create_sessions[0].values())
    # One pair for the create operation and one pair for the automatic refresh.
    assert [c["server_id"] for c in connect.calls] == ["A", "B", "A", "B"]
    assert all(session.closed for session in connect.sessions)
    assert recorder.errors == []
    assert recorder.infos[-1][0] == "客户端「alpha」已创建"
    assert "A 端：已创建" in recorder.infos[-1][1]
    assert _checked_names(window.client_panel.table) == ["alpha"]
    assert window.client_panel.creation_result_label.isVisible() is False


def test_create_partial_result_is_visible_and_never_claims_completion(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    fake.preview_result = _fresh_preview()
    fake.create_result = _partial("alpha")
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(fake.create_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    qtbot.waitUntil(lambda: bool(recorder.warnings), timeout=4000)

    title, text = recorder.warnings[-1]
    assert "未全部完成" in title
    assert "A 端：已创建" in text
    assert "B 端：失败" in text
    assert "不会自动删除" in text
    # Partial success must not switch the operator to the generation page.
    assert window.tabs.currentIndex() == 1
    assert recorder.errors == []
    banner = window.client_panel.creation_result_label
    assert banner.isVisible() is True
    assert "A 端：已创建" in banner.text()
    assert "B 端：失败" in banner.text()
    assert "未全部完成" in banner.text()


def test_one_sided_existing_client_requires_second_confirmation_to_repair(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    fake.preview_result = _fresh_preview()
    fake.create_error = HaUiError(errors.E_CLIENT_PARTIAL_EXISTS, detail="A")
    fake.create_result = _created("alpha")
    recorder.partial_reply = True
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: len(fake.create_calls) == 2, timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)

    assert recorder.partial_confirms == [("alpha", "A")]
    assert fake.create_calls[0]["allow_partial_repair"] is False
    assert fake.create_calls[1]["allow_partial_repair"] is True
    assert recorder.errors == []


def test_create_refused_when_operator_declines_repair(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    fake.create_error = HaUiError(errors.E_CLIENT_PARTIAL_EXISTS, detail="B")
    recorder.partial_reply = False
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.partial_confirms), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    assert len(fake.create_calls) == 1
    assert recorder.errors[-1].code == errors.E_CLIENT_PARTIAL_EXISTS
    assert "创建失败" in window.client_panel.status_label.text()
    assert "未修改任何客户端" in (
        window.client_panel.creation_result_label.text())


def test_password_snapshot_runs_on_the_gui_thread(qtbot, ui_workspace,
                                                  monkeypatch):
    window, _recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    fake.preview_result = _fresh_preview()
    fake.create_result = _created("alpha")
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    original = window.password_overrides
    seen: list[int] = []

    def snapshot():
        seen.append(threading.get_ident())
        return original()

    # The panel captured the bound method at construction; replace that seam.
    window.client_panel._password_provider = snapshot

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(fake.create_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)

    # Called for the create snapshot and again by the post-create refresh, but
    # always on the GUI thread and never inside a worker.
    assert seen
    assert set(seen) == {threading.get_ident()}


def test_password_provider_refuses_an_off_thread_read(qtbot, ui_workspace):
    window, _recorder, _fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    outcome: dict[str, str] = {}

    def read() -> None:
        try:
            window.password_overrides()
        except HaUiError as exc:
            outcome["code"] = exc.code

    worker = threading.Thread(target=read)
    worker.start()
    worker.join(5.0)
    assert outcome.get("code") == errors.E_USAGE


def test_uncertain_create_says_maybe_written_and_refreshes(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace)
    fake.preview_result = _fresh_preview()
    fake.create_error = HaUiError(errors.E_CREATE_UNCERTAIN, detail="timeout")
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    qtbot.waitUntil(lambda: len(connect.calls) == 4, timeout=4000)

    label = window.client_panel.creation_result_label
    assert label.isVisible() is True
    assert "可能已写入" in label.text()
    assert "不要重复创建同名客户端" in label.text()
    # The old blanket "nothing was modified" claim must be gone for this case.
    assert "未修改任何客户端" not in label.text()
    # A second session pair was opened just to re-read the real state.
    assert [call["server_id"] for call in connect.calls] == ["A", "B", "A", "B"]


def test_unconfirmed_create_blocks_retry_and_shows_stale_on_refresh_failure(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    fake.create_error = HaUiError(errors.E_CREATE_UNCERTAIN, detail="timeout")
    fake.preview_error = HaUiError(errors.E_SSH_TIMEOUT)
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    qtbot.waitUntil(
        lambda: "STALE" in window.client_panel.creation_result_label.text(),
        timeout=4000)

    assert "STALE" in window.client_panel.creation_result_label.text()
    assert "不能据此判断服务器未被修改" in (
        window.client_panel.creation_result_label.text())

    # A blind retry of the same name is refused while the state is unconfirmed.
    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.warnings), timeout=4000)
    assert len(fake.create_calls) == 1
    assert "未确认" in recorder.warnings[-1][0]


def test_prewrite_refusal_still_says_nothing_was_modified(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace)
    fake.create_error = HaUiError(errors.E_CLIENT_INCOMPLETE, detail="A")
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)

    label = window.client_panel.creation_result_label
    assert "未修改任何客户端" in label.text()
    assert "可能已写入" not in label.text()
    # Only the create attempt touched SSH: a pre-write refusal needs no refresh.
    assert [call["server_id"] for call in connect.calls] == ["A", "B"]


def test_create_is_double_click_safe(qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    entered = threading.Event()
    release = threading.Event()

    def gate():
        entered.set()
        release.wait(5.0)

    fake.create_gate = gate
    fake.create_result = _created("alpha")
    fake.preview_result = _fresh_preview()
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")

    window.client_panel.create_button.click()
    qtbot.waitUntil(entered.is_set, timeout=4000)
    window.client_panel.create_button.click()  # ignored while busy
    release.set()
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    assert len(fake.create_calls) == 1
    assert recorder.errors == []


def test_create_blocks_before_connect_when_fingerprint_missing(
        qtbot, ui_workspace, monkeypatch):
    window, recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace, fingerprint_b=None)
    monkeypatch.setattr(window.client_panel, "_ask_create_name",
                        lambda: "alpha")
    window.client_panel.create_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)
    assert recorder.errors[0].code == errors.E_HOSTKEY_MISSING
    assert fake.create_calls == []
    assert connect.calls == []


def test_unconfirmed_creation_is_refused_before_any_ssh_session(
        qtbot, ui_workspace):
    window, _recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace)
    with pytest.raises(HaUiError) as excinfo:
        window._session_service.create_client(name="alpha", confirmed=False)
    assert excinfo.value.code == errors.E_USAGE
    assert excinfo.value.detail == "create-consent"
    assert connect.calls == []
    assert fake.create_calls == []


# --------------------------------------------------------------------------- #
# 11. Self-test / policy defaults
# --------------------------------------------------------------------------- #
def test_app_self_test_exits_zero(qtbot, ui_workspace, capsys):
    from ha_ui import app as app_module

    assert app_module.main(["--self-test"]) == 0
    captured = capsys.readouterr()
    assert "HA-UI self-test: OK" in captured.out
    assert captured.err == ""


def test_probe_policy_default_and_legacy_option(qtbot, ui_workspace):
    window, recorder, _fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    combo = window.generate_panel.policy_combo
    assert ProbePolicy() == ProbePolicy(5, 5000)
    assert combo.currentData() == ProbePolicy()
    assert combo.itemText(combo.currentIndex()).startswith("5s / 5000ms")
    expected = (
        ("5s / 2000ms", ProbePolicy(5, 2000)),
        ("3s / 1000ms", ProbePolicy(3, 1000)),
        ("10s / 5000ms", ProbePolicy(10, 5000)),
    )
    for text, policy in expected:
        index = combo.findText(text)
        assert index >= 0, text
        combo.setCurrentIndex(index)
        assert combo.currentData() == policy
    combo.setCurrentIndex(combo.findText("5s / 5000ms（默认）"))
    assert combo.currentData() == ProbePolicy(5, 5000)
    assert recorder.errors == []


@pytest.mark.parametrize("size", [(1120, 780), (1366, 768)])
def test_common_window_sizes_keep_the_primary_actions_visible(
        qtbot, ui_workspace, size):
    window, _recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    window.resize(*size)
    qtbot.wait(50)
    panel = window.client_panel
    assert panel.create_button.isVisible() is True
    assert panel.generate_yaml_button.isVisible() is True
    assert panel.table.isVisible() is True
    assert panel.table.width() > 600
    assert panel.create_button.width() > 0
