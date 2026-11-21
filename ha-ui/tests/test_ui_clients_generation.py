"""pytest-qt tests for the issue #110 client-management + generation UI slice.

Everything runs offscreen and hermetic:

* the real :class:`~ha_ui.ui.session_service.SessionGenerationService` wiring is
  exercised (identity validation, password resolution, pinned connect, session
  close), but both the SSH ``connect`` callable and the core
  ``GenerationService`` (``preview``/``generate``) are injected fakes, so no
  test touches a network, a real VPS, the Windows Credential Manager or the
  reviewed HA tools;
* a fake generation service is injected into ``MainWindow`` and is the only
  object that produces previews/results/cancellation;
* each test workspace is a per-test directory below the worktree's ignored
  ``.scratch/`` tree with ``HA_UI_HOME`` redirected to it.

The tests assert the security/UX contract of the slice: blocked rows for a
one-side-only or incomplete client, select-all excluding them, explicit group
mapping, pre-connect E_HOSTKEY_MISSING/E_CREDENTIAL_MISSING/E_CONFIG gates,
consent only when an export is stale, safe stage labels and E_ code failures,
cancellation, and that no password/YAML sentinel can reach any widget text.
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
from PySide6.QtGui import QFontDatabase
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
    ClientRecord,
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
    COL_DIAGNOSIS,
    COL_GROUP,
    COL_NAME,
    COL_REALITY,
    COL_SELECT,
)
from ha_ui.ui.generate_panel import (
    COL_FILE,
    COL_FOLDER,
    COL_SHA,
    CONSENT_TEXT,
)
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
    """Per-test workspace below the worktree, never the real LOCALAPPDATA."""
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
    """Pinned-session stand-in owned by the session service (closed in finally)."""

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
    """Fake ``ssh_client.connect``-style callable injected into ServerActions."""

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
    """Duck-typed core ``GenerationService``: preview/generate only."""

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

    def preview(self, sessions):
        self.preview_calls += 1
        self.preview_sessions = dict(sessions)
        if self.preview_error is not None:
            raise self.preview_error
        assert self.preview_result is not None, "test forgot preview_result"
        return self.preview_result

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

    def install(self, window: MainWindow) -> None:
        window.show_error = self.errors.append  # type: ignore[method-assign]
        window.show_info = lambda title, text: self.infos.append(  # type: ignore[method-assign]
            (title, text))
        window.ask_host_key = lambda info, existing=None: None  # type: ignore[method-assign]


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
    window.client_panel.preview_button.click()
    qtbot.waitUntil(lambda: window.client_panel.preview_result is not None,
                    timeout=4000)
    qtbot.waitUntil(lambda: not window.client_panel.busy, timeout=4000)


def _select_only(window: MainWindow, *names: str) -> None:
    """Check exactly *names* (bypassing the button, still ready rows only)."""
    table = window.client_panel.table
    window.client_panel.clear_selection()
    for name in names:
        _check_item(table, name).setCheckState(Qt.CheckState.Checked)


def _widget_texts(window: MainWindow) -> str:
    """All rendered text of the window except the (masked) password QLineEdits."""
    chunks: list[str] = []
    for label in window.findChildren(QLabel):
        chunks.append(label.text())
    for log in window.findChildren(QPlainTextEdit):
        chunks.append(log.toPlainText())
    for table in window.findChildren(QTableWidget):
        for row in range(table.rowCount()):
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None:
                    chunks.append(item.text())
    for combo in window.findChildren(QComboBox):
        chunks.append(combo.currentText())
        for index in range(combo.count()):
            chunks.append(combo.itemText(index))
    for button in window.findChildren(QPushButton):
        chunks.append(button.text())
    for box in window.findChildren(QCheckBox):
        chunks.append(box.text())
    return "\n".join(chunks)


# --------------------------------------------------------------------------- #
# 1. Preview: union rows, blocked rows, PIN validity, warnings
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

    # beta exists on A only -> visibly blocked, reason visible, not checkable.
    beta = _row_index(table, "beta")
    assert table.item(beta, COL_A).text() == "是"
    assert table.item(beta, COL_B).text() == "否"
    assert "不可生成" in table.item(beta, COL_DIAGNOSIS).text()
    assert "仅 A 端存在" in table.item(beta, COL_DIAGNOSIS).text()
    assert _is_checkable(table, "beta") is False

    # gamma is complete on both sides but lacks the HY2 credential on A.
    gamma = _row_index(table, "gamma")
    assert "HY2" in table.item(gamma, COL_DIAGNOSIS).text()
    assert _is_checkable(table, "gamma") is False

    # alpha is complete on both sides and export-fresh on both sides.
    assert table.item(_row_index(table, "alpha"), COL_REALITY).text() == (
        "A ✓ / B ✓")
    assert _is_checkable(table, "alpha") is True
    assert table.item(_row_index(table, "alpha"), COL_DIAGNOSIS).text() == "可生成"

    # PIN validity summary shows not_after (never the fingerprint) + warning.
    pin_text = panel.pin_label.text()
    assert "A 端证书到期" in pin_text and "B 端证书到期" in pin_text
    assert PIN_NOT_AFTER.strftime("%Y-%m-%d") in pin_text
    assert "SHA256:" not in pin_text
    assert PIN_WARNING in panel.warning_label.text()

    # Both pinned sessions were opened with the vault password and closed again.
    assert [call["server_id"] for call in connect.calls] == ["A", "B"]
    assert connect.calls[0]["password"] == PASSWORD_A
    assert connect.calls[1]["password"] == PASSWORD_B
    assert connect.calls[0]["expected_fingerprint"] == FINGERPRINT_A
    assert connect.calls[1]["expected_fingerprint"] == FINGERPRINT_B
    assert fake.preview_sessions is not None
    assert all(session.closed for session in fake.preview_sessions.values())
    assert recorder.errors == []


def test_preview_uses_typed_session_password_before_vault(qtbot, ui_workspace):
    window, recorder, fake, connect, _folders = _make_window(qtbot, ui_workspace)
    window.panels["A"].password_edit.setText("typed-only-pw")
    _load_preview(qtbot, window, fake, _fresh_preview())

    assert connect.calls[0]["password"] == "typed-only-pw"
    # B kept empty -> the Windows vault fallback is used for that role only.
    assert connect.calls[1]["password"] == PASSWORD_B
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 2. Select-all excludes every blocked row
# --------------------------------------------------------------------------- #
def test_select_all_generatable_excludes_blocked_rows(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel

    panel.select_all_button.click()

    assert _checked_names(panel.table) == ["alpha", "delta"]
    assert window.generate_panel.selection_label.text().startswith("已选 2 个客户端")
    assert "alpha → A-first" in window.generate_panel.selection_label.text()
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 3. Group mapping is visible before generation and reaches the service
# --------------------------------------------------------------------------- #
def test_group_mapping_is_visible_and_passed_to_generation(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel
    panel.select_all_button.click()
    alpha_row = _row_index(panel.table, "alpha")
    combo = panel.table.cellWidget(alpha_row, COL_GROUP)
    assert isinstance(combo, QComboBox)
    assert combo.currentData() == "A-first"  # default

    combo.setCurrentIndex(combo.findData("B-first"))

    label = window.generate_panel.selection_label.text()
    assert "alpha → B-first" in label
    assert "delta → A-first" in label

    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace, "alpha", "B-first"),
                       _delivered(ui_workspace, "delta", "A-first")])
    # delta's export is stale on A, so the explicit CLI consent is required.
    window.generate_panel.consent_checkbox.setChecked(True)
    window.generate_panel.generate_button.click()

    qtbot.waitUntil(lambda: bool(fake.generate_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.generate_panel.busy, timeout=4000)
    call = fake.generate_calls[0]
    assert [(item.name, item.group) for item in call["selected"]] == [
        ("alpha", "B-first"), ("delta", "A-first")]
    assert call["policy"] == ProbePolicy(5, 2000)  # default policy
    assert call["allow_cli"] is True
    assert call["cleanup_failed"] is False
    assert fake.generate_sessions is not None
    assert all(session.closed for session in fake.generate_sessions.values())
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 4. Pre-connect identity gates: no SSH call on missing config/hostkey/password
# --------------------------------------------------------------------------- #
def test_missing_fingerprint_blocks_before_any_connect(qtbot, ui_workspace):
    window, recorder, fake, connect, _folders = _make_window(
        qtbot, ui_workspace, fingerprint_b=None)
    window.client_panel.preview_button.click()

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
    window.client_panel.preview_button.click()
    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    assert recorder.errors[0].code == errors.E_CREDENTIAL_MISSING
    assert connect.calls == []

    window2, recorder2, _fake2, connect2, _folders2 = _make_window(
        qtbot, ui_workspace, host_a="")
    window2.client_panel.preview_button.click()
    qtbot.waitUntil(lambda: bool(recorder2.errors), timeout=4000)
    assert recorder2.errors[0].code == errors.E_CONFIG
    assert connect2.calls == []


def test_failed_second_connect_closes_the_first_session(qtbot, ui_workspace):
    connect = RecordingConnect(fail_role="B")
    window, recorder, _fake, _connect, _folders = _make_window(
        qtbot, ui_workspace, connect=connect)
    window.client_panel.preview_button.click()

    qtbot.waitUntil(lambda: bool(recorder.errors), timeout=4000)
    assert recorder.errors[0].code == errors.E_SSH_CONNECT
    assert [call["server_id"] for call in connect.calls] == ["A", "B"]
    assert len(connect.sessions) == 1
    assert connect.sessions[0].closed is True


# --------------------------------------------------------------------------- #
# 5. Consent: required for a stale derived export, not for fresh exports
# --------------------------------------------------------------------------- #
def test_consent_required_for_stale_export_and_granted_by_checkbox(
        qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _standard_preview())
    panel = window.client_panel
    generate = window.generate_panel
    panel.select_all_button.click()  # alpha + delta (delta is stale on A)

    assert "必须勾选" in generate.consent_hint_label.text()
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
    assert len(recorder.errors) == 1  # only the initial consent block


def test_consent_not_required_when_exports_are_fresh(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    panel = window.client_panel
    panel.select_all_button.click()
    assert "无需勾选同意" in window.generate_panel.consent_hint_label.text()

    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace, "alpha")])
    window.generate_panel.consent_checkbox.setChecked(False)
    window.generate_panel.generate_button.click()

    qtbot.waitUntil(lambda: bool(fake.generate_calls), timeout=4000)
    qtbot.waitUntil(lambda: not window.generate_panel.busy, timeout=4000)
    assert fake.generate_calls[0]["allow_cli"] is False
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 6. Successful generation: files + SHA + open-folder
# --------------------------------------------------------------------------- #
def test_successful_generation_populates_files_sha_and_open_folder(
        qtbot, ui_workspace):
    opened: list[str] = []
    window, recorder, fake, _connect, _folders = _make_window(
        qtbot, ui_workspace, opened_folders=opened)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    delivered = _delivered(ui_workspace)
    fake.generate_result = _success_result(ui_workspace, [delivered])

    generate = window.generate_panel
    generate.generate_button.click()
    qtbot.waitUntil(lambda: generate.results_table.rowCount() == 1,
                    timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)

    table = generate.results_table
    assert table.item(0, 0).text() == "alpha"
    assert table.item(0, COL_FILE).text() == "alpha-A-first.yaml"
    sha_item = table.item(0, COL_SHA)
    assert sha_item.text() == "c" * 64
    fixed_family = QFontDatabase.systemFont(
        QFontDatabase.SystemFont.FixedFont).family()
    assert sha_item.font().family() == fixed_family  # monospace SHA column
    folder_button = table.cellWidget(0, COL_FOLDER)
    assert isinstance(folder_button, QPushButton)
    assert folder_button.text() == "打开目录"

    assert "1 个文件" in generate.output_note.text()
    assert generate.open_output_button.isEnabled() is True
    generate.open_output_button.click()
    expected_folder = str(Path(delivered.path).parent)
    assert opened == [expected_folder]
    folder_button.click()
    assert opened == [expected_folder, expected_folder]
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 7. Stage failure: E_ code shown, previous output kept, new run id on retry
# --------------------------------------------------------------------------- #
def test_stage_failure_shows_code_and_keeps_previous_output(
        qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.client_panel.select_all_button.click()
    generate = window.generate_panel
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace)])
    generate.generate_button.click()
    qtbot.waitUntil(lambda: generate.results_table.rowCount() == 1,
                    timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    previous_note = generate.output_note.text()

    fake.generate_error = HaUiError(errors.E_CHAIN_STAGE,
                                    detail="ha03:E_PIN_EXPIRED")
    generate.retry_button.click()
    qtbot.waitUntil(
        lambda: errors.E_CHAIN_STAGE in generate.failure_label.text(),
        timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)

    assert "E_CHAIN_STAGE" in generate.failure_label.text()
    assert recorder.errors[-1].code == errors.E_CHAIN_STAGE
    # The previous successful output note and delivered-file row are kept.
    assert generate.results_table.rowCount() == 1
    assert generate.output_note.text() == previous_note
    # Retry was a new attempt with a fresh run id.
    assert len(fake.generate_calls) == 2
    assert fake.generate_calls[0]["run_id"] != fake.generate_calls[1]["run_id"]
    assert generate.delete_failed_button.isEnabled() is False  # no run dir left


# --------------------------------------------------------------------------- #
# 8. Cancel sets the cancel event and surfaces E_CANCELLED
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
    generate.generate_button.click()
    qtbot.waitUntil(entered.is_set, timeout=4000)
    assert generate.cancel_button.isEnabled() is True

    generate.cancel_button.click()

    qtbot.waitUntil(
        lambda: "E_CANCELLED" in generate.failure_label.text(), timeout=4000)
    qtbot.waitUntil(lambda: not generate.busy, timeout=4000)
    assert recorder.errors[-1].code == errors.E_CANCELLED
    assert "已请求取消" in generate.progress_log.toPlainText()


# --------------------------------------------------------------------------- #
# 9. No password/YAML sentinel can reach any rendered widget text
# --------------------------------------------------------------------------- #
def test_no_password_or_yaml_sentinel_in_rendered_widgets(qtbot, ui_workspace):
    window, recorder, fake, _connect, _folders = _make_window(qtbot, ui_workspace)
    fake.stage_tokens = ["stage:preflight", SENTINEL_YAML, "stage:friendly"]
    _load_preview(qtbot, window, fake, _fresh_preview())
    window.panels["A"].password_edit.setText(SENTINEL_PASSWORD)
    window.client_panel.select_all_button.click()
    fake.generate_result = _success_result(
        ui_workspace, [_delivered(ui_workspace)])
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
# 10. Late generation result after window close is ignored
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
    window.generate_panel.generate_button.click()
    qtbot.waitUntil(entered.is_set, timeout=4000)
    window.close()
    release.set()
    qtbot.wait(100)
    assert recorder.errors == []


# --------------------------------------------------------------------------- #
# 11. --self-test still exits 0 with no network/vault
# --------------------------------------------------------------------------- #
def test_app_self_test_exits_zero(qtbot, ui_workspace, capsys):
    from ha_ui import app as app_module

    assert app_module.main(["--self-test"]) == 0
    captured = capsys.readouterr()
    assert "HA-UI self-test: OK" in captured.out
    assert captured.err == ""
