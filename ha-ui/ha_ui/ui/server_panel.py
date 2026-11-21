"""One server card: non-secret identity fields plus the action buttons.

Security rules enforced here:

* the password field starts masked and the 显示/隐藏 toggle only changes the Qt
  echo mode -- the value is never logged, never put in a status text, and never
  written to ``servers.json``; the config store holds no password key at all;
* "记住密码" writes only through the Windows Credential Manager and is reported
  as success only after the backend confirms the write; an unavailable/failing
  vault is reported as a failure and the field is kept for the current session;
* "测试连接" uses the *saved* configuration and its confirmed fingerprint (it
  never trusts unsaved edits) and delegates the fixed read-only preflight to
  :class:`~ha_ui.ui.services.ServerActions` inside a worker thread;
* selecting a new host key always goes through the explicit "我已核对" dialog in
  :class:`~ha_ui.ui.dialogs.HostKeyDialog` (owned by ``MainWindow.ask_host_key``).
"""

from __future__ import annotations

from typing import Protocol

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..core import errors
from ..core.errors import HaUiError
from ..core.models import HostKeyInfo, RemoteFacts, ServerConfig
from .services import ServerActions
from .workers import WorkerRunner


class UiNotifier(Protocol):
    """The parts of ``MainWindow`` a panel is allowed to call."""

    def show_error(self, error: HaUiError) -> None: ...

    def show_info(self, title: str, text: str) -> None: ...

    def ask_host_key(self, info: HostKeyInfo,
                     existing_fingerprint: str | None) -> str | None: ...


def format_remote_facts(facts: RemoteFacts) -> str:
    """Fixed, non-secret one-line report for the status label."""
    parts = [
        "root=%s" % ("是" if facts.root else "否"),
        "配置=%s" % ("存在" if facts.config_present else "缺失"),
        "管理菜单=%s" % ("存在" if facts.miaomiao_present else "缺失"),
    ]
    if facts.os_release:
        parts.append("系统=%s" % facts.os_release)
    return "连接正常（%s）" % "，".join(parts)


class ServerPanel(QGroupBox):
    """Editable identity + explicit actions for one VPS (A or B)."""

    def __init__(self, server_id: str, actions: ServerActions,
                 runner: WorkerRunner, notifier: UiNotifier,
                 parent: QWidget | None = None) -> None:
        super().__init__("VPS %s" % server_id, parent)
        self.server_id = server_id
        self._actions = actions
        self._runner = runner
        self._notifier = notifier
        self._fingerprint: str | None = None
        self._busy = False
        self._build_ui()
        self._refresh_credential_hint()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.alias_edit = QLineEdit(self)
        self.alias_edit.setMaxLength(40)
        self.alias_edit.setPlaceholderText("例如：香港 A")
        self.host_edit = QLineEdit(self)
        self.host_edit.setMaxLength(253)
        self.host_edit.setPlaceholderText("IP 或主机名（仅字母数字、点和横线）")
        self.port_spin = QSpinBox(self)
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(22)
        self.username_edit = QLineEdit(self)
        self.username_edit.setMaxLength(64)
        self.username_edit.setText("root")

        self.password_edit = QLineEdit(self)
        self.password_edit.setObjectName("passwordEdit")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("仅本次会话使用；勾选“记住密码”才会保存")
        self.show_password_button = QToolButton(self)
        self.show_password_button.setObjectName("togglePasswordButton")
        self.show_password_button.setText("显示")
        self.show_password_button.setCheckable(True)
        self.show_password_button.setToolTip("显示密码")
        password_row = QWidget(self)
        password_layout = QHBoxLayout(password_row)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.addWidget(self.password_edit, 1)
        password_layout.addWidget(self.show_password_button)

        form.addRow("名称/别名", self.alias_edit)
        form.addRow("IP 或主机名", self.host_edit)
        form.addRow("SSH 端口", self.port_spin)
        form.addRow("用户名", self.username_edit)
        form.addRow("SSH 密码", password_row)

        self.remember_checkbox = QCheckBox(
            "记住密码（Windows 凭据管理器）", self)
        form.addRow("", self.remember_checkbox)
        layout.addLayout(form)

        self.credential_hint_label = QLabel(self)
        self.credential_hint_label.setObjectName("credentialHint")
        self.credential_hint_label.setWordWrap(True)
        layout.addWidget(self.credential_hint_label)

        self.fingerprint_label = QLabel(self)
        self.fingerprint_label.setObjectName("fingerprintStatus")
        self.fingerprint_label.setWordWrap(True)
        layout.addWidget(self.fingerprint_label)
        self._update_fingerprint_label()

        self.status_label = QLabel("未连接/未配置", self)
        self.status_label.setObjectName("connectionStatus")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        self.save_button = QPushButton("保存配置", self)
        self.probe_button = QPushButton("获取并确认指纹", self)
        self.test_button = QPushButton("测试连接", self)
        self.delete_button = QPushButton("删除已保存密码", self)
        for button in (self.save_button, self.probe_button,
                       self.test_button, self.delete_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)

        note = QLabel(
            "测试连接只读取服务器状态，使用已保存的配置与已确认指纹；"
            "不会修改服务器。", self)
        note.setObjectName("hint")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)

        self.show_password_button.toggled.connect(
            self._on_password_visibility_toggled)
        self.remember_checkbox.toggled.connect(
            self._on_remember_toggled)
        self.save_button.clicked.connect(self._on_save_clicked)
        self.probe_button.clicked.connect(self._on_probe_clicked)
        self.test_button.clicked.connect(self._on_test_clicked)
        self.delete_button.clicked.connect(self._on_delete_clicked)

    # ------------------------------------------------------------------ state --
    @property
    def busy(self) -> bool:
        return self._busy

    def load_from(self, server: ServerConfig) -> None:
        """Populate from the non-secret store; never a password."""
        self.alias_edit.setText(server.alias)
        self.host_edit.setText(server.host)
        self.port_spin.setValue(server.port)
        self.username_edit.setText(server.username or "root")
        self._fingerprint = server.host_key_fingerprint
        self._update_fingerprint_label()
        if server.host:
            self.status_label.setText("未连接/已配置")
        else:
            self.status_label.setText("未连接/未配置")

    # -------------------------------------------------------------- password ---
    def _on_password_visibility_toggled(self, visible: bool) -> None:
        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        self.show_password_button.setText("隐藏" if visible else "显示")
        self.show_password_button.setToolTip("隐藏密码" if visible else "显示密码")

    def _on_remember_toggled(self, _checked: bool) -> None:
        self._refresh_credential_hint()

    def _refresh_credential_hint(self) -> None:
        if not self._actions.credential_available():
            self.credential_hint_label.setText(
                "凭据管理器不可用：密码不会保存（仍可用于本次连接测试）。")
            return
        backend = self._actions.credential_backend_name()
        if self.remember_checkbox.isChecked():
            self.credential_hint_label.setText("保存目标：%s" % backend)
        else:
            self.credential_hint_label.setText("当前不保存密码（后端：%s）" % backend)

    # ----------------------------------------------------------------- helper --
    def _build_server_config(
            self, fingerprint_override: str | None = None) -> ServerConfig:
        fingerprint = (self._fingerprint if fingerprint_override is None
                       else fingerprint_override)
        return ServerConfig(
            server_id=self.server_id,
            alias=self.alias_edit.text().strip(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            username=self.username_edit.text().strip(),
            host_key_fingerprint=fingerprint,
        )

    def _update_fingerprint_label(self) -> None:
        if self._fingerprint:
            self.fingerprint_label.setText("主机指纹：已确认（连接时会校验）")
        else:
            self.fingerprint_label.setText("主机指纹：未确认（请先获取并确认）")

    def _begin_operation(self) -> None:
        self._busy = True
        for button in (self.save_button, self.probe_button,
                       self.test_button, self.delete_button):
            button.setEnabled(False)

    def _end_operation(self) -> None:
        self._busy = False
        for button in (self.save_button, self.probe_button,
                       self.test_button, self.delete_button):
            button.setEnabled(True)

    def _fail(self, prefix: str, error: HaUiError) -> None:
        # Only fixed code + safe message; never the password or raw exception.
        self.status_label.setText("%s：%s" % (prefix, error.safe_text))
        self._notifier.show_error(error)

    # ------------------------------------------------------------------ save ---
    def _on_save_clicked(self) -> None:
        if self._busy:
            return
        try:
            self._save_config_and_credential()
        except HaUiError as exc:
            self._fail("保存失败", exc)
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._fail("保存失败", HaUiError(errors.E_INTERNAL))

    def _save_config_and_credential(self) -> None:
        server = self._build_server_config()
        self._actions.save_server(server)
        self._fingerprint = server.host_key_fingerprint
        self._update_fingerprint_label()
        self.status_label.setText("配置已保存（未连接）")
        if self.remember_checkbox.isChecked():
            self._start_credential_save()

    def _start_credential_save(self) -> None:
        password = self.password_edit.text()
        if not password:
            self.remember_checkbox.setChecked(False)
            self._fail("密码未保存", HaUiError(
                errors.E_USAGE, detail="password-empty",
                message="请先填写要保存的密码"))
            return
        if not self._actions.credential_available():
            self.remember_checkbox.setChecked(False)
            self._fail("密码未保存",
                       HaUiError(errors.E_CREDENTIAL_UNAVAILABLE, detail="backend"))
            self._refresh_credential_hint()
            return
        backend = self._actions.credential_backend_name()
        self._begin_operation()

        def job() -> None:
            self._actions.save_password(self.server_id, password)

        def success(_result: object) -> None:
            self.password_edit.clear()
            self.status_label.setText("密码已保存到 %s" % backend)

        def failure(exc: HaUiError) -> None:
            self.remember_checkbox.setChecked(False)
            self._fail("密码保存失败", exc)

        self._runner.run(job, on_success=success, on_error=failure,
                         on_done=self._end_operation)

    # ----------------------------------------------------------------- probe ---
    def _on_probe_clicked(self) -> None:
        if self._busy:
            return
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        self._begin_operation()
        self.status_label.setText("正在读取主机指纹…")

        def job() -> HostKeyInfo:
            return self._actions.probe_host_key(host, port)

        def success(info: HostKeyInfo) -> None:
            existing = self._fingerprint
            try:
                accepted = self._notifier.ask_host_key(info, existing)
            except HaUiError as exc:
                self._fail("指纹确认失败", exc)
                return
            except BaseException:  # noqa: BLE001 - hard GUI boundary
                self._fail("指纹确认失败", HaUiError(errors.E_INTERNAL))
                return
            if not accepted:
                self.status_label.setText("已取消指纹确认")
                return
            try:
                server = self._build_server_config(
                    fingerprint_override=accepted)
                self._actions.save_server(server)
            except HaUiError as exc:
                self._fail("指纹保存失败", exc)
                return
            except BaseException:  # noqa: BLE001 - hard GUI boundary
                self._fail("指纹保存失败", HaUiError(errors.E_INTERNAL))
                return
            self._fingerprint = accepted
            self._update_fingerprint_label()
            self.status_label.setText("指纹已确认；未连接")

        def failure(exc: HaUiError) -> None:
            self._fail("指纹读取失败", exc)

        self._runner.run(job, on_success=success, on_error=failure,
                         on_done=self._end_operation)

    # ------------------------------------------------------------------ test ---
    def _on_test_clicked(self) -> None:
        if self._busy:
            return
        password = self.password_edit.text()
        self._begin_operation()
        self.status_label.setText("正在测试连接…")

        def job() -> RemoteFacts:
            servers = self._actions.load_servers()
            server = servers[self.server_id]
            effective = password or self._actions.load_password(self.server_id) or ""
            return self._actions.test_connection(server, effective)

        def success(facts: RemoteFacts) -> None:
            self.status_label.setText(format_remote_facts(facts))

        def failure(exc: HaUiError) -> None:
            self._fail("连接失败", exc)

        self._runner.run(job, on_success=success, on_error=failure,
                         on_done=self._end_operation)

    # ---------------------------------------------------------------- delete ---
    def _on_delete_clicked(self) -> None:
        if self._busy:
            return
        self._begin_operation()
        self.status_label.setText("正在删除已保存密码…")

        def job() -> bool:
            return self._actions.delete_password(self.server_id)

        def success(deleted: bool) -> None:
            self.password_edit.clear()
            if deleted:
                self.status_label.setText("已删除保存的密码")
            else:
                self.status_label.setText("没有已保存的密码")
                self._notifier.show_info("删除密码", "没有找到该服务器的已保存密码。")

        def failure(exc: HaUiError) -> None:
            self._fail("删除密码失败", exc)

        self._runner.run(job, on_success=success, on_error=failure,
                         on_done=self._end_operation)
