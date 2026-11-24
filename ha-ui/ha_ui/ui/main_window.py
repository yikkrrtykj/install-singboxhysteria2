"""Main window: page navigation, shared workers and safe operator dialogs.

The 0.2.0 layout follows the actual job instead of the internal architecture:

   服务器  →  客户端  →  生成 YAML

The default page is 客户端 because that is the daily flow; the page itself
shows the A/B connection state and the primary "新建客户端" action. The old
always-on safety banner and debug status bar are gone: the accurate write
boundary is stated in the create dialog and in the help dialog.

Every error reaching the UI is a :class:`~ha_ui.core.errors.HaUiError` with a
fixed code and safe message. Raw exception text is never rendered.
"""

from __future__ import annotations

import threading
from typing import Callable

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME, APP_VERSION, SERVER_IDS
from ..core import config_store, errors
from ..core.errors import HaUiError
from ..core.models import HostKeyInfo
from .clients_panel import ClientsPanel
from .dialogs import HostKeyDialog
from .generate_panel import GeneratePanel
from .server_panel import ServerPanel
from .services import ServerActions
from .session_service import GenerationBackend, SessionGenerationService
from .workers import WorkerRunner

HEADER_TITLE = "双 VPS 主备配置"
HEADER_SUBTITLE = "连接 A / B   →   创建或选择客户端   →   生成 YAML"
HELP_TEXT = (
    "使用顺序：\n"
    "1. 在「服务器」页填写两台 VPS 的连接信息，核对 SSH 主机指纹并保存。\n"
    "2. 在「客户端」页刷新两端清单，或直接新建同名客户端。\n"
    "3. 勾选客户端、选择 A-first / B-first，然后生成 YAML。\n\n"
    "边界：\n"
    "• 生成 YAML 完全在本地进行，不导入 Clash、不开启 TUN、不改系统代理。\n"
    "• 新建客户端会修改两台 VPS 的 sing-box 客户端配置，并可能执行 reload；"
    "两端写入不是原子事务，若一端失败，另一端不会被自动删除。\n"
    "• 软件不显示 UUID、HY2 密码或 YAML 内容。"
)


class MainWindow(QMainWindow):
    """Two-VPS window; takes an injected :class:`ServerActions`."""

    def __init__(
        self,
        actions: ServerActions,
        parent: QWidget | None = None,
        *,
        generation_service: GenerationBackend | None = None,
        open_folder_fn: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        # The thread that constructed the widgets owns every widget read. The
        # password snapshot below is the only shared mutable UI input, so it is
        # guarded rather than trusted.
        self._gui_thread = threading.get_ident()
        self._actions = actions
        self._runner = WorkerRunner(self)
        self._startup_error: HaUiError | None = None
        self._session_service = SessionGenerationService(
            self._actions.workspace,
            self._actions,
            generation_service=generation_service,
            open_folder_fn=open_folder_fn,
        )

        self.setWindowTitle("%s %s" % (APP_NAME, APP_VERSION))
        self.resize(1120, 780)
        self._build_ui()
        self._load_config()
        self.tabs.setCurrentIndex(1)

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        title = QLabel(HEADER_TITLE, central)
        title.setObjectName("appTitle")
        subtitle = QLabel(HEADER_SUBTITLE, central)
        subtitle.setObjectName("appSubtitle")
        heading = QVBoxLayout()
        heading.setSpacing(0)
        heading.addWidget(title)
        heading.addWidget(subtitle)
        header.addLayout(heading)
        header.addStretch(1)
        self.help_button = QPushButton("使用说明", central)
        self.help_button.setObjectName("linkButton")
        self.help_button.clicked.connect(self.show_help)
        header.addWidget(self.help_button)
        layout.addLayout(header)

        self.tabs = QTabWidget(central)
        server_tab = QWidget(self.tabs)
        server_layout = QHBoxLayout(server_tab)
        server_layout.setContentsMargins(8, 8, 8, 8)
        server_layout.setSpacing(10)
        self.panels: dict[str, ServerPanel] = {}
        for server_id in SERVER_IDS:
            panel = ServerPanel(server_id, self._actions, self._runner, self,
                                server_tab)
            self.panels[server_id] = panel
            server_layout.addWidget(panel, 1)
        self.tabs.addTab(server_tab, "服务器")

        self.client_panel = ClientsPanel(
            self._session_service, self._runner, self,
            self.password_overrides, self.tabs)
        self.tabs.addTab(self.client_panel, "客户端")

        self.generate_panel = GeneratePanel(
            self._session_service, self._runner, self, self.client_panel,
            self.password_overrides, self.tabs)
        self.tabs.addTab(self.generate_panel, "生成 YAML")

        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        self.client_panel.generate_requested.connect(self.show_generate_page)
        self.client_panel.client_created.connect(self._on_client_created)
        self.statusBar().showMessage("就绪", 4000)

    # ----------------------------------------------------------------- config --
    def _load_config(self) -> None:
        try:
            servers = self._actions.load_servers()
        except HaUiError as exc:
            servers = config_store.default_servers()
            self._startup_error = exc
            QTimer.singleShot(0, self._report_startup_error)
        for server_id in SERVER_IDS:
            self.panels[server_id].load_from(servers[server_id])
        self.client_panel.set_configured_servers(servers)

    def _report_startup_error(self) -> None:
        error = self._startup_error
        self._startup_error = None
        if error is not None and self._runner.active:
            self.show_error(error)

    # -------------------------------------------------------------- password ---
    def password_overrides(self) -> dict[str, str]:
        """Snapshot the two session password fields (GUI thread only).

        Reading a QWidget from a worker thread is undefined behaviour, so this
        method refuses loudly instead of returning a half-read value. Callers
        snapshot on the GUI thread and hand the immutable dict to the worker.
        """
        if threading.get_ident() != self._gui_thread:
            raise HaUiError(errors.E_USAGE, detail="gui-thread")
        return {server_id: panel.password_edit.text()
                for server_id, panel in self.panels.items()}

    # -------------------------------------------------------------- navigation --
    def show_generate_page(self) -> None:
        self.tabs.setCurrentWidget(self.generate_panel)
        self.generate_panel.focus_generate()

    def _on_client_created(self, name: str) -> None:
        self.show_generate_page()
        self.statusBar().showMessage("客户端「%s」已创建，可以生成 YAML" % name,
                                     8000)

    # ----------------------------------------------------------------- errors --
    def show_error(self, error: HaUiError) -> None:
        """Fixed code + safe message only; never raw exception text."""
        QMessageBox.critical(self, "操作失败", error.safe_text)

    def show_info(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

    def show_warning(self, title: str, text: str) -> None:
        QMessageBox.warning(self, title, text)

    def show_help(self) -> None:
        QMessageBox.information(self, "使用说明", HELP_TEXT)

    def confirm_partial_creation(self, name: str,
                                 existing_role: str) -> bool:
        """Second, explicit confirmation before creating only the missing side."""
        existing = existing_role if existing_role in ("A", "B") else "一端"
        missing = "B" if existing == "A" else "A"
        answer = QMessageBox.warning(
            self,
            "仅补齐缺失端",
            "客户端「%s」在 %s 端已存在。为避免误改已有凭据，软件默认不会补齐。\n\n"
            "是否只在 %s 端创建同名客户端？%s 端已有凭据不会被修改、覆盖或删除。"
            % (name, existing, missing, existing),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def ask_host_key(self, info: HostKeyInfo,
                     existing_fingerprint: str | None) -> str | None:
        """Explicit fingerprint confirmation; returns the accepted fingerprint."""
        replace = bool(existing_fingerprint
                       and existing_fingerprint != info.fingerprint)
        if replace:
            answer = QMessageBox.warning(
                self,
                "主机指纹变化",
                "本次探测到的 SSH 主机指纹与已保存的指纹不一致。\n"
                "只有在你确认服务器确实更换了主机密钥时才替换；"
                "否则请取消并先排查。\n\n是否继续并替换已保存指纹？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return None
        dialog = HostKeyDialog(info, replace_existing=replace, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        if not dialog.verified:
            return None
        return info.fingerprint

    # ---------------------------------------------------------------- closing --
    def closeEvent(self, event) -> None:  # noqa: ANN001 - Qt signature
        # Drop every pending callback: a worker that outlives the window must
        # never touch destroyed widgets or pop a late dialog.
        self._runner.stop()
        super().closeEvent(event)
