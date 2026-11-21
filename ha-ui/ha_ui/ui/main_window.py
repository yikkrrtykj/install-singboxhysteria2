"""Main window: safety banner, two server cards and the (disabled) future tabs.

The first slice of issue #110 only implements server management. The
client-management and generation tabs are visible but disabled placeholders
("下一阶段 PR"): nothing in this window exports configuration, starts a tunnel,
imports Clash or changes the remote sing-box configuration.

Every error that reaches the UI is a :class:`~ha_ui.core.errors.HaUiError` with
a fixed code and a safe message; :meth:`MainWindow.show_error` renders it in a
``QMessageBox``. Expected failures from workers are routed here by
:class:`~ha_ui.ui.workers.WorkerRunner`; unexpected exceptions were already
collapsed to ``E_INTERNAL`` at the worker boundary.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME, APP_VERSION, SERVER_IDS
from ..core import config_store
from ..core.errors import HaUiError
from ..core.models import HostKeyInfo
from .dialogs import HostKeyDialog
from .server_panel import ServerPanel
from .services import ServerActions
from .workers import WorkerRunner

SAFETY_BANNER_TEXT = (
    "本地工具；不会开启 TUN、不会导入 Clash、不会修改服务器 sing-box 配置"
)
PLACEHOLDER_TAB_TEXT = "下一阶段 PR"


class MainWindow(QMainWindow):
    """Two-VPS server management window; takes an injected :class:`ServerActions`."""

    def __init__(self, actions: ServerActions, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._actions = actions
        self._runner = WorkerRunner(self)
        self._startup_error: HaUiError | None = None

        self.setWindowTitle("%s %s" % (APP_NAME, APP_VERSION))
        self.resize(1120, 780)
        self._build_ui()
        self._load_config()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        banner = QLabel(SAFETY_BANNER_TEXT, central)
        banner.setObjectName("safetyBanner")
        banner.setWordWrap(True)
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(banner)

        self.tabs = QTabWidget(central)
        server_tab = QWidget(self.tabs)
        server_layout = QHBoxLayout(server_tab)
        server_layout.setContentsMargins(6, 6, 6, 6)
        server_layout.setSpacing(10)
        self.panels: dict[str, ServerPanel] = {}
        for server_id in SERVER_IDS:
            panel = ServerPanel(server_id, self._actions, self._runner, self,
                                server_tab)
            self.panels[server_id] = panel
            server_layout.addWidget(panel, 1)
        self.tabs.addTab(server_tab, "服务器管理")

        self.client_tab, self.client_placeholder = self._placeholder_tab()
        self.tabs.addTab(self.client_tab, "客户端管理")
        self.tabs.setTabEnabled(1, False)
        self.tabs.setTabToolTip(1, PLACEHOLDER_TAB_TEXT)
        self.generate_tab, self.generate_placeholder = self._placeholder_tab()
        self.tabs.addTab(self.generate_tab, "生成")
        self.tabs.setTabEnabled(2, False)
        self.tabs.setTabToolTip(2, PLACEHOLDER_TAB_TEXT)

        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage(
            "就绪（工作目录：%s）" % str(self._actions.workspace))

    def _placeholder_tab(self) -> tuple[QWidget, QLabel]:
        page = QWidget(self.tabs)
        page_layout = QVBoxLayout(page)
        page_layout.addStretch(1)
        label = QLabel(PLACEHOLDER_TAB_TEXT, page)
        label.setObjectName("placeholderLabel")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page_layout.addWidget(label)
        page_layout.addStretch(1)
        return page, label

    # ----------------------------------------------------------------- config --
    def _load_config(self) -> None:
        try:
            servers = self._actions.load_servers()
        except HaUiError as exc:
            servers = config_store.default_servers()
            self._startup_error = exc
            # Report after the window is constructed so a corrupt local config
            # can never block startup inside __init__.
            QTimer.singleShot(0, self._report_startup_error)
        for server_id in SERVER_IDS:
            self.panels[server_id].load_from(servers[server_id])

    def _report_startup_error(self) -> None:
        error = self._startup_error
        self._startup_error = None
        if error is not None and self._runner.active:
            self.show_error(error)

    # ----------------------------------------------------------------- errors --
    def show_error(self, error: HaUiError) -> None:
        """Fixed code + safe message only; never raw exception text."""
        QMessageBox.critical(self, "操作失败", error.safe_text)

    def show_info(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

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
