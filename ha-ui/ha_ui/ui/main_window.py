"""Main window: safety banner, two server cards and the client/generation tabs.

The window owns the shared :class:`~ha_ui.ui.workers.WorkerRunner` (stopped on
close, so a late worker result can never touch a destroyed widget) and wraps the
production :class:`~ha_ui.ui.session_service.SessionGenerationService`. The
client-management tab reads both VPS inventories; the generation tab runs the
local HA chain. Nothing in this window exports configuration by itself, starts
a tunnel, imports Clash or changes the remote sing-box configuration: the only
remote write is the existing ``miaomiao`` CLI's derived-file generation, and
only after the operator ticks the explicit consent box.

Every error that reaches the UI is a :class:`~ha_ui.core.errors.HaUiError` with
a fixed code and a safe message; :meth:`MainWindow.show_error` renders it in a
``QMessageBox``. Expected failures from workers are routed here by
:class:`~ha_ui.ui.workers.WorkerRunner`; unexpected exceptions were already
collapsed to ``E_INTERNAL`` at the worker boundary.
"""

from __future__ import annotations

from typing import Callable

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
from .clients_panel import ClientsPanel
from .dialogs import HostKeyDialog
from .generate_panel import GeneratePanel
from .server_panel import ServerPanel
from .services import ServerActions
from .session_service import GenerationBackend, SessionGenerationService
from .workers import WorkerRunner

SAFETY_BANNER_TEXT = (
    "本地工具；不会开启 TUN、不会导入 Clash、不会修改服务器 sing-box 配置"
)


class MainWindow(QMainWindow):
    """Two-VPS window; takes an injected :class:`ServerActions`.

    Tests may inject a fake core ``generation_service`` (the object with
    ``preview``/``generate``) and a fake ``open_folder_fn``; production passes
    neither and gets the reviewed core :class:`GenerationService` plus
    :func:`ha_ui.core.private_fs.open_folder`.
    """

    def __init__(
        self,
        actions: ServerActions,
        parent: QWidget | None = None,
        *,
        generation_service: GenerationBackend | None = None,
        open_folder_fn: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
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

        self.client_panel = ClientsPanel(
            self._session_service, self._runner, self,
            self.password_overrides, self.tabs)
        self.tabs.addTab(self.client_panel, "客户端管理")

        self.generate_panel = GeneratePanel(
            self._session_service, self._runner, self, self.client_panel,
            self.password_overrides, self.tabs)
        self.tabs.addTab(self.generate_panel, "生成")

        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage(
            "就绪（工作目录：%s）" % str(self._actions.workspace))

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

    # -------------------------------------------------------------- password ---
    def password_overrides(self) -> dict[str, str]:
        """Snapshot the two session password fields (GUI thread only).

        The returned mapping is only kept for the duration of one worker call so
        the operator can type a password without saving it to the vault. It is
        never rendered or logged.
        """
        return {server_id: panel.password_edit.text()
                for server_id, panel in self.panels.items()}

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
