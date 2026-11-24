"""Application entry point for the local HA-UI tool (issue #110, slice A).

``main(argv=None)`` returns a process exit code. ``--self-test`` constructs the
real window with an in-memory credential store and a temporary workspace,
processes the event loop briefly and exits 0 without any network or Windows
Credential Manager access. The packaged EXE's cold-start smoke test uses it.

Workspace root: ``HA_UI_HOME`` when set (handled by the security core's
``default_workspace_root``), otherwise ``%LOCALAPPDATA%\\HASingbox``.

No external style asset is loaded; one embedded QSS string is enough for a
readable Windows 11 look. No logging is configured: safe error codes are
rendered in dialogs, passwords never are.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from . import APP_NAME, APP_VERSION
from .core import errors, secrets_store
from .core.config_store import default_workspace_root
from .core.errors import HaUiError
from .ui.main_window import MainWindow
from .ui.services import ServerActions

SIMPLE_QSS = """
QMainWindow { background: #f4f6fa; }
QWidget { font-family: "Microsoft YaHei UI", "Segoe UI"; font-size: 13px; }
QLabel#appTitle { font-size: 21px; font-weight: 700; color: #172033; }
QLabel#appSubtitle { color: #667085; padding-top: 2px; }
QTabWidget::pane {
    border: 2px solid #e4e7ec; background: #ffffff; border-radius: 10px;
    top: -1px;
}
QTabBar::tab {
    background: transparent; color: #475467; padding: 9px 22px;
    margin-right: 4px; border: none; font-weight: 600;
}
QTabBar::tab:selected { color: #1a56db; border-bottom: 2px solid #1a56db; }
QTabBar::tab:hover { color: #1a56db; }
QGroupBox {
    background: #ffffff; border: 1px solid #e4e7ec; border-radius: 8px;
    margin-top: 14px; padding: 12px 12px 10px 12px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 12px; padding: 0 4px;
    color: #1f2a37; font-weight: 600;
}
QLabel#connectionStatus { color: #1f2a37; font-weight: 600; }
QLabel#fingerprintStatus, QLabel#credentialHint, QLabel#hint { color: #667085; }
QLabel#hostKeyWarning { color: #9a2a00; font-weight: 600; }
QLabel#serverSummary {
    background: #eef4ff; color: #1f2a37; border-radius: 11px;
    padding: 4px 11px; font-weight: 600;
}
QLabel#clientCount { color: #475467; }
QLabel#certSummary { padding: 4px 8px; }
QLabel#emptyState {
    color: #667085; padding: 28px 12px; border: 1px dashed #d0d5dd;
    border-radius: 8px; background: #fcfcfd;
}
QLabel#selectionCount { color: #344054; font-weight: 600; }
QLabel#generationSelection { color: #1f2a37; font-size: 14px; }
QLabel#generationSuccess { color: #1f6b3a; font-size: 15px; font-weight: 600; }
QLabel#generationFailure {
    background: #fef3f2; border: 1px solid #fda29b; border-radius: 6px;
    color: #912018; padding: 8px 10px;
}
QLabel#consentHint { color: #7a4b00; }
QLabel#creationResult {
    background: #fffaeb; border: 1px solid #fec84b; border-radius: 6px;
    color: #7a4b00; padding: 8px 10px;
}
QLabel#validationError { color: #b42318; }
QLabel#createWarning {
    background: #fffaeb; border: 1px solid #fec84b; border-radius: 6px;
    color: #7a4b00; padding: 9px 10px;
}
QPushButton {
    padding: 6px 12px; border: 1px solid #d0d5dd; border-radius: 6px;
    background: #ffffff; color: #344054;
}
QPushButton:hover { background: #f9fafb; }
QPushButton:disabled { color: #98a2b3; background: #f2f4f7; }
QPushButton#primaryButton {
    background: #1a56db; color: #ffffff; border: 1px solid #1a56db;
    font-weight: 600; padding: 8px 16px;
}
QPushButton#primaryButton:hover { background: #1546b8; }
QPushButton#primaryButton:disabled {
    background: #b2c7f7; border-color: #b2c7f7; color: #ffffff;
}
QPushButton#secondaryButton { background: #ffffff; }
QPushButton#linkButton {
    background: transparent; border: none; color: #1a56db; padding: 2px 6px;
}
QPushButton#linkButton:hover { text-decoration: underline; }
QToolButton#advancedToggle {
    border: none; background: transparent; color: #475467; font-weight: 600;
    padding: 4px 2px;
}
QToolButton#advancedToggle:hover { color: #1a56db; }
QTableWidget {
    background: #ffffff; alternate-background-color: #f9fafb;
    border: 1px solid #e4e7ec; border-radius: 8px; gridline-color: transparent;
}
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section {
    background: #f9fafb; color: #475467; border: none;
    border-bottom: 1px solid #e4e7ec; padding: 7px 8px; font-weight: 600;
}
QComboBox { padding: 4px 8px; border: 1px solid #d0d5dd; border-radius: 5px; }
QPlainTextEdit#generationLog {
    background: #fcfcfd; border: 1px solid #e4e7ec; border-radius: 6px;
    font-family: Consolas, "Cascadia Mono", monospace; color: #475467;
}
QStatusBar { color: #667085; }
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ha-ui",
        description="%s %s（本地工具）" % (APP_NAME, APP_VERSION),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="构造主窗口、短暂处理事件后退出 0（不访问网络或凭据管理器）",
    )
    return parser


def ensure_application() -> QApplication:
    """Return the QApplication, creating an offscreen-safe one when needed."""
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    app = QApplication([sys.argv[0] if sys.argv else "ha-ui"])
    QCoreApplication.setApplicationName(APP_NAME)
    QCoreApplication.setApplicationVersion(APP_VERSION)
    QCoreApplication.setOrganizationName("ha-ui")
    app.setStyle("Fusion")
    app.setStyleSheet(SIMPLE_QSS)
    return app


def _pump_events(app: QApplication, milliseconds: int = 100) -> None:
    """Process queued events briefly without blocking forever."""
    loop = QEventLoop()
    QTimer.singleShot(max(1, milliseconds), loop.quit)
    loop.exec()
    app.processEvents()


def _exercise_private_storage(workspace: Path) -> None:
    """Exercise the real private-storage path (ACL + atomic write) once.

    The packaged EXE is windowed (no console); without this step the cold-start
    smoke test never spawns the ``icacls`` console child that the private ACL
    needs, so a console-window regression would go unnoticed. Only a fixed
    ``HaUiError`` code reaches the caller; no file content or path is printed.
    """
    from .core import private_fs

    root = workspace / "selftest-private"
    payload = b'{"selftest": 1}\n'
    try:
        private_fs.ensure_private_dir(root, workspace=workspace)
        private_fs.verify_private_dir(root)
        target = root / "selftest.bin"
        private_fs.secure_write_replace(target, payload, workspace=workspace)
        private_fs.verify_private_file(target)
        if private_fs.read_private_file(target, workspace=workspace) != payload:
            raise HaUiError(errors.E_STORE_IO, detail="selftest-readback")
    finally:
        # Best-effort: a failed self-test must not leave a private test tree.
        try:
            private_fs.delete_tree_under(workspace, root)
        except HaUiError:
            pass


def run_self_test() -> int:
    """Cold-start smoke: real window, in-memory vault, temporary workspace."""
    app = ensure_application()
    override = os.environ.get("HA_UI_HOME")
    created_workspace = False
    if override:
        workspace = Path(override)
    else:
        workspace = Path(tempfile.mkdtemp(prefix="ha-ui-selftest-"))
        created_workspace = True
    window = None
    status = 0
    try:
        actions = ServerActions(
            workspace,
            credential_store=secrets_store.InMemoryCredentialStore(),
        )
        window = MainWindow(actions)
        window.show()
        _pump_events(app)
        if window.windowTitle() != "%s %s" % (APP_NAME, APP_VERSION):
            status = 1
        if status == 0:
            _exercise_private_storage(workspace)
    except HaUiError as exc:
        print("HA-UI self-test: FAILED %s" % exc.code, file=sys.stderr)
        status = 1
    except BaseException:  # noqa: BLE001 - never render raw exception text
        print("HA-UI self-test: FAILED %s" % errors.E_INTERNAL, file=sys.stderr)
        status = 1
    finally:
        if window is not None:
            try:
                window.close()
            except BaseException:  # noqa: BLE001 - best-effort teardown
                pass
        app.processEvents()
        if created_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
    if status == 0:
        print("HA-UI self-test: OK")
    return status


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return run_self_test()

    app = ensure_application()
    try:
        actions = ServerActions(default_workspace_root())
    except HaUiError as exc:
        # A broken local setup must fail with a fixed code, not a traceback.
        print("HA-UI: %s" % exc.safe_text, file=sys.stderr)
        return 1
    window = MainWindow(actions)
    window.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
