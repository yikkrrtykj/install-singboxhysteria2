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
QMainWindow { background: #f3f5f8; }
QLabel#safetyBanner {
    background: #fff4ce; border: 1px solid #e2c56b; border-radius: 6px;
    color: #5a4300; padding: 8px 12px; font-weight: 600;
}
QGroupBox {
    background: #ffffff; border: 1px solid #d6dae1; border-radius: 8px;
    margin-top: 14px; padding: 10px 10px 8px 10px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 12px; padding: 0 4px;
    color: #1f2a37; font-weight: 600;
}
QLabel#connectionStatus { color: #1f2a37; font-weight: 600; }
QLabel#fingerprintStatus, QLabel#credentialHint, QLabel#hint { color: #5b6472; }
QLabel#hostKeyWarning { color: #9a2a00; font-weight: 600; }
QPushButton { padding: 5px 10px; }
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
