"""Off-GUI-thread execution for blocking SSH and Credential Manager work.

Rules:

* a worker never raises into Qt: every exception is converted at this boundary
  and delivered as a :class:`~ha_ui.core.errors.HaUiError`; an unexpected
  exception becomes the fixed, detail-free ``E_INTERNAL`` (the original text is
  never rendered because it can embed paths or credentials);
* a result is delivered to the GUI thread through queued Qt signals only;
* :meth:`WorkerRunner.stop` (called from ``MainWindow.closeEvent``) drops every
  pending callback, so a late result from a worker that outlives the window is
  ignored instead of touching a destroyed widget.

Qt objects live in the GUI thread; :class:`FunctionWorker.run` is executed by
the global ``QThreadPool`` and only emits signals.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from ..core.errors import E_INTERNAL, HaUiError, wrap_unexpected

SuccessCallback = Callable[[Any], None]
ErrorCallback = Callable[[HaUiError], None]
DoneCallback = Callable[[], None]


class WorkerSignals(QObject):
    """Signals emitted from the pool thread and queued into the GUI thread.

    The token identifies the submission; a late token that :class:`WorkerRunner`
    no longer knows (cleared by ``stop()``) is ignored.
    """

    finished = Signal(int, object)   # token, result
    failed = Signal(int, object)     # token, HaUiError
    done = Signal(int)               # token, always last


class FunctionWorker(QRunnable):
    """Run one callable in the pool; convert every failure to ``E_INTERNAL``."""

    def __init__(self, token: int, function: Callable[[], Any]) -> None:
        super().__init__()
        self._token = token
        self._function = function
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    def run(self) -> None:  # noqa: D401 - QRunnable entry point
        try:
            result = self._function()
        except HaUiError as exc:
            self.signals.failed.emit(self._token, exc)
        except BaseException as exc:  # noqa: BLE001 - hard UI boundary
            self.signals.failed.emit(self._token, wrap_unexpected(exc))
        else:
            # An object emitted through a queued signal stays referenced until
            # the GUI thread handles it; a dataclass or bool is safe here.
            self.signals.finished.emit(self._token, result)
        finally:
            try:
                self.signals.done.emit(self._token)
            except RuntimeError:  # signals object already torn down at exit
                pass


class WorkerRunner(QObject):
    """Submit callables to the global thread pool and route results via Qt signals."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()
        self._active = True
        self._next_token = 1
        self._callbacks: dict[int, tuple[SuccessCallback | None,
                                         ErrorCallback | None,
                                         DoneCallback | None]] = {}
        # Keep the Python wrappers alive until ``done`` is delivered; the C++
        # QRunnable is owned (and deleted) by the thread pool itself.
        self._workers: dict[int, FunctionWorker] = {}

    # ------------------------------------------------------------------ submit --
    def run(
        self,
        function: Callable[[], Any],
        *,
        on_success: SuccessCallback | None = None,
        on_error: ErrorCallback | None = None,
        on_done: DoneCallback | None = None,
    ) -> int:
        """Run *function* in the pool; return the token (0 when stopped)."""
        if not self._active:
            return 0
        token = self._next_token
        self._next_token += 1
        worker = FunctionWorker(token, function)
        self._callbacks[token] = (on_success, on_error, on_done)
        self._workers[token] = worker
        worker.signals.finished.connect(self._handle_finished)
        worker.signals.failed.connect(self._handle_failed)
        worker.signals.done.connect(self._handle_done)
        self._pool.start(worker)
        return token

    # ------------------------------------------------------------------ stop ---
    def stop(self) -> None:
        """Ignore every pending/queued result (safe to call more than once)."""
        self._active = False
        self._callbacks.clear()

    @property
    def active(self) -> bool:
        return self._active

    # --------------------------------------------------------------- delivery --
    @Slot(int, object)
    def _handle_finished(self, token: int, result: object) -> None:
        callback = self._callbacks.get(token)
        if not self._active or callback is None:
            return
        self._invoke(callback[0], result)

    @Slot(int, object)
    def _handle_failed(self, token: int, error: object) -> None:
        callback = self._callbacks.get(token)
        if not self._active or callback is None:
            return
        failure = error if isinstance(error, HaUiError) else HaUiError(E_INTERNAL)
        self._invoke(callback[1], failure)

    @Slot(int)
    def _handle_done(self, token: int) -> None:
        callback = self._callbacks.pop(token, None)
        self._workers.pop(token, None)
        if not self._active or callback is None:
            return
        self._invoke(callback[2])

    @staticmethod
    def _invoke(callback: Callable[..., None] | None, *args: object) -> None:
        """Call a UI callback without letting its exception escape into Qt."""
        if callback is None:
            return
        try:
            callback(*args)
        except BaseException:  # noqa: BLE001 - defensive Qt boundary
            # A bug in a UI callback must not crash the event loop. The
            # operation itself has already reported its own failure through the
            # normal on_error path; rendering callback tracebacks is not safe
            # either (it may embed data held by the callback).
            pass
