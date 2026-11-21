"""Per-operation session wiring for the client-management / generation tabs.

This module is the only place where the two GUI tabs meet the reviewed security
core. It is deliberately Qt-free so it is safe to run inside
:class:`~ha_ui.ui.workers.WorkerRunner` worker threads:

* the saved *non-secret* server identity is loaded from
  :class:`~ha_ui.ui.services.ServerActions`;
* a password is resolved per role from the current session field when the
  operator typed one, otherwise from the Windows Credential Manager;
* missing host / missing confirmed fingerprint / missing password are rejected
  with ``E_CONFIG`` / ``E_HOSTKEY_MISSING`` / ``E_CREDENTIAL_MISSING`` *before*
  any network use, so a connection attempt is never made with an incomplete
  identity;
* both pinned SSH sessions are opened for exactly one preview/generation call
  and are always closed in ``finally`` (including the failure of the second
  connect);
* the already-authenticated sessions are handed to the injected core
  :class:`~ha_ui.core.service.GenerationService`; this module never re-implements
  the generation gates.

Passwords are kept in local variables for the duration of one call and are
never stored on the service instance, logged or rendered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping, Protocol

from ..core import chain, errors, private_fs
from ..core.errors import HaUiError
from ..core.models import (
    GenerationResult,
    ProbePolicy,
    SelectedClient,
    ServerConfig,
)
from ..core.remote import RemoteSession
from ..core.service import GenerationService, PreviewResult
from .services import ServerActions

# Stage tokens emitted by the core pipeline -> fixed, safe UI labels. The raw
# token is only used as a mapping key; an unknown token is never rendered
# verbatim (it could, in a future refactor, carry an operator-derived value).
STAGE_LABELS: dict[str, str] = {
    "stage:preflight": "读取两端服务器状态",
    "stage:inventory": "读取两端客户端清单",
    "stage:pins": "校验证书 PIN 与有效期",
    "stage:exports": "读取规范导出（必要时运行 miaomiao 菜单）",
    "stage:validate": "本地校验导出与凭据",
    "stage:ha02": "HA-02 批量生成",
    "stage:ha03": "HA-03 证书校验与配置生成",
    "stage:ha04": "HA-04 快速探测策略生成",
    "stage:friendly": "发布 A-first / B-first 文件",
}
UNKNOWN_STAGE_LABEL = "处理中"


def format_stage(token: str) -> str:
    """Map a core progress token to a fixed, non-secret UI label."""
    return STAGE_LABELS.get(token, UNKNOWN_STAGE_LABEL)


class GenerationBackend(Protocol):
    """The core service methods the UI needs (kept small for test fakes)."""

    def preview(self, sessions: Mapping[str, RemoteSession]) -> PreviewResult: ...

    def generate(self, *, sessions: Mapping[str, RemoteSession],
                 selected: list[SelectedClient], policy: ProbePolicy,
                 allow_cli: bool, run_id: str | None = ...,
                 progress: Callable[[str], None] | None = ...,
                 cancel: Callable[[], bool] | None = ...,
                 cleanup_failed: bool = ...) -> GenerationResult: ...


class SessionGenerationService:
    """One operation == one pair of pinned sessions, always closed again."""

    def __init__(
        self,
        workspace: str | Path,
        actions: ServerActions,
        *,
        generation_service: GenerationBackend | None = None,
        open_folder_fn: Callable[[str | Path], None] | None = None,
        discard_failed_run_fn: Callable[[Path, str], None] | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self._actions = actions
        self._service: GenerationBackend = (
            generation_service
            if generation_service is not None
            else GenerationService(self.workspace))
        self._open_folder = (open_folder_fn if open_folder_fn is not None
                             else private_fs.open_folder)
        self._discard_failed_run = (
            discard_failed_run_fn if discard_failed_run_fn is not None
            else chain.discard_failed_run)

    # ------------------------------------------------------------- identities --
    def _validated_servers(self) -> dict[str, ServerConfig]:
        """Load both identities and reject an incomplete pair before any SSH."""
        servers = self._actions.load_servers()
        for role in ("A", "B"):
            server = servers.get(role)
            if server is None or not server.host:
                raise HaUiError(errors.E_CONFIG, detail=role)
        for role in ("A", "B"):
            if not servers[role].host_key_fingerprint:
                raise HaUiError(errors.E_HOSTKEY_MISSING, detail=role)
        return servers

    def _resolve_passwords(
        self,
        password_overrides: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Session field first (operator just typed it), then the Windows vault."""
        overrides = password_overrides or {}
        passwords: dict[str, str] = {}
        for role in ("A", "B"):
            typed = overrides.get(role, "")
            password = typed if isinstance(typed, str) else ""
            if not password:
                # The vault read can fail (E_CREDENTIAL_STORE); that error is
                # already safe and is propagated unchanged.
                password = self._actions.load_password(role) or ""
            if not password:
                raise HaUiError(errors.E_CREDENTIAL_MISSING, detail=role)
            passwords[role] = password
        return passwords

    @staticmethod
    def _cancel_requested(cancel: Callable[[], bool] | None) -> bool:
        return bool(cancel and cancel())

    # --------------------------------------------------------------- sessions --
    def _open_sessions(
        self,
        password_overrides: Mapping[str, str] | None,
        cancel: Callable[[], bool] | None,
    ) -> dict[str, RemoteSession]:
        servers = self._validated_servers()
        passwords = self._resolve_passwords(password_overrides)
        if self._cancel_requested(cancel):
            raise HaUiError(errors.E_CANCELLED)
        sessions: dict[str, RemoteSession] = {}
        try:
            for role in ("A", "B"):
                if self._cancel_requested(cancel):
                    raise HaUiError(errors.E_CANCELLED)
                # ServerActions.open_session re-checks host/fingerprint/password
                # and pins the confirmed fingerprint inside ssh_client.connect.
                sessions[role] = self._actions.open_session(
                    servers[role], passwords[role])
        except BaseException:
            # A failed/cancelled B connect must not leak the A session.
            self._close_sessions(sessions)
            raise
        return sessions

    @staticmethod
    def _close_sessions(sessions: Mapping[str, RemoteSession]) -> None:
        for session in sessions.values():
            try:
                session.close()
            except Exception:  # noqa: BLE001 - closing must not mask errors
                pass

    # ---------------------------------------------------------------- preview --
    def preview(self, *, password_overrides: Mapping[str, str] | None = None,
                cancel: Callable[[], bool] | None = None) -> PreviewResult:
        sessions = self._open_sessions(password_overrides, cancel)
        try:
            return self._service.preview(sessions)
        finally:
            self._close_sessions(sessions)

    # --------------------------------------------------------------- generate --
    def generate(
        self,
        *,
        selected: list[SelectedClient],
        policy: ProbePolicy,
        allow_cli: bool,
        run_id: str | None = None,
        password_overrides: Mapping[str, str] | None = None,
        progress: Callable[[str], None] | None = None,
        cancel: Callable[[], bool] | None = None,
        cleanup_failed: bool = False,
    ) -> GenerationResult:
        """Run one generation attempt; both sessions are closed in ``finally``.

        ``cleanup_failed=False`` keeps a failed attempt's private run directory
        so the operator can inspect it and remove it explicitly with
        :meth:`discard_failed_run` (the UI's 删除失败运行目录 button).
        """
        sessions = self._open_sessions(password_overrides, cancel)
        try:
            return self._service.generate(
                sessions=sessions,
                selected=selected,
                policy=policy,
                allow_cli=allow_cli,
                run_id=run_id,
                progress=progress,
                cancel=cancel,
                cleanup_failed=cleanup_failed,
            )
        finally:
            self._close_sessions(sessions)

    # ---------------------------------------------------------------- helpers --
    @staticmethod
    def new_run_id() -> str:
        return chain.new_run_id()

    def run_dir_exists(self, run_id: str | None) -> bool:
        """Whether a failed attempt's staging directory is present locally."""
        if not isinstance(run_id, str) or not chain.RUN_ID_RE.fullmatch(run_id):
            return False
        try:
            return (self.workspace / "runs" / run_id).is_dir()
        except OSError:
            return False

    def open_output_folder(self, path: str | Path) -> None:
        self._open_folder(path)

    def discard_failed_run(self, run_id: str) -> None:
        self._discard_failed_run(self.workspace, run_id)


__all__ = [
    "STAGE_LABELS",
    "UNKNOWN_STAGE_LABEL",
    "GenerationBackend",
    "SessionGenerationService",
    "format_stage",
]
