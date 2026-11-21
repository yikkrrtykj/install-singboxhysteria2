"""End-to-end generation service (remote read + local HA chain).

The UI talks to this class from a worker thread. It is deliberately free of Qt:

* inject the two SSH sessions (real :class:`~ha_ui.core.ssh_client.ParamikoSession`
  or test fakes);
* it preflights both servers, reads the existing client inventories, reads and
  cross-checks the two HY2 certificate pins, downloads (or, with explicit
  consent, has the server CLI generate) the canonical exports, and then runs the
  local HA-02 -> HA-03 -> HA-04 -> friendly pipeline.

No password is passed to this layer: sessions are already authenticated, and
the passwords never leave the UI's credential manager / SSH connect call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from . import errors
from .chain import (
    GenerationPipeline,
    new_config_version,
    new_run_id,
    validate_selection,
)
from .errors import HaUiError
from .models import (
    CertPin,
    ClientRecord,
    GenerationResult,
    ProbePolicy,
    SelectedClient,
)
from .remote import (
    MIN_PIN_VALIDITY_HOURS,
    RemotePreflight,
    RemoteProvider,
    RemoteSession,
    pin_warning,
    validate_pins_pair,
)

MIN_PIN = MIN_PIN_VALIDITY_HOURS


@dataclass(frozen=True)
class ServerPreview:
    facts: RemotePreflight
    records: dict[str, ClientRecord]
    pins: CertPin


@dataclass
class PreviewResult:
    servers: dict[str, ServerPreview] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def clients_a(self) -> dict[str, ClientRecord]:
        return self.servers["A"].records

    @property
    def clients_b(self) -> dict[str, ClientRecord]:
        return self.servers["B"].records

    @property
    def names(self) -> list[str]:
        names = set(self.clients_a) | set(self.clients_b)
        return sorted(names, key=str.casefold)


class GenerationService:
    def __init__(self, workspace: Path,
                 provider_factory: Callable[[str, RemoteSession],
                                            RemoteProvider] = RemoteProvider,
                 pipeline: GenerationPipeline | None = None) -> None:
        self.workspace = Path(workspace)
        self._provider_factory = provider_factory
        self._pipeline = pipeline or GenerationPipeline(self.workspace)

    # ---------------------------------------------------------------- helpers --
    @staticmethod
    def _check_sessions(sessions: Mapping[str, RemoteSession]) -> None:
        if set(sessions) != {"A", "B"}:
            raise HaUiError(errors.E_CONFIG, detail="sessions")

    def _providers(self, sessions: Mapping[str, RemoteSession]
                   ) -> dict[str, RemoteProvider]:
        self._check_sessions(sessions)
        return {role: self._provider_factory(role, sessions[role])
                for role in ("A", "B")}

    # --------------------------------------------------------------- preview --
    def preview(self, sessions: Mapping[str, RemoteSession]) -> PreviewResult:
        providers = self._providers(sessions)
        result = PreviewResult()
        for role in ("A", "B"):
            provider = providers[role]
            facts = provider.preflight()
            records = provider.list_clients()
            pins = provider.read_pins()
            if len(pins) != 1:
                raise HaUiError(errors.E_REMOTE_PIN, detail=role)
            result.servers[role] = ServerPreview(
                facts=facts, records=records, pins=pins[role])
        validate_pins_pair({role: result.servers[role].pins
                            for role in ("A", "B")})
        warning = pin_warning({role: result.servers[role].pins
                               for role in ("A", "B")})
        if warning:
            result.warnings.append(warning)
        incomplete = []
        for name in result.names:
            a = result.clients_a.get(name)
            b = result.clients_b.get(name)
            if a is None or b is None or not a.complete or not b.complete:
                incomplete.append(name)
        if incomplete:
            result.warnings.append(
                "有 %d 个客户端仅单端存在或协议不完整，不能生成双活配置"
                % len(incomplete))
        return result

    # -------------------------------------------------------------- generate --
    def generate(self, *,
                 sessions: Mapping[str, RemoteSession],
                 selected: list[SelectedClient],
                 policy: ProbePolicy,
                 allow_cli: bool,
                 run_id: str | None = None,
                 config_version: str | None = None,
                 progress: Callable[[str], None] | None = None,
                 cancel: Callable[[], bool] | None = None,
                 cleanup_failed: bool = True) -> GenerationResult:
        report = progress or (lambda _stage: None)
        cancelled = cancel or (lambda: False)
        providers = self._providers(sessions)
        report("stage:preflight")
        for role in ("A", "B"):
            providers[role].preflight()
        report("stage:inventory")
        records = {role: providers[role].list_clients()
                   for role in ("A", "B")}
        validate_selection(selected, records["A"], records["B"])

        report("stage:pins")
        pins: dict[str, CertPin] = {}
        for role in ("A", "B"):
            found = providers[role].read_pins()
            if set(found) != {role}:
                raise HaUiError(errors.E_REMOTE_PIN, detail=role)
            pins[role] = found[role]
        validate_pins_pair(pins)
        if cancelled():
            raise HaUiError(errors.E_CANCELLED)

        report("stage:exports")
        names = [item.name for item in selected]
        exports: dict[str, dict[str, bytes]] = {"A": {}, "B": {}}
        for role in ("A", "B"):
            stale = [name for name in names
                     if not records[role][name].derived_export_present]
            if stale and not allow_cli:
                raise HaUiError(errors.E_REMOTE_EXPORT, detail="cli-consent")
            if stale:
                generated = providers[role].generate_exports(
                    stale, allow_cli=True)
                fresh = [name for name in names if name not in stale]
                downloaded = providers[role].read_exports(fresh)
                merged = dict(generated)
                merged.update(downloaded)
            else:
                merged = providers[role].read_exports(names)
            if set(merged) != set(names):
                raise HaUiError(errors.E_REMOTE_EXPORT, detail="missing")
            exports[role] = merged
        if cancelled():
            raise HaUiError(errors.E_CANCELLED)

        return self._pipeline.generate(
            run_id=run_id or new_run_id(),
            config_version=config_version or new_config_version(),
            policy=policy,
            selected=selected,
            exports=exports,
            pins=pins,
            progress=progress,
            cancel=cancel,
            cleanup_failed=cleanup_failed,
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
