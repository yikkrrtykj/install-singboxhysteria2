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
from typing import Callable, Mapping, Sequence

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
    ClientCreationResult,
    ClientRecord,
    CreationSideResult,
    GenerationResult,
    ProbePolicy,
    SelectedClient,
)
from .remote import (
    MIN_PIN_VALIDITY_HOURS,
    RESERVED_CLIENT_NAME,
    RemotePreflight,
    RemoteProvider,
    RemoteSession,
    pin_warning,
    validate_client_name,
    validate_pins_pair,
)

MIN_PIN = MIN_PIN_VALIDITY_HOURS

# Errors after which the remote write may have happened but cannot be proven
# completed. They must be surfaced as "uncertain", never as a clean failure.
_UNCERTAIN_CREATE_CODES = frozenset({
    errors.E_CREATE_UNCERTAIN,
    errors.E_REMOTE_VERIFY,
    errors.E_SSH_TIMEOUT,
    errors.E_SSH_CLOSED,
})

# ``E_REMOTE_CREATE`` detail tokens that prove the write was refused before the
# config file was replaced (or that the server itself proved the restore). Any
# other token — including a missing one — is uncertain: a clean "nothing was
# written" claim must never be the default.
_CLEAN_WRITE_REFUSALS = frozenset({
    "consistency", "incomplete", "missing-config", "name-invalid",
    "permission", "reserved", "exists", "lock", "create",
    "rolled-back",
})


def _pending_role_state(overview, record) -> str:
    """Per-side release decision from durable evidence + the live record.

    ``absent``       no claim and no request: nothing known is in flight.
    ``terminal-safe`` every same-name request ended in a proven outcome and the
                      live record agrees with it.
    ``blocked``      anything else: claim without record, unfinished/damaged
                      request, live worker, rollback_manual, or a live record
                      that contradicts the transaction outcome.
    """
    if overview.claim and not any(
            status.tx_id == overview.claim for status in overview.records):
        return "blocked"
    if not overview.records:
        return "blocked" if overview.claim else "absent"
    if any(not status.release_safe for status in overview.records):
        return "blocked"
    newest = overview.records[0]
    if newest.outcome == "created":
        return ("terminal-safe"
                if record is not None and record.exportable else "blocked")
    if newest.outcome in ("rolled-back", "refused"):
        return "terminal-safe" if record is None else "blocked"
    return "blocked"


def _creation_is_uncertain(exc: HaUiError) -> bool:
    if exc.code in _UNCERTAIN_CREATE_CODES:
        return True
    if exc.code == errors.E_REMOTE_CREATE:
        return exc.detail not in _CLEAN_WRITE_REFUSALS
    return False


@dataclass(frozen=True)
class ServerPreview:
    facts: RemotePreflight
    records: dict[str, ClientRecord]
    pins: CertPin


@dataclass
class PreviewResult:
    servers: dict[str, ServerPreview] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # Per client name, the durable managed-transaction state observed on both
    # sides: absent / terminal / running / unknown. Used by the UI to decide
    # whether an UNCERTAIN creation may be released.
    pending: dict[str, str] = field(default_factory=dict)

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
    def preview(self, sessions: Mapping[str, RemoteSession], *,
                pending_names: Sequence[str] = ()) -> PreviewResult:
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
        # Durable transaction state for names the UI still treats as pending.
        # Release requires a *proven* terminal outcome on every side plus a live
        # state that agrees; anything else stays blocked.
        for name in pending_names:
            states: list[str] = []
            for role in ("A", "B"):
                try:
                    overview = providers[role].pending_transactions(name)
                except HaUiError:
                    states.append("blocked")
                    continue
                states.append(_pending_role_state(
                    overview, result.servers[role].records.get(name)))
            if "blocked" in states:
                result.pending[name] = "blocked"
            elif all(state == "absent" for state in states):
                result.pending[name] = "absent"
            else:
                result.pending[name] = "terminal-safe"
        return result

    # ---------------------------------------------------------------- create --
    def create_client(self, *,
                      sessions: Mapping[str, RemoteSession],
                      name: str,
                      confirmed: bool,
                      allow_partial_repair: bool = False,
                      progress: Callable[[str], None] | None = None
                      ) -> ClientCreationResult:
        """Create one same-named client on both VPSes, sequentially.

        The two writes are **not** a distributed transaction. Before any write,
        both servers must pass preflight, the name must be absent on both (or
        present-and-complete on exactly one side when the operator explicitly
        authorised a repair), and the HY2 certificate identity must validate.
        A is committed first; B is attempted only if A is confirmed. A failed or
        uncertain B is reported as a partial result and A is never auto-deleted.

        The method returns a per-side receipt rather than raising for a write
        failure, because the UI must display "A 已创建；B 失败" accurately. It
        raises only for a pre-write refusal (existing client, incomplete
        existing client, pin/preflight failure) or an invalid request.
        """
        report = progress or (lambda _stage: None)
        if confirmed is not True:
            raise HaUiError(errors.E_USAGE, detail="create-consent")
        validated = validate_client_name(name)
        if validated.casefold() == RESERVED_CLIENT_NAME.casefold():
            raise HaUiError(errors.E_USAGE, detail="reserved-name")

        providers = self._providers(sessions)
        report("stage:create-preflight")
        for role in ("A", "B"):
            providers[role].preflight()
        records = {role: providers[role].list_clients()
                   for role in ("A", "B")}

        # Same identity gate as generation: the two HY2 certificates must be
        # independently valid. Creation itself does not need the pin values,
        # but this is the only shared trust anchor proving A/B role separation.
        report("stage:create-pins")
        pins: dict[str, CertPin] = {}
        for role in ("A", "B"):
            found = providers[role].read_pins()
            if set(found) != {role}:
                raise HaUiError(errors.E_REMOTE_PIN, detail=role)
            pins[role] = found[role]
        validate_pins_pair(pins)

        existing = tuple(role for role in ("A", "B")
                         if validated in records[role])
        if len(existing) == 2:
            raise HaUiError(errors.E_CLIENT_EXISTS, detail="AB")
        if existing:
            existing_role = existing[0]
            if not records[existing_role][validated].exportable:
                # complete() only proves both credentials exist; a structurally
                # anomalous record must not be treated as a valid repair base.
                raise HaUiError(errors.E_CLIENT_INCOMPLETE,
                                detail=existing_role)
            if not allow_partial_repair:
                raise HaUiError(errors.E_CLIENT_PARTIAL_EXISTS,
                                detail=existing_role)

        result = ClientCreationResult(name=validated,
                                      repaired_existing=existing)
        for role in existing:
            result.sides[role] = CreationSideResult(
                role=role, status="existing")

        stopped = False
        for role in ("A", "B"):
            if role in existing:
                continue
            if stopped:
                result.sides[role] = CreationSideResult(
                    role=role, status="skipped", detail="not-attempted")
                continue
            report("stage:create-" + role.lower())
            try:
                providers[role].create_client(validated, confirmed=True)
            except HaUiError as exc:
                if _creation_is_uncertain(exc):
                    result.sides[role] = CreationSideResult(
                        role=role, status="uncertain", code=exc.code,
                        detail=exc.detail)
                else:
                    result.sides[role] = CreationSideResult(
                        role=role, status="failed", code=exc.code,
                        detail=exc.detail)
                # Never attempt the next side after a failure/uncertain write:
                # the operator must inspect the actual state first.
                stopped = True
            else:
                result.sides[role] = CreationSideResult(
                    role=role, status="created")

        # A success claim is only returned after a fresh live read proves the
        # name is EXPORTABLE (both protocols and no structural anomaly) on every
        # side that should now hold it. Merely "both credentials exist" is not
        # enough: a duplicate/name-set-mismatch inventory cannot be generated.
        report("stage:create-verify")
        for role in ("A", "B"):
            side = result.sides.get(role)
            if side is None or side.status not in ("created", "existing"):
                continue
            try:
                live = providers[role].list_clients()
            except HaUiError as exc:
                result.sides[role] = CreationSideResult(
                    role=role, status="uncertain", code=exc.code,
                    detail="verify")
                continue
            record = live.get(validated)
            if record is None:
                if side.status == "created":
                    result.sides[role] = CreationSideResult(
                        role=role, status="failed",
                        code=errors.E_REMOTE_VERIFY, detail="missing")
                else:
                    result.sides[role] = CreationSideResult(
                        role=role, status="uncertain",
                        code=errors.E_REMOTE_VERIFY,
                        detail="existing-changed")
            elif not record.exportable:
                # The write is visible, but the client is not safely usable.
                # Never report it as created+generatable; the operator must look.
                if side.status == "created":
                    result.sides[role] = CreationSideResult(
                        role=role, status="uncertain",
                        code=errors.E_REMOTE_VERIFY, detail="incomplete")
                else:
                    result.sides[role] = CreationSideResult(
                        role=role, status="uncertain",
                        code=errors.E_REMOTE_VERIFY,
                        detail="existing-changed")
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
