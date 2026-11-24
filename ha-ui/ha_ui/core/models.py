"""Immutable data types shared by the UI, the SSH layer and the HA pipeline.

Nothing in this module may carry credential material: the rendered YAML stays
inside the private run directory, and passwords stay inside the Windows
Credential Manager and the short-lived SSH client memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping

SERVER_IDS = ("A", "B")
GROUPS = ("A-first", "B-first")
GROUP_TO_VPS = {"A-first": "A", "B-first": "B"}
VPS_TO_GROUP = {"A": "A-first", "B": "B-first"}

# Probe policy values accepted by the reviewed HA-04 fast-probe tool. The
# untouched HA-03 profile keeps the historical 60 s / 5000 ms policy and is
# preserved in the run directory as the comparison artifact.
INTERVALS = (3, 5, 10)
TIMEOUTS = (1000, 2000, 5000)
DEFAULT_INTERVAL = 5
DEFAULT_TIMEOUT = 5000


@dataclass(frozen=True)
class ServerConfig:
    """Non-secret identity of one VPS A/B. Never contains a password."""

    server_id: str
    alias: str = ""
    host: str = ""
    port: int = 22
    username: str = "root"
    host_key_fingerprint: str | None = None

    @property
    def role(self) -> str:
        return self.server_id

    @property
    def display_name(self) -> str:
        if self.alias:
            return "%s（%s）" % (self.server_id, self.alias)
        return self.server_id

    @property
    def host_key_confirmed(self) -> bool:
        return bool(self.host_key_fingerprint)


@dataclass(frozen=True)
class HostKeyInfo:
    algorithm: str
    fingerprint: str


@dataclass(frozen=True)
class ProbePolicy:
    interval: int = DEFAULT_INTERVAL
    timeout: int = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if self.interval not in INTERVALS:
            raise ValueError("interval")
        if self.timeout not in TIMEOUTS:
            raise ValueError("timeout")

    @property
    def label(self) -> str:
        return "%ss / %sms" % (self.interval, self.timeout)


@dataclass(frozen=True)
class ClientRecord:
    name: str
    reality_ok: bool
    hy2_ok: bool
    derived_export_present: bool
    problems: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """Both protocols carry a credential — protocol completeness only.

        This is NOT "safe to generate": ``problems`` (duplicate/name-set
        mismatch/unnamed entries/inbound-count anomalies) can invalidate the
        whole inventory. Every success or readiness decision must use
        :attr:`exportable`; ``complete`` is for display of one endpoint.
        """
        return self.reality_ok and self.hy2_ok

    @property
    def exportable(self) -> bool:
        """True only when the client is complete AND structurally sound."""
        return self.complete and not self.problems


@dataclass(frozen=True)
class CertPin:
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    source: str


@dataclass(frozen=True)
class RemoteFacts:
    root: bool
    os_release: str
    config_present: bool
    miaomiao_present: bool
    root_config_sha256: str | None = None


@dataclass(frozen=True)
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class StageOutcome:
    stage: str
    ok: bool
    code: str = ""
    summary: str = ""


@dataclass(frozen=True)
class DeliveredFile:
    client: str
    group: str
    filename: str
    path: str
    sha256: str


@dataclass
class GenerationResult:
    run_id: str
    files: list[DeliveredFile] = field(default_factory=list)
    stages: list[StageOutcome] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    failed_stage: StageOutcome | None = None

    @property
    def ok(self) -> bool:
        return self.failed_stage is None and bool(self.files)


CREATION_SIDE_STATUSES = ("created", "existing", "failed", "uncertain", "skipped")


@dataclass(frozen=True)
class CreationSideResult:
    """One VPS's fixed, non-secret creation outcome.

    ``code`` is a reviewed ``E_...`` token or an empty string. No credential,
    UUID, password, YAML or raw remote output may be stored here.
    """

    role: str
    status: str
    code: str = ""
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.role not in SERVER_IDS:
            raise ValueError("role")
        if self.status not in CREATION_SIDE_STATUSES:
            raise ValueError("status")

    @property
    def succeeded(self) -> bool:
        return self.status in ("created", "existing")


@dataclass
class ClientCreationResult:
    """The two independent per-side outcomes of one creation attempt.

    The two VPS writes are deliberately not a distributed transaction. A side
    that was created is never deleted because the other side failed; the UI must
    show ``partial`` instead of claiming completion.
    """

    name: str
    sides: dict[str, CreationSideResult] = field(default_factory=dict)
    repaired_existing: tuple[str, ...] = ()

    def side(self, role: str) -> CreationSideResult | None:
        return self.sides.get(role)

    @property
    def created_roles(self) -> tuple[str, ...]:
        return tuple(role for role in SERVER_IDS
                     if self.sides.get(role) is not None
                     and self.sides[role].status == "created")

    @property
    def failed_roles(self) -> tuple[str, ...]:
        return tuple(role for role in SERVER_IDS
                     if self.sides.get(role) is not None
                     and self.sides[role].status in ("failed", "uncertain"))

    @property
    def complete(self) -> bool:
        """True only when both sides are confirmed present after the attempt."""
        return all(self.sides.get(role) is not None
                   and self.sides[role].succeeded for role in SERVER_IDS)

    @property
    def partial(self) -> bool:
        """A write happened on one side while the other side is not confirmed."""
        return bool(self.created_roles) and not self.complete

    @property
    def ok(self) -> bool:
        return self.complete and not self.failed_roles


@dataclass(frozen=True)
class SelectedClient:
    name: str
    group: str

    def __post_init__(self) -> None:
        if self.group not in GROUPS:
            raise ValueError("group")


@dataclass(frozen=True)
class GenerationRequest:
    servers: Mapping[str, ServerConfig]
    clients: tuple[SelectedClient, ...]
    policy: ProbePolicy
    config_version: str
    output_dir: str
