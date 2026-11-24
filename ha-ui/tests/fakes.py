"""Hermetic fakes and synthetic fixtures for the HA-UI data/HA-chain slice.

Issue #110: the Windows GUI reads two VPS over a pinned root SSH channel and
then runs the *reviewed* HA-02 -> HA-03 -> HA-04 -> friendly-export tools
locally.  These fakes let the tests drive that slice end-to-end on a plain
Windows host:

* :class:`FakeSession` implements the ``RemoteSession`` protocol of
  :mod:`ha_ui.core.remote`: it script-matches the fixed command strings the
  provider sends and returns realistic, per-VPS metadata.  Every command the
  provider would ever send across the trust boundary is answered here; an
  unrecognised command raises ``AssertionError`` (fail closed, so a drift in
  the provider command set is noticed instead of silently "passing").
* :class:`FakeProvider` is the smallest object ``GenerationService`` needs
  (``preflight``/``list_clients``/``read_pins``/``read_exports``/
  ``generate_exports``) and can inject one fixed :class:`HaUiError` per method.
* :func:`synthetic_batch` builds the canonical two-VPS exports used by
  ``.scratch/chain_smoke.py`` (the reviewed tools accept these bytes), the
  matching ``SelectedClient`` list and the credential sentinels the receipt
  must never contain.

No network, no real VPS, no Windows Credential Manager and no credentials:
every address is RFC 5737 documentation space (``203.0.113.0/24`` /
``198.51.100.0/24``) and every UUID/password is a synthetic sentinel.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid as uuidlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Mapping, Sequence

from ha_ui.core import errors, private_fs, remote
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import (
    CertPin,
    ClientRecord,
    ProbePolicy,
    SelectedClient,
    ToolResult,
)
from ha_ui.core.remote import (
    CLIENTS_DIR,
    DERIVED_IDENTITY_END,
    MAX_EXPORT_BYTES,
    RemotePreflight,
)

# The worktree root is the ancestor of ``ha-ui/tests/fakes.py``; never rely on
# the current working directory (pytest is run from ``ha-ui``).
WORKTREE = Path(__file__).resolve().parents[2]
TOOLS_DIR = WORKTREE / "tools"
SCRATCH_ROOT = WORKTREE / ".scratch" / "tests"

# Synthetic but canonical metric: every status/derived read compares against it.
DEFAULT_CONFIG_MTIME = 1_763_600_000
# Identity of the scripted live config file. A successful add rewrites it; a
# proven rollback restores the exact pre-write value, exactly like the real
# ``restore_file_atomically`` path.
DEFAULT_CONFIG_SHA = hashlib.sha256(b"scripted-config").hexdigest()

# Synthetic two-VPS fixture (RFC 5737 documentation addresses).
SERVER_A = "203.0.113.7"
SERVER_B = "198.51.100.9"
PUBKEY_A = "A" * 43
PUBKEY_B = "B" * 43
SHORTID_A = "0123456789abcdef"
SHORTID_B = "fedcba9876543210"

TEST_POLICY = ProbePolicy(5, 2000)

# Deliberately letter-bearing so an upper-case normalisation can be observed.
PIN_A = "aa" * 32
PIN_B = "bb" * 32
NOT_BEFORE = datetime(2026, 5, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2027, 5, 1, tzinfo=timezone.utc)


def uuid_for(role: str, index: int) -> str:
    """Synthetic canonical UUID sentinel for one role/client index."""
    return "%s1%06d-1111-2222-3333-%012d" % (role.lower(), index, index)


def password_for(role: str, index: int) -> str:
    """Synthetic HY2 password sentinel for one role/client index."""
    return "ha-%s-%02d-pppppppppppppppppppppppp" % (role.upper(), index)


# --------------------------------------------------------------------------- #
# Canonical synthetic exports (copied from .scratch/chain_smoke.py).
# --------------------------------------------------------------------------- #
_CANONICAL_TEMPLATE = """mixed-port: 7897
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
unified-delay: true
ipv6: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: "0.0.0.0:53"
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

tun:
  enable: true
  stack: mixed
  device: Mihomo
  mtu: 1420
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53

proxies:
  - name: Reality
    type: vless
    server: {server}
    port: 8443
    uuid: {uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: {pubkey}
      short-id: {shortid}

  - name: Hysteria2
    type: hysteria2
    server: {server}
    port: 8444
    password: {password}
    sni: www.example.com
    skip-cert-verify: true
    alpn:
      - h3

proxy-groups:
  - name: 节点选择
    type: select
    default-selected: 自动选择
    proxies:
      - Reality
      - Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: fallback
    proxies:
      - Reality
      - Hysteria2
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"


rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择

"""


def canonical_export(server: str, uuid: str, password: str, *,
                     pubkey: str = PUBKEY_A,
                     shortid: str = SHORTID_A) -> bytes:
    """One canonical single-VPS export the reviewed merge tool accepts."""
    return _CANONICAL_TEMPLATE.format(server=server, uuid=uuid,
                                     password=password, pubkey=pubkey,
                                     shortid=shortid).encode("utf-8")


@dataclass(frozen=True)
class SyntheticBatch:
    """A complete synthetic A/B batch: selection, exports and sentinels."""

    selected: list[SelectedClient]
    exports: dict[str, dict[str, bytes]]
    sentinels: tuple[str, ...]

    def run_pins(self) -> dict[str, CertPin]:
        return pins_pair()

    def expected_filenames(self) -> list[str]:
        return ["%s-%s.yaml" % (item.name, item.group)
                for item in self.selected]


def synthetic_batch(
    entries: Sequence[tuple[str, str]] | None = None, *,
    shared_credentials: bool = False,
) -> SyntheticBatch:
    """Build the canonical two-client A/B fixture used by the smoke reference."""
    if entries is None:
        entries = (("event-ob01", "A-first"), ("event-ob02", "B-first"))
    selected = [SelectedClient(name, group) for name, group in entries]
    exports: dict[str, dict[str, bytes]] = {"A": {}, "B": {}}
    sentinels: list[str] = []
    for index, item in enumerate(selected, 1):
        uuid_a = uuid_for("A", index)
        password_a = password_for("A", index)
        uuid_b = uuid_for("B", index)
        password_b = password_for("B", index)
        if shared_credentials:
            uuid_b, password_b = uuid_a, password_a
        exports["A"][item.name] = canonical_export(
            SERVER_A, uuid_a, password_a, pubkey=PUBKEY_A,
            shortid=SHORTID_A)
        exports["B"][item.name] = canonical_export(
            SERVER_B, uuid_b, password_b, pubkey=PUBKEY_B,
            shortid=SHORTID_B)
        for sentinel in (uuid_a, uuid_b, password_a, password_b):
            if sentinel not in sentinels:
                sentinels.append(sentinel)
    return SyntheticBatch(selected=selected, exports=exports,
                          sentinels=tuple(sentinels))


def pins_pair(*, a: str = PIN_A, b: str = PIN_B,
              not_before: datetime = NOT_BEFORE,
              not_after: datetime = NOT_AFTER,
              source: str = "test-fixture") -> dict[str, CertPin]:
    """A valid (CURRENT-date-valid) A/B pin pair for pipeline calls."""
    return {
        "A": CertPin(a, not_before, not_after, source),
        "B": CertPin(b, not_before, not_after, source),
    }


def cert_pin(fingerprint: str = PIN_A,
             not_before: datetime = NOT_BEFORE,
             not_after: datetime = NOT_AFTER,
             source: str = "test-fixture") -> CertPin:
    return CertPin(fingerprint, not_before, not_after, source)


# --------------------------------------------------------------------------- #
# Temporary private workspaces below the worktree (system temp is not safe).
# --------------------------------------------------------------------------- #
def new_workspace(label: str = "ws") -> Path:
    """Create a fresh, ACL-verified private workspace directory."""
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    workspace = SCRATCH_ROOT / ("%s-%s" % (label, uuidlib.uuid4().hex[:12]))
    private_fs.ensure_private_dir(workspace, workspace=workspace)
    return workspace


def create_private_workspace(label: str = "ws", *, monkeypatch=None) -> Path:
    """Create a private workspace and (with ``monkeypatch``) pin the env."""
    workspace = new_workspace(label)
    if monkeypatch is not None:
        monkeypatch.setenv("HA_UI_HOME", str(workspace))
        monkeypatch.setenv("HA_UI_TOOLS_DIR", str(TOOLS_DIR))
    return workspace


def remove_workspace(workspace: str | os.PathLike) -> None:
    shutil.rmtree(str(workspace), ignore_errors=True)


@contextmanager
def workspace_environment(label: str = "ws") -> Iterator[Path]:
    """Module-scoped style workspace whose env vars are restored afterwards."""
    old = {key: os.environ.get(key)
           for key in ("HA_UI_HOME", "HA_UI_TOOLS_DIR")}
    workspace = new_workspace(label)
    os.environ["HA_UI_HOME"] = str(workspace)
    os.environ["HA_UI_TOOLS_DIR"] = str(TOOLS_DIR)
    try:
        yield workspace
    finally:
        remove_workspace(workspace)
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def snapshot_files(root: str | os.PathLike) -> dict[Path, str]:
    """Map every regular file below *root* to its SHA-256 (no-clobber proof)."""
    result: dict[Path, str] = {}
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            result[path] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def file_sha256(path: str | os.PathLike) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass
class ChainRun:
    """A successfully generated run, with a snapshot of its artifacts."""

    workspace: Path
    batch: SyntheticBatch
    result: object
    run_id: str
    artifacts: dict[Path, str] = field(default_factory=dict)

    @property
    def run_root(self) -> Path:
        return self.workspace / "runs" / self.run_id

    def delivered_paths(self) -> list[Path]:
        return [Path(entry.path) for entry in self.result.files]

    def assert_artifacts_untouched(self) -> None:
        """Fail if any previously delivered artifact changed or disappeared."""
        for path, digest in self.artifacts.items():
            assert path.is_file(), "previous artifact disappeared: %s" % path
            assert file_sha256(path) == digest, (
                "previous artifact was modified: %s" % path)


# --------------------------------------------------------------------------- #
# Remote session fake (one scripted VPS).
# --------------------------------------------------------------------------- #
@dataclass
class DerivedState:
    """Metadata of one derived ``/root/sbox/clients/<name>/mihomo.yaml``."""

    mode: int = 0o600
    uid: int = 0
    size: int = 2048
    fresh: bool = True


@dataclass
class ClientSpec:
    """One scripted client of one VPS.

    ``reality_cred``/``hy2_cred`` are ``True`` for a present credential,
    ``False`` for an entry with an empty credential and ``None`` for a missing
    protocol entry.  ``derived`` ``None`` means "no derived file on disk".
    """

    name: str | None = None
    reality_cred: bool | None = True
    hy2_cred: bool | None = True
    derived: DerivedState | None = None


@dataclass
class VpsFacts:
    """The answer set of the remote preflight command."""

    root: bool = True
    os_name: str = "Linux"
    config_present: bool = True
    state_present: bool = True
    manager_present: bool = True
    jq_present: bool = True
    openssl_present: bool = True
    api_present: bool = True
    management_active: bool = False
    config_mtime: int = DEFAULT_CONFIG_MTIME
    config_sha: str = DEFAULT_CONFIG_SHA
    reality_inbounds: int = 1
    hy2_inbounds: int = 1
    preflight_rc: int = 0
    curl_present: bool = True
    timeout_present: bool = True
    missing_host_deps: tuple[str, ...] = ()


@dataclass
class PinsReply:
    """The answer of the remote HY2 pin command."""

    fingerprint: str = PIN_A
    not_before: str = "2026-05-01T00:00:00Z"
    not_after: str = "2027-05-01T00:00:00Z"
    rc: int = 0
    stderr: str = ""
    raw_stdout: str | None = None


class FakeSession:
    """Scripted ``RemoteSession`` for a single VPS (no network, no SSH)."""

    def __init__(self, role: str = "A", *, facts: VpsFacts | None = None,
                 clients: Sequence[ClientSpec] = (),
                 pins: PinsReply | None = None,
                 exports: Mapping[str, bytes] | None = None,
                 hash_overrides: Mapping[str, str] | None = None,
                 missing_exports: Sequence[str] = (),
                 menu_side_effect: bool = True,
                 menu_end_marker: bool = True,
                 menu_exit: int = 0,
                 menu_pipe_exit: int = 0,
                 menu_printf_exit: int = 0,
                 menu_rc_marker: bool = True,
                 menu_transcript_markers: bool = True,
                 menu_success: str = "all",
                 menu_fail: str | None = None,
                 menu_corrupt: str | None = None,
                 menu_extra: str = "",
                 add_side_effect: bool = True,
                 add_fail: str | None = None,
                 add_success_marker: bool = True,
                 add_commit_marker: bool = True,
                 add_no_process: bool = False,
                 add_menu_rc: tuple[int, int, int] = (0, 0, 0),
                 add_end_marker: bool = True,
                 add_timeout: bool = False,
                 add_timeout_write: bool = False,
                 add_timeout_stage: str | None = None,
                 add_duplicate: bool = False,
                 add_raise_timeout: bool = False) -> None:
        self.role = role
        self.facts = facts or VpsFacts()
        self.clients = list(clients)
        default_pin = PIN_A if role == "A" else PIN_B
        self.pins = pins or PinsReply(fingerprint=default_pin)
        self.exports = dict(exports or {})
        self.hash_overrides = dict(hash_overrides or {})
        self.missing_exports = set(missing_exports)
        self.menu_side_effect = menu_side_effect
        self.menu_end_marker = menu_end_marker
        # Failure-injection knobs for the menu generation contract.
        self.menu_exit = menu_exit
        self.menu_pipe_exit = menu_pipe_exit
        self.menu_printf_exit = menu_printf_exit
        self.menu_rc_marker = menu_rc_marker
        self.menu_transcript_markers = menu_transcript_markers
        self.menu_success = menu_success
        self.menu_fail = menu_fail
        self.menu_corrupt = menu_corrupt
        self.menu_extra = menu_extra
        self.add_side_effect = add_side_effect
        self.add_fail = add_fail
        self.add_success_marker = add_success_marker
        self.add_commit_marker = add_commit_marker
        self.add_no_process = add_no_process
        self.add_menu_rc = add_menu_rc
        self.add_end_marker = add_end_marker
        self.add_timeout = add_timeout
        self.add_timeout_write = add_timeout_write
        self.add_timeout_stage = add_timeout_stage
        self.add_duplicate = add_duplicate
        self.add_raise_timeout = add_raise_timeout
        self.commands: list[str] = []
        self.downloads: list[str] = []
        self.menu_invoked = False
        self.create_invoked = False
        self.created_credentials: dict[str, tuple[str, str]] = {}
        self._created_counter = 0
        self.identity_calls = 0
        self.derived: dict[str, DerivedState] = {}
        self._mtime_epoch: dict[str, int] = {}
        self._mtime_ns: dict[str, int] = {}
        for spec in self.clients:
            if spec.name and spec.derived is not None:
                self.derived[spec.name] = spec.derived
                base = (self.facts.config_mtime if spec.derived.fresh
                        else self.facts.config_mtime - 600)
                self._mtime_epoch[spec.name] = base
                self._mtime_ns[spec.name] = 1

    # ------------------------------------------------------------- protocol --
    def exec(self, command: str, *, stdin_data: bytes | None = None,
             timeout: float = 60.0,
             max_output: int = 1024 * 1024) -> tuple[int, str, str]:
        del stdin_data, timeout, max_output
        self.commands.append(command)
        if "HAUI_MENU_END" in command or "ha-ui-installer" in command:
            if re.search(r"(?:^|\n)2\n([A-Za-z0-9][A-Za-z0-9._-]*)\n0\n",
                         command):
                return self._add_menu(command)
            return self._menu(command)
        if "HAUI_STAT_END" in command:
            return self._identity(command)
        if "id -u" in command:
            return self._preflight()
        if "jq -c" in command:
            return self._list()
        if "BEGIN CERTIFICATE" in command:
            return self._pins()
        if command.startswith("sha256sum "):
            return self._sha256sum(command)
        # Fail closed: the provider must never send an unreviewed command.
        raise AssertionError(
            "FakeSession(%s): unexpected remote command" % self.role)

    def download_file(self, remote_path: str, *,
                      max_bytes: int = MAX_EXPORT_BYTES) -> bytes:
        del max_bytes
        self.downloads.append(remote_path)
        prefix = CLIENTS_DIR + "/"
        if not remote_path.startswith(prefix) or not remote_path.endswith(
                "/mihomo.yaml"):
            raise AssertionError(
                "FakeSession(%s): unexpected download path" % self.role)
        name = remote_path[len(prefix):].rsplit("/", 1)[0]
        if name in self.missing_exports or name not in self.exports:
            raise HaUiError(errors.E_REMOTE_FILE, detail="missing")
        return self.exports[name]

    # -------------------------------------------------------------- scripts --
    def _preflight(self) -> tuple[int, str, str]:
        facts = self.facts
        if facts.preflight_rc != 0:
            return facts.preflight_rc, "", "preflight: FAIL E_REMOTE\n"

        def _presence(key: str, present: bool) -> str:
            return "%s=%s" % (key, "present" if present else "missing")

        lines = [
            str(0 if facts.root else 1000),
            facts.os_name,
            _presence("config", facts.config_present),
            _presence("state", facts.state_present),
            _presence("manager", facts.manager_present),
            _presence("jq", facts.jq_present),
            _presence("openssl", facts.openssl_present),
            "management=%s" % ("active" if facts.management_active
                               else "inactive"),
            _presence("api", facts.api_present),
            _presence("curl", facts.curl_present),
            _presence("timeout", facts.timeout_present),
            "cfgsha=%s" % (facts.config_sha if facts.config_present
                           else "none"),
            "mtime=%d" % facts.config_mtime,
        ]
        for dep in remote.INSTALLER_HOST_DEPS:
            lines.append("hostdep_%s=%s" % (
                dep, "missing" if dep in facts.missing_host_deps
                else "present"))
        return 0, "\n".join(lines) + "\n", ""

    def _list(self) -> tuple[int, str, str]:
        facts = self.facts
        reality = [{"name": spec.name or "", "cred": bool(spec.reality_cred)}
                   for spec in self.clients if spec.reality_cred is not None]
        hy2 = [{"name": spec.name or "", "cred": bool(spec.hy2_cred)}
               for spec in self.clients if spec.hy2_cred is not None]
        document = {
            "rn": facts.reality_inbounds,
            "hn": facts.hy2_inbounds,
            "reality": reality,
            "hy2": hy2,
        }
        lines = [
            "mtime=%d" % facts.config_mtime,
            "cfgsha=%s" % (facts.config_sha if facts.config_present
                           else "none"),
            json.dumps(document, separators=(",", ":"), ensure_ascii=True),
            "DERIVED",
        ]
        for name, derived in self.derived.items():
            mtime = (facts.config_mtime if derived.fresh
                     else facts.config_mtime - 600)
            lines.append("%s/%s/mihomo.yaml|%s|%d|%d|%d" % (
                CLIENTS_DIR, name, format(int(derived.mode), "o"),
                derived.uid, derived.size, mtime))
        return 0, "\n".join(lines) + "\n", ""

    def _pins(self) -> tuple[int, str, str]:
        if self.pins.rc != 0:
            return self.pins.rc, "", self.pins.stderr
        if self.pins.raw_stdout is not None:
            return 0, self.pins.raw_stdout, ""
        return 0, "fingerprint=%s not_before=%s not_after=%s\n" % (
            self.pins.fingerprint, self.pins.not_before,
            self.pins.not_after), ""

    def _sha256sum(self, command: str) -> tuple[int, str, str]:
        prefix = CLIENTS_DIR + "/"
        paths = [token for token in command.split()
                 if token.startswith(prefix)]
        lines = []
        for path in paths:
            name = path[len(prefix):].split("/", 1)[0]
            if name in self.missing_exports:
                return 1, "", "sha256sum: remote file unavailable\n"
            digest = self.hash_overrides.get(name)
            if digest is None:
                payload = self.exports.get(name)
                if payload is None:
                    return 1, "", "sha256sum: remote file unavailable\n"
                digest = hashlib.sha256(payload).hexdigest()
            lines.append("%s  %s" % (digest, path))
        return 0, "\n".join(lines) + ("\n" if lines else ""), ""

    def _write_derived(self, name: str) -> None:
        state = DerivedState()
        if self.menu_corrupt == "mode":
            state.mode = 0o644
        elif self.menu_corrupt == "uid":
            state.uid = 1000
        elif self.menu_corrupt == "size":
            state.size = 0
        self.derived[name] = state
        self._mtime_epoch[name] = self.facts.config_mtime + 1
        self._mtime_ns[name] = self._mtime_ns.get(name, 1) + 1

    def _identity(self, command: str) -> tuple[int, str, str]:
        """The pre/post identity command (stat + sha256sum)."""
        self.identity_calls += 1
        prefix = CLIENTS_DIR + "/"
        paths = [token for token in command.split()
                 if token.startswith(prefix) and token.endswith("/mihomo.yaml")]
        stat_lines: list[str] = []
        sha_lines: list[str] = []
        for path in paths:
            name = path[len(prefix):].split("/", 1)[0]
            derived = self.derived.get(name)
            if derived is None:
                continue
            epoch = self._mtime_epoch.get(name, self.facts.config_mtime)
            ns = self._mtime_ns.get(name, 1)
            stat_lines.append("%s|%s|%s|%d|%d|%d|2026-11-21 17:00:00.%09d +0000"
                              % ("regular file", path,
                                 format(int(derived.mode), "o"), derived.uid,
                                 derived.size, epoch, ns))
            payload = self.exports.get(name)
            if payload is not None:
                digest = self.hash_overrides.get(
                    name, hashlib.sha256(payload).hexdigest())
            else:
                digest = self.hash_overrides.get(name, "00" * 32)
            sha_lines.append("%s  %s" % (digest, path))
        output = "\n".join(stat_lines + [DERIVED_IDENTITY_END] + sha_lines)
        return 0, output + ("\n" if output else ""), ""

    def _menu(self, command: str) -> tuple[int, str, str]:
        self.menu_invoked = True
        if self.menu_fail is not None:
            return 0, "HAUI_MENU_FAIL=%s\n" % self.menu_fail, ""
        requested = re.findall(
            r"\n3\n([A-Za-z0-9][A-Za-z0-9._-]*)\n", command)
        if not requested:
            requested = list(self.derived)
        written = []
        if self.menu_side_effect:
            written = requested
            for name in written:
                self._write_derived(name)
        if self.menu_success == "none":
            claimed = []
        elif self.menu_success == "first":
            claimed = requested[:1]
        else:
            claimed = requested
        lines: list[str] = []
        if self.menu_transcript_markers:
            lines.append("***** 客户端管理 *****")
            lines.append("NAME             REALITY      HY2")
        for name in claimed:
            lines.append(
                "客户端 '%s' 的 Mihomo 配置已生成: %s/%s/mihomo.yaml"
                "（使用 '%s' 自己的 UUID/password）"
                % (name, CLIENTS_DIR, name, name))
        if self.menu_extra:
            lines.append(self.menu_extra)
        output = "\n".join(lines)
        if self.menu_rc_marker:
            output += ("\nHAUI_MENU_RC=%d,%d,%d"
                       % (self.menu_printf_exit, self.menu_exit,
                          self.menu_pipe_exit))
        if self.menu_end_marker:
            output += "\nHAUI_MENU_END"
        return 0, output + "\n", ""

    def _add_menu(self, command: str) -> tuple[int, str, str]:
        """Scripted menu 10→2 canonical add path for one client."""
        self.create_invoked = True
        if self.menu_fail is not None:
            return 0, "HAUI_MENU_FAIL=%s\n" % self.menu_fail, ""
        match = re.search(r"(?:^|\n)2\n([A-Za-z0-9][A-Za-z0-9._-]*)\n0\n",
                          command)
        assert match is not None
        name = match.group(1)
        before_sha = self.facts.config_sha
        if self.add_raise_timeout:
            raise HaUiError(errors.E_SSH_TIMEOUT, detail="channel")
        if self.add_timeout:
            if self.add_timeout_write:
                # The write landed, then the menu was killed before printing
                # anything: no transcript evidence at all.
                self._scripted_replace(name)
            return 0, ("***** 客户端管理 *****\n"
                       "正在添加客户端…\n"
                       "HAUI_MENU_RC=0,124,0\nHAUI_MENU_END\n"), ""
        if self.add_timeout_stage is not None:
            # A timeout at a named commit stage: the transcript stops there and
            # the remote process state is unknown (it may still be running).
            stage = self.add_timeout_stage
            if stage in ("reload", "health", "rollback"):
                self._scripted_replace(name)
            lines = ["***** 客户端管理 *****", "2. 添加客户端"]
            if stage == "replace":
                lines.append("正在写入 add candidate…")
            elif stage == "reload":
                lines.append("正在重载 sing-box…")
            elif stage == "health":
                lines.append("reload 后健康检查失败（add client %s），自动回滚..." % name)
            elif stage == "rollback":
                lines.append("正在从备份恢复上一份配置…")
            else:
                raise AssertionError("unknown add timeout stage: %r" % stage)
            return self._add_frame(lines)
        existing = any(spec.name == name for spec in self.clients)
        if existing or self.add_fail is not None:
            if existing:
                warning = "客户端 '%s' 已存在（Reality 或 HY2），拒绝重复添加" % name
            elif self.add_fail == "exists":
                warning = "客户端 '%s' 已存在（Reality 或 HY2），拒绝重复添加" % name
            elif self.add_fail == "lock":
                warning = "配置锁 /root/sbox/config.lock 获取失败或超时（15s），操作已中止（fail-closed）"
            elif self.add_fail == "lock-after-write":
                # The refusal token is a pre-write code, but the live bytes and
                # the client set changed: reconciliation must not call this a
                # clean refusal.
                self._scripted_replace(name)
                warning = "配置锁 /root/sbox/config.lock 获取失败或超时（15s），操作已中止（fail-closed）"
            elif self.add_fail == "consistency":
                warning = "当前 Reality/HY2 用户集合不一致，先修复后再添加客户端"
            elif self.add_fail == "rollback":
                # lib/client-management.sh:338 — the ONLY proven restore.
                warning = ("reload 后健康检查失败（add client %s），自动回滚...\n"
                           "已回滚并重新加载上一份配置" % name)
            elif self.add_fail == "rolled-back-stale":
                # The sentence claims a restore, but the bytes did not go back:
                # reconciliation must refuse to treat this as a clean failure.
                self._scripted_replace(name)
                warning = ("reload 后健康检查失败（add client %s），自动回滚...\n"
                           "已回滚并重新加载上一份配置" % name)
            elif self.add_fail == "rollback-failed":
                # lib/client-management.sh:330 — restore itself failed.
                self._scripted_replace(name)
                warning = ("reload 后健康检查失败（add client %s），自动回滚...\n"
                           "回滚恢复失败，请立即人工介入！备份: /root/sbox/singbox.json.bak"
                           % name)
            elif self.add_fail == "rollback-unconfirmed":
                # lib/client-management.sh:344 — bytes restored, service not
                # confirmed: the file hash equals the pre-write value but the
                # server explicitly did NOT prove recovery.
                self._scripted_replace(name)
                self.facts.config_sha = before_sha
                self.clients = [spec for spec in self.clients
                                if spec.name != name]
                warning = ("reload 后健康检查失败（add client %s），自动回滚...\n"
                           "已回滚配置文件，但服务未能确认恢复，请立即人工检查！"
                           "备份: /root/sbox/singbox.json.bak" % name)
            else:
                warning = "生成 add candidate 失败"
            output = ("***** 客户端管理 *****\n" + warning)
            return self._add_frame(output.splitlines())
        # Canonical add success: independent credential per physical side.
        self._created_counter += 1
        uuid = uuid_for(self.role, 100 + self._created_counter)
        password = password_for(self.role, 100 + self._created_counter)
        self.created_credentials[name] = (uuid, password)
        if self.add_side_effect:
            self._scripted_replace(name)
        lines = [
            "***** 客户端管理 *****",
            "2. 添加客户端",
            "正在添加客户端…",
        ]
        if self.add_commit_marker:
            if self.add_no_process:
                lines.append(
                    "配置已提交（当前无运行中的 sing-box 进程，跳过 reload）: "
                    "add client %s" % name)
            else:
                lines.append("配置已提交并重载成功: add client %s" % name)
        if self.add_success_marker:
            lines.append("客户端 '%s' 已同时添加到 Reality 与 HY2"
                         "（UUID/password 已生成）" % name)
        return self._add_frame(lines)

    def _add_frame(self, lines: list[str]) -> tuple[int, str, str]:
        """Close an add transcript with the pinned rc frame / end marker."""
        output = "\n".join(lines) + "\nHAUI_MENU_RC=%d,%d,%d" % self.add_menu_rc
        if self.add_end_marker:
            output += "\nHAUI_MENU_END"
        return 0, output + "\n", ""

    def _scripted_replace(self, name: str) -> None:
        """Simulate one committed config replace (new bytes, new client)."""
        if not any(spec.name == name for spec in self.clients):
            self.clients.append(ClientSpec(name))
        if self.add_duplicate:
            # A duplicate name invalidates the whole inventory (structural
            # ``duplicate-name``): the client is present but not exportable.
            self.clients.append(ClientSpec(name))
        self.facts.config_mtime += 1
        self.facts.config_sha = hashlib.sha256(
            ("config:%s:%d" % (name, self.facts.config_mtime)).encode()
        ).hexdigest()


# --------------------------------------------------------------------------- #
# Provider fake for GenerationService.
# --------------------------------------------------------------------------- #
def preflight_facts(**overrides) -> RemotePreflight:
    base = dict(root=True, os_name="Linux", config_present=True,
                state_present=True, manager_present=True, jq_present=True,
                openssl_present=True, api_secret_present=True,
                management_active=False, config_mtime=DEFAULT_CONFIG_MTIME,
                curl_present=True, timeout_present=True)
    base.update(overrides)
    return RemotePreflight(**base)


def client_record(name: str, *, reality: bool = True, hy2: bool = True,
                  derived: bool = True,
                  problems: Sequence[str] = ()) -> ClientRecord:
    return ClientRecord(name=name, reality_ok=reality, hy2_ok=hy2,
                        derived_export_present=derived,
                        problems=tuple(problems))


@dataclass
class FakeProvider:
    """Duck-typed ``RemoteProvider`` for ``GenerationService`` tests."""

    role: str
    facts: RemotePreflight = field(default_factory=preflight_facts)
    records: dict[str, ClientRecord] = field(default_factory=dict)
    pin: CertPin = field(default_factory=cert_pin)
    exports: dict[str, bytes] = field(default_factory=dict)
    generated: dict[str, bytes] = field(default_factory=dict)
    pins_reply: dict[str, CertPin] | None = None
    errors_by_method: dict[str, str | tuple[str, str]] = field(
        default_factory=dict)
    calls: list[str] = field(default_factory=list)
    export_requests: list[list[str]] = field(default_factory=list)
    generate_requests: list[tuple[tuple[str, ...], bool]] = field(
        default_factory=list)
    create_requests: list[tuple[str, bool]] = field(default_factory=list)
    create_effect: bool = True

    def _enter(self, method: str) -> None:
        self.calls.append(method)
        failure = self.errors_by_method.get(method)
        if failure:
            if isinstance(failure, tuple):
                code, detail = failure
            else:
                code, detail = failure, method
            raise HaUiError(code, detail=detail)

    def preflight(self) -> RemotePreflight:
        self._enter("preflight")
        return self.facts

    def list_clients(self) -> dict[str, ClientRecord]:
        self._enter("list_clients")
        return dict(self.records)

    def read_pins(self) -> dict[str, CertPin]:
        self._enter("read_pins")
        if self.pins_reply is not None:
            return dict(self.pins_reply)
        return {self.role: self.pin}

    def read_exports(self, names: list[str]) -> dict[str, bytes]:
        self._enter("read_exports")
        self.export_requests.append(list(names))
        result = {}
        for name in names:
            if name not in self.exports:
                raise HaUiError(errors.E_REMOTE_EXPORT, detail="missing")
            result[name] = self.exports[name]
        return result

    def generate_exports(self, names: list[str], *,
                         allow_cli: bool) -> dict[str, bytes]:
        self._enter("generate_exports")
        self.generate_requests.append((tuple(names), allow_cli))
        if not allow_cli:
            raise HaUiError(errors.E_REMOTE_EXPORT, detail="cli-consent")
        result = {}
        for name in names:
            payload = self.generated.get(name) or self.exports.get(name)
            if payload is None:
                raise HaUiError(errors.E_REMOTE_EXPORT, detail="missing")
            self.exports[name] = payload
            result[name] = payload
        return result

    def create_client(self, name: str, *, confirmed: bool) -> None:
        self.create_requests.append((name, confirmed))
        self._enter("create_client")
        if not confirmed:
            raise HaUiError(errors.E_CLIENT_EXISTS, detail="consent")
        if self.create_effect:
            self.records[name] = client_record(name)
        return None


class FakeProviderFactory:
    """``provider_factory(role, session)`` used by GenerationService."""

    def __init__(self, providers: Mapping[str, FakeProvider]) -> None:
        self.providers = dict(providers)
        self.calls: list[tuple[str, object]] = []

    def __call__(self, role: str, session: object) -> FakeProvider:
        self.calls.append((role, session))
        return self.providers[role]


def providers_for_batch(batch: SyntheticBatch, *,
                        derived: bool | Mapping[str, bool] = True,
                        ) -> dict[str, FakeProvider]:
    """One ready :class:`FakeProvider` per role for *batch*."""

    def _derived_present(name: str) -> bool:
        if isinstance(derived, Mapping):
            return bool(derived.get(name, True))
        return bool(derived)

    pins = batch.run_pins()
    providers: dict[str, FakeProvider] = {}
    for role in ("A", "B"):
        records = {
            item.name: client_record(
                item.name, derived=_derived_present(item.name))
            for item in batch.selected
        }
        providers[role] = FakeProvider(
            role=role,
            facts=preflight_facts(),
            records=records,
            pin=pins[role],
            exports=dict(batch.exports[role]),
        )
    return providers


class PipelineSpy:
    """A ``GenerationPipeline`` stand-in that fails if it is ever used."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        raise AssertionError("generation pipeline must not run in this test")


# --------------------------------------------------------------------------- #
# Tool-execution helpers (monkeypatched ha_tools.run_tool in failure tests).
# --------------------------------------------------------------------------- #
def recording_tools(monkeypatch) -> list[tuple[str, tuple[str, ...]]]:
    """Replace ``ha_tools.run_tool`` with a recorder that fails closed."""
    calls: list[tuple[str, tuple[str, ...]]] = []

    def _fake(name: str, argv: Sequence[str]) -> ToolResult:
        calls.append((name, tuple(argv)))
        raise AssertionError("reviewed HA tool must not run before validation")

    monkeypatch.setattr("ha_ui.core.ha_tools.run_tool", _fake)
    return calls


def fail_tool(monkeypatch, name: str, stderr: str, *,
              when=None) -> None:
    """Patch ``ha_tools.run_tool`` to fail *name* (optionally only *when*)."""
    from ha_ui.core import ha_tools as ha_tools_module
    original = ha_tools_module.run_tool

    def _wrapper(tool_name: str, argv: Sequence[str]) -> ToolResult:
        if tool_name == name and (when is None or when(tuple(argv))):
            return ToolResult(exit_code=1, stdout="", stderr=stderr)
        return original(tool_name, list(argv))

    monkeypatch.setattr(ha_tools_module, "run_tool", _wrapper)


def sync_pins(not_before: datetime, not_after: datetime) -> dict[str, CertPin]:
    """Small helper for tests that need custom validity windows."""
    return {"A": cert_pin(PIN_A, not_before, not_after),
            "B": cert_pin(PIN_B, not_before, not_after)}
