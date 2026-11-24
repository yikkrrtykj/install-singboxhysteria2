"""Read-only remote access to one VPS over the trusted root SSH channel.

Why the operator CLI and not the privileged ``client.export`` RPC? (See
``docs/windows-ha-ui-data-path.md`` and issue #110.)

* the E3 ``client.export`` op needs the sboxweb AF_UNIX peer identity and a
  FRESH management status with an *active*, non-degraded management plane; it
  is also behind the Monitor web session/CSRF/step-up authentication. The root
  SSH user is explicitly rejected by the socket peer check, so calling it from
  this tool would bypass the Monitor authentication boundary. Production E3
  management is disabled/not activated (Phase 3 is a separate approval), so the
  op would fail regardless;
* the sanctioned manual operator path is ``miaomiao`` -> menu 10 -> option 3,
  which renders the same canonical ``cm_render_client_mihomo_yaml`` bytes into
  ``/root/sbox/clients/<name>/mihomo.yaml`` (0600) and is what the HA-00 runbook
  copies with ``scp``;
* listing is a read-only ``jq`` read of the same root-owned configuration file;
  the authoritative consistency/credential gates still run inside the reviewed
  HA-02/03/04 tools on the downloaded bytes.

Nothing here writes to ``sbconfig_server.json``, activates the management
plane, or opens a port. The only server-side write is the existing CLI's
documented derived file generation, performed only after the operator consents
in the UI.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol

from . import errors
from .errors import HaUiError
from .models import CertPin, ClientRecord

CONFIG_PATH = "/root/sbox/sbconfig_server.json"
STATE_PATH = "/root/sbox/config"
CLIENTS_DIR = "/root/sbox/clients"
MANAGEMENT_MARKER = "/var/lib/sbox-cm/management.active"

# ---------------------------------------------------------------------------
# Installer trust anchor (reviewed, immutable).
#
# The GUI never executes `main` bytes. Both files it executes are fetched from
# an exact reviewed commit and must match an independently embedded SHA-256
# before execution; the installer's own embedded client-management pin must
# also match the separately downloaded library. Updating these constants is a
# security-review action: re-review the installer + library, recompute both
# hashes, and update docs/windows-ha-ui-data-path.md and the tests together.
# ---------------------------------------------------------------------------
INSTALLER_REVIEWED_COMMIT = "9402be91284551210f2d455f1af42e3b97ccb81e"
INSTALLER_SHA256 = (
    "1a9923eb31ee29b899ba87651c102e83dbde0d397db91387245a489f2e647f10")
CLIENT_MANAGEMENT_SHA256 = (
    "52e08db43b8c94dc42a3c8eea96e8bc3c6adb64155002e82ac3dee985e3b6a53")
_REPO_RAW_BASE = ("https://raw.githubusercontent.com/yikkrrtykj/"
                  "install-singboxhysteria2/")
INSTALLER_URL = _REPO_RAW_BASE + INSTALLER_REVIEWED_COMMIT + "/install.sh"
CLIENT_MANAGEMENT_URL = (_REPO_RAW_BASE + INSTALLER_REVIEWED_COMMIT
                         + "/lib/client-management.sh")

# The installer's pre-menu `install_pkgs` would otherwise run `apt update/install`
# for any missing HOST_DEP_SPECS entry. Preflight refuses auto generation when
# any of these commands is absent, so the pinned execution path never mutates
# host packages (and never executes unlocked distro-repository code).
INSTALLER_HOST_DEPS = (
    "qrencode", "jq", "iptables", "setfacl", "getfacl", "runuser",
    # Commands the pinned execution/verification path itself requires.
    "sha256sum", "date", "stat", "mktemp", "sed", "grep", "awk",
)

CANONICAL_CLIENT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
RESERVED_CLIENT_NAME = "legacy"
MAX_EXPORT_BYTES = 64 * 1024
MAX_LIST_JSON = 256 * 1024
MAX_MENU_OUTPUT = 1024 * 1024
MAX_TX_OUTPUT = 256 * 1024

# Structure markers that must exist in the downloaded installer before any byte
# of it is executed. A renumbered menu (the main catastrophic drift: "10" could
# select an unrelated destructive action) or a renamed client option stops here.
MENU_SCRIPT_MARKERS = (
    "10. 客户端管理",
    "client_management_menu",
    "3) generate_client_configuration_interactive",
    "的 Mihomo 配置已生成",
)
# Additional static markers required before the add path may execute. They bind
# option 2 to the reviewed canonical add_client wrapper and its success line;
# the per-name success string is checked in the transcript afterwards.
MENU_ADD_MARKERS = (
    "2) add_client_interactive",
    "add_client()",
    "_add_client_locked()",
    "已同时添加到 Reality 与 HY2",
)
# Transcript markers proving the expected menu path actually ran: the menu
# notice, and the option-1 client table header.
MENU_TRANSCRIPT_MARKERS = ("客户端管理", "NAME", "REALITY")
MENU_SUCCESS_TEMPLATE = "客户端 '%s' 的 Mihomo 配置已生成"
MENU_ADD_SUCCESS_TEMPLATE = "客户端 '%s' 已同时添加到 Reality 与 HY2"

MENU_FETCH_TIMEOUT = 60
MENU_RUN_TIMEOUT = 420
MENU_KILL_GRACE = 10
MENU_EXEC_TIMEOUT = 540.0

# Managed create transaction. The worker is a detached one-shot server process
# that keeps a durable phase journal; the client only reads that state.
TX_ROOT = "/root/sbox/.ha-ui-tx"
TX_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}-[0-9a-f]{32}\Z")
TX_WAIT_TIMEOUT = 1800.0      # stop waiting here; never kill the worker
TX_PRECOMMIT_SECONDS = 120    # watchdog may stop the menu only pre-replace
PATH_ENV = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

DERIVED_STAT_FORMAT = "%F|%n|%a|%u|%s|%Y|%y"
DERIVED_IDENTITY_END = "HAUI_STAT_END"
# Exact, mutually exclusive server outcomes. A generic "回滚" needle is NOT
# usable: lib/client-management.sh prints it for three different results
# (restore failed / restored+reloaded / restored-but-service-unconfirmed) and
# only the middle one proves the write was undone. The three needles below are
# the exact sentences:
#   :330  "回滚恢复失败，请立即人工介入"
#   :338  "已回滚并重新加载上一份配置"        (proven restore)
#   :344  "已回滚配置文件，但服务未能确认恢复"
_MENU_FAIL_TOKENS = (
    ("consistency", "一致性"),
    ("incomplete", "不完整"),
    ("missing-config", "服务端配置不存在"),
    ("name-invalid", "客户端名称非法"),
    ("permission", "权限"),
    ("reserved", "保留名称"),
    ("exists", "已存在"),
    ("lock", "配置锁"),
    ("create", "生成 add candidate 失败"),
    ("rollback-failed", "回滚恢复失败"),
    ("rollback-unconfirmed", "服务未能确认恢复"),
    ("rolled-back", "已回滚并重新加载上一份配置"),
)

# Refusals the canonical add path raises before it replaces the config file,
# paired with the read-only transcript counter that proves the sentence
# appeared. Order matters: the first matching token wins.
_TX_REFUSALS = (
    ("exists", "EXISTS"),
    ("lock", "LOCK"),
    ("consistency", "CONSISTENCY"),
    ("incomplete", "INCOMPLETE"),
    ("create", "CREATE"),
    ("missing-config", "MISSING_CONFIG"),
    ("name-invalid", "NAME_INVALID"),
    ("reserved", "RESERVED"),
)

# The commit line the canonical installer prints only after the candidate was
# written; the reload wording varies (reload vs "no running process"), so this
# prefix is the shared proof that the write boundary was crossed.
COMMIT_PROVEN_MARKER = "配置已提交"
# Pre-execution pin failures disable automatic menu generation explicitly; the
# read-existing-exports path remains available. These are not retried.
_INSTALLER_UNTRUSTED_TOKENS = frozenset({
    "installer-hash", "lib-hash", "lib-pin", "installer-version",
})

# Fixed minimum remaining HY2 certificate validity for this MVP. The HA-03
# tool keeps its own floor; this is an additional app-level stop so a
# certificate that expires tomorrow cannot be delivered by accident.
MIN_PIN_VALIDITY_HOURS = 24
PIN_WARN_DAYS = 30
_CLOCK_SKEW_SECONDS = 300

_REDACT_ANSI = r"\x1b\[[0-9;]*[A-Za-z]"
_REDACT_LINK = r"^(Reality|HY2) 链接:.*$"


class RemoteSession(Protocol):
    """The subset of the SSH transport this module needs (fake-able)."""

    def exec(self, command: str, *, stdin_data: bytes | None = None,
             timeout: float = 60.0) -> tuple[int, str, str]: ...

    def download_file(self, remote_path: str, *,
                      max_bytes: int = MAX_EXPORT_BYTES) -> bytes: ...


@dataclass(frozen=True)
class RemotePreflight:
    root: bool
    os_name: str
    config_present: bool
    state_present: bool
    manager_present: bool
    jq_present: bool
    openssl_present: bool
    api_secret_present: bool
    management_active: bool
    config_mtime: int
    curl_present: bool = False
    timeout_present: bool = False
    # Identity of the live config file, read read-only. It is the only evidence
    # a client can hold that a write boundary was (or was not) crossed.
    config_sha256: str | None = None

    @property
    def okay(self) -> bool:
        return (self.root and self.os_name == "Linux" and self.config_present
                and self.state_present and self.manager_present
                and self.jq_present and self.openssl_present
                and self.curl_present and self.timeout_present
                and self.api_secret_present and not self.management_active)


def validate_client_name(name: str) -> str:
    if not isinstance(name, str) or not CANONICAL_CLIENT_NAME_RE.fullmatch(name):
        raise HaUiError(errors.E_USAGE, detail="client-name")
    return name


def _parse_key_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.replace("\r", "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            if key and key not in values:
                values[key] = value.strip()
    return values


def _safe_code(output: str) -> str:
    """Extract a fixed ``E_...``/``REFUSE`` token from a tool output."""
    for line in output.replace("\r", "").splitlines():
        for token in line.replace(":", " ").split():
            token = token.strip()
            if token.startswith("E_") and token[2:].replace("_", "").isalnum():
                return token[:48]
            if token.startswith("REFUSE"):
                return "REFUSE"
    return "E_REMOTE"


@dataclass(frozen=True)
class DerivedIdentity:
    """One remote derived export's metadata + SHA-256 at a point in time."""

    name: str
    regular: bool
    mode: int
    uid: int
    size: int
    mtime_epoch: int
    mtime_ns: str
    sha256: str | None


def _menu_client_name(path: str) -> str:
    prefix = CLIENTS_DIR + "/"
    if not path.startswith(prefix):
        return ""
    remainder = path[len(prefix):]
    if "/" not in remainder:
        return ""
    name = remainder.split("/", 1)[0]
    return name if CANONICAL_CLIENT_NAME_RE.fullmatch(name) else ""


def _pinned_menu_command(sequence: str, markers: tuple[str, ...]) -> str:
    """Fixed remote script: fetch/verify pinned bytes, run menu, prove statuses.

    Trust chain: both the installer and the client-management library are
    fetched from ``INSTALLER_REVIEWED_COMMIT`` (never ``main``) and must match
    their independently embedded SHA-256 before any byte executes. The
    installer's own embedded library pin must match the separately downloaded
    library, proving the reviewed internal dependency chain. The installer is
    then run with a sanitized environment and the pinned library path, so its
    library loader does not fetch anything else. Host dependency commands were
    already required by preflight, so the installer's ``install_pkgs`` path is
    a no-op and cannot apt-install unlocked code.

    No operator-supplied text except strict canonical client names is
    interpolated. The credential link lines are redacted server-side, ANSI
    colours are stripped, and ``PIPESTATUS`` is captured for printf, the menu
    process and sed so a non-zero menu can never be hidden by a later marker.
    """
    checks = " ".join(
        "grep -qF -- " + shlex.quote(marker) + " \"$d/install.sh\" "
        "|| { echo HAUI_MENU_FAIL=menu-drift; exit 5; };"
        for marker in markers)
    path_env = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    env_assignments = (
        "env -i PATH=" + path_env + " HOME=/root LANG=C.UTF-8 TERM=dumb "
        "SB_CLIENT_MANAGEMENT_REF=" + INSTALLER_REVIEWED_COMMIT + " "
        "SB_CLIENT_MANAGEMENT_LIB=\"$d/client-management.sh\" ")
    script = (
        "set -o pipefail; umask 077; "
        "d=$(mktemp -d /tmp/ha-ui-installer.XXXXXXXX) "
        "|| { echo HAUI_MENU_FAIL=temp; exit 3; }; "
        "trap 'rm -rf -- \"$d\"' EXIT HUP INT TERM; "
        "curl -fsSL --connect-timeout 10 --max-time "
        + str(MENU_FETCH_TIMEOUT) + " --retry 1 " + shlex.quote(INSTALLER_URL)
        + " -o \"$d/install.sh\" || { echo HAUI_MENU_FAIL=fetch; exit 4; }; "
        "if [ \"$(sha256sum \"$d/install.sh\" | awk '{print $1}')\" != "
        + shlex.quote(INSTALLER_SHA256)
        + " ]; then echo HAUI_MENU_FAIL=installer-hash; exit 6; fi; "
        "grep -qF " + shlex.quote(
            'SB_CLIENT_MANAGEMENT_SHA256="' + CLIENT_MANAGEMENT_SHA256 + '"')
        + " \"$d/install.sh\" "
        "|| { echo HAUI_MENU_FAIL=lib-pin; exit 7; }; "
        + checks + " "
        "curl -fsSL --connect-timeout 10 --max-time "
        + str(MENU_FETCH_TIMEOUT) + " --retry 1 "
        + shlex.quote(CLIENT_MANAGEMENT_URL)
        + " -o \"$d/client-management.sh\" "
        "|| { echo HAUI_MENU_FAIL=fetch-lib; exit 8; }; "
        "if [ \"$(sha256sum \"$d/client-management.sh\" | awk '{print $1}')\" != "
        + shlex.quote(CLIENT_MANAGEMENT_SHA256)
        + " ]; then echo HAUI_MENU_FAIL=lib-hash; exit 9; fi; "
        "chmod 600 \"$d/install.sh\" \"$d/client-management.sh\"; "
        "printf '%s' " + shlex.quote(sequence)
        + " | timeout -k " + str(MENU_KILL_GRACE) + " "
        + str(MENU_RUN_TIMEOUT) + " " + env_assignments
        + "bash \"$d/install.sh\" 2>&1 "
        "| sed -E -e " + shlex.quote("s/" + _REDACT_ANSI + "//g")
        + " -e " + shlex.quote("s/" + _REDACT_LINK + "/[redacted-link]/g")
        + "; ha_ui_rc=(\"${PIPESTATUS[@]}\"); "
        "printf '\\nHAUI_MENU_RC=%s,%s,%s\\n' "
        "\"${ha_ui_rc[0]}\" \"${ha_ui_rc[1]}\" \"${ha_ui_rc[2]}\"; "
        "printf 'HAUI_MENU_END\\n'"
    )
    return "bash -c " + shlex.quote(script)


def _menu_command(names: list[str]) -> str:
    """Pinned menu 10→1→3 command for one or more existing client exports."""
    sequence = "10\n1\n" + "".join(
        "3\n%s\n" % name for name in names) + "0\n"
    return _pinned_menu_command(sequence, MENU_SCRIPT_MARKERS)


def _tx_id(name: str) -> str:
    return "%s-%s" % (name, uuid.uuid4().hex)


def _tx_env_text(txid: str) -> str:
    """Reviewed BASH_ENV text for one attempt.

    The hook stays a *function* (the library contract). The variable is set
    without ``export`` so no child process sees a name that has no function,
    and ``BASH_ENV`` is unset right after loading so child shells do not re-run
    the file. ``hook-loaded`` is the load-time sentinel: bash silently ignores a
    missing BASH_ENV file, so an exit status proves nothing.
    """
    tx = TX_ROOT + "/" + txid
    return (
        "#!/bin/bash\n"
        "# ha-ui managed transaction hook (reviewed source: ha-ui/ha_ui/core/remote.py)\n"
        "ha_ui_tx_journal() {\n"
        "    local phase=${1:-unknown} backup=${2:-}\n"
        "    umask 077\n"
        "    printf '%s\\t%s\\t%s\\n' \"$phase\" \"$(date +%s)\" \"$backup\" "
        ">> " + shlex.quote(tx) + "/phases || return 1\n"
        "    sync -f " + shlex.quote(tx) + "/phases 2>/dev/null || sync\n"
        "    sync -f " + shlex.quote(tx) + " 2>/dev/null || sync\n"
        "    return 0\n"
        "}\n"
        "CM_TX_JOURNAL_HOOK=ha_ui_tx_journal\n"
        "printf 'loaded\\n' > " + shlex.quote(tx) + "/hook-loaded\n"
        "unset BASH_ENV\n"
    )


def _tx_env_sha(txid: str) -> str:
    return hashlib.sha256(_tx_env_text(txid).encode("utf-8")).hexdigest()


def _tx_worker_script(precommit: int | None = None) -> str:
    """Exact detached worker text (the Linux lab runs this same text)."""
    seconds = TX_PRECOMMIT_SECONDS if precommit is None else int(precommit)
    ansi = shlex.quote("s/" + _REDACT_ANSI + "//g")
    link = shlex.quote("s/" + _REDACT_LINK + "/[redacted-link]/g")
    return (
        "set -u\n"
        "tx=$1; d=$2; started=$3\n"
        "env -i PATH=" + PATH_ENV + " HOME=/root LANG=C.UTF-8 TERM=dumb "
        "BASH_ENV=\"$tx/env.sh\" SB_CLIENT_MANAGEMENT_REF="
        + INSTALLER_REVIEWED_COMMIT + " "
        "SB_CLIENT_MANAGEMENT_LIB=\"$d/client-management.sh\" "
        "bash \"$d/install.sh\" < \"$tx/in\" > \"$tx/raw\" 2>&1 &\n"
        "menu=$!\n"
        "( while kill -0 \"$menu\" 2>/dev/null; do\n"
        "    if grep -q '^replace' \"$tx/phases\" 2>/dev/null; then exit 0; fi\n"
        "    now=$(date +%s)\n"
        "    if [ $((now - started)) -gt " + str(seconds) + " ]; then\n"
        "      printf 'watchdog=precommit-timeout\\n' >> \"$tx/notes\"\n"
        "      kill -TERM \"$menu\" 2>/dev/null\n"
        "      exit 0\n"
        "    fi\n"
        "    sleep 1\n"
        "  done ) &\n"
        "watchdog=$!\n"
        "wait \"$menu\"; rc=$?\n"
        "kill \"$watchdog\" 2>/dev/null || true\n"
        "sed -E -e " + ansi + " -e " + link
        + " \"$tx/raw\" > \"$tx/out\" 2>/dev/null || true\n"
        "rm -f \"$tx/raw\"\n"
        "printf 'rc=%s\\nfinished=%s\\n' \"$rc\" \"$(date +%s)\" "
        "> \"$tx/result.tmp\" && mv -- \"$tx/result.tmp\" \"$tx/result\"\n"
        "sync -f \"$tx/result\" 2>/dev/null || sync\n"
        "sync -f \"$tx\" 2>/dev/null || sync\n"
        "rm -rf -- \"$d\"\n"
    )


# Read-only evidence block. Every value is a fixed token or a count over the
# redacted transcript; transcript text itself never leaves the server.
_TX_STATUS_TEMPLATE = r"""echo HAUI_TX_PHASES_BEGIN; sed -n '1,80p' "$tx/phases" 2>/dev/null || true; echo HAUI_TX_PHASES_END; echo HAUI_TX_RESULT_BEGIN; sed -n '1,8p' "$tx/result" 2>/dev/null || true; echo HAUI_TX_RESULT_END; echo "HAUI_TX_NOTES=$(sed -n '1,4p' "$tx/notes" 2>/dev/null | tr '\n' ',')"; pid=$(cat -- "$tx/pid" 2>/dev/null || true); if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo HAUI_TX_RUNNING=1; else echo HAUI_TX_RUNNING=0; fi; for pair in "配置已提交:COMMIT" "已回滚并重新加载上一份配置:ROLLED_BACK" "回滚恢复失败:ROLLBACK_FAILED" "服务未能确认恢复:ROLLBACK_UNCONFIRMED" "自动回滚:ROLLBACK_INTENT" "客户端 __NAME__:SUCCESS" "已存在:EXISTS" "配置锁:LOCK" "一致性:CONSISTENCY" "不完整:INCOMPLETE" "add candidate:CREATE" "服务端配置不存在:MISSING_CONFIG" "客户端名称非法:NAME_INVALID" "保留名称:RESERVED"; do needle=${pair%%:*}; key=${pair##*:}; n=$(grep -c -F -- "$needle" "$tx/out" 2>/dev/null || true); echo "HAUI_TX_${key}=${n:-0}"; done; echo "HAUI_TX_ID=${tx##*/}"
"""


def _tx_status_body(name: str) -> str:
    return _TX_STATUS_TEMPLATE.replace("__NAME__", "'" + name + "'")


def _add_client_command(name: str, txid: str) -> str:
    """Managed create transaction: verified launcher + detached durable worker.

    Order of operations on the server:

    1. fetch/verify the pinned installer and library, and the menu markers
       (nothing executes before this, and no byte of the live config changes);
    2. create the root-only transaction directory and the reviewed ``env.sh``,
       then verify its digest against the client-computed value;
    3. prove the hook is really loaded in the transaction shell (sentinel +
       ``declare -F`` + "not exported" probe) — BASH_ENV failures are silent, so
       this is the only fail-closed gate; any failure aborts before a write;
    4. start the detached worker (own session, file-backed stdin/stdout) and
       wait for it; the wait is the client's patience, not a kill switch.

    The worker may stop the menu only before the ``replace`` phase is journaled.
    Once the commit boundary is recorded, nothing in this path kills it.
    """
    sequence = "10\n2\n%s\n0\n" % name
    tx = TX_ROOT + "/" + txid
    env_text = _tx_env_text(txid)
    env_sha = _tx_env_sha(txid)
    checks = " ".join(
        "grep -qF -- " + shlex.quote(marker) + " \"$d/install.sh\" "
        "|| { echo HAUI_MENU_FAIL=menu-drift; exit 5; };"
        for marker in MENU_SCRIPT_MARKERS + MENU_ADD_MARKERS)
    script = (
        "set -o pipefail; umask 077; "
        "d=$(mktemp -d /tmp/ha-ui-installer.XXXXXXXX) "
        "|| { echo HAUI_MENU_FAIL=temp; exit 3; }; "
        "cleanup=1; "
        "trap 'if [ \"${cleanup:-1}\" = 1 ]; then rm -rf -- \"$d\"; fi' "
        "EXIT HUP INT TERM; "
        "curl -fsSL --connect-timeout 10 --max-time "
        + str(MENU_FETCH_TIMEOUT) + " --retry 1 " + shlex.quote(INSTALLER_URL)
        + " -o \"$d/install.sh\" || { echo HAUI_MENU_FAIL=fetch; exit 4; }; "
        "if [ \"$(sha256sum \"$d/install.sh\" | awk '{print $1}')\" != "
        + shlex.quote(INSTALLER_SHA256)
        + " ]; then echo HAUI_MENU_FAIL=installer-hash; exit 6; fi; "
        "grep -qF " + shlex.quote(
            'SB_CLIENT_MANAGEMENT_SHA256="' + CLIENT_MANAGEMENT_SHA256 + '"')
        + " \"$d/install.sh\" "
        "|| { echo HAUI_MENU_FAIL=lib-pin; exit 7; }; "
        + checks + " "
        "curl -fsSL --connect-timeout 10 --max-time "
        + str(MENU_FETCH_TIMEOUT) + " --retry 1 "
        + shlex.quote(CLIENT_MANAGEMENT_URL)
        + " -o \"$d/client-management.sh\" "
        "|| { echo HAUI_MENU_FAIL=fetch-lib; exit 8; }; "
        "if [ \"$(sha256sum \"$d/client-management.sh\" | awk '{print $1}')\" != "
        + shlex.quote(CLIENT_MANAGEMENT_SHA256)
        + " ]; then echo HAUI_MENU_FAIL=lib-hash; exit 9; fi; "
        "chmod 600 \"$d/install.sh\" \"$d/client-management.sh\"; "
        "tx=" + shlex.quote(tx) + "; root=" + shlex.quote(TX_ROOT) + "; "
        "mkdir -p -- \"$root\" && chmod 700 -- \"$root\"; "
        "if [ -e \"$tx\" ]; then echo HAUI_MENU_FAIL=tx-exists; exit 11; fi; "
        "mkdir -p -- \"$tx\" || { echo HAUI_MENU_FAIL=txdir; exit 10; }; "
        "chmod 700 -- \"$tx\"; "
        # Expiry: keep finished requests for 7 days, unfinished for 30, and
        # never delete a directory whose worker is still alive.
        "for old in \"$root\"/*/; do "
        "  [ -d \"$old\" ] || continue; "
        "  [ \"${old%/}\" = \"$tx\" ] && continue; "
        "  opid=$(cat -- \"$old/pid\" 2>/dev/null || true); "
        "  if [ -n \"$opid\" ] && kill -0 \"$opid\" 2>/dev/null; then continue; fi; "
        "  if [ -f \"$old/result\" ]; then "
        "    find \"$old\" -maxdepth 0 -mtime +7 -exec rm -rf -- {} + 2>/dev/null; "
        "  else "
        "    find \"$old\" -maxdepth 0 -mtime +30 -exec rm -rf -- {} + 2>/dev/null; "
        "  fi; "
        "done; "
        "printf '%s' " + shlex.quote(sequence) + " > \"$tx/in\"; "
        "chmod 600 -- \"$tx/in\"; "
        "printf '%s' " + shlex.quote(env_text) + " > \"$tx/env.sh\"; "
        "chmod 600 -- \"$tx/env.sh\"; "
        "if [ \"$(sha256sum -- \"$tx/env.sh\" | awk '{print $1}')\" != "
        + shlex.quote(env_sha) + " ]; then "
        "echo HAUI_MENU_FAIL=env-hash; exit 12; fi; "
        "probe=$(env -i PATH=" + PATH_ENV + " HOME=/root BASH_ENV=\"$tx/env.sh\" "
        "bash -c 'declare -F ha_ui_tx_journal >/dev/null && echo OK' "
        "2>/dev/null); "
        "if [ \"$probe\" != OK ] || [ ! -f \"$tx/hook-loaded\" ]; then "
        "echo HAUI_MENU_FAIL=hook-unproven; exit 13; fi; "
        "exported=$(env -i PATH=" + PATH_ENV + " HOME=/root BASH_ENV=\"$tx/env.sh\" "
        "bash -c 'env | grep -c \"^CM_TX_JOURNAL_HOOK=\" || true' 2>/dev/null); "
        "if [ \"$exported\" != 0 ]; then "
        "echo HAUI_MENU_FAIL=hook-exported; exit 14; fi; "
        "started=$(date +%s); printf '%s\\n' \"$started\" > \"$tx/started\"; "
        "cleanup=0; "
        "setsid bash -c " + shlex.quote(_tx_worker_script())
        + " haui_tx \"$tx\" \"$d\" \"$started\" >/dev/null 2>&1 < /dev/null & "
        "child=$!; printf '%s\\n' \"$child\" > \"$tx/pid\"; "
        "wait \"$child\" 2>/dev/null || true; "
        "echo HAUI_TX_STARTED=1; "
        + _tx_status_body(name)
    )
    return "bash -c " + shlex.quote(script)


def _pending_tx_command(name: str) -> str:
    """Read-only: newest transaction state for *name*. Writes nothing."""
    script = (
        "tx=$(ls -1dt " + shlex.quote(TX_ROOT + "/" + name + "-*")
        + " 2>/dev/null | head -n 1); "
        "if [ -z \"$tx\" ] || [ ! -d \"$tx\" ]; then "
        "echo HAUI_TX_ABSENT=1; exit 0; fi; "
        "echo HAUI_TX_ABSENT=0; "
        + _tx_status_body(name)
    )
    return "bash -c " + shlex.quote(script)


def _derived_identity_command(names: list[str]) -> str:
    paths = " ".join(
        shlex.quote("%s/%s/mihomo.yaml" % (CLIENTS_DIR, name))
        for name in names)
    return ("LC_ALL=C stat -c " + shlex.quote(DERIVED_STAT_FORMAT) + " "
            + paths + " 2>/dev/null; echo " + DERIVED_IDENTITY_END
            + "; sha256sum " + paths + " 2>/dev/null; true")


def _parse_derived_identities(
        output: str, names: list[str]) -> dict[str, DerivedIdentity | None]:
    wanted = set(names)
    result: dict[str, DerivedIdentity | None] = {name: None for name in names}
    hashes: dict[str, str] = {}
    section = "stat"
    for raw_line in (output or "").replace("\r", "").splitlines():
        line = raw_line.strip()
        if line == DERIVED_IDENTITY_END:
            section = "sha"
            continue
        if not line:
            continue
        if section == "stat":
            parts = line.split("|", 6)
            if len(parts) != 7:
                continue
            kind, path, mode_s, uid_s, size_s, epoch_s, mtime_ns = parts
            name = _menu_client_name(path)
            if name not in wanted:
                continue
            try:
                mode = int(mode_s, 8)
                uid = int(uid_s)
                size = int(size_s)
                mtime_epoch = int(epoch_s)
            except ValueError:
                continue
            result[name] = DerivedIdentity(
                name=name,
                regular=kind.startswith("regular file"),
                mode=mode,
                uid=uid,
                size=size,
                mtime_epoch=mtime_epoch,
                mtime_ns=mtime_ns,
                sha256=None,
            )
        else:
            parts = line.split()
            if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                continue
            name = _menu_client_name(parts[1])
            if name in wanted:
                hashes[name] = parts[0]
    for name, identity in list(result.items()):
        if identity is not None and name in hashes:
            result[name] = replace(identity, sha256=hashes[name])
    return result


def _menu_failure_token(transcript: str) -> str:
    for token, needle in _MENU_FAIL_TOKENS:
        if needle in transcript:
            return token
    return "partial"


_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def _config_sha(value: str | None) -> str | None:
    """Return a strict lowercase SHA-256, or ``None`` for "unknown".

    A missing/unreadable/garbage hash must never be compared as if it were an
    identity: callers treat ``None`` as "no evidence", never as "unchanged".
    """
    if isinstance(value, str) and _SHA256_RE.match(value):
        return value
    return None


@dataclass(frozen=True)
class RemoteSnapshot:
    """One read-only observation of the live config identity + inventory.

    ``config_sha256`` is ``None`` when the server could not prove the hash; it
    must then never be treated as "unchanged".
    """

    config_sha256: str | None
    config_mtime: int
    records: Mapping[str, ClientRecord]

    def record(self, name: str) -> ClientRecord | None:
        return self.records.get(name)


@dataclass(frozen=True)
class _ReconcileEvidence:
    """What a read-only re-read could prove after a failed add.

    Every field is evidence, never a transaction status:

    * ``readable`` — the re-read succeeded at all;
    * ``config_changed`` — ``True``/``False`` only when both hashes are known;
    * ``present`` — the name is in the live inventory;
    * ``exportable`` — that record is complete and structurally trustworthy.
    """

    readable: bool
    config_sha256: str | None = None
    config_changed: bool | None = None
    present: bool | None = None
    exportable: bool | None = None

    @property
    def write_observed(self) -> bool:
        return self.config_changed is True or self.present is True

    @property
    def rolled_back_proven(self) -> bool:
        """Config bytes identical to the pre-write value AND name absent.

        Both halves are required: identical bytes alone could also be a
        not-yet-started write, and an absent name alone could be a lost update.
        """
        return (self.readable
                and self.config_changed is False
                and self.present is False)


@dataclass(frozen=True)
class TxStatus:
    """Durable state of one managed create transaction.

    ``terminal`` is only true when the worker published its ``result`` file;
    ``running`` is a live PID check. Neither is ever inferred from the client
    list or from a single snapshot.
    """

    tx_id: str
    absent: bool
    phases: tuple[str, ...]
    notes: tuple[str, ...]
    rc: int | None
    finished: int | None
    running: bool
    counts: Mapping[str, int]

    @property
    def terminal(self) -> bool:
        return self.finished is not None

    @property
    def last_phase(self) -> str:
        return self.phases[-1] if self.phases else ""

    @property
    def committed(self) -> bool:
        return self.counts.get("COMMIT", 0) > 0

    @property
    def success(self) -> bool:
        return self.counts.get("SUCCESS", 0) > 0

    @property
    def precommit_timeout(self) -> bool:
        return any("precommit-timeout" in note for note in self.notes)


_TX_PHASES_RE = re.compile(
    r"HAUI_TX_PHASES_BEGIN\n(.*?)HAUI_TX_PHASES_END", re.S)
_TX_RESULT_RE = re.compile(
    r"HAUI_TX_RESULT_BEGIN\n(.*?)HAUI_TX_RESULT_END", re.S)
_TX_PHASE_RE = re.compile(r"\A[a-z_]{1,32}\Z")
_TX_COUNT_KEYS = (
    "COMMIT", "SUCCESS", "ROLLED_BACK", "ROLLBACK_FAILED",
    "ROLLBACK_UNCONFIRMED", "ROLLBACK_INTENT", "EXISTS", "LOCK",
    "CONSISTENCY", "INCOMPLETE", "CREATE", "MISSING_CONFIG",
    "NAME_INVALID", "RESERVED",
)


def _tx_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _parse_tx_status(output: str) -> TxStatus:
    """Parse the fixed read-only evidence block; never guesses."""
    text = (output or "").replace("\r", "")
    values = _parse_key_values(text)
    phases: list[str] = []
    match = _TX_PHASES_RE.search(text)
    if match:
        for line in match.group(1).splitlines():
            phase = line.split("\t", 1)[0].strip()
            if _TX_PHASE_RE.match(phase):
                phases.append(phase)
    notes: list[str] = []
    raw_notes = values.get("HAUI_TX_NOTES", "")
    for note in raw_notes.split(","):
        note = note.strip()
        if note and re.fullmatch(r"[a-z-]{1,32}", note):
            notes.append(note)
    rc = finished = None
    match = _TX_RESULT_RE.search(text)
    if match:
        result_values = _parse_key_values(match.group(1))
        rc = _tx_int(result_values.get("rc"))
        finished = _tx_int(result_values.get("finished"))
    counts = {key: _tx_int(values.get("HAUI_TX_" + key)) or 0
              for key in _TX_COUNT_KEYS}
    return TxStatus(
        tx_id=values.get("HAUI_TX_ID", ""),
        absent=values.get("HAUI_TX_ABSENT") == "1",
        phases=tuple(phases),
        notes=tuple(notes),
        rc=rc,
        finished=finished,
        running=values.get("HAUI_TX_RUNNING") == "1",
        counts=counts,
    )


class RemoteProvider:
    """One VPS; every method is a read-only observation or the documented CLI."""

    def __init__(self, server_id: str, session: RemoteSession) -> None:
        if server_id not in ("A", "B"):
            raise HaUiError(errors.E_CONFIG, detail="server-id")
        self.server_id = server_id
        self.session = session

    # ------------------------------------------------------------- preflight --
    def preflight(self) -> RemotePreflight:
        command = (
            "id -u; "
            "uname -s; "
            "if [ -f %s ]; then echo config=present; else echo config=missing; fi; "
            "if [ -f %s ]; then echo state=present; else echo state=missing; fi; "
            "if command -v miaomiao >/dev/null 2>&1; then echo manager=present; "
            "else echo manager=missing; fi; "
            "if command -v jq >/dev/null 2>&1; then echo jq=present; "
            "else echo jq=missing; fi; "
            "if command -v openssl >/dev/null 2>&1; then echo openssl=present; "
            "else echo openssl=missing; fi; "
            "if command -v curl >/dev/null 2>&1; then echo curl=present; "
            "else echo curl=missing; fi; "
            "if command -v timeout >/dev/null 2>&1; then echo timeout=present; "
            "else echo timeout=missing; fi; "
            "for dep in " + " ".join(INSTALLER_HOST_DEPS) + "; do "
            "if command -v \"$dep\" >/dev/null 2>&1; then "
            "echo \"hostdep_$dep=present\"; else "
            "echo \"hostdep_$dep=missing\"; fi; done; "
            "if [ -e %s ] || [ -L %s ]; then echo management=active; "
            "else echo management=inactive; fi; "
            "if jq -e '.services[]? | select(.tag==\"monitor-api\") | has(\"secret\")' "
            "%s >/dev/null 2>&1; then echo api=present; else echo api=missing; fi; "
            "if [ -f %s ]; then "
            "echo cfgsha=$(sha256sum %s | awk '{print $1}'); "
            "else echo cfgsha=none; fi; "
            "stat -c 'mtime=%%Y' %s 2>/dev/null || echo mtime=0"
        ) % (CONFIG_PATH, STATE_PATH, MANAGEMENT_MARKER, MANAGEMENT_MARKER,
             CONFIG_PATH, CONFIG_PATH, CONFIG_PATH, CONFIG_PATH)
        rc, out, err = self.session.exec(command, timeout=60.0)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_COMMAND, detail="preflight")
        values = _parse_key_values(out)
        lines = [line.strip() for line in out.replace("\r", "").splitlines()
                 if line.strip()]
        try:
            uid = int(lines[0]) if lines else -1
        except ValueError:
            uid = -1
        os_name = lines[1] if len(lines) > 1 else ""
        try:
            mtime = int(values.get("mtime", "0"))
        except ValueError:
            mtime = 0
        facts = RemotePreflight(
            root=uid == 0,
            os_name=os_name,
            config_present=values.get("config") == "present",
            state_present=values.get("state") == "present",
            manager_present=values.get("manager") == "present",
            jq_present=values.get("jq") == "present",
            openssl_present=values.get("openssl") == "present",
            api_secret_present=values.get("api") == "present",
            management_active=values.get("management") == "active",
            config_mtime=mtime,
            curl_present=values.get("curl") == "present",
            timeout_present=values.get("timeout") == "present",
            config_sha256=_config_sha(values.get("cfgsha")),
        )
        if not facts.root:
            raise HaUiError(errors.E_REMOTE_NOT_ROOT)
        if facts.os_name != "Linux":
            raise HaUiError(errors.E_REMOTE_PLATFORM)
        if not facts.config_present or not facts.state_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="install")
        if not facts.manager_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="miaomiao")
        if not facts.jq_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="jq")
        if not facts.openssl_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="openssl")
        missing_deps = [
            dep for dep in INSTALLER_HOST_DEPS
            if values.get("hostdep_" + dep) != "present"]
        if missing_deps:
            # Refuse before the installer's install_pkgs/apt path could run:
            # the pinned execution path must not install distro packages.
            raise HaUiError(errors.E_REMOTE_PREFLIGHT,
                            detail="host-deps:" + ",".join(missing_deps))
        if not facts.curl_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="curl")
        if not facts.timeout_present:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="timeout")
        if facts.management_active:
            # The privileged E3 plane is a different transaction boundary; this
            # MVP must not read across it. Activation is a separate approval.
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="management-active")
        if not facts.api_secret_present:
            # The operator CLI would enter its interactive auth migration first;
            # refuse instead of desynchronising the piped menu input.
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="api-migration")
        return facts

    # ------------------------------------------------------------------ list --
    def snapshot(self) -> "RemoteSnapshot":
        """Read the live config identity and the client inventory together.

        Both are emitted by ONE read-only command so they describe the same
        moment. ``preflight`` still runs first: the snapshot is only meaningful
        on a host that passed the canonical gates.
        """
        preflight = self.preflight()
        command = (
            "stat -c 'mtime=%%Y' %s 2>/dev/null || echo mtime=0; "
            "if [ -f %s ]; then "
            "echo cfgsha=$(sha256sum %s | awk '{print $1}'); "
            "else echo cfgsha=none; fi; "
            "jq -c '([.inbounds[]? | select(.tag==\"vless-in\")] | length) as $rn | "
            "([.inbounds[]? | select(.tag==\"hy2-in\")] | length) as $hn | "
            "{rn:$rn, hn:$hn, "
            "reality:([.inbounds[]? | select(.tag==\"vless-in\") | .users[]? | "
            "{name:(.name // \"\"), cred:((.uuid // \"\") | length > 0)}]), "
            "hy2:([.inbounds[]? | select(.tag==\"hy2-in\") | .users[]? | "
            "{name:(.name // \"\"), cred:((.password // \"\") | length > 0)}])}' "
            "%s 2>/dev/null; "
            "echo DERIVED; "
            "stat -c '%%n|%%a|%%u|%%s|%%Y' %s/*/mihomo.yaml 2>/dev/null || true"
        ) % (CONFIG_PATH, CONFIG_PATH, CONFIG_PATH, CONFIG_PATH, CLIENTS_DIR)
        rc, out, err = self.session.exec(command, timeout=60.0,
                                         max_output=MAX_LIST_JSON)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_LIST, detail="jq")
        values = _parse_key_values(out)
        json_lines = [line for line in out.replace("\r", "").splitlines()
                      if line.startswith("{")]
        if len(json_lines) != 1:
            raise HaUiError(errors.E_REMOTE_LIST, detail="json")
        import json
        try:
            doc = json.loads(json_lines[0])
        except ValueError:
            raise HaUiError(errors.E_REMOTE_LIST, detail="json") from None
        try:
            config_mtime = int(values.get("mtime", preflight.config_mtime))
        except ValueError:
            config_mtime = preflight.config_mtime
        return RemoteSnapshot(
            config_sha256=_config_sha(values.get("cfgsha")),
            config_mtime=config_mtime,
            records=_build_records(doc, out, config_mtime))

    def list_clients(self) -> dict[str, ClientRecord]:
        return dict(self.snapshot().records)

    # ---------------------------------------------------------------- export --
    def generate_exports(self, names: list[str], *,
                         allow_cli: bool) -> dict[str, bytes]:
        """Generate the CLI's canonical derived files for *names*, then read them.

        ``allow_cli`` must be an explicit operator consent. The remote side
        downloads the same ``main`` installer the ``miaomiao`` wrapper executes,
        verifies its menu structure before executing those verified bytes, and
        the existing installer then performs its documented idempotent
        host-dependency/permission repair before the menu. Menu option 3 never
        edits the sing-box configuration; all generation proofs are in
        :meth:`_run_cli_generation`.
        """
        validated = [validate_client_name(name) for name in names]
        if not validated:
            raise HaUiError(errors.E_USAGE, detail="clients")
        records = self.list_clients()
        stale = [name for name in validated
                 if name not in records
                 or not records[name].derived_export_present]
        if stale and not allow_cli:
            raise HaUiError(errors.E_REMOTE_EXPORT, detail="cli-consent")
        if stale:
            self._run_cli_generation(stale)
        return self.read_exports(validated)

    # ---------------------------------------------------------------- create --
    def create_client(self, name: str, *, confirmed: bool) -> None:
        """Create one logical client on THIS VPS through the canonical add path.

        This is a write operation. It requires the UI's explicit confirmation
        and only ever invokes the reviewed installer menu 10→2, which runs the
        existing ``add_client`` → ``with_client_lock`` →
        ``cm_add_client_candidate_planned`` → ``commit_server_config`` chain
        (independent credentials, backup, sing-box check, reload/health and
        rollback). It never edits ``sbconfig_server.json`` directly.

        The transaction itself runs in a detached one-shot server worker with a
        durable phase journal (see ``_add_client_command``), so a GUI timeout, an
        SSH abort or a closed stdout consumer cannot terminate the write,
        reload or rollback. The client only stops *waiting*; the durable state is
        what decides the outcome:

        * success requires the worker's terminal ``rc=0``, the commit marker and
          the canonical success line in its redacted transcript, plus a fresh
          live read proving the record exportable;
        * a proven rollback requires the exact restore sentence AND a live read
          showing the pre-write bytes with the name absent;
        * everything else — still running, crashed without a terminal record,
          failed/unconfirmed rollback, unreadable reconciliation — is
          ``E_CREATE_UNCERTAIN``. Only ``pending_transaction`` may later clear
          that state, and only when the request has actually ended.

        Power loss or a kernel crash are not covered by this promise: they are
        detected by the missing terminal record and must stay UNCERTAIN. No
        credential, UUID, YAML or raw remote text is returned.
        """
        if confirmed is not True:
            raise HaUiError(errors.E_USAGE, detail="create-consent")
        validated = validate_client_name(name)
        if validated.casefold() == RESERVED_CLIENT_NAME.casefold():
            raise HaUiError(errors.E_USAGE, detail="reserved-name")
        before = self.snapshot()
        if before.record(validated) is not None:
            raise HaUiError(errors.E_CLIENT_EXISTS, detail="server")
        txid = _tx_id(validated)
        if TX_ID_RE.match(txid) is None:  # defensive: never interpolate junk
            raise HaUiError(errors.E_INTERNAL)
        command = _add_client_command(validated, txid)
        try:
            _rc, out, _err = self.session.exec(
                command, timeout=TX_WAIT_TIMEOUT, max_output=MAX_TX_OUTPUT)
        except HaUiError as exc:
            if exc.code in (errors.E_SSH_TIMEOUT, errors.E_SSH_CLOSED):
                # We stopped waiting; the detached worker may still be running.
                # Only a later read-only query may resolve it.
                raise HaUiError(errors.E_CREATE_UNCERTAIN,
                                detail="tx-transport") from None
            raise
        if "HAUI_TX_STARTED=1" not in out:
            self._raise_launch_failure(out)
        self._judge_tx(_parse_tx_status(out), validated, before)
        return None

    def pending_transaction(self, name: str) -> "TxStatus":
        """Read-only query of the newest managed transaction for *name*.

        Never writes, never kills, never retries. ``absent`` means no
        transaction directory exists for the name; ``terminal`` distinguishes a
        finished request from one that may still be running.
        """
        validated = validate_client_name(name)
        self.preflight()
        rc, out, _err = self.session.exec(_pending_tx_command(validated),
                                          timeout=45.0)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_LIST, detail="tx-status")
        return _parse_tx_status(out)

    @staticmethod
    def _raise_launch_failure(output: str) -> None:
        match = re.search(r"HAUI_MENU_FAIL=([a-z-]{1,32})", output)
        token = match.group(1) if match else ""
        if token in _INSTALLER_UNTRUSTED_TOKENS:
            raise HaUiError(errors.E_INSTALLER_UNTRUSTED, detail=token)
        if token in ("fetch", "fetch-lib", "menu-drift", "txdir", "temp"):
            # Nothing ran against the live config.
            raise HaUiError(errors.E_REMOTE_MENU, detail=token)
        if token in ("hook-unproven", "hook-exported", "env-hash"):
            # The transaction shell is not proven: fail closed before a write.
            raise HaUiError(errors.E_CREATE_UNCERTAIN, detail=token)
        if token == "tx-exists":
            raise HaUiError(errors.E_CREATE_UNCERTAIN, detail="tx-exists")
        raise HaUiError(errors.E_CREATE_UNCERTAIN, detail="launch-unproven")

    def _judge_tx(self, status: "TxStatus", name: str,
                  before: RemoteSnapshot) -> None:
        """Turn one managed transaction's durable state into a verdict."""
        if status.absent:
            raise HaUiError(errors.E_CREATE_UNCERTAIN, detail="tx-absent")
        if not status.terminal:
            # Still running, or the worker vanished without publishing a
            # terminal record: never decide anything from this.
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="running" if status.running
                            else "tx-unfinished")
        evidence = self._reconcile(before, name)
        counts = status.counts
        if status.success and status.committed and status.rc == 0:
            self._prove_created(name, before)
            return
        if status.success and not status.committed:
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="commit-unproven")
        if counts.get("ROLLED_BACK", 0) and evidence.rolled_back_proven:
            raise HaUiError(errors.E_REMOTE_CREATE, detail="rolled-back")
        if counts.get("ROLLBACK_FAILED", 0):
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="rollback-failed")
        if (counts.get("ROLLBACK_UNCONFIRMED", 0)
                or "rollback_manual" in status.phases):
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="rollback-unconfirmed")
        if counts.get("ROLLBACK_INTENT", 0):
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="rollback-unconfirmed")
        for token, key in _TX_REFUSALS:
            if not counts.get(key, 0):
                continue
            if evidence.write_observed:
                # A refusal sentence is not trustworthy if the bytes or the
                # name set changed anyway.
                raise HaUiError(errors.E_CREATE_UNCERTAIN,
                                detail="refusal-after-write")
            if token == "exists":
                raise HaUiError(errors.E_CLIENT_EXISTS, detail="server")
            raise HaUiError(errors.E_REMOTE_CREATE, detail=token)
        if evidence.write_observed:
            raise HaUiError(errors.E_CREATE_UNCERTAIN, detail="write-unproven")
        raise HaUiError(errors.E_CREATE_UNCERTAIN, detail="unconfirmed")

    def _prove_created(self, name: str, before: RemoteSnapshot) -> None:
        """Post-write proof: the live record must be exportable."""
        del before  # kept for symmetry/extensibility; evidence is the live read
        try:
            after = self.snapshot()
        except HaUiError:
            raise HaUiError(errors.E_CREATE_UNCERTAIN,
                            detail="verify-unreadable") from None
        record = after.record(name)
        if record is None:
            raise HaUiError(errors.E_REMOTE_VERIFY, detail="missing")
        if not record.exportable:
            # Both credentials present but a structural anomaly exists: the
            # client must not be reported as a completed, generatable client.
            raise HaUiError(errors.E_REMOTE_VERIFY, detail="incomplete")

    def _reconcile(self, before: RemoteSnapshot,
                   name: str) -> "_ReconcileEvidence":
        """Read-only evidence after a failed/timed-out add; never raises."""
        try:
            after = self.snapshot()
        except HaUiError:
            return _ReconcileEvidence(readable=False)
        changed: bool | None = None
        if (before.config_sha256 is not None
                and after.config_sha256 is not None):
            changed = before.config_sha256 != after.config_sha256
        record = after.record(name)
        return _ReconcileEvidence(
            readable=True,
            config_sha256=after.config_sha256,
            config_changed=changed,
            present=record is not None,
            exportable=None if record is None else record.exportable)

    def _run_cli_generation(self, names: list[str]) -> None:
        """Run the verified installer menu and prove every requested export.

        Safety properties, in order:

        1. the installer is fetched read-only to a root-only temp file and its
           menu structure is checked BEFORE the file is executed (a renumbered
           menu would otherwise receive "10" and could run an unrelated action);
        2. the exact verified bytes are executed with piped menu input under a
           hard ``timeout`` (own process group), never via a second unverified
           wrapper download;
        3. the pipeline exit statuses are captured with ``PIPESTATUS`` into the
           response and must all be zero (menu 124 = timeout);
        4. the transcript must show the menu/table and the per-client
           "Mihomo 配置已生成" line for every requested name;
        5. each target file's metadata/SHA-256 is compared before and after the
           run; an unchanged pre-existing file cannot be mistaken for a new one.

        A partial or failed run aborts before any download. Server-side derived
        files that were already rewritten are canonical, root:0600 derived
        artifacts (``/root/sbox/clients``), never the live config; a retry
        safely regenerates them.
        """
        before = self._derived_identities(names)
        command = _menu_command(names)
        try:
            rc, out, _err = self.session.exec(
                command, timeout=MENU_EXEC_TIMEOUT, max_output=MAX_MENU_OUTPUT)
        except HaUiError as exc:
            if exc.code == errors.E_SSH_TIMEOUT:
                raise HaUiError(errors.E_REMOTE_MENU, detail="timeout") from None
            raise
        if int(rc) == 124:
            raise HaUiError(errors.E_REMOTE_MENU, detail="timeout")
        self._verify_menu_output(out, names)
        after = self._derived_identities(names)
        self._verify_derived_written(names, before, after)

    # ------------------------------------------------- menu proof primitives --
    @staticmethod
    def _menu_completion(text: str) -> str:
        """Validate the pinned-wrapper completion frame; return transcript.

        Both the export and add paths share this frame: a completed pinned
        fetch/verification, a real menu transcript, and the three pipeline exit
        statuses. The returned transcript excludes the trailing markers so
        callers can require their own operation-specific success line.
        """
        text = (text or "").replace("\r", "")
        fail = re.search(r"HAUI_MENU_FAIL=([a-z-]{1,32})", text)
        if fail:
            token = fail.group(1)
            if token in _INSTALLER_UNTRUSTED_TOKENS:
                raise HaUiError(errors.E_INSTALLER_UNTRUSTED, detail=token)
            raise HaUiError(errors.E_REMOTE_MENU,
                            detail="precheck-" + token)
        if "HAUI_MENU_END" not in text:
            raise HaUiError(errors.E_REMOTE_MENU, detail="no-end")
        match = re.search(r"HAUI_MENU_RC=(\d{1,3}),(\d{1,3}),(\d{1,3})", text)
        if not match:
            raise HaUiError(errors.E_REMOTE_MENU, detail="no-exit-status")
        printf_rc, menu_rc, sed_rc = (int(value) for value in match.groups())
        if menu_rc == 124:
            raise HaUiError(errors.E_REMOTE_MENU, detail="timeout")
        if printf_rc != 0 or menu_rc != 0 or sed_rc != 0:
            raise HaUiError(errors.E_REMOTE_MENU, detail="exit-status")
        return text[:match.start()]

    @staticmethod
    def _verify_menu_output(output: str, names: list[str]) -> None:
        transcript = RemoteProvider._menu_completion(output)
        for marker in MENU_TRANSCRIPT_MARKERS:
            if marker not in transcript:
                raise HaUiError(errors.E_REMOTE_MENU, detail="menu-drift")
        for name in names:
            if (MENU_SUCCESS_TEMPLATE % name) not in transcript:
                raise HaUiError(errors.E_REMOTE_MENU,
                                detail=_menu_failure_token(transcript))

    def _derived_identities(self, names: list[str]) -> dict[str, object]:
        rc, out, _err = self.session.exec(_derived_identity_command(names),
                                          timeout=120.0,
                                          max_output=MAX_LIST_JSON)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_MENU, detail="identity")
        return _parse_derived_identities(out, names)

    @staticmethod
    def _verify_derived_written(names: list[str], before, after) -> None:
        for name in names:
            current = after.get(name)
            previous = before.get(name)
            if (current is None or not current.regular or current.uid != 0
                    or current.mode & 0o077
                    or not 0 < current.size <= MAX_EXPORT_BYTES
                    or not current.sha256):
                raise HaUiError(errors.E_REMOTE_MENU, detail="provenance")
            if previous is not None:
                # A successful re-render always rewrites the file (new mtime or
                # new bytes). Unchanged bytes+timestamp means the CLI failed
                # while a stale but "fresh-looking" file was already present.
                if (current.mtime_ns == previous.mtime_ns
                        and current.sha256 == previous.sha256):
                    raise HaUiError(errors.E_REMOTE_MENU,
                                    detail="not-regenerated")

    def read_exports(self, names: list[str]) -> dict[str, bytes]:
        """Download derived files and verify the remote and local SHA-256."""
        validated = [validate_client_name(name) for name in names]
        remote_hashes = self._remote_sha256(validated)
        result: dict[str, bytes] = {}
        for name in validated:
            path = "%s/%s/mihomo.yaml" % (CLIENTS_DIR, name)
            data = self.session.download_file(path, max_bytes=MAX_EXPORT_BYTES)
            if hashlib.sha256(data).hexdigest() != remote_hashes.get(name):
                raise HaUiError(errors.E_REMOTE_HASH, detail="mismatch")
            result[name] = data
        return result

    def _remote_sha256(self, names: list[str]) -> dict[str, str]:
        command = "sha256sum " + " ".join(
            "%s/%s/mihomo.yaml" % (CLIENTS_DIR, name) for name in names)
        rc, out, err = self.session.exec(command, timeout=120.0)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_HASH, detail="sha256sum")
        result: dict[str, str] = {}
        for line in out.replace("\r", "").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            digest, path = parts[0], parts[1]
            match = re.fullmatch(
                r"%s/(%s)/mihomo\.yaml" % (re.escape(CLIENTS_DIR),
                                           CANONICAL_CLIENT_NAME_RE.pattern[2:-2]),
                path)
            if match and re.fullmatch(r"[0-9a-f]{64}", digest):
                result[match.group(1)] = digest
        return result

    # ------------------------------------------------------------------ pins --
    def read_pins(self) -> dict[str, CertPin]:
        command = (
            "set -euo pipefail\n"
            "CONFIG=%s\n"
            "refuse() { echo \"REFUSE: $1\" >&2; exit 3; }\n"
            "CERT=$(jq -er '.inbounds[] | select(.tag == \"hy2-in\") | "
            ".tls.certificate_path' \"$CONFIG\") || refuse cert-path\n"
            "case \"$CERT\" in \"\") refuse empty-path ;; "
            "*$'\\n'*|*$'\\r'*) refuse multiline-path ;; esac\n"
            "[ -f \"$CERT\" ] && [ -r \"$CERT\" ] || refuse cert-unreadable\n"
            "CERT_PEM=$(cat -- \"$CERT\") || refuse cert-read\n"
            "printf '%%s\\n' \"$CERT_PEM\" | grep -q -- 'BEGIN CERTIFICATE' "
            "|| refuse not-pem\n"
            "printf '%%s\\n' \"$CERT_PEM\" | openssl x509 -noout -checkend 0 "
            ">/dev/null || refuse expired-or-invalid\n"
            "FP=$(printf '%%s\\n' \"$CERT_PEM\" | openssl x509 -outform DER "
            "| sha256sum | awk '{print $1}') || refuse fingerprint\n"
            "printf '%%s' \"$FP\" | grep -Eq '^[0-9a-f]{64}$' "
            "|| refuse fingerprint-format\n"
            "NOT_BEFORE=$(printf '%%s\\n' \"$CERT_PEM\" | openssl x509 -noout "
            "-startdate | cut -d= -f2) || refuse notbefore\n"
            "NOT_AFTER=$(printf '%%s\\n' \"$CERT_PEM\" | openssl x509 -noout "
            "-enddate | cut -d= -f2) || refuse notafter\n"
            "ISO_BEFORE=$(date -u -d \"$NOT_BEFORE\" +%%Y-%%m-%%dT%%H:%%M:%%SZ) "
            "|| refuse notbefore-parse\n"
            "ISO_AFTER=$(date -u -d \"$NOT_AFTER\" +%%Y-%%m-%%dT%%H:%%M:%%SZ) "
            "|| refuse notafter-parse\n"
            "printf 'fingerprint=%%s not_before=%%s not_after=%%s\\n' "
            "\"$FP\" \"$ISO_BEFORE\" \"$ISO_AFTER\"\n"
        ) % CONFIG_PATH
        rc, out, err = self.session.exec(command, timeout=60.0)
        if rc != 0:
            raise HaUiError(errors.E_REMOTE_PIN,
                            detail=_safe_code(err) or "cert")
        text = out.replace("\r", "")
        match = re.search(
            r"^fingerprint=([0-9a-fA-F]{64}) "
            r"not_before=([0-9T:\-Z]+) not_after=([0-9T:\-Z]+)$",
            text, re.MULTILINE)
        if not match:
            raise HaUiError(errors.E_REMOTE_PIN, detail="output")
        fingerprint = match.group(1).lower()
        try:
            not_before = datetime.strptime(match.group(2),
                                           "%Y-%m-%dT%H:%M:%SZ").replace(
                                               tzinfo=timezone.utc)
            not_after = datetime.strptime(match.group(3),
                                          "%Y-%m-%dT%H:%M:%SZ").replace(
                                              tzinfo=timezone.utc)
        except ValueError:
            raise HaUiError(errors.E_REMOTE_PIN, detail="date") from None
        if not_before >= not_after:
            raise HaUiError(errors.E_PIN_FORMAT, detail="window")
        return {self.server_id: CertPin(
            fingerprint_sha256=fingerprint,
            not_before=not_before,
            not_after=not_after,
            source="ssh-openssl-hy2-in-%s" % not_before.strftime("%Y-%m-%d"),
        )}


def validate_pins_pair(pins: Mapping[str, CertPin], *,
                       now: datetime | None = None) -> None:
    """Cross-server checks the HA-03 pins file also performs, plus validity."""
    if set(pins) != {"A", "B"}:
        raise HaUiError(errors.E_REMOTE_PIN, detail="servers")
    current = now or datetime.now(timezone.utc)
    a = pins["A"].fingerprint_sha256
    b = pins["B"].fingerprint_sha256
    for role, pin in pins.items():
        if not re.fullmatch(r"[0-9a-f]{64}", pin.fingerprint_sha256):
            raise HaUiError(errors.E_PIN_FORMAT, detail=role)
        if pin.not_before >= pin.not_after:
            raise HaUiError(errors.E_PIN_FORMAT, detail=role)
        if pin.not_before > current + timedelta(seconds=_CLOCK_SKEW_SECONDS):
            raise HaUiError(errors.E_PIN_FORMAT, detail=role)
        if pin.not_after <= current:
            raise HaUiError(errors.E_PIN_EXPIRED, detail=role)
        remaining = pin.not_after - current
        if remaining < timedelta(hours=MIN_PIN_VALIDITY_HOURS):
            raise HaUiError(errors.E_PIN_EXPIRED, detail=role)
    if a == b:
        raise HaUiError(errors.E_PIN_REUSED, detail="pin")


def pin_warning(pins: Mapping[str, CertPin],
                now: datetime | None = None) -> str | None:
    current = now or datetime.now(timezone.utc)
    days = min((pin.not_after - current).days for pin in pins.values())
    if days < PIN_WARN_DAYS:
        return "HY2 证书剩余 %d 天，低于 %d 天提醒线" % (days, PIN_WARN_DAYS)
    return None


def _build_records(doc: dict, raw_output: str,
                   config_mtime: int) -> dict[str, ClientRecord]:
    if not isinstance(doc, dict):
        raise HaUiError(errors.E_REMOTE_LIST, detail="shape")
    try:
        reality_inbounds = int(doc.get("rn"))
        hy2_inbounds = int(doc.get("hn"))
        reality = list(doc.get("reality") or [])
        hy2 = list(doc.get("hy2") or [])
    except (TypeError, ValueError):
        raise HaUiError(errors.E_REMOTE_LIST, detail="shape") from None
    structural: list[str] = []
    if reality_inbounds != 1:
        structural.append("reality-inbound-count")
    if hy2_inbounds != 1:
        structural.append("hy2-inbound-count")
    rmap: dict[str, bool] = {}
    hmap: dict[str, bool] = {}
    reality_names: list[str] = []
    hy2_names: list[str] = []
    for entry in reality:
        if not isinstance(entry, dict):
            structural.append("reality-entry")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            structural.append("unnamed-reality")
            continue
        reality_names.append(name)
        rmap[name] = bool(entry.get("cred"))
    for entry in hy2:
        if not isinstance(entry, dict):
            structural.append("hy2-entry")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            structural.append("unnamed-hy2")
            continue
        hy2_names.append(name)
        hmap[name] = bool(entry.get("cred"))
    # Duplicate detection must run on the raw entry lists: a dict would collapse
    # a repeated same-spelling name before the check, silently accepting it.
    structural.extend(_duplicates(reality_names) + _duplicates(hy2_names))
    if set(rmap) != set(hmap):
        structural.append("name-set-mismatch")
    derived = _parse_derived(raw_output, config_mtime)
    names = sorted(set(rmap) | set(hmap), key=str.casefold)
    records: dict[str, ClientRecord] = {}
    for name in names:
        # Global structural anomalies (ambiguous inbound count, unnamed user,
        # duplicate name, name-set mismatch) block every client: a partial list
        # must never be presented as a generation-ready inventory.
        problems: list[str] = []
        for issue in structural:
            if issue not in problems:
                problems.append(issue)
        if name not in rmap:
            problems.append("missing-reality")
        elif not rmap[name]:
            problems.append("no-reality-credential")
        if name not in hmap:
            problems.append("missing-hy2")
        elif not hmap[name]:
            problems.append("no-hy2-credential")
        records[name] = ClientRecord(
            name=name,
            reality_ok=name in rmap and rmap[name],
            hy2_ok=name in hmap and hmap[name],
            derived_export_present=derived.get(name, False),
            problems=tuple(problems),
        )
    return records


def _duplicates(names) -> list[str]:  # Iterable[str], raw entry order
    seen: set[str] = set()
    duplicates: list[str] = []
    for name in names:
        folded = name.casefold()
        if folded in seen:
            duplicates.append("duplicate-name")
        seen.add(folded)
    return duplicates


def _parse_derived(raw_output: str, config_mtime: int) -> dict[str, bool]:
    """Map client name -> fresh, 0600, root-owned derived export present."""
    result: dict[str, bool] = {}
    started = False
    for line in raw_output.replace("\r", "").splitlines():
        if line.strip() == "DERIVED":
            started = True
            continue
        if not started or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) != 5:
            continue
        path, mode, uid, size, mtime = parts
        name = path.rsplit("/", 2)[-2] if path.count("/") >= 2 else ""
        if not CANONICAL_CLIENT_NAME_RE.fullmatch(name):
            continue
        try:
            mode_int = int(mode, 8)
            uid_int = int(uid)
            size_int = int(size)
            mtime_int = int(mtime)
        except ValueError:
            continue
        fresh = mtime_int >= config_mtime
        private = (uid_int == 0 and mode_int & 0o077 == 0
                   and 0 < size_int <= MAX_EXPORT_BYTES)
        result[name] = fresh and private
    return result
