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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol

from . import errors
from .errors import HaUiError
from .models import CertPin, ClientRecord

CONFIG_PATH = "/root/sbox/sbconfig_server.json"
STATE_PATH = "/root/sbox/config"
CLIENTS_DIR = "/root/sbox/clients"
MANAGEMENT_MARKER = "/var/lib/sbox-cm/management.active"

CANONICAL_CLIENT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
MAX_EXPORT_BYTES = 64 * 1024
MAX_LIST_JSON = 256 * 1024
MAX_MENU_OUTPUT = 1024 * 1024

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

    @property
    def okay(self) -> bool:
        return (self.root and self.os_name == "Linux" and self.config_present
                and self.state_present and self.manager_present
                and self.jq_present and self.openssl_present
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
            "if [ -e %s ] || [ -L %s ]; then echo management=active; "
            "else echo management=inactive; fi; "
            "if jq -e '.services[]? | select(.tag==\"monitor-api\") | has(\"secret\")' "
            "%s >/dev/null 2>&1; then echo api=present; else echo api=missing; fi; "
            "stat -c 'mtime=%%Y' %s 2>/dev/null || echo mtime=0"
        ) % (CONFIG_PATH, STATE_PATH, MANAGEMENT_MARKER, MANAGEMENT_MARKER,
             CONFIG_PATH, CONFIG_PATH)
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
    def list_clients(self) -> dict[str, ClientRecord]:
        preflight = self.preflight()
        command = (
            "stat -c 'mtime=%Y' %s 2>/dev/null || echo mtime=0; "
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
        ) % (CONFIG_PATH, CONFIG_PATH, CLIENTS_DIR)
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
        return _build_records(doc, out, config_mtime)

    # ---------------------------------------------------------------- export --
    def generate_exports(self, names: list[str], *,
                         allow_cli: bool) -> dict[str, bytes]:
        """Generate the CLI's canonical derived files for *names*, then read them.

        ``allow_cli`` must be an explicit operator consent: the command runs the
        existing ``miaomiao`` management script, which performs its documented
        idempotent host-dependency/permission repair before the menu. It never
        edits the sing-box configuration for menu option 3.
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

    def _run_cli_generation(self, names: list[str]) -> None:
        sequence = "10\n1\n" + "".join(
            "3\n%s\n" % name for name in names) + "0\n"
        # Fixed command: no operator string is interpolated except strict
        # canonical client names; the credential link lines are redacted
        # before they ever leave the server, and ANSI colours are stripped.
        command = (
            "printf '%s' | miaomiao 2>&1 "
            "| sed -E 's/%s//g' "
            "| sed -E 's/%s/[redacted-link]/g'; "
            "printf '\\nHAUI_MENU_END\\n'"
        ) % (sequence.replace("\\", "\\\\").replace("'", "'\\''"),
             _REDACT_ANSI, _REDACT_LINK)
        rc, out, err = self.session.exec(command, timeout=420.0,
                                         max_output=MAX_MENU_OUTPUT)
        if "HAUI_MENU_END" not in out:
            raise HaUiError(errors.E_REMOTE_MENU, detail="no-end")
        self._assert_derived_ready(names)

    def _assert_derived_ready(self, names: list[str]) -> None:
        records = self.list_clients()
        missing = [name for name in names
                   if name not in records
                   or not records[name].derived_export_present]
        if missing:
            raise HaUiError(errors.E_REMOTE_MENU, detail="not-generated")

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
    for entry in reality:
        if not isinstance(entry, dict):
            structural.append("reality-entry")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            structural.append("unnamed-reality")
            continue
        rmap[name] = bool(entry.get("cred"))
    for entry in hy2:
        if not isinstance(entry, dict):
            structural.append("hy2-entry")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            structural.append("unnamed-hy2")
            continue
        hmap[name] = bool(entry.get("cred"))
    structural.extend(_duplicates(rmap) + _duplicates(hmap))
    if set(rmap) != set(hmap):
        structural.append("name-set-mismatch")
    derived = _parse_derived(raw_output, config_mtime)
    names = sorted(set(rmap) | set(hmap), key=str.casefold)
    records: dict[str, ClientRecord] = {}
    for name in names:
        problems: list[str] = []
        if "name-set-mismatch" in structural:
            problems.append("name-set-mismatch")
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


def _duplicates(names: Mapping[str, object]) -> list[str]:
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
