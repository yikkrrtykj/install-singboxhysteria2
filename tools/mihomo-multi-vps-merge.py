#!/usr/bin/env python3
"""Issue #48 PR-48A -- offline multi-VPS Mihomo profile merge.

Operator-local and hermetic: two `client.export` YAML files go in, one merged
profile comes out. No network, no VPS contacting a VPS, no server-side state,
no database, no Monitor involvement, no credential material in argv/env/stdout.

This is a CANONICAL PROFILE PARSER, not a general YAML tool. It accepts only
the current output of
`lib/client-management.sh :: cm_render_client_mihomo_yaml` and fails closed on
anything else. Merging never re-serialises YAML: the primary file stays the
base, its two proxy blocks keep their original bytes, the backup proxy blocks
are copied with their original fields, and only the two backup NAMES change.

Python 3.10 standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import sys
import tempfile

MAX_INPUT_BYTES = 48 * 1024
EXPORT_SUFFIX = "-mihomo.yaml"

E_USAGE = "E_USAGE"
E_PRIMARY_NOT_CANONICAL = "E_PRIMARY_NOT_CANONICAL"
E_BACKUP_NOT_CANONICAL = "E_BACKUP_NOT_CANONICAL"
E_NAME_MISMATCH = "E_NAME_MISMATCH"
E_SOURCE_COLLISION = "E_SOURCE_COLLISION"
E_CREDENTIAL_REUSE = "E_CREDENTIAL_REUSE"
E_OUTPUT_EXISTS = "E_OUTPUT_EXISTS"
E_IO = "E_IO"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
UUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                     r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
PUBKEY_RE = re.compile(r"\A[A-Za-z0-9_-]{43,44}\Z")
SHORT_ID_RE = re.compile(r"\A(?:[0-9a-fA-F]{2}){1,16}\Z")
PASSWORD_RE = re.compile(r"\A[A-Za-z0-9._~+/=-]{8,128}\Z")
HOSTNAME_RE = re.compile(r"\A[A-Za-z0-9]([A-Za-z0-9._-]{0,252}[A-Za-z0-9])?\Z")
HOP_RANGE_RE = re.compile(r"\A(\d{1,5})-(\d{1,5})\Z")

# The exact top-level key sequence of a canonical export, in order, once each.
# Any extra key, duplicate, unknown construct (anchor, tag, comment) or
# reordering fails closed, which also proves there is exactly one proxies,
# proxy-groups and rules section.
TOP_LEVEL_KEYS = (
    "mixed-port", "allow-lan", "bind-address", "mode", "log-level",
    "unified-delay", "ipv6", "profile", "dns", "tun",
    "proxies", "proxy-groups", "rules",
)

PROXIES_KEY = "proxies:"
GROUPS_KEY = "proxy-groups:"
RULES_KEY = "rules:"

REALITY_NAME = "Reality"
HISTERIA2_NAME = "Hysteria2"
BACKUP_REALITY_NAME = "Backup-Reality"
BACKUP_HISTERIA2_NAME = "Backup-Hysteria2"

AUTO_GROUP_NAME = "自动选择"
DIRECT_NAME = "DIRECT"

# The accepted issue #42 policy, exactly as the renderer emits it (blank lines
# removed). An input must carry this block or it is not the current export.
GROUPS_SINGLE_OUTER = (
    "  - name: 节点选择",
    "    type: select",
    "    default-selected: 自动选择",
    "    proxies:",
    "      - Reality",
    "      - Hysteria2",
    "      - 自动选择",
    "      - DIRECT",
)
GROUPS_SINGLE_AUTO = (
    "  - name: 自动选择",
    "    type: fallback",
    "    proxies:",
    "      - Reality",
    "      - Hysteria2",
    '    url: "https://www.gstatic.com/generate_204"',
    "    interval: 60",
    "    timeout: 5000",
    "    lazy: false",
    '    expected-status: "204"',
)
# Where each group's member lines sit inside its own tuple: the Selector holds
# Reality / Hysteria2 / 自动选择 / DIRECT (indices 4..7), the automatic group
# holds Reality / Hysteria2 (indices 3..4). Everything outside those slices is
# carried over untouched.
OUTER_MEMBER_SLICE = slice(4, 8)
AUTO_MEMBER_SLICE = slice(3, 5)
DUAL_MEMBERS = (REALITY_NAME, HISTERIA2_NAME,
                BACKUP_REALITY_NAME, BACKUP_HISTERIA2_NAME)
# PR-48A output contract (issue #48 section 9): the automatic group holds the
# four members only, the Selector keeps 自动选择 / DIRECT after them, and the
# probe policy (interval 60 / timeout 5000 / lazy false / expected 204) is NOT
# touched here -- topology only.
DUAL_AUTO_MEMBERS = DUAL_MEMBERS
DUAL_OUTER_MEMBERS = DUAL_MEMBERS + (AUTO_GROUP_NAME, DIRECT_NAME)

RULES_LINES = (
    "  - GEOIP,LAN,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "  - MATCH,节点选择",
)

TRAILING_BLANKS = ["", ""]             # the template's final blank line


class MergeError(Exception):
    """A failure that may only ever be reported as its fixed code."""

    def __init__(self, code, exit_status=EXIT_FAILED):
        super().__init__(code)
        self.code = code
        self.exit_status = exit_status


def is_port(value):
    return value.isdigit() and 1 <= int(value) <= 65535


def is_server(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(value))


def field_value(line, prefix):
    """Return the value of a '<prefix><value>' line, or None.

    An empty value, or one padded with spaces, is not canonical: the renderer
    always emits `key: value`. This also rejects `key: &anchor`, `key: *alias`
    and `key: !!tag`, because those never satisfy the per-field regexes.
    """
    if not line.startswith(prefix):
        return None
    value = line[len(prefix):]
    if not value or value != value.strip():
        return None
    return value


def _literal(expected):
    return ("literal", expected, None, None)


def _field(prefix, checker, key):
    return ("value", prefix, checker, key)


REALITY_SPEC = (
    _literal("  - name: Reality"),
    _literal("    type: vless"),
    _field("    server: ", is_server, "server"),
    _field("    port: ", is_port, "port"),
    _field("    uuid: ", UUID_RE.match, "uuid"),
    _literal("    network: tcp"),
    _literal("    udp: true"),
    _literal("    tls: true"),
    _literal("    flow: xtls-rprx-vision"),
    _field("    servername: ", HOSTNAME_RE.match, "servername"),
    _literal("    client-fingerprint: chrome"),
    _literal("    reality-opts:"),
    _field("      public-key: ", PUBKEY_RE.match, "public-key"),
    _field("      short-id: ", SHORT_ID_RE.match, "short-id"),
)

HISTERIA2_HEAD = (
    _literal("  - name: Hysteria2"),
    _literal("    type: hysteria2"),
    _field("    server: ", is_server, "server"),
    _field("    port: ", is_port, "port"),
)

HISTERIA2_TAIL = (
    _field("    password: ", PASSWORD_RE.match, "password"),
    _literal('    up: "300 Mbps"'),
    _literal('    down: "300 Mbps"'),
    _field("    sni: ", HOSTNAME_RE.match, "sni"),
    _literal("    skip-cert-verify: true"),
    _literal("    alpn:"),
    _literal("      - h3"),
)


def run_spec(lines, index, spec, fields, fail):
    for kind, expected, checker, key in spec:
        if index >= len(lines):
            raise fail()
        line = lines[index]
        if kind == "literal":
            if line != expected:
                raise fail()
        else:
            value = field_value(line, expected)
            if value is None or not checker(value):
                raise fail()
            fields[key] = value
        index += 1
    return index


class Profile(object):
    """One validated canonical export, kept as its original lines."""

    def __init__(self, raw, lines):
        self.raw = raw
        self.lines = lines
        self.proxies_at = 0
        self.groups_at = 0
        self.rules_at = 0
        self.reality_at = 0
        self.reality_len = 0
        self.hysteria_at = 0
        self.hysteria_len = 0
        self.reality = {}
        self.hysteria = {}

    def block(self, which):
        if which == "reality":
            return self.lines[self.reality_at:self.reality_at + self.reality_len]
        return self.lines[self.hysteria_at:self.hysteria_at + self.hysteria_len]


def read_export(path, fail):
    """Regular file, no symlink, <= 48 KiB, UTF-8 strict, no NUL, no CR."""
    if os.path.islink(path):
        raise fail()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise fail() from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise fail()
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(MAX_INPUT_BYTES + 1)
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > MAX_INPUT_BYTES or b"\x00" in raw or b"\t" in raw:
        raise fail()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise fail() from None
    if "\r" in text:
        raise fail()
    return Profile(raw, text.split("\n"))


def check_top_level(profile, fail):
    """Column-0 lines must be exactly the canonical keys, in order, once each."""
    lines = profile.lines
    keys = []
    for line in lines:
        if not line or line[0] == " ":
            continue
        if line.lstrip().startswith("#"):
            raise fail()
        match = re.match(r"\A([A-Za-z0-9_-]+:)\S*(?: \S*)*\Z", line)
        if not match:
            raise fail()
        keys.append(match.group(1))
    if tuple(keys) != tuple(key + ":" for key in TOP_LEVEL_KEYS):
        raise fail()
    profile.proxies_at = next(index for index, line in enumerate(lines)
                              if line == PROXIES_KEY)
    profile.groups_at = next(index for index, line in enumerate(lines)
                             if line == GROUPS_KEY)
    profile.rules_at = next(index for index, line in enumerate(lines)
                            if line == RULES_KEY)
    if not (profile.proxies_at < profile.groups_at < profile.rules_at):
        raise fail()


def parse_proxies(profile, fail):
    lines = profile.lines
    index = profile.proxies_at + 1
    end = profile.groups_at

    fields = {}
    reality_at = index
    index = run_spec(lines, index, REALITY_SPEC, fields, fail)
    reality_len = index - reality_at
    if lines[index] != "":
        raise fail()
    index += 1

    hy_fields = {}
    hysteria_at = index
    index = run_spec(lines, index, HISTERIA2_HEAD, hy_fields, fail)

    # Port hopping: the renderer emits either a bare port, or the matched
    # ports + hop-interval pair. A half pair is not canonical.
    if index < len(lines) and lines[index].startswith("    ports:"):
        value = field_value(lines[index], "    ports: ")
        match = HOP_RANGE_RE.match(value or "")
        if not match or not is_port(match.group(1)) or not is_port(match.group(2)):
            raise fail()
        if int(match.group(1)) > int(match.group(2)):
            raise fail()
        hy_fields["ports"] = value
        index += 1
        if lines[index] != "    hop-interval: 30":
            raise fail()
        index += 1

    index = run_spec(lines, index, HISTERIA2_TAIL, hy_fields, fail)
    hysteria_len = index - hysteria_at
    if lines[index:index + 2] != TRAILING_BLANKS or index + 2 != end:
        raise fail()

    profile.reality = fields
    profile.reality_at, profile.reality_len = reality_at, reality_len
    profile.hysteria = hy_fields
    profile.hysteria_at, profile.hysteria_len = hysteria_at, hysteria_len


def parse_groups(profile, fail):
    region = profile.lines[profile.groups_at + 1:profile.rules_at]
    expected = list(GROUPS_SINGLE_OUTER) + [""] + list(GROUPS_SINGLE_AUTO) \
        + TRAILING_BLANKS
    if region != expected:
        raise fail()


def parse_rules(profile, fail):
    lines = profile.lines
    start = profile.rules_at
    if tuple(lines[start + 1:start + 4]) != RULES_LINES:
        raise fail()
    if lines[start + 4:] != TRAILING_BLANKS:
        raise fail()


def parse_export(path, fail):
    profile = read_export(path, fail)
    check_top_level(profile, fail)
    parse_proxies(profile, fail)
    parse_groups(profile, fail)
    parse_rules(profile, fail)
    return profile


def check_provenance(path, name, fail):
    """The logical client name is only carried by the downloaded file name,
    so this is a provenance guard against mixing up exports -- never an
    identity proof."""
    expected = name + EXPORT_SUFFIX
    if os.path.basename(path) != expected:
        raise fail()


def check_sources(primary, backup):
    """Two exports of the SAME VPS would carry one endpoint for both tunnels.

    The renderer puts SERVER_IP into both proxies, so an intra-file mismatch
    and an inter-file match are both 'this is not A plus B'.
    """
    def fail():
        return MergeError(E_SOURCE_COLLISION)

    for profile in (primary, backup):
        if profile.reality["server"] != profile.hysteria["server"]:
            raise fail()
    if primary.reality["server"] == backup.reality["server"]:
        raise fail()


def check_credentials(primary, backup):
    """Issue #48 freezes per-VPS credentials: a shared UUID or password means
    the two exports are not independent tenants, and the merged profile would
    carry one credential twice."""
    def fail():
        return MergeError(E_CREDENTIAL_REUSE)

    if primary.reality["uuid"] == backup.reality["uuid"]:
        raise fail()
    if primary.hysteria["password"] == backup.hysteria["password"]:
        raise fail()


def member_lines(names):
    return ["      - %s" % member for member in names]


def dual_groups_block():
    """The two groups with the backup pair inserted in member order.

    Everything else -- group names, types, default-selected, the whole probe
    policy line set -- is carried over from the accepted #42 block untouched.
    """
    outer = (list(GROUPS_SINGLE_OUTER[:OUTER_MEMBER_SLICE.start]) +
             member_lines(DUAL_OUTER_MEMBERS) +
             list(GROUPS_SINGLE_OUTER[OUTER_MEMBER_SLICE.stop:]))
    auto = (list(GROUPS_SINGLE_AUTO[:AUTO_MEMBER_SLICE.start]) +
            member_lines(DUAL_AUTO_MEMBERS) +
            list(GROUPS_SINGLE_AUTO[AUTO_MEMBER_SLICE.stop:]))
    return outer + [""] + auto


def renamed(block, new_name):
    out = list(block)
    out[0] = "  - name: %s" % new_name
    return out


def build_output(primary, backup):
    """Single mode returns the primary bytes untouched; dual mode splices."""
    if backup is None:
        return primary.raw
    lines = [GROUPS_KEY] + list(dual_groups_block()) + TRAILING_BLANKS
    proxies = []
    proxies += primary.block("reality")
    proxies += [""]
    proxies += primary.block("hysteria")
    proxies += [""]
    proxies += renamed(backup.block("reality"), BACKUP_REALITY_NAME)
    proxies += [""]
    proxies += renamed(backup.block("hysteria"), BACKUP_HISTERIA2_NAME)
    body = (primary.lines[:primary.proxies_at + 1] + proxies +
            TRAILING_BLANKS + lines +
            primary.lines[primary.rules_at:])
    return "\n".join(body).encode("utf-8")


def write_output(payload, output_path):
    """Private temp in the output directory, fsync, then a no-clobber publish.

    The file is created 0600 and never world-readable; the publish step is
    atomic and refuses to replace an existing file.
    """
    if os.path.lexists(output_path):
        raise MergeError(E_OUTPUT_EXISTS)
    directory = os.path.dirname(os.path.abspath(output_path))
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".mihomo-merge-", dir=directory)
    except OSError:
        raise MergeError(E_IO) from None
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        try:
            os.link(temp_path, output_path)
        except FileExistsError:
            raise MergeError(E_OUTPUT_EXISTS) from None
    except OSError:
        raise MergeError(E_IO) from None
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def merge(name, primary_path, backup_path, output_path):
    primary = parse_export(primary_path,
                           lambda: MergeError(E_PRIMARY_NOT_CANONICAL))
    backup = None
    if backup_path is not None:
        backup = parse_export(backup_path,
                              lambda: MergeError(E_BACKUP_NOT_CANONICAL))
    check_provenance(primary_path, name,
                     lambda: MergeError(E_NAME_MISMATCH))
    if backup is not None:
        check_provenance(backup_path, name, lambda: MergeError(E_NAME_MISMATCH))
        check_sources(primary, backup)
        check_credentials(primary, backup)
    payload = build_output(primary, backup)
    write_output(payload, output_path)
    return "dual" if backup is not None else "single"


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Offline merge of two canonical Mihomo client.export "
                    "profiles into one multi-VPS profile (operator-local; "
                    "no network, no VPS-to-VPS contact)")
    parser.add_argument("--name", required=True,
                        help="logical client name; each input must be named "
                             "<name>%s" % EXPORT_SUFFIX)
    parser.add_argument("--primary", required=True,
                        help="path to the primary VPS export")
    parser.add_argument("--backup",
                        help="path to the backup VPS export; omit for "
                             "single-VPS mode (byte-for-byte passthrough)")
    parser.add_argument("--output", required=True,
                        help="path to write the merged profile (0600; an "
                             "existing file is refused)")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    try:
        if not CLIENT_NAME_RE.match(args.name):
            return report("merge: FAIL %s" % E_USAGE, EXIT_USAGE)
        mode = merge(args.name, args.primary, args.backup, args.output)
    except MergeError as exc:
        return report("merge: FAIL %s" % exc.code, exc.exit_status)
    except Exception:  # noqa: BLE001 -- a traceback could echo file bytes
        return report("merge: FAIL %s" % E_IO, EXIT_FAILED)
    print("merge: OK")
    print("mode: %s" % mode)
    print("output: written")
    return EXIT_OK


def report(message, exit_status=EXIT_FAILED):
    print(message, file=sys.stderr)
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
