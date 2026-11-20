#!/usr/bin/env python3
"""Issue #48 HA-03 -- competition-safe profile transform for a HA-02 delivery.

One operator-local command turns the HA-02 dual-active delivery into a second,
independent competition delivery:

    delivery/<name>-ha.yaml + pins.json + competition version
        -> competition/<name>-hac.yaml                    (per terminal)
        -> competition/ha-competition-<version>.json      (pins, hashes, rollback)

The transform is intentionally tiny and deterministic (three edits per file):

- DNS listener 0.0.0.0:53 -> 127.0.0.1:53 (loopback management only);
- Hysteria2 (the terminal's primary VPS): skip-cert-verify true -> false and a
  SHA-256 DER certificate pin for that physical VPS;
- Backup-Hysteria2 (the terminal's backup VPS): same, with that VPS's pin.

It never re-serialises YAML and never touches the HA-02 input files. The pin
mapping comes from the HA-02 manifest's `primary_vps`/`backup_vps` fields, so a
B-first terminal pins B on `Hysteria2` and A on `Backup-Hysteria2`. Pins are
loaded from a local, access-controlled pins file whose `not_after` dates are
enforced here (Mihomo leaf pinning does not validate certificate expiry); the
generation and `--check` modes both refuse expired or soon-expiring pins.

Default OFF: this tool only writes files. Importing/activating the competition
profile in Clash Verge Rev is an explicit operator action; no daemon, GUI, web
service or scheduled task is added. Quality Failover remains opt-in and off.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time

MAX_INPUT_BYTES = 256 * 1024
BATCH_TOOL_NAME = "mihomo-competition-ha-batch.py"
PIN_SCHEMA = "mihomo-competition-ha-pins/1"
PROFILE_SCHEMA = "mihomo-competition-ha-profile/1"
OUTPUT_SUFFIX = "-hac.yaml"
MANIFEST_PREFIX = "ha-competition-"
MANIFEST_SUFFIX = ".json"
TOOL_VERSION = "1"
MIN_VALIDITY_DEFAULT = 7
MAX_VALIDITY_DAYS = 3650

PIN_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
TIME_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
MANIFEST_RE = re.compile(
    r"\Aha-competition-[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json\Z")
DELIVERY_MANIFEST_RE = re.compile(
    r"\Aha-delivery-[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json\Z")

E_USAGE = "E_USAGE"
E_DELIVERY = "E_DELIVERY"
E_DELIVERY_HASH = "E_DELIVERY_HASH"
E_PINS = "E_PINS"
E_PINS_EXPIRED = "E_PINS_EXPIRED"
E_TRANSFORM = "E_TRANSFORM"
E_OUTPUT_EXISTS = "E_OUTPUT_EXISTS"
E_PATH_CONFLICT = "E_PATH_CONFLICT"
E_INSECURE_PERMISSIONS = "E_INSECURE_PERMISSIONS"
E_TOOL_MISSING = "E_TOOL_MISSING"
E_IO = "E_IO"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def load_batch_tool():
    """Load the HA-02 tool (which loads the canonical merge writer)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        BATCH_TOOL_NAME)
    try:
        spec = importlib.util.spec_from_file_location(
            "mihomo_competition_ha_batch", path)
        if spec is None or spec.loader is None:
            raise OSError(path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        raise SystemExit("ha-profile: FAIL %s" % E_TOOL_MISSING)


def read_json(path, code):
    """Private, regular, bounded UTF-8 JSON file; no symlink/reparse."""
    try:
        info = os.lstat(path)
    except OSError:
        raise ProfileError(code) from None
    if (stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_INPUT_BYTES):
        raise ProfileError(code)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise ProfileError(code) from None
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise ProfileError(code) from None
    if len(raw) > MAX_INPUT_BYTES or b"\x00" in raw:
        raise ProfileError(code)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(code) from None
    if text.startswith("\ufeff"):
        raise ProfileError(code)
    try:
        return json.loads(text), raw
    except ValueError:
        raise ProfileError(code) from None


def parse_utc(value):
    if not isinstance(value, str) or not TIME_RE.match(value):
        raise ProfileError(E_PINS)
    try:
        return datetime.datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc)
    except ValueError:
        raise ProfileError(E_PINS) from None


def parse_pins(path, min_validity_days):
    """Return {'A': {...}, 'B': {...}} or fail closed."""
    if min_validity_days < 0 or min_validity_days > MAX_VALIDITY_DAYS:
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
    doc, _raw = read_json(path, E_PINS)
    if not isinstance(doc, dict) or set(doc) != {"schema", "vps"}:
        raise ProfileError(E_PINS)
    if doc.get("schema") != PIN_SCHEMA:
        raise ProfileError(E_PINS)
    vps = doc.get("vps")
    if not isinstance(vps, dict) or set(vps) != {"A", "B"}:
        raise ProfileError(E_PINS)
    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = now + datetime.timedelta(days=min_validity_days)
    pins = {}
    for alias in ("A", "B"):
        entry = vps.get(alias)
        if (not isinstance(entry, dict)
                or set(entry) != {"fingerprint_sha256", "not_after",
                                  "source"}):
            raise ProfileError(E_PINS)
        fingerprint = entry["fingerprint_sha256"]
        if not isinstance(fingerprint, str) or not PIN_RE.match(fingerprint):
            raise ProfileError(E_PINS)
        source = entry["source"]
        if (not isinstance(source, str) or not 1 <= len(source) <= 200
                or "\n" in source or "\r" in source):
            raise ProfileError(E_PINS)
        not_after = parse_utc(entry["not_after"])
        if not_after <= threshold:
            raise ProfileError(E_PINS_EXPIRED, vps=alias,
                               detail="not_after=" + entry["not_after"])
        pins[alias] = {
            "fingerprint_sha256": fingerprint.lower(),
            "not_after": entry["not_after"],
            "source": source,
        }
    if pins["A"]["fingerprint_sha256"] == pins["B"]["fingerprint_sha256"]:
        raise ProfileError(E_PINS, detail="A/B fingerprints are identical")
    return pins


def is_reparse(path):
    """True for a Windows junction/symlink or any other reparse point."""
    try:
        info = os.lstat(path)
    except OSError:
        return True
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def find_delivery_manifest(delivery):
    if (os.path.islink(delivery) or is_reparse(delivery)
            or not os.path.isdir(delivery)):
        raise ProfileError(E_DELIVERY)
    names = sorted(name for name in os.listdir(delivery)
                   if DELIVERY_MANIFEST_RE.match(name))
    if len(names) != 1:
        raise ProfileError(E_DELIVERY)
    return os.path.join(delivery, names[0])


def load_delivery(delivery, merge):
    """Read and verify the HA-02 manifest and every delivered profile."""
    manifest_path = find_delivery_manifest(delivery)
    doc, _raw = read_json(manifest_path, E_DELIVERY)
    if (not isinstance(doc, dict)
            or doc.get("schema") != "mihomo-competition-ha-batch/1"):
        raise ProfileError(E_DELIVERY)
    entries = doc.get("terminals")
    if not isinstance(entries, list) or not entries:
        raise ProfileError(E_DELIVERY)
    if doc.get("terminal_count") != len(entries):
        raise ProfileError(E_DELIVERY)
    terminals = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProfileError(E_DELIVERY)
        name = entry.get("name")
        group = entry.get("group")
        output = entry.get("output")
        primary = entry.get("primary_vps")
        backup = entry.get("backup_vps")
        expected_group = {"A": "A-first", "B": "B-first"}.get(primary)
        if (not isinstance(name, str)
                or not merge.CLIENT_NAME_RE.match(name)
                or name.casefold() in seen
                or group != expected_group
                or backup not in ("A", "B") or primary == backup
                or output != name + "-ha.yaml"):
            raise ProfileError(E_DELIVERY)
        seen.add(name.casefold())
        path = os.path.join(delivery, output)
        if (os.path.dirname(os.path.realpath(path))
                != os.path.realpath(delivery)
                or os.path.islink(path) or not os.path.isfile(path)):
            raise ProfileError(E_DELIVERY)
        data = open(path, "rb").read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ProfileError(E_DELIVERY)
        if hashlib.sha256(data).hexdigest() != entry.get("output_sha256"):
            raise ProfileError(E_DELIVERY_HASH, terminal=name)
        terminals.append({
            "name": name,
            "group": group,
            "primary_vps": primary,
            "backup_vps": backup,
            "input": output,
            "input_sha256": entry["output_sha256"],
            "data": data,
        })
    return doc, terminals


def find_block(lines, name):
    """Line range of a proxy block, ending at the blank separator."""
    start = None
    for index, line in enumerate(lines):
        if line == "  - name: " + name:
            if start is not None:
                raise ProfileError(E_TRANSFORM)
            start = index
    if start is None:
        raise ProfileError(E_TRANSFORM)
    end = start + 1
    while end < len(lines) and lines[end] != "":
        end += 1
    if end == len(lines):
        raise ProfileError(E_TRANSFORM)
    return start, end


def transform(data, primary_pin, backup_pin):
    """Exactly three deterministic edits; everything else is byte-preserved."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(E_TRANSFORM) from None
    if "\r" in text:
        raise ProfileError(E_TRANSFORM)
    lines = text.split("\n")
    listen_at = [index for index, line in enumerate(lines)
                 if line == '  listen: "0.0.0.0:53"']
    if len(listen_at) != 1:
        raise ProfileError(E_TRANSFORM)
    replacements = {listen_at[0]: ['  listen: "127.0.0.1:53"']}
    for name, pin in (("Hysteria2", primary_pin),
                      ("Backup-Hysteria2", backup_pin)):
        start, end = find_block(lines, name)
        skips = [index for index in range(start, end)
                 if lines[index] == "    skip-cert-verify: true"]
        pins = [index for index in range(start, end)
                if lines[index].startswith("    fingerprint: ")]
        if len(skips) != 1 or pins:
            raise ProfileError(E_TRANSFORM)
        replacements[skips[0]] = ["    skip-cert-verify: false",
                                  "    fingerprint: " + pin]
    if len(replacements) != 3:
        raise ProfileError(E_TRANSFORM)
    output = []
    for index, line in enumerate(lines):
        output.extend(replacements.get(index, [line]))
    result = "\n".join(output)
    verify_transform(result, primary_pin, backup_pin)
    return result.encode("utf-8")


def verify_transform(text, primary_pin, backup_pin):
    lines = text.split("\n")
    if lines.count('  listen: "127.0.0.1:53"') != 1:
        raise ProfileError(E_TRANSFORM)
    if '  listen: "0.0.0.0:53"' in lines:
        raise ProfileError(E_TRANSFORM)
    if text.count("    skip-cert-verify: true") != 0:
        raise ProfileError(E_TRANSFORM)
    if text.count("    skip-cert-verify: false") != 2:
        raise ProfileError(E_TRANSFORM)
    if text.count("    fingerprint: " + primary_pin) != 1:
        raise ProfileError(E_TRANSFORM)
    if text.count("    fingerprint: " + backup_pin) != 1:
        raise ProfileError(E_TRANSFORM)
    if text.count("    fingerprint: ") != 2:
        raise ProfileError(E_TRANSFORM)


def manifest_name(version):
    return MANIFEST_PREFIX + version + MANIFEST_SUFFIX


def prevalidate_outputs(terminals, delivery, output_dir, manifest):
    if (os.path.islink(output_dir) or is_reparse(output_dir)
            or not os.path.isdir(output_dir)):
        raise ProfileError(E_PATH_CONFLICT, role="output-dir")
    output_real = os.path.realpath(output_dir)
    delivery_real = os.path.realpath(delivery)
    if (output_real == delivery_real
            or output_real.startswith(delivery_real + os.sep)):
        raise ProfileError(E_PATH_CONFLICT, role="output-dir")
    existing = {name.casefold() for name in os.listdir(output_dir)}
    seen = set()
    targets = []
    for terminal in terminals:
        name = terminal["name"] + OUTPUT_SUFFIX
        key = name.casefold()
        if key in seen:
            raise ProfileError(E_PATH_CONFLICT, terminal=terminal["name"])
        seen.add(key)
        if name.casefold() in existing:
            raise ProfileError(E_OUTPUT_EXISTS, terminal=terminal["name"],
                               role="output")
        targets.append(os.path.join(output_dir, name))
    if manifest.casefold() in existing:
        raise ProfileError(E_OUTPUT_EXISTS, role="manifest")
    return targets, os.path.join(output_dir, manifest)


def generate(delivery, pins_path, output_dir, config_version, min_days,
             batch, merge):
    if not batch.CONFIG_VERSION_RE.match(config_version or ""):
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
    delivery = os.path.abspath(delivery)
    output_dir = os.path.abspath(output_dir)
    pins_path = os.path.abspath(pins_path)
    batch.check_private_path(delivery, "delivery-input")
    batch.check_local_boundary(delivery, "delivery-input")
    batch.check_private_path(pins_path, "pins")
    batch.check_local_boundary(pins_path, "pins")
    batch.check_directory(output_dir, "output-dir")
    batch.check_private_path(output_dir, "output-dir")
    batch.check_local_boundary(output_dir, "output-dir")
    batch.verify_temp_inheritance(output_dir)
    source_doc, terminals = load_delivery(delivery, merge)
    pins = parse_pins(pins_path, min_days)
    pin_of = {alias: pins[alias]["fingerprint_sha256"] for alias in "AB"}
    manifest = manifest_name(config_version)
    targets, manifest_path = prevalidate_outputs(
        terminals, delivery, output_dir, manifest)
    payloads = []
    for terminal, target in zip(terminals, targets):
        payload = transform(terminal["data"], pin_of[terminal["primary_vps"]],
                            pin_of[terminal["backup_vps"]])
        payloads.append(payload)
    created = []
    entries = []
    try:
        for terminal, target, payload in zip(terminals, targets, payloads):
            try:
                merge.write_output(payload, target)
            except merge.MergeError as exc:
                raise ProfileError(exc.code, terminal=terminal["name"],
                                   role="output") from None
            identity = batch.file_identity(target)
            if identity is None:
                raise ProfileError(E_IO, terminal=terminal["name"])
            created.append((target, hashlib.sha256(payload).hexdigest(),
                            len(payload), identity[0], identity[1]))
            data = open(target, "rb").read(len(payload) + 1)
            if data != payload:
                raise ProfileError(E_IO, terminal=terminal["name"])
            batch.check_private_path(target, "output-file")
            entries.append({
                "name": terminal["name"],
                "group": terminal["group"],
                "primary_vps": terminal["primary_vps"],
                "backup_vps": terminal["backup_vps"],
                "input": terminal["input"],
                "input_sha256": terminal["input_sha256"],
                "output": os.path.basename(target),
                "output_sha256": hashlib.sha256(payload).hexdigest(),
                "output_bytes": len(payload),
                "pins": {
                    "primary": pin_of[terminal["primary_vps"]],
                    "backup": pin_of[terminal["backup_vps"]],
                },
            })
        document = {
            "schema": PROFILE_SCHEMA,
            "generator": {
                "tool": "tools/" + os.path.basename(__file__),
                "version": TOOL_VERSION,
                "config_version": config_version,
            },
            "canonical_source": {
                "delivery_manifest": os.path.basename(
                    find_delivery_manifest(delivery)),
                "delivery_schema": source_doc.get("schema"),
                "delivery_config_version": source_doc.get(
                    "generator", {}).get("config_version"),
            },
            "pins": {alias: pins[alias] for alias in "AB"},
            "validity": {
                "min_validity_days": min_days,
                "checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime()),
            },
            "permission_gate": ("windows-acl-allowlist"
                                if os.name == "nt" else "posix-mode-owner"),
            "terminal_count": len(entries),
            "terminals": entries,
            "rollback": {
                "kind": "delete-files-created-by-this-batch",
                "files": [entry["output"] for entry in entries] + [manifest],
            },
        }
        manifest_payload = json.dumps(
            document, sort_keys=True, indent=2,
            ensure_ascii=True).encode("utf-8") + b"\n"
        try:
            merge.write_output(manifest_payload, manifest_path)
        except merge.MergeError as exc:
            raise ProfileError(exc.code, role="manifest") from None
        identity = batch.file_identity(manifest_path)
        if identity is None:
            raise ProfileError(E_IO, role="manifest")
        created.append((manifest_path,
                        hashlib.sha256(manifest_payload).hexdigest(),
                        len(manifest_payload), identity[0], identity[1]))
        data = open(manifest_path, "rb").read(len(manifest_payload) + 1)
        if data != manifest_payload:
            raise ProfileError(E_IO, role="manifest")
        batch.check_private_path(manifest_path, "manifest-file")
    except BaseException as exc:
        result = batch.rollback(created)
        if isinstance(exc, (ProfileError, batch.BatchError)):
            exc.rollback = result
            raise
        error = ProfileError(E_IO)
        error.rollback = result
        raise error from None
    return {
        "terminals": len(terminals),
        "manifest": manifest,
        "output_paths": targets,
    }


def find_competition_manifest(delivery):
    if (os.path.islink(delivery) or is_reparse(delivery)
            or not os.path.isdir(delivery)):
        raise ProfileError(E_DELIVERY)
    names = sorted(name for name in os.listdir(delivery)
                   if MANIFEST_RE.match(name))
    if len(names) != 1:
        raise ProfileError(E_DELIVERY)
    return os.path.join(delivery, names[0])


def check(delivery, pins_path, min_days, batch, merge):
    delivery = os.path.abspath(delivery)
    pins_path = os.path.abspath(pins_path)
    batch.check_private_path(delivery, "delivery-input")
    batch.check_private_path(pins_path, "pins")
    manifest_path = find_competition_manifest(delivery)
    doc, _raw = read_json(manifest_path, E_DELIVERY)
    if (not isinstance(doc, dict) or doc.get("schema") != PROFILE_SCHEMA):
        raise ProfileError(E_DELIVERY)
    entries = doc.get("terminals")
    if not isinstance(entries, list) or not entries:
        raise ProfileError(E_DELIVERY)
    pins = parse_pins(pins_path, min_days)
    recorded_pins = doc.get("pins")
    if not isinstance(recorded_pins, dict):
        raise ProfileError(E_DELIVERY)
    for alias in "AB":
        recorded = recorded_pins.get(alias)
        if (not isinstance(recorded, dict)
                or recorded.get("fingerprint_sha256")
                != pins[alias]["fingerprint_sha256"]
                or recorded.get("not_after") != pins[alias]["not_after"]):
            raise ProfileError(E_PINS, vps=alias, detail="manifest mismatch")
    for entry in entries:
        path = os.path.join(delivery, entry.get("output", ""))
        if (os.path.basename(entry.get("output", "")) != entry.get("output")
                or not os.path.isfile(path) or os.path.islink(path)):
            raise ProfileError(E_DELIVERY)
        data = open(path, "rb").read(MAX_INPUT_BYTES + 1)
        if (len(data) != entry.get("output_bytes")
                or hashlib.sha256(data).hexdigest()
                != entry.get("output_sha256")):
            raise ProfileError(E_DELIVERY_HASH,
                               terminal=entry.get("name"))
    return {
        "terminals": len(entries),
        "validity": {alias: pins[alias]["not_after"] for alias in "AB"},
    }


class ProfileError(Exception):
    def __init__(self, code, exit_status=EXIT_FAILED, terminal=None, vps=None,
                 role=None, detail=None):
        super().__init__(code)
        self.code = code
        self.exit_status = exit_status
        self.terminal = terminal
        self.vps = vps
        self.role = role
        self.detail = detail
        self.rollback = None


def build_parser(merge):
    parser = merge._SilentParser(
        prog="mihomo-competition-ha-profile", add_help=False,
        allow_abbrev=False,
        description="Offline HA-03 competition profile transform "
                    "(operator-local; no network, no activation)")
    parser.add_argument("--delivery", required=True)
    parser.add_argument("--pins", required=True)
    parser.add_argument("--output-dir")
    parser.add_argument("--config-version")
    parser.add_argument("--min-validity-days", type=int,
                        default=MIN_VALIDITY_DEFAULT)
    parser.add_argument("--check", action="store_true")
    return parser


def report_failure(error):
    line = "ha-profile: FAIL %s" % error.code
    if error.terminal is not None:
        line += " terminal=%s" % error.terminal
    if error.vps is not None:
        line += " vps=%s" % error.vps
    if error.role is not None:
        line += " role=%s" % error.role
    if error.detail is not None:
        line += " detail=%s" % error.detail
    print(line, file=sys.stderr)
    if error.rollback is not None:
        print("ha-profile: ROLLBACK removed=%d skipped=%d complete=%s"
              % (error.rollback["removed"], error.rollback["skipped"],
                 "yes" if error.rollback["complete"] else "no"),
              file=sys.stderr)


def main(argv=None):
    batch = load_batch_tool()
    merge = batch.load_merge_tool()
    try:
        args = build_parser(merge).parse_args(argv)
    except merge.MergeError as exc:
        report_failure(ProfileError(exc.code, exit_status=exc.exit_status))
        return exc.exit_status
    except Exception:
        report_failure(ProfileError(E_IO))
        return EXIT_FAILED
    try:
        if args.check:
            result = check(args.delivery, args.pins,
                           args.min_validity_days, batch, merge)
            print("ha-profile: OK")
            print("terminals: %d" % result["terminals"])
            print("pins: valid")
            print("validity: A=%s B=%s" % (result["validity"]["A"],
                                           result["validity"]["B"]))
            return EXIT_OK
        if not args.output_dir or not args.config_version:
            raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
        result = generate(args.delivery, args.pins, args.output_dir,
                          args.config_version, args.min_validity_days, batch,
                          merge)
    except (ProfileError, batch.BatchError) as exc:
        report_failure(exc)
        return exc.exit_status
    except Exception:
        report_failure(ProfileError(E_IO))
        return EXIT_FAILED
    print("ha-profile: OK")
    print("terminals: %d" % result["terminals"])
    print("version: %s" % args.config_version)
    print("manifest: %s" % result["manifest"])
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
