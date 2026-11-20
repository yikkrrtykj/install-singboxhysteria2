#!/usr/bin/env python3
"""Issue #48 HA-03 -- competition-safe profile transform for a HA-02 delivery.

One operator-local command turns the HA-02 dual-active delivery into a second,
independent competition delivery:

    delivery/<name>-ha.yaml + pins.json + competition version
        -> competition/<name>-hac.yaml                    (per terminal)
        -> competition/ha-competition-<version>.json      (pins, hashes, rollback)

The transform is intentionally tiny and deterministic (five edits per file):

- allow-lan true -> false and bind-address "*" -> "127.0.0.1";
- DNS listener 0.0.0.0:53 -> 127.0.0.1:53;
- Hysteria2 (the terminal's primary VPS): skip-cert-verify true -> false and a
  SHA-256 DER certificate pin for that physical VPS;
- Backup-Hysteria2 (the terminal's backup VPS): same, with that VPS's pin.

It never re-serialises YAML and never touches the HA-02 input files. The pin
mapping comes from the HA-02 manifest's `primary_vps`/`backup_vps`, so a B-first
terminal pins B on `Hysteria2` and A on `Backup-Hysteria2`. Pins are loaded from
a local, access-controlled pins file whose certificate `not_before`/`not_after`
dates are enforced here (Mihomo leaf pinning does not validate certificate
expiry). Generation and `--check` both refuse expired/soon-expiring pins, and
`--check` cannot lower the validity floor recorded at delivery time.

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
MAX_TERMINALS = 256
BATCH_TOOL_NAME = "mihomo-competition-ha-batch.py"
PIN_SCHEMA = "mihomo-competition-ha-pins/2"
PROFILE_SCHEMA = "mihomo-competition-ha-profile/2"
OUTPUT_SUFFIX = "-hac.yaml"
MANIFEST_PREFIX = "ha-competition-"
MANIFEST_SUFFIX = ".json"
TOOL_VERSION = "2"
MIN_VALIDITY_DEFAULT = 7
MAX_VALIDITY_DAYS = 3650
CLOCK_SKEW_SECONDS = 300

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


def _no_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document


def read_json(path, code):
    """Private, regular, bounded UTF-8 JSON file; no symlink/reparse.

    Duplicate object keys are rejected so two readers cannot disagree about
    which value a manifest/pins field has.
    """
    try:
        info = os.lstat(path)
    except OSError:
        raise ProfileError(code) from None
    if (stat.S_ISLNK(info.st_mode) or is_reparse(path)
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
        return json.loads(text, object_pairs_hook=_no_duplicate_keys), raw
    except ValueError:
        raise ProfileError(code) from None


def is_reparse(path):
    """True for a Windows junction/symlink or any other reparse point."""
    try:
        info = os.lstat(path)
    except OSError:
        return True
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def check_regular_private_file(batch, path, role, code):
    """A regular, non-reparse, bounded, private, boundary-safe file."""
    try:
        info = os.lstat(path)
    except OSError:
        raise ProfileError(code) from None
    if (stat.S_ISLNK(info.st_mode) or is_reparse(path)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_INPUT_BYTES):
        raise ProfileError(code)
    batch.check_private_path(path, role)
    batch.check_local_boundary(path, role)


def parse_utc(value):
    if not isinstance(value, str) or not TIME_RE.match(value):
        raise ProfileError(E_PINS)
    try:
        return datetime.datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc)
    except ValueError:
        raise ProfileError(E_PINS) from None


def validate_pins_document(doc, min_validity_days, required_through):
    """Return normalised A/B pins or fail closed."""
    if min_validity_days < 0 or min_validity_days > MAX_VALIDITY_DAYS:
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
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
                or set(entry) != {"fingerprint_sha256", "not_before",
                                  "not_after", "source"}):
            raise ProfileError(E_PINS)
        fingerprint = entry["fingerprint_sha256"]
        if not isinstance(fingerprint, str) or not PIN_RE.match(fingerprint):
            raise ProfileError(E_PINS)
        source = entry["source"]
        if (not isinstance(source, str) or not 1 <= len(source) <= 200
                or "\n" in source or "\r" in source):
            raise ProfileError(E_PINS)
        not_before = parse_utc(entry["not_before"])
        not_after = parse_utc(entry["not_after"])
        if not_after <= not_before:
            raise ProfileError(E_PINS)
        if not_before > now + datetime.timedelta(seconds=CLOCK_SKEW_SECONDS):
            raise ProfileError(E_PINS, vps=alias,
                               detail="not_before=in the future")
        if not_after <= threshold:
            raise ProfileError(E_PINS_EXPIRED, vps=alias,
                               detail="not_after=" + entry["not_after"])
        if required_through is not None and not_after < required_through:
            raise ProfileError(E_PINS_EXPIRED, vps=alias,
                               detail="require-valid-through")
        pins[alias] = {
            "fingerprint_sha256": fingerprint.lower(),
            "not_before": entry["not_before"],
            "not_after": entry["not_after"],
            "source": source,
        }
    if pins["A"]["fingerprint_sha256"] == pins["B"]["fingerprint_sha256"]:
        raise ProfileError(E_PINS, detail="A/B fingerprints are identical")
    return pins


def parse_pins(path, min_validity_days, required_through):
    doc, _raw = read_json(path, E_PINS)
    return validate_pins_document(doc, min_validity_days, required_through)


def parse_required_through(value):
    if value is None:
        return None
    try:
        return parse_utc(value)
    except ProfileError:
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE) from None


def find_delivery_manifest(delivery):
    if (os.path.islink(delivery) or is_reparse(delivery)
            or not os.path.isdir(delivery)):
        raise ProfileError(E_DELIVERY)
    names = sorted(name for name in os.listdir(delivery)
                   if DELIVERY_MANIFEST_RE.match(name))
    if len(names) != 1:
        raise ProfileError(E_DELIVERY)
    return os.path.join(delivery, names[0])


def load_delivery(delivery, merge, batch):
    """Read and verify the HA-02 manifest and every delivered profile."""
    batch.check_directory(delivery, "delivery-input")
    batch.check_private_path(delivery, "delivery-input")
    batch.check_local_boundary(delivery, "delivery-input")
    manifest_path = find_delivery_manifest(delivery)
    check_regular_private_file(batch, manifest_path, "input-manifest",
                               E_DELIVERY)
    doc, _raw = read_json(manifest_path, E_DELIVERY)
    if (not isinstance(doc, dict)
            or doc.get("schema") != "mihomo-competition-ha-batch/1"):
        raise ProfileError(E_DELIVERY)
    entries = doc.get("terminals")
    if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TERMINALS):
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
                or primary not in ("A", "B") or backup not in ("A", "B")
                or primary == backup
                or output != name + "-ha.yaml"):
            raise ProfileError(E_DELIVERY)
        seen.add(name.casefold())
        path = os.path.join(delivery, output)
        if (os.path.dirname(os.path.realpath(path))
                != os.path.realpath(delivery)):
            raise ProfileError(E_DELIVERY)
        check_regular_private_file(batch, path, "input-profile",
                                   E_DELIVERY_HASH
                                   if os.path.exists(path) else E_DELIVERY)
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
    actual = {name.casefold() for name in os.listdir(delivery)
              if name.endswith("-ha.yaml")}
    if actual != {t["name"].casefold() + "-ha.yaml" for t in terminals}:
        raise ProfileError(E_DELIVERY)
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
    """Exactly five deterministic edits; everything else is byte-preserved."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(E_TRANSFORM) from None
    if "\r" in text:
        raise ProfileError(E_TRANSFORM)
    lines = text.split("\n")
    replacements = {}
    singles = (
        ("allow-lan: true", ["allow-lan: false"]),
        ('bind-address: "*"', ['bind-address: "127.0.0.1"']),
        ('  listen: "0.0.0.0:53"', ['  listen: "127.0.0.1:53"']),
    )
    for original, replacement in singles:
        positions = [index for index, line in enumerate(lines)
                     if line == original]
        if len(positions) != 1:
            raise ProfileError(E_TRANSFORM)
        replacements[positions[0]] = replacement
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
    if len(replacements) != 5:
        raise ProfileError(E_TRANSFORM)
    output = []
    for index, line in enumerate(lines):
        output.extend(replacements.get(index, [line]))
    result = "\n".join(output)
    verify_competition_profile(result.encode("utf-8"), primary_pin,
                               backup_pin)
    return result.encode("utf-8")


def verify_competition_profile(data, primary_pin, backup_pin):
    """Independently prove the competition security invariants of a profile."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(E_TRANSFORM) from None
    if "\r" in text:
        raise ProfileError(E_TRANSFORM)
    lines = text.split("\n")
    required = {
        "allow-lan: false": 1,
        'bind-address: "127.0.0.1"': 1,
        '  listen: "127.0.0.1:53"': 1,
        "    skip-cert-verify: false": 2,
    }
    for line, count in required.items():
        if lines.count(line) != count:
            raise ProfileError(E_TRANSFORM)
    for forbidden in ("allow-lan: true", 'bind-address: "*"',
                      '  listen: "0.0.0.0:53"',
                      "    skip-cert-verify: true"):
        if forbidden in lines:
            raise ProfileError(E_TRANSFORM)
    if text.count("    fingerprint: ") != 2:
        raise ProfileError(E_TRANSFORM)
    for name, pin in (("Hysteria2", primary_pin),
                      ("Backup-Hysteria2", backup_pin)):
        start, end = find_block(lines, name)
        block = lines[start:end]
        pins = [line[len("    fingerprint: "):] for line in block
                if line.startswith("    fingerprint: ")]
        skips = [line for line in block
                 if line == "    skip-cert-verify: false"]
        if pins != [pin] or len(skips) != 1:
            raise ProfileError(E_TRANSFORM)


def manifest_name(version):
    return MANIFEST_PREFIX + version + MANIFEST_SUFFIX


def prevalidate_outputs(terminals, delivery, output_dir, manifest, batch):
    batch.check_directory(output_dir, "output-dir")
    batch.check_private_path(output_dir, "output-dir")
    batch.check_local_boundary(output_dir, "output-dir")
    batch.verify_temp_inheritance(output_dir)
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
             required_through, batch, merge):
    if not batch.CONFIG_VERSION_RE.match(config_version or ""):
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
    delivery = os.path.abspath(delivery)
    output_dir = os.path.abspath(output_dir)
    pins_path = os.path.abspath(pins_path)
    check_regular_private_file(batch, pins_path, "pins", E_PINS)
    source_doc, terminals = load_delivery(delivery, merge, batch)
    pins = parse_pins(pins_path, min_days, required_through)
    pin_of = {alias: pins[alias]["fingerprint_sha256"] for alias in "AB"}
    manifest = manifest_name(config_version)
    targets, manifest_path = prevalidate_outputs(
        terminals, delivery, output_dir, manifest, batch)
    payloads = [transform(terminal["data"],
                          pin_of[terminal["primary_vps"]],
                          pin_of[terminal["backup_vps"]])
                for terminal in terminals]
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
            check_regular_private_file(batch, target, "output-file", E_IO)
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
                    "primary": pins[terminal["primary_vps"]],
                    "backup": pins[terminal["backup_vps"]],
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
            "pins": pins,
            "validity": {
                "min_validity_days": min_days,
                "required_valid_through": (
                    required_through.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if required_through is not None else None),
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
        check_regular_private_file(batch, manifest_path, "manifest-file", E_IO)
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


def _validate_manifest_entries(doc, merge):
    if (not isinstance(doc, dict) or doc.get("schema") != PROFILE_SCHEMA):
        raise ProfileError(E_DELIVERY)
    entries = doc.get("terminals")
    if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TERMINALS):
        raise ProfileError(E_DELIVERY)
    if doc.get("terminal_count") != len(entries):
        raise ProfileError(E_DELIVERY)
    seen_names = set()
    seen_outputs = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProfileError(E_DELIVERY)
        name = entry.get("name")
        group = entry.get("group")
        primary = entry.get("primary_vps")
        backup = entry.get("backup_vps")
        output = entry.get("output")
        expected_group = {"A": "A-first", "B": "B-first"}.get(primary)
        if (not isinstance(name, str) or not merge.CLIENT_NAME_RE.match(name)
                or not isinstance(output, str)
                or output != name + OUTPUT_SUFFIX
                or os.path.basename(output) != output
                or group != expected_group
                or primary not in ("A", "B") or backup not in ("A", "B")
                or primary == backup
                or entry.get("input") != name + "-ha.yaml"
                or not isinstance(entry.get("pins"), dict)):
            raise ProfileError(E_DELIVERY)
        if (name.casefold() in seen_names
                or output.casefold() in seen_outputs):
            raise ProfileError(E_DELIVERY)
        seen_names.add(name.casefold())
        seen_outputs.add(output.casefold())
    return entries


def check(delivery, pins_path, min_days, required_through, batch, merge):
    delivery = os.path.abspath(delivery)
    pins_path = os.path.abspath(pins_path)
    batch.check_directory(delivery, "delivery-input")
    batch.check_private_path(delivery, "delivery-input")
    batch.check_local_boundary(delivery, "delivery-input")
    check_regular_private_file(batch, pins_path, "pins", E_PINS)
    manifest_path = find_competition_manifest(delivery)
    check_regular_private_file(batch, manifest_path, "manifest-file",
                               E_DELIVERY)
    doc, _raw = read_json(manifest_path, E_DELIVERY)
    entries = _validate_manifest_entries(doc, merge)
    pins_doc, _pins_raw = read_json(pins_path, E_PINS)
    validity = doc.get("validity")
    if (not isinstance(validity, dict)
            or set(validity) != {"min_validity_days",
                                 "required_valid_through", "checked_utc"}
            or not isinstance(validity.get("checked_utc"), str)
            or not TIME_RE.match(validity.get("checked_utc", ""))):
        raise ProfileError(E_DELIVERY)
    recorded_days = validity.get("min_validity_days")
    if (not isinstance(recorded_days, int)
            or not 0 <= recorded_days <= MAX_VALIDITY_DAYS):
        raise ProfileError(E_DELIVERY)
    # The check may raise the recorded floor, never lower it.
    effective_days = max(recorded_days, min_days)
    recorded_through = validity.get("required_valid_through")
    through = required_through
    if recorded_through is not None:
        try:
            recorded_dt = parse_utc(recorded_through)
        except ProfileError:
            raise ProfileError(E_DELIVERY) from None
        through = recorded_dt if through is None else max(through, recorded_dt)
    pins = validate_pins_document(pins_doc, effective_days, through)
    recorded_pins = doc.get("pins")
    if not isinstance(recorded_pins, dict) or set(recorded_pins) != {"A", "B"}:
        raise ProfileError(E_DELIVERY)
    for alias in "AB":
        recorded = recorded_pins.get(alias)
        if (not isinstance(recorded, dict)
                or set(recorded) != {"fingerprint_sha256", "not_before",
                                     "not_after", "source"}
                or recorded != pins[alias]):
            raise ProfileError(E_PINS, vps=alias, detail="manifest mismatch")
    files = {name.casefold() for name in os.listdir(delivery)
             if name.endswith(OUTPUT_SUFFIX)}
    expected = {entry["output"].casefold() for entry in entries}
    if files != expected:
        raise ProfileError(E_DELIVERY)
    for entry in entries:
        path = os.path.join(delivery, entry["output"])
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(delivery):
            raise ProfileError(E_DELIVERY)
        check_regular_private_file(batch, path, "output-file",
                                   E_DELIVERY_HASH)
        data = open(path, "rb").read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ProfileError(E_DELIVERY)
        if (len(data) != entry.get("output_bytes")
                or hashlib.sha256(data).hexdigest()
                != entry.get("output_sha256")):
            raise ProfileError(E_DELIVERY_HASH, terminal=entry["name"])
        primary_pin = pins[entry["primary_vps"]]["fingerprint_sha256"]
        backup_pin = pins[entry["backup_vps"]]["fingerprint_sha256"]
        declared = entry.get("pins")
        if (not isinstance(declared, dict)
                or declared.get("primary") != pins[entry["primary_vps"]]
                or declared.get("backup") != pins[entry["backup_vps"]]):
            raise ProfileError(E_PINS, terminal=entry["name"],
                               detail="manifest mismatch")
        # Security semantics are re-derived from the YAML itself; a modified
        # profile cannot pass merely by updating the manifest hashes.
        verify_competition_profile(data, primary_pin, backup_pin)
    return {
        "terminals": len(entries),
        "validity": {alias: pins[alias]["not_after"] for alias in "AB"},
    }


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
    parser.add_argument("--require-valid-through")
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
        required_through = parse_required_through(args.require_valid_through)
        if args.check:
            result = check(args.delivery, args.pins,
                           args.min_validity_days, required_through, batch,
                           merge)
            print("ha-profile: OK")
            print("terminals: %d" % result["terminals"])
            print("pins: valid")
            print("validity: A=%s B=%s" % (result["validity"]["A"],
                                           result["validity"]["B"]))
            return EXIT_OK
        if not args.output_dir or not args.config_version:
            raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
        result = generate(args.delivery, args.pins, args.output_dir,
                          args.config_version, args.min_validity_days,
                          required_through, batch, merge)
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
