#!/usr/bin/env python3
"""Issue #48 HA-04 -- competition fast-probe profile variants for a HA-03 delivery.

Issue #92 compares native Mihomo health-probe policies without any extra
controller. This tool derives an experiment/acceptance-candidate profile per
terminal from an already-verified HA-03 competition delivery:

    HA-02 delivery  --(HA-03 tool)-->  competition/<name>-hac.yaml
                                             |
        this tool, two deterministic edits:  v
    <name>-ha4f.yaml + ha4-fastprobe-<version>-i<I>-t<T>.json

Edits inside the `自动选择` fallback group only:

- `interval: 60`  -> `interval: <3|5|10>`
- `timeout: 5000` -> `timeout: <1000|2000|5000>`

Everything else is byte-identical to the HA-03 competition profile: the four
fixed-priority nodes, the probe URL and `expected-status: "204"`, `lazy: false`,
the HY2 pins / `skip-cert-verify: false`, the loopback-only listeners and
`allow-lan: false`. The shipped generic 60 s template is never modified: HA-04
only writes new files in a separate output directory.

Security compatibility is explicit, not hand-edited YAML. Both generation and
`--check` first run the HA-03 preflight (`--ha02-delivery` + `--pins`) against
the untouched HA-03 delivery, so the HA-02 source hashes, role mapping, pin
mapping, per-file permissions and recorded validity floor are all re-verified
exactly as HA-03 requires. The check then re-derives the expected HA-04 bytes
against the trusted HA-03 delivery and compares them byte-for-byte.

Default OFF: this tool only writes files. No profile is imported or activated,
no Mihomo source/core is patched, no client is restarted and no business
connections are cleared. Quality Failover stays opt-in and disabled.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import sys

MAX_INPUT_BYTES = 256 * 1024
MAX_TERMINALS = 256

BATCH_TOOL_NAME = "mihomo-competition-ha-batch.py"
HA03_TOOL_NAME = "mihomo-competition-ha-profile.py"

SCHEMA = "mihomo-competition-ha4-fastprobe/1"
TOOL_VERSION = "1"
VARIANT_SUFFIX = "-ha4f.yaml"
SOURCE_SUFFIX = "-hac.yaml"
MANIFEST_PREFIX = "ha4-fastprobe-"
MANIFEST_SUFFIX = ".json"
GROUP_NAME = "自动选择"
NODE_ORDER = ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")
INTERVALS = (3, 5, 10)
TIMEOUTS = (1000, 2000, 5000)
GENERIC_INTERVAL = 60
GENERIC_TIMEOUT = 5000
PROBE_URL = '    url: "https://www.gstatic.com/generate_204"'
EXPECTED_STATUS = '    expected-status: "204"'
LAZY_OFF = "    lazy: false"

VARIANT_RE = re.compile(
    r"\Aha4-fastprobe-[A-Za-z0-9][A-Za-z0-9._-]{0,63}-i(?:3|5|10)-"
    r"t(?:1000|2000|5000)\.json\Z")
# Trailing policy suffix of the manifest name, used to bind the file name to the
# interval/timeout recorded inside the manifest and to the generated profiles.
MANIFEST_POLICY_RE = re.compile(r"-i([0-9]+)-t([0-9]+)\.json\Z")

E_USAGE = "E_USAGE"
E_DELIVERY = "E_DELIVERY"
E_DELIVERY_HASH = "E_DELIVERY_HASH"
E_TRANSFORM = "E_TRANSFORM"
E_OUTPUT_EXISTS = "E_OUTPUT_EXISTS"
E_PATH_CONFLICT = "E_PATH_CONFLICT"
E_INSECURE_PERMISSIONS = "E_INSECURE_PERMISSIONS"
E_TOOL_MISSING = "E_TOOL_MISSING"
E_IO = "E_IO"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def load_module(name, filename):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise OSError(path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        raise SystemExit("ha4-fastprobe: FAIL %s" % E_TOOL_MISSING)


# The HA-03 tool is loaded once so its verified transform, JSON reader,
# permission helpers and preflight are reused instead of duplicated.
ha03 = load_module("mihomo_competition_ha_profile", HA03_TOOL_NAME)
ProfileError = ha03.ProfileError
_ha03_json = ha03.json
_ha03_batch = None


def batch_tool():
    global _ha03_batch
    if _ha03_batch is None:
        _ha03_batch = ha03.load_batch_tool()
    return _ha03_batch


def validate_policy(interval, timeout):
    if interval not in INTERVALS or timeout not in TIMEOUTS:
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)


def find_block(lines, name):
    start = None
    for index, line in enumerate(lines):
        if line == "  - name: " + name:
            if start is not None:
                raise ProfileError(E_TRANSFORM, detail="duplicate group")
            start = index
    if start is None:
        raise ProfileError(E_TRANSFORM, detail="group missing")
    end = start + 1
    while end < len(lines) and lines[end] != "":
        end += 1
    if end == len(lines):
        raise ProfileError(E_TRANSFORM, detail="unterminated group")
    return start, end


def overlay(data, interval, timeout):
    """Exactly two deterministic edits inside the 自动选择 group."""
    validate_policy(interval, timeout)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(E_TRANSFORM) from None
    if "\r" in text:
        raise ProfileError(E_TRANSFORM, detail="CRLF source")
    lines = text.split("\n")
    start, end = find_block(lines, GROUP_NAME)
    block = lines[start:end]
    # The peer generation template must still be the generic shipped policy:
    # fixed four-node priority, 204 health URL, lazy false, 60 s / 5000 ms.
    expected_proxies = ["    proxies:"] + [
        "      - " + name for name in NODE_ORDER]
    proxies_at = None
    for index, line in enumerate(block):
        if line == "    proxies:":
            if proxies_at is not None:
                raise ProfileError(E_TRANSFORM, detail="duplicate proxies")
            proxies_at = index
    if (proxies_at is None
            or block[proxies_at:proxies_at + 5] != expected_proxies
            or len(block) <= proxies_at + 5
            or block[proxies_at + 5] != PROBE_URL
            or len([line for line in block
                    if line.startswith("      - ")]) != len(NODE_ORDER)):
        raise ProfileError(E_TRANSFORM, detail="node order/shape")
    for marker, label in ((PROBE_URL, "url"), (LAZY_OFF, "lazy"),
                          (EXPECTED_STATUS, "expected-status")):
        if block.count(marker) != 1:
            raise ProfileError(E_TRANSFORM, detail=label)
    if block.count("    interval: %d" % GENERIC_INTERVAL) != 1:
        raise ProfileError(E_TRANSFORM, detail="base interval is not 60")
    if block.count("    timeout: %d" % GENERIC_TIMEOUT) != 1:
        raise ProfileError(E_TRANSFORM, detail="base timeout is not 5000")
    if "    lazy: true" in block:
        raise ProfileError(E_TRANSFORM, detail="lazy must stay false")
    replacements = 0
    output = []
    for index, line in enumerate(lines):
        if start < index < end and line == "    interval: %d" % GENERIC_INTERVAL:
            output.append("    interval: %d" % interval)
            replacements += 1
        elif start < index < end and line == "    timeout: %d" % GENERIC_TIMEOUT:
            output.append("    timeout: %d" % timeout)
            replacements += 1
        else:
            output.append(line)
    if replacements != 2:
        raise ProfileError(E_TRANSFORM, detail="overlay did not apply twice")
    result = "\n".join(output).encode("utf-8")
    if result.count(b"    interval: %d\n" % interval) != 1:
        raise ProfileError(E_TRANSFORM)
    if result.count(b"    timeout: %d\n" % timeout) != 1:
        raise ProfileError(E_TRANSFORM)
    if result.count(b"    lazy: false") != 1:
        raise ProfileError(E_TRANSFORM)
    return result


def manifest_name(config_version, interval, timeout):
    return "%s%s-i%d-t%d%s" % (MANIFEST_PREFIX, config_version,
                               interval, timeout, MANIFEST_SUFFIX)


def load_ha03_delivery(delivery, merge):
    """Read the HA-03 competition manifest and every verified output profile."""
    batch = batch_tool()
    batch.check_directory(delivery, "delivery-input")
    batch.check_private_path(delivery, "delivery-input")
    batch.check_local_boundary(delivery, "delivery-input")
    names = ha03.list_names(delivery, E_DELIVERY)
    manifests = sorted(name for name in names
                       if name.startswith("ha-competition-")
                       and name.endswith(".json"))
    if len(manifests) != 1:
        raise ProfileError(E_DELIVERY, detail="ha-03 manifest ambiguous")
    manifest_path = os.path.join(delivery, manifests[0])
    ha03.check_regular_private_file(batch, manifest_path, "input-manifest",
                                    E_DELIVERY)
    doc, manifest_raw = ha03.read_json(manifest_path, E_DELIVERY)
    if (not isinstance(doc, dict)
            or doc.get("schema") != ha03.PROFILE_SCHEMA):
        raise ProfileError(E_DELIVERY)
    entries = doc.get("terminals")
    if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TERMINALS):
        raise ProfileError(E_DELIVERY)
    if doc.get("terminal_count") != len(entries):
        raise ProfileError(E_DELIVERY)
    pins = doc.get("pins")
    if not isinstance(pins, dict) or set(pins) != {"A", "B"}:
        raise ProfileError(E_DELIVERY)
    terminals = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProfileError(E_DELIVERY)
        name = entry.get("name")
        output = entry.get("output")
        primary = entry.get("primary_vps")
        backup = entry.get("backup_vps")
        expected_group = {"A": "A-first", "B": "B-first"}.get(primary)
        if (not isinstance(name, str)
                or not merge.CLIENT_NAME_RE.match(name)
                or name.casefold() in seen
                or output != name + SOURCE_SUFFIX
                or entry.get("group") != expected_group
                or primary not in ("A", "B") or backup not in ("A", "B")
                or primary == backup):
            raise ProfileError(E_DELIVERY)
        seen.add(name.casefold())
        path = os.path.join(delivery, output)
        if os.path.dirname(os.path.realpath(path)) != os.path.realpath(delivery):
            raise ProfileError(E_DELIVERY)
        ha03.check_regular_private_file(batch, path, "input-profile",
                                        E_DELIVERY_HASH)
        data = open(path, "rb").read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ProfileError(E_DELIVERY)
        if (len(data) != entry.get("output_bytes")
                or hashlib.sha256(data).hexdigest()
                != entry.get("output_sha256")):
            raise ProfileError(E_DELIVERY_HASH, terminal=name)
        terminals.append({
            "name": name,
            "group": entry.get("group"),
            "primary_vps": primary,
            "backup_vps": backup,
            "input": output,
            "input_sha256": entry["output_sha256"],
            "data": data,
        })
    actual = [name for name in names if name.casefold().endswith(SOURCE_SUFFIX)]
    if set(actual) != {terminal["name"] + SOURCE_SUFFIX
                       for terminal in terminals}:
        raise ProfileError(E_DELIVERY)
    return doc, manifests[0], manifest_raw, terminals


def prevalidate_outputs(terminals, inputs, output_dir, manifest):
    batch = batch_tool()
    batch.check_directory(output_dir, "output-dir")
    batch.check_private_path(output_dir, "output-dir")
    batch.check_local_boundary(output_dir, "output-dir")
    batch.verify_temp_inheritance(output_dir)
    output_real = os.path.realpath(output_dir)
    for source in inputs:
        source_real = os.path.realpath(source)
        if (output_real == source_real
                or output_real.startswith(source_real + os.sep)):
            raise ProfileError(E_PATH_CONFLICT, role="output-dir")
    existing = {name.casefold() for name in
                ha03.list_names(output_dir, E_PATH_CONFLICT)}
    seen = set()
    targets = []
    for terminal in terminals:
        name = terminal["name"] + VARIANT_SUFFIX
        key = name.casefold()
        if key in seen:
            raise ProfileError(E_PATH_CONFLICT, terminal=terminal["name"])
        seen.add(key)
        if key in existing:
            raise ProfileError(E_OUTPUT_EXISTS, terminal=terminal["name"],
                               role="output")
        targets.append(os.path.join(output_dir, name))
    if manifest.casefold() in existing:
        raise ProfileError(E_OUTPUT_EXISTS, role="manifest")
    return targets, os.path.join(output_dir, manifest)


def generate(ha03_delivery, ha02_delivery, pins_path, output_dir, config_version,
             interval, timeout, batch=None, merge=None):
    batch = batch if batch is not None else batch_tool()
    merge = merge if merge is not None else batch.load_merge_tool()
    validate_policy(interval, timeout)
    if not batch.CONFIG_VERSION_RE.match(config_version or ""):
        raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
    ha03_delivery = os.path.abspath(ha03_delivery)
    ha02_delivery = os.path.abspath(ha02_delivery)
    pins_path = os.path.abspath(pins_path)
    output_dir = os.path.abspath(output_dir)
    # Full HA-03 chain preflight first: HA-02 source hashes, role/pin mapping,
    # recorded validity floor and the five-edit security transform of the
    # untouched HA-03 delivery must all still hold.
    ha03.check(ha03_delivery, ha02_delivery, pins_path, 0, None, batch, merge)
    source_doc, source_manifest_name, source_manifest_raw, terminals = \
        load_ha03_delivery(ha03_delivery, merge)
    pin_a = source_doc["pins"]["A"]["fingerprint_sha256"]
    pin_b = source_doc["pins"]["B"]["fingerprint_sha256"]
    manifest = manifest_name(config_version, interval, timeout)
    targets, manifest_path = prevalidate_outputs(
        terminals, (ha03_delivery, ha02_delivery), output_dir, manifest)
    payloads = []
    for terminal in terminals:
        payload = overlay(terminal["data"], interval, timeout)
        primary_pin = pin_a if terminal["primary_vps"] == "A" else pin_b
        backup_pin = pin_a if terminal["backup_vps"] == "A" else pin_b
        ha03.verify_competition_profile(payload, primary_pin, backup_pin)
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
            ha03.check_regular_private_file(batch, target, "output-file", E_IO)
            entries.append({
                "name": terminal["name"],
                "group": terminal["group"],
                "primary_vps": terminal["primary_vps"],
                "backup_vps": terminal["backup_vps"],
                "source": terminal["input"],
                "source_sha256": terminal["input_sha256"],
                "output": os.path.basename(target),
                "output_sha256": hashlib.sha256(payload).hexdigest(),
                "output_bytes": len(payload),
            })
        document = {
            "schema": SCHEMA,
            "generator": {
                "tool": "tools/" + os.path.basename(__file__),
                "version": TOOL_VERSION,
                "config_version": config_version,
            },
            "canonical_source": {
                "profile_manifest": source_manifest_name,
                "profile_manifest_sha256": hashlib.sha256(
                    source_manifest_raw).hexdigest(),
                "profile_schema": source_doc.get("schema"),
                "profile_config_version": source_doc.get(
                    "generator", {}).get("config_version"),
            },
            "policy": {
                "group": GROUP_NAME,
                "interval": interval,
                "timeout": timeout,
                "lazy": False,
                "expected_status": "204",
                "generic_defaults_preserved": True,
                "nodes": list(NODE_ORDER),
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
        manifest_payload = _ha03_json.dumps(
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
        ha03.check_regular_private_file(batch, manifest_path, "manifest-file",
                                        E_IO)
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
        "policy": "interval=%d timeout=%d" % (interval, timeout),
    }


def load_variant_delivery(delivery):
    batch = batch_tool()
    batch.check_directory(delivery, "delivery-input")
    batch.check_private_path(delivery, "delivery-input")
    batch.check_local_boundary(delivery, "delivery-input")
    names = ha03.list_names(delivery, E_DELIVERY)
    manifests = sorted(name for name in names
                       if name.startswith(MANIFEST_PREFIX)
                       and name.endswith(MANIFEST_SUFFIX))
    if len(manifests) != 1 or not VARIANT_RE.match(manifests[0]):
        raise ProfileError(E_DELIVERY, detail="ha-04 manifest ambiguous")
    manifest_path = os.path.join(delivery, manifests[0])
    ha03.check_regular_private_file(batch, manifest_path, "manifest-file",
                                    E_DELIVERY)
    doc, _raw = ha03.read_json(manifest_path, E_DELIVERY)
    if (not isinstance(doc, dict) or doc.get("schema") != SCHEMA):
        raise ProfileError(E_DELIVERY)
    generator = doc.get("generator")
    if (not isinstance(generator, dict)
            or set(generator) != {"tool", "version", "config_version"}
            or generator.get("tool")
            != "tools/" + os.path.basename(__file__)
            or generator.get("version") != TOOL_VERSION
            or not isinstance(generator.get("config_version"), str)
            or not batch.CONFIG_VERSION_RE.match(
                generator.get("config_version") or "")):
        raise ProfileError(E_DELIVERY, detail="ha-04 generator metadata")
    policy = doc.get("policy")
    if (not isinstance(policy, dict)
            or set(policy) != {"group", "interval", "timeout", "lazy",
                               "expected_status", "generic_defaults_preserved",
                               "nodes"}
            or policy.get("group") != GROUP_NAME
            or policy.get("interval") not in INTERVALS
            or policy.get("timeout") not in TIMEOUTS
            or policy.get("lazy") is not False
            or policy.get("expected_status") != "204"
            or policy.get("generic_defaults_preserved") is not True
            or policy.get("nodes") != list(NODE_ORDER)):
        raise ProfileError(E_DELIVERY)
    # Bind the audit metadata to the file name: the manifest is only valid for
    # the config version and the interval/timeout encoded in its own name.
    match = MANIFEST_POLICY_RE.search(manifests[0])
    if (match is None
            or int(match.group(1)) != policy["interval"]
            or int(match.group(2)) != policy["timeout"]):
        raise ProfileError(E_DELIVERY, detail="manifest policy mismatch")
    expected_name = manifest_name(generator["config_version"],
                                  policy["interval"], policy["timeout"])
    if manifests[0] != expected_name:
        raise ProfileError(E_DELIVERY,
                           detail="manifest config-version mismatch")
    entries = doc.get("terminals")
    if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TERMINALS):
        raise ProfileError(E_DELIVERY)
    if doc.get("terminal_count") != len(entries):
        raise ProfileError(E_DELIVERY)
    return doc, manifests[0], entries, names


def validate_manifest_entries(entries, merge):
    batch = batch_tool()
    seen_names = set()
    seen_outputs = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProfileError(E_DELIVERY)
        name = entry.get("name")
        output = entry.get("output")
        source = entry.get("source")
        primary = entry.get("primary_vps")
        backup = entry.get("backup_vps")
        expected_group = {"A": "A-first", "B": "B-first"}.get(primary)
        if (not isinstance(name, str)
                or not merge.CLIENT_NAME_RE.match(name)
                or output != name + VARIANT_SUFFIX
                or source != name + SOURCE_SUFFIX
                or os.path.basename(output) != output
                or os.path.basename(source) != source
                or entry.get("group") != expected_group
                or primary not in ("A", "B") or backup not in ("A", "B")
                or primary == backup
                or not isinstance(entry.get("source_sha256"), str)
                or not isinstance(entry.get("output_sha256"), str)):
            raise ProfileError(E_DELIVERY)
        if (name.casefold() in seen_names
                or output.casefold() in seen_outputs):
            raise ProfileError(E_DELIVERY)
        seen_names.add(name.casefold())
        seen_outputs.add(output.casefold())
    return entries


def check(variant_delivery, ha03_delivery, ha02_delivery, pins_path,
          batch=None, merge=None):
    batch = batch if batch is not None else batch_tool()
    merge = merge if merge is not None else batch.load_merge_tool()
    variant_delivery = os.path.abspath(variant_delivery)
    ha03_delivery = os.path.abspath(ha03_delivery)
    ha02_delivery = os.path.abspath(ha02_delivery)
    pins_path = os.path.abspath(pins_path)
    if (os.path.realpath(variant_delivery) == os.path.realpath(ha03_delivery)
            or os.path.realpath(variant_delivery)
            == os.path.realpath(ha02_delivery)):
        raise ProfileError(E_PATH_CONFLICT, role="delivery-input")
    # 1. The HA-03 security gate must still pass on the untouched parent.
    ha03.check(ha03_delivery, ha02_delivery, pins_path, 0, None, batch, merge)
    # 2. Bind the variant to the exact trusted HA-03 delivery.
    (source_doc, source_manifest_name, source_manifest_raw, terminals) = \
        load_ha03_delivery(ha03_delivery, merge)
    pin_a = source_doc["pins"]["A"]["fingerprint_sha256"]
    pin_b = source_doc["pins"]["B"]["fingerprint_sha256"]
    (doc, manifest_name_value, entries, names) = load_variant_delivery(
        variant_delivery)
    entries = validate_manifest_entries(entries, merge)
    policy = doc["policy"]
    interval, timeout = policy["interval"], policy["timeout"]
    canonical = doc.get("canonical_source")
    if (not isinstance(canonical, dict)
            or set(canonical) != {"profile_manifest",
                                  "profile_manifest_sha256",
                                  "profile_schema",
                                  "profile_config_version"}):
        raise ProfileError(E_DELIVERY)
    if canonical.get("profile_manifest") != source_manifest_name:
        raise ProfileError(E_DELIVERY)
    if canonical.get("profile_manifest_sha256") != hashlib.sha256(
            source_manifest_raw).hexdigest():
        raise ProfileError(E_DELIVERY_HASH, role="source-manifest")
    if (canonical.get("profile_schema") != source_doc.get("schema")
            or canonical.get("profile_config_version")
            != source_doc.get("generator", {}).get("config_version")):
        raise ProfileError(E_DELIVERY)
    # 3. Exact file set / canonical names, then byte-for-byte re-derivation.
    profile_names = [name for name in names
                     if name.casefold().endswith(VARIANT_SUFFIX)]
    if set(profile_names) != {entry["output"] for entry in entries}:
        raise ProfileError(E_DELIVERY)
    source_by_name = {terminal["name"]: terminal for terminal in terminals}
    if len(source_by_name) != len(entries):
        raise ProfileError(E_DELIVERY)
    for entry in entries:
        terminal = source_by_name.get(entry["name"])
        if (terminal is None
                or entry.get("group") != terminal["group"]
                or entry.get("primary_vps") != terminal["primary_vps"]
                or entry.get("backup_vps") != terminal["backup_vps"]
                or entry.get("source") != terminal["input"]
                or entry.get("source_sha256") != terminal["input_sha256"]):
            raise ProfileError(E_DELIVERY, terminal=entry["name"])
    for entry in entries:
        terminal = source_by_name[entry["name"]]
        path = os.path.join(variant_delivery, entry["output"])
        if (os.path.dirname(os.path.realpath(path))
                != os.path.realpath(variant_delivery)):
            raise ProfileError(E_DELIVERY)
        ha03.check_regular_private_file(batch, path, "output-file",
                                        E_DELIVERY_HASH)
        data = open(path, "rb").read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            raise ProfileError(E_DELIVERY)
        if (len(data) != entry.get("output_bytes")
                or hashlib.sha256(data).hexdigest()
                != entry.get("output_sha256")):
            raise ProfileError(E_DELIVERY_HASH, terminal=entry["name"])
        expected_bytes = overlay(terminal["data"], interval, timeout)
        if data != expected_bytes:
            raise ProfileError(
                E_TRANSFORM, terminal=entry["name"],
                detail="not the deterministic fast-probe transform of the source")
        primary_pin = pin_a if terminal["primary_vps"] == "A" else pin_b
        backup_pin = pin_a if terminal["backup_vps"] == "A" else pin_b
        # 4. Competition security invariants must still hold in the variant.
        ha03.verify_competition_profile(data, primary_pin, backup_pin)
    return {
        "terminals": len(entries),
        "policy": "interval=%d timeout=%d" % (interval, timeout),
        "manifest": manifest_name_value,
    }


def build_parser(merge):
    parser = merge._SilentParser(
        prog="mihomo-competition-ha4-fastprobe", add_help=False,
        allow_abbrev=False,
        description="HA-04 fast-probe profile variants derived from a verified "
                    "HA-03 competition delivery (offline; no activation)")
    parser.add_argument("--delivery", required=True)
    parser.add_argument("--source-delivery")
    parser.add_argument("--ha02-delivery", required=True)
    parser.add_argument("--pins", required=True)
    parser.add_argument("--output-dir")
    parser.add_argument("--config-version")
    parser.add_argument("--interval", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--check", action="store_true")
    return parser


def report_failure(error):
    line = "ha4-fastprobe: FAIL %s" % error.code
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
        print("ha4-fastprobe: ROLLBACK removed=%d skipped=%d complete=%s"
              % (error.rollback["removed"], error.rollback["skipped"],
                 "yes" if error.rollback["complete"] else "no"),
              file=sys.stderr)


def main(argv=None):
    batch = batch_tool()
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
            if not args.source_delivery:
                raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
            if args.output_dir or args.config_version is not None:
                raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
            if args.interval is not None or args.timeout is not None:
                raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
            result = check(args.delivery, args.source_delivery,
                           args.ha02_delivery, args.pins)
            print("ha4-fastprobe: OK")
            print("terminals: %d" % result["terminals"])
            print("policy: %s" % result["policy"])
            print("manifest: %s" % result["manifest"])
            return EXIT_OK
        if args.source_delivery is not None:
            raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
        if not args.output_dir or not args.config_version:
            raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
        if args.interval is None or args.timeout is None:
            raise ProfileError(E_USAGE, exit_status=EXIT_USAGE)
        result = generate(args.delivery, args.ha02_delivery, args.pins,
                          args.output_dir, args.config_version, args.interval,
                          args.timeout)
    except (ProfileError, batch.BatchError) as exc:
        report_failure(exc)
        return exc.exit_status
    except Exception:
        report_failure(ProfileError(E_IO))
        return EXIT_FAILED
    print("ha4-fastprobe: OK")
    print("terminals: %d" % result["terminals"])
    print("policy: %s" % result["policy"])
    print("version: %s" % args.config_version)
    print("manifest: %s" % result["manifest"])
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
