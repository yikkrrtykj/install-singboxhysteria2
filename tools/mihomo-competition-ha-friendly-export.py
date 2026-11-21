#!/usr/bin/env python3
"""Publish a human-readable HA-04 YAML after rechecking the complete HA chain.

This is an offline delivery adapter for the planned Windows A/B console, NOT a
replacement for HA-02/03/04. It never edits the trusted generated deliveries,
rewrites YAML, contacts a VPS, or activates Clash. The original manifests remain
in the operator's private workspace.

Output: <terminal>-A-first.yaml or <terminal>-B-first.yaml. There is no --force.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys


NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
GROUPS = {"A-first": "A", "B-first": "B"}
MAX_PROFILE_BYTES = 128 * 1024


class ExportError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def output_name(terminal: str, group: str) -> str:
    if not isinstance(terminal, str) or not NAME_RE.fullmatch(terminal):
        raise ExportError("E_NAME")
    if group not in GROUPS:
        raise ExportError("E_GROUP")
    return terminal + "-" + group + ".yaml"


def _fastprobe():
    path = Path(__file__).resolve().with_name(
        "mihomo-competition-ha4-fastprobe.py")
    spec = importlib.util.spec_from_file_location("ha4_friendly_source", path)
    if spec is None or spec.loader is None:
        raise ExportError("E_TOOL_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inside(path: Path, ancestor: Path) -> bool:
    try:
        path.resolve().relative_to(ancestor.resolve())
        return True
    except ValueError:
        return False


def _publish_no_clobber(path: Path, data: bytes, batch) -> None:
    # Exclusive creation plus private-parent ACL prevents overwriting earlier
    # deliveries. Both the output hash and permissions are checked after write.
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        batch.check_private_path(str(path), "output-file")
        with open(path, "rb") as handle:
            actual = handle.read(len(data) + 1)
        if actual != data:
            raise ExportError("E_IO")
    except FileExistsError as exc:
        raise ExportError("E_OUTPUT_EXISTS") from exc
    except Exception:
        # Never delete a possibly replaced path: leave a failed file for
        # operator inspection and refuse to report successful delivery.
        if fd is not None:
            os.close(fd)
        raise


def export_one(ha04_dir: str, ha03_dir: str, ha02_dir: str,
               pins_file: str, terminal: str, group: str,
               output_dir: str, fast=None) -> tuple[str, str]:
    filename = output_name(terminal, group)
    fast = _fastprobe() if fast is None else fast
    variant = Path(ha04_dir).resolve()
    competition = Path(ha03_dir).resolve()
    delivery = Path(ha02_dir).resolve()
    pins = Path(pins_file).resolve()
    dest = Path(output_dir).resolve()

    for source in (variant, competition, delivery):
        if dest == source or _inside(dest, source) or _inside(source, dest):
            raise ExportError("E_PATH_CONFLICT")

    batch = fast.batch_tool()
    batch.check_directory(str(dest), "output-dir")
    batch.check_private_path(str(dest), "output-dir")
    batch.check_local_boundary(str(dest), "output-dir")
    # This calls the real HA-03 + HA-04 byte-for-byte derivation checks and
    # the HY2 pin validity floor before any output is created.
    fast.check(str(variant), str(competition), str(delivery), str(pins))

    doc, _manifest, entries, _names = fast.load_variant_delivery(str(variant))
    merge = batch.load_merge_tool()
    fast.validate_manifest_entries(entries, merge)
    matches = [e for e in entries if e["name"] == terminal]
    if len(matches) != 1:
        raise ExportError("E_TERMINAL")
    entry = matches[0]
    if (entry["group"] != group
            or entry["primary_vps"] != GROUPS[group]
            or entry["backup_vps"] != ("B" if group == "A-first" else "A")):
        raise ExportError("E_ROLE_MISMATCH")

    source = variant / entry["output"]
    # The original source was checked; re-read and rehash before publication.
    if source.is_symlink() or not source.is_file():
        raise ExportError("E_SOURCE")
    data = source.read_bytes()
    if (len(data) > MAX_PROFILE_BYTES
            or len(data) != entry["output_bytes"]
            or hashlib.sha256(data).hexdigest() != entry["output_sha256"]):
        raise ExportError("E_SOURCE_HASH")

    target = dest / filename
    _publish_no_clobber(target, data, batch)
    return filename, hashlib.sha256(data).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ha04", required=True)
    parser.add_argument("--ha03", required=True)
    parser.add_argument("--ha02", required=True)
    parser.add_argument("--pins", required=True)
    parser.add_argument("--terminal", required=True)
    parser.add_argument("--group", required=True, choices=sorted(GROUPS))
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        name, digest = export_one(args.ha04, args.ha03, args.ha02,
                                  args.pins, args.terminal, args.group,
                                  args.output_dir)
    except ExportError as error:
        print("friendly-export: FAIL " + error.code, file=sys.stderr)
        return 1
    except Exception:
        # The underlying tools can fail closed for ACL, source or pin errors.
        # Never print an exception that might embed a credential or private path.
        print("friendly-export: FAIL E_PREFLIGHT_OR_IO", file=sys.stderr)
        return 1
    print("friendly-export: OK")
    print("file: " + name)
    print("sha256: " + digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
