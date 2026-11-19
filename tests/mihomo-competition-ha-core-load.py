#!/usr/bin/env python3
"""Issue #48 HA-02 -- load a generated delivery with a pinned real Mihomo core.

Static YAML assertions cannot prove that Mihomo accepts the generated profiles.
This harness takes an operator-supplied, SHA-256-pinned Mihomo binary, checks
the delivery manifest's hashes byte for byte, and then asks that exact core to
load every generated profile (`mihomo -t`). It downloads nothing itself.

It is NOT part of the hermetic contract suite: it needs a real core binary.
CI runs it against a pinned Linux release; an operator runs it on the target
platform with the target binary. The core itself may fetch its GeoIP database on
first use, so a private scratch `--workdir` is reused across profiles.

Failure output never repeats the core's own message: a config error can quote a
YAML field value, and a real delivery is credential-bearing. Use
`--show-core-output` only for a synthetic local delivery.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
import time

PROFILE_SUFFIX = "-ha.yaml"
MANIFEST_GLOB = "ha-delivery-*.json"

E_USAGE = "E_USAGE"
E_CORE_HASH = "E_CORE_HASH"
E_MANIFEST = "E_MANIFEST"
E_PROFILE_HASH = "E_PROFILE_HASH"
E_PROFILE_LOAD = "E_PROFILE_LOAD"
E_NO_PROFILES = "E_NO_PROFILES"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


class LoadError(Exception):
    def __init__(self, code, exit_status=EXIT_FAILED):
        super().__init__(code)
        self.code = code
        self.exit_status = exit_status


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def one_manifest(delivery):
    manifests = sorted(glob.glob(os.path.join(delivery, MANIFEST_GLOB)))
    if len(manifests) != 1:
        raise LoadError(E_MANIFEST)


def check_delivery(delivery, expect_terminals=None):
    """Verify the manifest and return [(name, profile_path)] in manifest order."""
    one_manifest(delivery)
    manifest_path = sorted(glob.glob(os.path.join(delivery, MANIFEST_GLOB)))[0]
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        raise LoadError(E_MANIFEST) from None
    if manifest.get("schema") != "mihomo-competition-ha-batch/1":
        raise LoadError(E_MANIFEST)
    entries = manifest.get("terminals")
    if not isinstance(entries, list) or not entries:
        raise LoadError(E_MANIFEST)
    if expect_terminals is not None and len(entries) != expect_terminals:
        raise LoadError(E_MANIFEST)
    if manifest.get("terminal_count") != len(entries):
        raise LoadError(E_MANIFEST)
    files = []
    seen = set()
    for entry in entries:
        name = entry.get("name")
        output = entry.get("output")
        if (not isinstance(name, str) or not isinstance(output, str)
                or output != name + PROFILE_SUFFIX or name in seen):
            raise LoadError(E_MANIFEST)
        seen.add(name)
        path = os.path.join(delivery, output)
        if not os.path.isfile(path) or os.path.islink(path):
            raise LoadError(E_MANIFEST)
        digest = file_sha256(path)
        if digest != entry.get("output_sha256"):
            raise LoadError(E_PROFILE_HASH)
        if os.path.getsize(path) != entry.get("output_bytes"):
            raise LoadError(E_PROFILE_HASH)
        files.append((name, path))
    profiles = sorted(glob.glob(os.path.join(delivery, "*" + PROFILE_SUFFIX)))
    if len(profiles) != len(entries):
        raise LoadError(E_MANIFEST)
    return files


def core_version(binary):
    try:
        result = subprocess.run([binary, "-v"], capture_output=True, text=True,
                                errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise LoadError(E_CORE_HASH) from None
    if result.returncode != 0:
        raise LoadError(E_CORE_HASH)
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def load_profile(binary, profile, workdir, timeout, show_output):
    """Load one profile; retry once so a transient core-side fetch cannot fail
    an otherwise loadable delivery (a genuinely invalid profile fails twice)."""
    command = [binary, "-t", "-d", workdir, "-f", profile]
    last = None
    for attempt in range(2):
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    errors="replace", timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            last = exc
            result = None
        if result is not None and result.returncode == 0:
            return
        if result is not None:
            last = result
        if attempt == 0:
            time.sleep(1.0)
    if show_output and isinstance(last, subprocess.CompletedProcess):
        for line in (last.stdout + last.stderr).splitlines()[:5]:
            print("  core: %s" % line, file=sys.stderr)
    raise LoadError(E_PROFILE_LOAD)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mihomo-competition-ha-core-load",
        description="Load every generated HA-02 profile with a pinned Mihomo "
                    "core after verifying the delivery manifest")
    parser.add_argument("--mihomo", required=True, help="path to the core")
    parser.add_argument("--expect-sha256", required=True,
                        help="required SHA-256 of that exact core binary")
    parser.add_argument("--delivery", required=True,
                        help="delivery directory produced by the HA-02 tool")
    parser.add_argument("--expect-terminals", type=int,
                        help="require exactly this many delivered profiles")
    parser.add_argument("--workdir", required=True,
                        help="private scratch directory for the core's state")
    parser.add_argument("--timeout", type=int, default=120,
                        help="per-profile load timeout in seconds")
    parser.add_argument("--show-core-output", action="store_true",
                        help="print core error lines (synthetic deliveries only)")
    return parser


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    if args.expect_terminals is not None and args.expect_terminals < 1:
        print("core-load: FAIL %s" % E_USAGE, file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isdir(args.delivery) or not os.path.isdir(args.workdir):
        print("core-load: FAIL %s" % E_USAGE, file=sys.stderr)
        return EXIT_USAGE
    if not os.path.isfile(args.mihomo):
        print("core-load: FAIL %s" % E_CORE_HASH, file=sys.stderr)
        return EXIT_FAILED
    digest = file_sha256(args.mihomo)
    if digest != args.expect_sha256.lower():
        print("core-load: FAIL %s" % E_CORE_HASH, file=sys.stderr)
        return EXIT_FAILED
    started = time.monotonic()
    try:
        files = check_delivery(args.delivery, args.expect_terminals)
        version = core_version(args.mihomo)
        for _name, profile in files:
            load_profile(args.mihomo, profile, args.workdir, args.timeout,
                         args.show_core_output)
    except LoadError as exc:
        print("core-load: FAIL %s" % exc.code, file=sys.stderr)
        return exc.exit_status
    except Exception:
        print("core-load: FAIL %s" % E_PROFILE_LOAD, file=sys.stderr)
        return EXIT_FAILED
    print("core-load: OK")
    print("core: %s" % version)
    print("core_sha256: %s" % digest)
    print("profiles: %d" % len(files))
    print("elapsed_seconds: %.1f" % (time.monotonic() - started))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
