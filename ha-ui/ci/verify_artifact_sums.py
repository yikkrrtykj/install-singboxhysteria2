#!/usr/bin/env python3
"""Verify every file hash listed in the build's ``SHA256SUMS.txt``.

This is the CI/operator-side companion to ``build_windows.write_receipt``:
hashes are recomputed from the bytes actually present in the artifact
directory, never from in-memory payloads. It fails closed on a wrong hash, a
missing or tampered file, a duplicate/malformed entry, a symlink, or an
unlisted extra file. Both LF and CRLF ``SHA256SUMS.txt`` files are accepted
(the verifier only cares about the delivered file bytes).

Usage:
    python ha-ui/ci/verify_artifact_sums.py --dist dist
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

SUM_FILE = "SHA256SUMS.txt"
REQUIRED_FILES = ("ha-ui.exe", "receipt.json")
HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sums(path: Path) -> tuple[dict[str, str], list[str]]:
    problems: list[str] = []
    entries: dict[str, str] = {}
    if not path.is_file():
        return entries, ["missing " + SUM_FILE]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return entries, ["unreadable " + SUM_FILE]
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            problems.append("malformed line %d" % lineno)
            continue
        digest, filename = parts
        if not HEX64.fullmatch(digest):
            problems.append("bad hash on line %d" % lineno)
            continue
        filename = filename.strip()
        if filename.startswith("*"):
            filename = filename[1:]
        if (not filename or filename in (".", "..")
                or "/" in filename or "\\" in filename):
            problems.append("unsafe filename on line %d" % lineno)
            continue
        if filename == SUM_FILE:
            problems.append(SUM_FILE + " must not list itself")
            continue
        if filename in entries:
            problems.append("duplicate entry: " + filename)
            continue
        entries[filename] = digest.lower()
    if not entries:
        problems.append("no file entries")
    return entries, problems


def verify(dist: Path) -> list[str]:
    dist = Path(dist)
    problems: list[str] = []
    entries, parse_problems = parse_sums(dist / SUM_FILE)
    problems.extend(parse_problems)
    on_disk = {path.name for path in dist.iterdir() if path.is_file()}
    for name in REQUIRED_FILES:
        if name not in entries:
            problems.append("missing entry: " + name)
    for name, digest in sorted(entries.items()):
        target = dist / name
        if target.is_symlink():
            problems.append("symlink not allowed: " + name)
            continue
        if not target.is_file():
            problems.append("missing file: " + name)
            continue
        if sha256_file(target) != digest:
            problems.append("hash mismatch: " + name)
    for name in sorted(on_disk - set(entries) - {SUM_FILE}):
        problems.append("unlisted file: " + name)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", default="dist")
    args = parser.parse_args(argv)
    problems = verify(Path(args.dist).resolve())
    if problems:
        for problem in problems:
            print("::error::artifact sums: " + problem, file=sys.stderr)
        return 1
    entries, _ = parse_sums(Path(args.dist).resolve() / SUM_FILE)
    print("SHA256SUMS OK (%d files)" % len(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
