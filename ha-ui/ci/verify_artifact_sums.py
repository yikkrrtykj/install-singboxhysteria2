#!/usr/bin/env python3
"""Verify every file hash listed in the build's ``SHA256SUMS.txt``.

This is the CI/operator-side companion to ``build_windows.write_receipt``:
hashes are recomputed from the bytes actually present in the artifact
directory, never from in-memory payloads. The delivery directory boundary is
strict: it must contain exactly the three regular files
``ha-ui.exe``, ``receipt.json`` and ``SHA256SUMS.txt``; the manifest must list
exactly the EXE and the receipt. Symlinks, Windows reparse points, extra files,
extra directories, malformed/duplicate entries and missing files all fail
closed. Both LF and CRLF ``SHA256SUMS.txt`` files are accepted.

Usage:
    python ha-ui/ci/verify_artifact_sums.py --dist dist
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

SUM_FILE = "SHA256SUMS.txt"
EXE_FILE = "ha-ui.exe"
RECEIPT_FILE = "receipt.json"
REQUIRED_FILES = (EXE_FILE, RECEIPT_FILE)
ALLOWED_FILES = REQUIRED_FILES + (SUM_FILE,)
HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(
    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_reparse_point(path: Path) -> bool:
    """True for symlinks and Windows reparse points (junctions, etc.)."""
    try:
        info = path.lstat()
    except OSError:
        return False
    if path.is_symlink():
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def parse_sums(path: Path) -> tuple[dict[str, str], list[str]]:
    problems: list[str] = []
    entries: dict[str, str] = {}
    if not path.exists():
        return entries, ["missing " + SUM_FILE]
    if is_reparse_point(path):
        return entries, ["reparse point not allowed: " + SUM_FILE]
    if not path.is_file():
        return entries, ["not a regular file: " + SUM_FILE]
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


def _plain_delivery_file(path: Path, name: str) -> list[str]:
    problems: list[str] = []
    if is_reparse_point(path):
        problems.append("reparse point not allowed: " + name)
        return problems
    try:
        info = path.lstat()
    except OSError:
        problems.append("missing file: " + name)
        return problems
    if not stat.S_ISREG(info.st_mode):
        problems.append("not a regular file: " + name)
    return problems


def verify(dist: Path) -> list[str]:
    dist = Path(dist)
    problems: list[str] = []
    if not dist.exists():
        return ["delivery directory missing: " + str(dist)]
    if is_reparse_point(dist):
        return ["delivery directory is a reparse point: " + str(dist)]
    if not dist.is_dir():
        return ["delivery path is not a directory: " + str(dist)]

    entries, parse_problems = parse_sums(dist / SUM_FILE)
    problems.extend(parse_problems)

    # The manifest must cover exactly the EXE and the receipt.
    entry_names = set(entries)
    for name in REQUIRED_FILES:
        if name not in entry_names:
            problems.append("missing entry: " + name)
    for name in sorted(entry_names - set(REQUIRED_FILES)):
        problems.append("unexpected entry in manifest: " + name)
    for name in REQUIRED_FILES:
        if not (dist / name).exists():
            problems.append("missing file: " + name)

    # The delivery directory itself must contain exactly the three allowed
    # plain files. Extra files, directories, symlinks and reparse points are
    # all rejected, so the uploaded artifact cannot silently grow.
    try:
        children = sorted(dist.iterdir(), key=lambda path: path.name)
    except OSError:
        return problems + ["unreadable delivery directory: " + str(dist)]
    for child in children:
        name = child.name
        if name not in ALLOWED_FILES:
            problems.append("unexpected entry in delivery directory: " + name)
            continue
        problems.extend(_plain_delivery_file(child, name))

    for name, digest in sorted(entries.items()):
        if name not in REQUIRED_FILES:
            continue
        target = dist / name
        if is_reparse_point(target):
            continue  # already reported by the boundary walk
        if not target.is_file():
            continue  # already reported as missing/non-regular
        if sha256_file(target) != digest:
            problems.append("hash mismatch: " + name)
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
