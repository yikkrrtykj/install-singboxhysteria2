#!/usr/bin/env python3
"""Installed root CLI; expected manifest SHA/publisher/scope supplied by operator."""
import argparse
import json
import os
import sys
from pathlib import Path

# The installed root-only helper tree contains these exact validators.
parent = Path(__file__).resolve().parent
sys.path.insert(0, str(parent))
if (parent.parent / 'monitor-v2').is_dir():
    sys.path.insert(0, str(parent.parent / 'monitor-v2'))
from p6_artifact import read_artifact
from p6_distribution import publish, retire


def main():
    p = argparse.ArgumentParser(); commands = p.add_subparsers(dest='operation', required=True)
    add = commands.add_parser('publish'); add.add_argument('--package', required=True); add.add_argument('--manifest', required=True)
    add.add_argument('--manifest-sha256', required=True); add.add_argument('--publisher', required=True)
    add.add_argument('--scope', choices=('production', 'lab'), required=True)
    remove = commands.add_parser('retire'); remove.add_argument('--archive', required=True)
    discard = commands.add_parser('discard-stage'); discard.add_argument('--stage', required=True)
    args = p.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        print('[FAIL] root authority'); return 2
    print('[PASS] root authority')
    try:
        if args.operation == 'publish':
            artifact, _ = read_artifact()
            result = publish(args.package, args.manifest, args.manifest_sha256, args.publisher.upper(), args.scope, artifact)
            print('[PASS] Windows distribution published ' + json.dumps(result, sort_keys=True))
        else:
            retire(args.stage if args.operation == 'discard-stage' else args.archive, stage=args.operation == 'discard-stage')
            print('[PASS] selected inactive managed distribution retired')
        print('[SKIP] no service, identity, firewall, code-signing trust or ingest activation change')
        return 0
    except Exception:
        print('[FAIL] windows_distribution_admission_unavailable; current selection retained or unavailable, never unsigned fallback')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
