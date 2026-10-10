#!/usr/bin/env python3
"""Explicit idle-bundle receiver update; secrets never appear in arguments or diagnostics."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from quality_failover.receiver_update import update_receiver


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bundle',required=True)
    parser.add_argument('--receiver-info',required=True)
    parser.add_argument('--clash-home',required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(update_receiver(Path(args.bundle),Path(args.receiver_info),Path(args.clash_home))))
        return 0
    except Exception:
        print('[FAIL] Receiver update incomplete. Close the quality window and check the new receiver; no secret displayed.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
