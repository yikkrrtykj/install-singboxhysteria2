#!/usr/bin/env python3
"""Operator entry for isolated protocol tests and explicit receiver preparation."""
import argparse
import json
import sys
from quality_failover.pilot import receiver_init, run_pilot, error_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    init = modes.add_parser("receiver-init")
    init.add_argument("--directory", required=True)
    init.add_argument("--ip", required=True)
    init.add_argument("--port", type=int, default=8448)
    init.add_argument("--openssl", default="openssl")
    for mode in ("run", "gui"):
        command = modes.add_parser(mode)
        command.add_argument("--mihomo", required=True)
        command.add_argument("--expect-sha256", required=True)
        if mode == "run":
            command.add_argument("--profile", required=True)
            command.add_argument("--name", required=True)
            command.add_argument("--receiver-info", required=True)
            command.add_argument("--ca", required=True)
            command.add_argument("--result", required=True)
            command.add_argument("--fail-mbps", type=float, default=4)
            command.add_argument("--recover-mbps", type=float, default=8)
        else:
            command.add_argument("--results", required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "receiver-init":
            print(json.dumps(receiver_init(args.directory, args.ip, args.port, args.openssl)))
        elif args.mode == "gui":
            from quality_failover.pilot_ui import show
            show(args.mihomo, args.expect_sha256, args.results)
        else:
            result = run_pilot(args.profile, args.name, args.receiver_info, args.ca,
                               args.mihomo, args.expect_sha256, args.result,
                               emit=lambda value: print(json.dumps(value), flush=True),
                               fail_mbps=args.fail_mbps, recover_mbps=args.recover_mbps)
            print(json.dumps({"v": 1, "passed": result["passed"], "cleanup_complete": result["cleanup_complete"]}))
            return 0 if result["passed"] else 1
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exception:
        print(json.dumps({"v": 1, "passed": False, "error": error_code(exception)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
