"""CLI entry point for the dark P6 office agent (issue #67 PR-6A).

Dark by design: this runs the agent's own cycle + spool + signing machinery.
It performs no server call unless a poster is injected by a caller, so the
shipped default is fixtures-only. Secrets are NEVER accepted on the command
line -- only paths to 0600 files.
"""

from __future__ import annotations

import argparse
import json
import sys

from .agent import AgentConfig, ConfigError, RemoteProbeAgent, read_config_file
from .spool import SpoolError


def build_parser():
    parser = argparse.ArgumentParser(
        description="P6 office remote-probe agent (DARK; issue #67 PR-6A)")
    parser.add_argument("--config", required=True,
                        help="JSON configuration file (no secret material)")
    parser.add_argument("--cycles", type=int, default=1,
                        help="number of cycles to run (default 1)")
    parser.add_argument("--status", action="store_true",
                        help="print the sanitized status object")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        config = read_config_file(args.config)
        agent = RemoteProbeAgent(config)
        agent.open()
        agent.run_forever(cycles=max(1, args.cycles))
    except ConfigError as exc:
        print("fatal configuration error: %s" % exc, file=sys.stderr)
        return 2
    except SpoolError as exc:
        # A storage refusal is a designed, sanitized outcome: report it like
        # one instead of dumping a traceback from a safe refusal.
        print("fatal storage refusal: %s" % exc, file=sys.stderr)
        return 3
    if args.status:
        print(json.dumps(agent.status(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
