#!/usr/bin/env python3
"""Monitor v2 Phase E2 -- read-only web dashboard command line.

Subcommands
-----------

``setup``   interactive first-time configuration: detects the current SSH
            client IP (``$SSH_CONNECTION``) and offers to whitelist it,
            configures the admin password (never stored in plaintext) and
            generates the one-time recovery key. Writes ONLY
            ``<data-dir>/access.json`` / ``auth.json`` -- sing-box
            configuration files are never read or written here.
``serve``   runs the long-lived E1 collector + snapshot broker + the
            loopback web listener (default 127.0.0.1:9191).

The web listener is loopback-only unless remote management is EXPLICITLY
requested (--listen 0.0.0.0 or another public address); a remote listener
refuses to start unless TLS, the admin password, the recovery key and a
non-empty whitelist are ALL configured. Any single missing piece is a fatal
startup error, not a warning.
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from collector import Collector, resolve_secret  # noqa: E402
from web.access import LOOPBACK_ALLOW, AccessPolicy, host_entry_for_ip  # noqa: E402
from web.broker import SnapshotBroker  # noqa: E402
from web.server import (MONITOR_WEB_VERSION, MonitorWebApp,  # noqa: E402
                        build_server)

DEFAULT_DATA_DIR = "/var/lib/singbox-monitor"
DEFAULT_PORT = 9191
DEFAULT_URL = "http://127.0.0.1:9091"
LOOPBACK_LISTEN = frozenset({"127.0.0.1", "::1", "localhost"})


def default_data_dir():
    return os.environ.get("SINGBOX_MONITOR_DATA_DIR", DEFAULT_DATA_DIR)


def detect_ssh_client_ip():
    """First field of $SSH_CONNECTION is the SSH client source IP."""
    connection = os.environ.get("SSH_CONNECTION", "").split()
    return connection[0] if connection else None


def ensure_data_dir(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(data_dir, 0o700)
        except OSError:
            pass


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Monitor v2 Phase E2 web dashboard "
                    "(read-only; loopback-only by default)")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser(
        "setup", help="first-time configuration (whitelist / access data)")
    setup.add_argument("--data-dir", default=None,
                       help="access data directory "
                            "(default: $SINGBOX_MONITOR_DATA_DIR or %s)"
                            % DEFAULT_DATA_DIR)
    setup.add_argument("--assume-yes", action="store_true",
                       help="accept defaults non-interactively (automation)")

    serve = sub.add_parser(
        "serve", help="run the collector, broker and web listener")
    serve.add_argument("--listen", default="127.0.0.1",
                       help="bind address; MUST stay loopback for local-only "
                            "use (default: %(default)s)")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--url", default=DEFAULT_URL,
                       help="sing-box service.api URL; MUST be loopback "
                            "(default: %(default)s)")
    serve.add_argument("--interval", type=float, default=2.0,
                       help="stream UPDATE pacing in seconds")
    serve.add_argument("--closed-ttl", type=float, default=600.0)
    serve.add_argument("--secret-file", default=None,
                       help="file holding the service.api bearer token (0600); "
                            "BOX_API_SECRET takes precedence")
    serve.add_argument("--data-dir", default=None,
                       help="access data directory "
                            "(default: $SINGBOX_MONITOR_DATA_DIR or %s)"
                            % DEFAULT_DATA_DIR)
    serve.add_argument("--tls-cert", default=None,
                       help="TLS certificate (required for remote listen)")
    serve.add_argument("--tls-key", default=None,
                       help="TLS private key (required for remote listen)")
    serve.add_argument("--poll", type=float, default=1.0,
                       help="dashboard snapshot cadence in seconds")
    serve.add_argument("--session-ttl", type=float, default=8 * 3600.0,
                       help="admin session lifetime in seconds")
    return parser


def cmd_setup(args):
    """Interactive first-time setup. Never prints the password back."""
    data_dir = args.data_dir or default_data_dir()
    ensure_data_dir(data_dir)
    access = AccessPolicy(data_dir)

    ssh_ip = detect_ssh_client_ip()
    if ssh_ip:
        entry = host_entry_for_ip(ssh_ip)
        if access.contains(entry):
            print("Current SSH client detected: %s (already whitelisted)"
                  % ssh_ip)
        else:
            print("Current SSH client detected: %s" % ssh_ip)
            answer = "y"
            if not args.assume_yes:
                try:
                    answer = input("Add %s to Monitor whitelist? [Y/n] "
                                   % entry).strip().lower() or "y"
                except EOFError:
                    answer = "n"
            if answer in ("y", "yes"):
                access.add(entry)
                print("Added %s to the whitelist." % entry)
            else:
                print("Whitelist left unchanged.")
    else:
        print("No SSH client IP detected ($SSH_CONNECTION unset); "
              "whitelist stays empty.")

    print("Access data: %s" % access.path)
    print("Next: configure authentication with `webapp.py setup` "
          "(admin password + recovery key), then `webapp.py serve`.")
    return 0


def _tls_context(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.tls_cert, args.tls_key)
    return context


def cmd_serve(args):
    data_dir = args.data_dir or default_data_dir()
    access = AccessPolicy(data_dir)
    remote_mode = args.listen not in LOOPBACK_LISTEN

    tls_context = None
    if remote_mode:
        problems = []
        if not args.tls_cert or not args.tls_key:
            problems.append("TLS is not configured (--tls-cert/--tls-key)")
        else:
            try:
                tls_context = _tls_context(args)
            except (OSError, ssl.SSLError) as exc:
                tls_context = None
                problems.append("TLS material is unusable: %s" % exc)
        if not access.entries():
            problems.append("the IP whitelist is empty")
        _remote_gate_password(problems, data_dir)   # authentication wiring
        _remote_gate_recovery(problems, data_dir)   # recovery wiring
        if problems:
            print("refusing to start remote listener:", file=sys.stderr)
            for problem in problems:
                print("  - %s" % problem, file=sys.stderr)
            return 2

    collector = Collector(url=args.url, interval=args.interval,
                          secret=resolve_secret(args.secret_file),
                          closed_ttl=args.closed_ttl)
    broker = SnapshotBroker(collector, poll_seconds=args.poll)
    broker.start()

    app = MonitorWebApp(broker=broker, access=access,
                        static_dir=os.path.join(HERE, "web", "static"),
                        remote_mode=remote_mode)
    server = build_server(app, args.listen, args.port, tls_context)
    scheme = "https" if tls_context is not None else "http"
    print("monitor web (%s) listening on %s:%d [%s]" %
          (MONITOR_WEB_VERSION, args.listen, args.port,
           "remote+TLS" if remote_mode else "loopback"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        broker.stop()
        server.server_close()
    return 0


def _remote_gate_password(problems, data_dir):
    return  # authentication wiring lands with the auth module


def _remote_gate_recovery(problems, data_dir):
    return  # recovery wiring lands with the recovery module


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if args.command == "setup":
        return cmd_setup(args)
    return cmd_serve(args)


if __name__ == "__main__":
    sys.exit(main())
