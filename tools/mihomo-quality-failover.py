#!/usr/bin/env python3
"""Issue #48 opt-in protocol quality worker / HTTPS sink / offline profile preparation."""
import argparse
import importlib.util
import ipaddress
import ssl
import sys
from pathlib import Path
from quality_failover.config import read_json, client
from quality_failover.policy import AUTO, GROUP
from quality_failover.runtime import run
from quality_failover.receiver import Server


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("usage")


def prepare(name, primary_path, backup_path, output, config):
    path = Path(__file__).with_name("mihomo-multi-vps-merge.py")
    spec = importlib.util.spec_from_file_location("canonical_merge", path)
    merge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(merge)
    if type(name) is not str or not merge.CLIENT_NAME_RE.fullmatch(name):
        raise ValueError("name")
    primary = merge.parse_export(primary_path, lambda: ValueError("canonical"))
    merge.check_provenance(primary_path, name, lambda: ValueError("name"))
    backup = None
    if backup_path:
        backup = merge.parse_export(backup_path, lambda: ValueError("canonical"))
        merge.check_provenance(backup_path, name, lambda: ValueError("name"))
        merge.check_sources(primary, backup)
        merge.check_credentials(primary, backup)
    engine, _, ports, _ = client(config)
    nodes = list(engine.paths)
    if (len(nodes) == 4) != (backup is not None):
        raise ValueError("profile_paths")
    text = merge.build_output(primary, backup).decode("utf-8")
    # Old defaults/cache/manual nodes and original fallback bytes stay intact.
    text = text.replace("      - DIRECT\n", f"      - {GROUP}\n      - DIRECT\n", 1)
    probe_options = list(merge.GROUPS_SINGLE_AUTO)
    probe_options = probe_options[next(i for i, line in enumerate(probe_options)
                                      if line.startswith("    url: ")):]
    quality = (f"  - name: {GROUP}\n    type: fallback\n    hidden: true\n    proxies:\n"
               + "".join(f"      - {node}\n" for node in nodes)
               + "\n".join(probe_options) + "\n\n")
    text = text.replace("rules:\n", quality + "rules:\n", 1)
    listeners = "listeners:\n"
    for index, node in enumerate(nodes):
        listeners += (f"  - name: quality-probe-{index}\n    type: socks\n"
                      f"    listen: 127.0.0.1\n    port: {ports[node]}\n"
                      f"    udp: false\n    proxy: {node}\n")
    text = text.replace("proxies:\n", listeners + "\nproxies:\n", 1)
    merge.write_output(text.encode("utf-8"), output)


def serve(config):
    if (type(config) is not dict or set(config) != {
            "v", "listen", "port", "token", "certificate", "private_key", "minute_bytes"}
            or type(config["v"]) is not int or config["v"] != 1
            or type(config["port"]) is not int or not 1024 <= config["port"] <= 65535
            or type(config["minute_bytes"]) is not int
            or not 32768 <= config["minute_bytes"] <= 4 * 1024 * 1024):
        raise ValueError("receiver_config")
    ipaddress.ip_address(config["listen"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["certificate"], config["private_key"])
    with Server((config["listen"], config["port"]), config["token"], context,
                config["minute_bytes"]) as server:
        print('{"v":1,"receiver":"ready"}', flush=True)
        server.serve_forever()


def main(argv=None):
    parser = Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("mode", choices=("prepare", "run", "receiver"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--name")
    parser.add_argument("--primary")
    parser.add_argument("--backup")
    parser.add_argument("--output")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    try:
        args = parser.parse_args(argv)
        config = read_json(args.config)
        if args.mode == "prepare":
            if not (args.name and args.primary and args.output) or args.once or args.confirm:
                raise ValueError("usage")
            prepare(args.name, args.primary, args.backup, args.output, config)
            print('{"v":1,"profile":"written","activation":"operator_required"}')
        elif any((args.name, args.primary, args.backup, args.output)):
            raise ValueError("usage")
        elif args.mode == "receiver":
            if args.once or args.confirm:
                raise ValueError("usage")
            serve(config)
        else:
            run(config, args.once, args.confirm)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Includes canonical merge errors: no reflected argv or traceback.
        print('quality: FAIL configuration_or_operation', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
