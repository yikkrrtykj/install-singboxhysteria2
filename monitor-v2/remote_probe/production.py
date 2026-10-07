"""Explicit P6B2 entry; the P6A DARK CLI remains unchanged."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys

from .agent import ConfigError
from .delivery import UploadConfigError
from .profiles import ProfileVault
from .production_runtime import ProductionRuntime
from .service_host import run_service
from .windows_security import StorageSecurityError


def incoming(path, limit):
    # Installer input is explicitly chosen by the administrator through the
    # trusted SSH download. Refuse links/special files/oversize, never print it.
    from .spool import check_no_symlink_component
    check_no_symlink_component(path)
    if os.name == "nt":
        from .windows_security import WindowsSecurity
        WindowsSecurity().check_components(path)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ConfigError("unsafe installer input")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ConfigError("installer input changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ConfigError("installer input oversized")
        return data
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="P6 production Agent foundations")
    parser.add_argument("--vault", required=True, help="protected state directory")
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("import")
    enroll.add_argument("--manifest", required=True)
    enroll.add_argument("--secret-file", required=True)
    enroll.add_argument("--certificate-file", required=True)
    commands.add_parser("status")
    commands.add_parser("run")
    service = commands.add_parser("service")
    service.add_argument("--name", default="P6RemoteProbe")
    for command in ("pause", "resume", "purge"):
        commands.add_parser(command).add_argument("--profile", required=True)
    args = parser.parse_args(argv)
    try:
        vault = ProfileVault(args.vault)
        if args.command == "service":
            run_service(args.name, lambda: ProductionRuntime(vault))
        elif args.command == "run":
            ProductionRuntime(vault).open().run()
        else:
            vault.open()
            if args.command == "import":
                manifest = json.loads(incoming(args.manifest, 16384))
                value = incoming(args.secret_file, 128).strip().decode("ascii")
                import re
                if not re.fullmatch(r"[0-9a-f]{64}", value):
                    raise ConfigError("invalid enrollment secret")
                key, created = vault.import_profile(manifest, bytes.fromhex(value),
                                incoming(args.certificate_file, 16384).decode("ascii"))
                print(json.dumps({"profile": key, "created": created}))
            elif args.command == "status":
                print(json.dumps({"v": 1, "profiles": [
                    {"id": key, "enabled": vault.enabled(key)} for key in vault.keys()]}))
            elif args.command in ("pause", "resume"):
                vault.set_enabled(args.profile, args.command == "resume")
            elif args.command == "purge":
                vault.purge(args.profile)
    except KeyboardInterrupt:
        return 0
    except (ConfigError, UploadConfigError, StorageSecurityError, OSError,
            ValueError, TypeError, KeyError):
        print("p6_operation_unavailable", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
