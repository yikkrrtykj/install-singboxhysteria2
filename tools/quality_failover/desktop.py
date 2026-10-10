"""Portable, user-started front end. Never installs or reconfigures Clash."""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

from .config import read_json
from .daily import WorkerLock, working_directory
from .pilot import module, receiver_info

FILES = {"receiver-info.json": 16384, "receiver-ca.pem": 16384}
EXE_NAME = "质量切换.exe"


def checked_bytes(path, maximum):
    if path.is_symlink():
        raise ValueError("package_invalid")
    with path.open("rb") as stream:
        row = os.fstat(stream.fileno())
        if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or not 0 < row.st_size <= maximum:
            raise ValueError("package_invalid")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("package_invalid")
    return raw


def package_inputs(directory):
    """Adjacent configuration is per recipient, never compiled into the EXE."""
    root = Path(directory)
    if root.is_symlink():
        raise ValueError("package_invalid")
    manifest = read_json(root / "quality-package.json")
    if (type(manifest) is not dict or set(manifest) != {"v", "client", "files"}
            or type(manifest["v"]) is not int or manifest["v"] != 1
            or type(manifest["client"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", manifest["client"])):
        raise ValueError("package_invalid")
    yaml_name = manifest["client"] + "-mihomo.yaml"
    expected = dict(FILES, **{yaml_name: 49152})
    if type(manifest["files"]) is not dict or set(manifest["files"]) != set(expected):
        raise ValueError("package_invalid")
    for name, maximum in expected.items():
        digest = manifest["files"][name]
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("package_invalid")
        if hashlib.sha256(checked_bytes(root / name, maximum)).hexdigest() != digest:
            raise ValueError("package_invalid")
    receiver_info(root / "receiver-info.json", root / "receiver-ca.pem")
    merge = module("mihomo-multi-vps-merge.py", "desktop_merge")
    merge.parse_export(root / yaml_name, lambda: ValueError("package_invalid"))
    merge.check_provenance(root / yaml_name, manifest["client"], lambda: ValueError("package_invalid"))
    # Different recipient/receiver inputs never reuse another recipient's state.
    identity = hashlib.sha256((manifest["client"] + "\n" + "\n".join(
        name + ":" + manifest["files"][name] for name in sorted(expected))).encode()).hexdigest()[:32]
    return root / yaml_name, root / "receiver-info.json", identity


def user_workspace(identity):
    local = os.environ.get("LOCALAPPDATA")
    if not local or not Path(local).is_absolute():
        raise ValueError("working_directory")
    parent = Path(local) / "ClashQualitySwitch"
    if parent.is_symlink():
        raise ValueError("working_directory")
    parent.mkdir(exist_ok=True)
    return working_directory(parent / identity)


def show_error(code):
    import tkinter as tk
    from tkinter import messagebox
    messages = {
        "package_invalid": "配置包不完整或已被改动。请向管理员重新领取完整压缩包，解压后再打开。",
        "package_missing": "请先完整解压管理员发给你的客户端包，再双击里面的“质量切换.exe”。不要只复制 EXE。",
    }
    from .daily_ui import MESSAGES
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("质量切换", messages.get(code, MESSAGES.get(code,
                        "暂时无法打开，请重新解压完整客户端包；仍有问题请联系管理员。")), parent=root)
    root.destroy()


def main():
    directory = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(sys.argv[0]).parent
    if len(sys.argv) == 3 and sys.argv[1] == "--self-check":
        # Build acceptance only: no workspace, controller, sampling or writes to Clash.
        import json
        phase = "adjacent_inputs"
        try:
            package_inputs(directory)
            phase = "bundled_modules"
            module("mihomo-quality-failover.py", "desktop_selfcheck_cli")
            phase = "tk_runtime"
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            root.update_idletasks()
            root.destroy()
            result = {"v": 1, "portable_package_valid": True, "tk_available": True,
                      "frozen": bool(getattr(sys, "frozen", False)), "controller_contacted": False}
            code = 0
        except Exception as exception:
            result = {"v": 1, "portable_package_valid": False, "controller_contacted": False,
                      "phase": phase, "failure_class": type(exception).__name__}
            code = 2
        fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream)
        return code
    try:
        primary, info, identity = package_inputs(directory)
        from .desktop_ui import show
        home = Path(os.environ.get("APPDATA", ".")) / "io.github.clash-verge-rev.clash-verge-rev"
        workspace = user_workspace(identity)
        lock = WorkerLock(workspace / "desktop.lock")
        lock.acquire()
        try:
            show(workspace, home, primary, info)
        finally:
            lock.close()
        return 0
    except Exception as exception:
        from .daily import error_code
        code = "package_missing" if isinstance(exception, FileNotFoundError) else (
            exception.args[0] if isinstance(exception, ValueError) and exception.args
            and exception.args[0] in ("package_invalid", "package_missing") else error_code(exception))
        show_error(code)
        return 1
