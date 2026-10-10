#!/usr/bin/env python3
"""User-started Clash quality window; never imports/reloads profiles or installs services."""
import argparse
import os
from pathlib import Path
from quality_failover.daily import error_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--primary")
    parser.add_argument("--receiver-info")
    parser.add_argument("--clash-home", default=str(Path(os.environ.get("APPDATA", ".")) /
                                                "io.github.clash-verge-rev.clash-verge-rev"))
    args = parser.parse_args(argv)
    try:
        from quality_failover.daily_ui import show
        show(args.workspace, args.clash_home, args.primary, args.receiver_info)
        return 0
    except Exception as exception:
        code = error_code(exception)
        # pythonw has no console. Always give the operator a visible, closed error.
        try:
            import tkinter as tk
            from tkinter import messagebox
            from quality_failover.daily_ui import MESSAGES
            root = tk.Tk()
            root.withdraw()
            try:
                messagebox.showerror("质量切换未启动", MESSAGES.get(code, MESSAGES["operation_unavailable"]), parent=root)
            finally:
                root.destroy()
        except Exception:
            print("quality-client: FAIL " + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
