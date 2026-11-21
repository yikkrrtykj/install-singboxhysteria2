#!/usr/bin/env python3
"""PyInstaller entry point for the Windows HA-UI EXE.

The windowed EXE has no console, so the build's cold-start smoke test asks this
entry point to also write a small result file (path from
``HA_UI_SELFTEST_RESULT``) after ``--self-test``. The file contains only the
exit status; it never contains a credential or YAML.
"""

from __future__ import annotations

import json
import os
import sys

from ha_ui.app import main


def _write_selftest_result(exit_code: int) -> None:
    target = os.environ.get("HA_UI_SELFTEST_RESULT")
    if not target:
        return
    payload = {"ok": exit_code == 0, "exit_code": int(exit_code)}
    temp = target + ".tmp"
    try:
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except OSError:
        try:
            os.unlink(temp)
        except OSError:
            pass


def run(argv: list[str]) -> int:
    exit_code = int(main(argv))
    if "--self-test" in argv:
        _write_selftest_result(exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
