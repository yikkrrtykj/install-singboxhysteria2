#!/usr/bin/env python3
"""Absolute-path entry usable by Windows SCM without a PYTHONPATH secret/env."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "monitor-v2"))
from remote_probe.production import main

if __name__ == "__main__":
    sys.exit(main())
