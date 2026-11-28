#!/usr/bin/env bash
# UM-LT real-protocol traffic E2E lab entrypoint.
#
# The orchestrator is um/deploy/lab/linux_traffic_e2e_lab.py (Python stdlib).
# This wrapper only locates the repository Python entrypoint and forwards argv;
# all pinned-download/SHA-verification, config generation, process management,
# assertions and cleanup live in the Python orchestrator.
#
# CI (Ubuntu 24.04):
#   bash um/deploy/lab/linux-traffic-e2e-lab.sh --artifacts "$RUNNER_TEMP/um-lt-artifacts"
#
# Local static check (no network/binaries required):
#   bash um/deploy/lab/linux-traffic-e2e-lab.sh --self-check
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${UM_LT_LAB_PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "linux-traffic-e2e-lab: no usable python3 on PATH (set UM_LT_LAB_PYTHON)" >&2
  exit 2
fi

exec "$PYTHON" "$HERE/linux_traffic_e2e_lab.py" "$@"
