#!/usr/bin/env bash
# E3 M1 -- RPC core probe driver. The real assertions live in
# m1-rpc-probe.py (the daemon is Python, so the probe is too). On platforms
# without AF_UNIX the probe runs the schema half and SKIPs the transport half.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$ROOT/tests/e3/m1-rpc-probe.py"

printf '===== E3 M1 RPC =====\n'

if [ ! -f "$PROBE" ]; then
    printf '  FAIL probe missing: %s\n' "$PROBE"
    printf 'E3_M1_RPC=FAIL\n'
    exit 1
fi

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    printf '  SKIP python3 unavailable\n'
    printf 'E3_M1_RPC=SKIP\n'
    exit 0
fi

"$PY" "$PROBE" "$ROOT"
rc=$?
exit "$rc"
