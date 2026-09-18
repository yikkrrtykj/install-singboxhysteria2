#!/usr/bin/env bash
set -u
SC="${SHELLCHECK_BIN:-/c/Users/31313/AppData/Local/Temp/shellcheck-dl/shellcheck.exe}"
rc=0
for f in lib/client-management.sh lib/sbox-cm-state.sh sbox-cm/deploy/install-sbox-cm.sh sbox-cm/sbox-cm-ops tests/e3/test-m1-crash.sh tests/e3/test-m1-systemd.sh tests/e3/test-m1-worker.sh; do
    tr -d '\r' < "$f" > /tmp/sc-tmp
    if "$SC" -S warning /tmp/sc-tmp > /tmp/sc-out 2>&1; then
        echo "CLEAN $f"
    else
        echo "---- $f"
        cat /tmp/sc-out
        rc=1
    fi
done
echo "TOTAL_RC=$rc"
