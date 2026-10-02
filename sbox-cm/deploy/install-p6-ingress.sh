#!/usr/bin/env bash
# Explicit identity/ingress installer. Requires an installed, reviewed helper.
# This command never downloads code, installs packages, touches nginx.service,
# or activates ingress as a consequence of prepare.
# Diagnostics go to stderr so the helper's JSON stdout remains unchanged.
# Collect read-only prerequisite results before dispatch; never rely on errexit.
failed=0
if [[ ${EUID} == 0 ]]; then
    echo '[PASS] root authority' >&2
else
    echo '[FAIL] root authority: run as root (E_P6_AUTHORITY)' >&2
    failed=1
fi
case "${1:-}" in
    prepare|activate|deactivate)
        echo '[PASS] supported operation' >&2 ;;
    *)
        echo '[FAIL] unsupported or missing operation' >&2
        echo 'Usage: install-p6-ingress.sh prepare IP [HIGH_PORT] [nft|none] | activate | deactivate' >&2
        failed=1 ;;
esac

if [[ -x /usr/bin/python3 ]] && /usr/bin/python3 -I -c 'import os, stat, sys' >/dev/null 2>&1; then
    echo '[PASS] python3 available' >&2
    if /usr/bin/python3 -I -c '
import os,stat,sys
failed=False
parents_safe=True
def report(status, label):
    print("["+status+"] "+label, file=sys.stderr)
for directory in ("/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/sbox-cm"):
    label="helper directory ownership: "+directory
    if not parents_safe:
        report("SKIP", label+" (unsafe parent)")
        continue
    try:
        st=os.lstat(directory)
        safe=stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
    except OSError:
        safe=False
    report("PASS" if safe else "FAIL", label)
    if not safe:
        parents_safe=False
        failed=True
for name in ("p6_ingress.py", "p6_provision.py"):
    label=name+" ownership/mode"
    if not parents_safe:
        report("SKIP", label+" (unsafe helper directory)")
        continue
    try:
        st=os.lstat("/usr/local/lib/sbox-cm/"+name)
        safe=stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)) == (0,0,0o644)
    except OSError:
        safe=False
    report("PASS" if safe else "FAIL", label)
    if not safe:
        failed=True
sys.exit(1 if failed else 0)
'; then
        : # All filesystem prerequisites passed.
    else
        echo '[FAIL] helper authority prerequisites (E_P6_AUTHORITY)' >&2
        failed=1
    fi
else
    echo '[FAIL] python3 available: /usr/bin/python3 is missing or unusable' >&2
    echo '[SKIP] helper directory ownership (python3 unavailable)' >&2
    echo '[SKIP] p6_ingress.py ownership/mode (python3 unavailable)' >&2
    echo '[SKIP] p6_provision.py ownership/mode (python3 unavailable)' >&2
    failed=1
fi

if [[ $failed != 0 ]]; then
    echo '[SKIP] helper execution: prerequisites failed; no operation performed' >&2
    exit 1
fi

if /usr/bin/python3 -I /usr/local/lib/sbox-cm/p6_ingress.py "$@"; then
    echo "[PASS] $1 completed (exit 0)" >&2
    exit 0
else
    result=$?
    echo "[FAIL] $1 failed (exit $result)" >&2
    exit "$result"
fi
