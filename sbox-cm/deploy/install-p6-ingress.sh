#!/usr/bin/env bash
# Explicit identity/ingress installer. Requires an installed, reviewed helper.
# This command never downloads code, installs packages, touches nginx.service,
# or activates ingress as a consequence of prepare.
set -euo pipefail
[[ ${EUID} == 0 ]] || { echo 'E_P6_AUTHORITY' >&2; exit 1; }
case "${1:-}" in
    prepare|activate|deactivate) ;;
    *) echo 'Usage: install-p6-ingress.sh prepare IP [HIGH_PORT] [nft|none] | activate | deactivate' >&2; exit 1 ;;
esac
exec /usr/bin/python3 -I -c '
import os,stat,sys
for directory in ("/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/sbox-cm"):
    st=os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise SystemExit("E_P6_AUTHORITY")
for name in ("p6_ingress.py", "p6_provision.py"):
    st=os.lstat("/usr/local/lib/sbox-cm/"+name)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)) != (0,0,0o644):
        raise SystemExit("E_P6_AUTHORITY")
os.execv("/usr/bin/python3",["/usr/bin/python3","-I","/usr/local/lib/sbox-cm/p6_ingress.py"]+sys.argv[1:])
' "$@"
