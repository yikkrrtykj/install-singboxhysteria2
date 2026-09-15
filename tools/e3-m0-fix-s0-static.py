#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "tests/test-security-baseline.sh"
s = P.read_text()


def one(old: str, new: str, label: str) -> None:
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one match, got {n}")
    s = s.replace(old, new, 1)

one(
    'INSTALL_SH="$HERE/../install.sh"\n',
    'INSTALL_SH="$HERE/../install.sh"\nCLIENT_LIB="$HERE/../lib/client-management.sh"\n',
    'shared library path',
)
one(
    'assert_grep \'flock -w "\\$SB_LOCK_TIMEOUT" 9\' "$INSTALL_SH" "lock acquisition uses a finite timeout"\n',
    'assert_grep \'flock -w "\\$SB_LOCK_TIMEOUT" 9\' "$CLIENT_LIB" "lock acquisition uses a finite timeout (shared lib)"\n',
    'lock timeout assertion',
)
one(
    'assert_grep \'操作已中止（fail-closed）\' "$INSTALL_SH" "lock failure aborts the operation"\n',
    'assert_grep \'操作已中止（fail-closed）\' "$CLIENT_LIB" "lock failure aborts the operation (shared lib)"\n',
    'lock fail-closed assertion',
)
one(
    'commit_body="$(awk \'/^commit_server_config\\(\\) \\{/,/^\\}/\' "$INSTALL_SH")"\n',
    'commit_body="$(awk \'/^commit_server_config\\(\\) \\{/,/^\\}/\' "$CLIENT_LIB")"\n',
    'commit scope source',
)

P.write_text(s)
print("S0 static assertions now follow canonical lib/client-management.sh")
