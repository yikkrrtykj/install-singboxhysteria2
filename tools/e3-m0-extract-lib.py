#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"

s = INSTALL.read_text()

# Replace the inlined lock implementation with a loader for the canonical lib.
lock_start_marker = "# Seconds to wait for the exclusive config lock before aborting. Web/E3 helpers\n"
lock_end_marker = "get_reality_client_names() { # [config] -> one name per line (\"\" = unnamed user)\n"
start = s.find(lock_start_marker)
end = s.find(lock_end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("unable to locate inlined lock block")

loader = r'''# M0/G1: the lock/commit/rollback primitives have a single canonical source in
# lib/client-management.sh. Local repository execution sources the sibling file;
# the historical curl/process-substitution entry point fetches the same path from
# the selected repository ref. Tests/helpers may inject SB_CLIENT_MANAGEMENT_LIB.
load_client_management_library() {
    local lib="${SB_CLIENT_MANAGEMENT_LIB:-}" source_dir="" tmp="" fn

    if [ -z "$lib" ] && [ -n "${BASH_SOURCE[0]:-}" ]; then
        source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
        if [ -n "$source_dir" ] && [ -f "$source_dir/lib/client-management.sh" ]; then
            lib="$source_dir/lib/client-management.sh"
        fi
    fi

    if [ -n "$lib" ]; then
        if [ ! -f "$lib" ]; then
            warning "共享事务库不存在: $lib"
            return 1
        fi
        # shellcheck source=/dev/null
        . "$lib" || return 1
    else
        local ref="${SB_CLIENT_MANAGEMENT_REF:-main}"
        tmp="$(mktemp 2>/dev/null)" || {
            warning "无法创建共享事务库临时文件"
            return 1
        }
        if ! curl -fsSL \
            "https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/${ref}/lib/client-management.sh" \
            -o "$tmp"; then
            warning "无法获取共享事务库 lib/client-management.sh (ref=$ref)"
            rm -f "$tmp"
            return 1
        fi
        # shellcheck source=/dev/null
        . "$tmp" || { rm -f "$tmp"; return 1; }
        rm -f "$tmp"
    fi

    for fn in with_client_lock reload_running_singbox reload_health_ok \
              restore_file_atomically new_candidate_path new_backup_path \
              commit_server_config cm_transaction_result_json; do
        if ! declare -F "$fn" >/dev/null 2>&1; then
            warning "共享事务库缺少函数: $fn"
            return 1
        fi
    done
    return 0
}

load_client_management_library || error "共享事务库加载失败，拒绝进入管理路径"

'''

s = s[:start] + loader + s[end:]

# Remove the remaining inlined reload/restore/commit/path implementation. All
# callers continue using the same function names, now provided by the shared lib.
tx_start_marker = "# Reload the running instance; succeeds trivially when nothing is running\n"
tx_end_marker = "client_name_exists() { # client_name_exists <name> [config] -> rc 0 if present in either inbound\n"
start = s.find(tx_start_marker)
end = s.find(tx_end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("unable to locate inlined transaction block")
s = s[:start] + "# Shared transaction primitives are loaded above from lib/client-management.sh.\n" + s[end:]

# Enforce source uniqueness before writing.
for fn in (
    "with_client_lock", "reload_running_singbox", "reload_health_ok",
    "restore_file_atomically", "new_candidate_path", "new_backup_path",
    "commit_server_config",
):
    if f"\n{fn}()" in s:
        raise SystemExit(f"install.sh still defines shared function {fn}")

INSTALL.write_text(s)

# Tests that source extracted install.sh blocks must inject the local canonical
# library; otherwise the block would (correctly) use its production remote fallback.
for path in sorted((ROOT / "tests").glob("*.sh")):
    t = path.read_text()
    if "phase-c client-management >>>" not in t and "phase-c client-management >>>/" not in t:
        continue
    if "SB_CLIENT_MANAGEMENT_LIB" in t:
        continue
    needle = 'export SB_LOCK_FILE=' 
    pos = t.find(needle)
    if pos < 0:
        raise SystemExit(f"{path}: extracts phase-c but has no SB_LOCK_FILE export")
    line_end = t.find("\n", pos)
    if line_end < 0:
        raise SystemExit(f"{path}: malformed SB_LOCK_FILE export")
    insert = 'export SB_CLIENT_MANAGEMENT_LIB="$HERE/../lib/client-management.sh"\n'
    t = t[:line_end + 1] + insert + t[line_end + 1:]
    path.write_text(t)

# The legacy suite had three static implementation assertions aimed at install.sh;
# after extraction those implementation details intentionally live in the lib.
legacy = ROOT / "tests/test-legacy-config-transactions.sh"
t = legacy.read_text()
t = t.replace(
    'assert_grep \'restore_file_atomically\' "$INSTALL_SH" "atomic restore primitive exists"',
    'assert_grep \'restore_file_atomically\' "$HERE/../lib/client-management.sh" "atomic restore primitive exists in shared lib"',
)
t = t.replace(
    'assert_grep \'cmp -s "\\$backup" "\\$live"\' "$INSTALL_SH" "restore verifies the committed file byte-for-byte"',
    'assert_grep \'cmp -s "\\$backup" "\\$live"\' "$HERE/../lib/client-management.sh" "restore verifies the committed file byte-for-byte"',
)
t = t.replace(
    'assert_grep \'\\.restore\\.XXXXXX\' "$INSTALL_SH" "restore uses a unique same-directory temp path"',
    'assert_grep \'\\.restore\\.XXXXXX\' "$HERE/../lib/client-management.sh" "restore uses a unique same-directory temp path"',
)
legacy.write_text(t)

print("canonical shared transaction library extraction applied")
