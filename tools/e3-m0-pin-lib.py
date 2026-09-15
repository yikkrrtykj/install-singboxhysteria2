#!/usr/bin/env python3
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
LIB = ROOT / "lib/client-management.sh"
STATIC = ROOT / "tests/e3/test-m0-static-contract.sh"
SHARED = ROOT / "tests/e3/test-m0-shared-lib.sh"

lib_bytes = LIB.read_bytes()
expected = hashlib.sha256(lib_bytes).hexdigest()

s = INSTALL.read_text()
start = s.find('load_client_management_library() {\n')
end_marker = 'load_client_management_library || error "共享事务库加载失败，拒绝进入管理路径"\n'
end = s.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit('shared-library loader block not found')
end += len(end_marker)

loader = f'''SB_CLIENT_MANAGEMENT_SHA256="{expected}"

verify_client_management_library() {{ # <path>
    local lib="$1" got=""
    if ! command -v sha256sum >/dev/null 2>&1; then
        warning "sha256sum 不可用，无法验证共享事务库，已拒绝加载（fail-closed）"
        return 1
    fi
    if [ ! -f "$lib" ]; then
        warning "共享事务库不存在: $lib"
        return 1
    fi
    got="$(sha256sum "$lib" 2>/dev/null | awk '{{print $1}}')" || return 1
    if [ "$got" != "$SB_CLIENT_MANAGEMENT_SHA256" ]; then
        warning "共享事务库完整性校验失败，已拒绝加载（fail-closed）"
        return 1
    fi
    return 0
}}

load_client_management_library() {{
    local lib="${{SB_CLIENT_MANAGEMENT_LIB:-}}" source_dir="" tmp="" fn

    if [ -z "$lib" ] && [ -n "${{BASH_SOURCE[0]:-}}" ]; then
        source_dir="$(cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" 2>/dev/null && pwd || true)"
        if [ -n "$source_dir" ] && [ -f "$source_dir/lib/client-management.sh" ]; then
            lib="$source_dir/lib/client-management.sh"
        fi
    fi

    if [ -z "$lib" ]; then
        local ref="${{SB_CLIENT_MANAGEMENT_REF:-main}}"
        tmp="$(mktemp 2>/dev/null)" || {{
            warning "无法创建共享事务库临时文件"
            return 1
        }}
        if ! curl -fsSL \\
            "https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/${{ref}}/lib/client-management.sh" \\
            -o "$tmp"; then
            warning "无法获取共享事务库 lib/client-management.sh (ref=$ref)"
            rm -f "$tmp"
            return 1
        fi
        lib="$tmp"
    fi

    # IMPORTANT: verify BEFORE sourcing. This binds install.sh to the exact
    # reviewed shared transaction implementation. A future main/lib change
    # makes an older installer fail closed instead of silently importing newer
    # privileged transaction code. SB_CLIENT_MANAGEMENT_REF changes location,
    # never the expected content digest.
    if ! verify_client_management_library "$lib"; then
        [ -n "$tmp" ] && rm -f "$tmp"
        return 1
    fi

    # shellcheck source=/dev/null
    . "$lib" || {{ [ -n "$tmp" ] && rm -f "$tmp"; return 1; }}
    [ -n "$tmp" ] && rm -f "$tmp"

    for fn in with_client_lock reload_running_singbox reload_health_ok \\
              restore_file_atomically new_candidate_path new_backup_path \\
              commit_server_config cm_transaction_result_json; do
        if ! declare -F "$fn" >/dev/null 2>&1; then
            warning "共享事务库缺少函数: $fn"
            return 1
        fi
    done
    return 0
}}

load_client_management_library || error "共享事务库加载失败，拒绝进入管理路径"
'''

s = s[:start] + loader + s[end:]
INSTALL.write_text(s)

# Static test: the installer must carry a literal 64-hex digest and verify the
# selected/fetched file before sourcing it.
t = STATIC.read_text()
needle = "has_install 'lib/client-management.sh' &&\n  ok 'install.sh loads canonical transaction library' ||\n  bad 'install.sh does not load canonical transaction library'\n"
addition = needle + f'''\nEXPECTED_LIB_SHA="$(sed -n 's/^SB_CLIENT_MANAGEMENT_SHA256="\\([0-9a-f]\\{{64\\}}\\)"$/\\1/p' "$INSTALL")"
ACTUAL_LIB_SHA="$(sha256sum "$LIB" | awk '{{print $1}}')"
if [ "$EXPECTED_LIB_SHA" = "$ACTUAL_LIB_SHA" ] && [ "$EXPECTED_LIB_SHA" = "{expected}" ]; then
  ok 'install.sh digest pin matches canonical shared library bytes'
else
  bad 'install.sh digest pin does not match canonical shared library'
fi
has_install 'verify_client_management_library "$lib"' &&
has_install '. "$lib"' &&
  ok 'loader verifies selected library before source' ||
  bad 'loader digest verification/source contract missing'
'''
if needle not in t:
    raise SystemExit('static test insertion point not found')
t = t.replace(needle, addition, 1)
STATIC.write_text(t)

# Dynamic integrity test: exact bytes validate; one-byte mutation must reject.
t = SHARED.read_text()
needle = "printf '===== E3 M0 SHARED LIB =====\\n'\n\n"
addition = needle + r'''EXPECTED_LIB_SHA="$(sed -n 's/^SB_CLIENT_MANAGEMENT_SHA256="\([0-9a-f]\{64\}\)"$/\1/p' "$INSTALL")"
ACTUAL_LIB_SHA="$(sha256sum "$LIB" | awk '{print $1}')"
assert_rc "$EXPECTED_LIB_SHA" "$ACTUAL_LIB_SHA" 'installer digest pin equals shared library SHA256'
cp "$LIB" "$TMP/tampered-lib.sh"
printf '\n# tampered\n' >> "$TMP/tampered-lib.sh"
TAMPERED_SHA="$(sha256sum "$TMP/tampered-lib.sh" | awk '{print $1}')"
if [ "$TAMPERED_SHA" != "$EXPECTED_LIB_SHA" ]; then pass 'one-byte/content drift changes shared-lib digest'; else fail 'tampered lib unexpectedly matches pinned digest'; fi

'''
if needle not in t:
    raise SystemExit('shared-lib test insertion point not found')
t = t.replace(needle, addition, 1)
SHARED.write_text(t)

print(f'pinned shared transaction library sha256={expected}')
