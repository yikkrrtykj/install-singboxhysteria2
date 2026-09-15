#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
TEST = ROOT / "tests/test-phase-d.sh"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one match, got {n}")
    return text.replace(old, new, 1)

s = INSTALL.read_text()

# Phase D paired rollback: config first, then executable binary, both through
# the single hardened restore primitive. Binary explicitly restores as 0755.
s = replace_once(
    s,
    '    if ! cp -a "$backup_bin" "$SB_SING_BOX_BIN" || ! cp -a "$backup_cfg" "$SB_SERVER_CONFIG"; then\n'
    '        warning "回滚文件恢复失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '        return 1\n'
    '    fi\n',
    '    if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG" 0600 ||\n'
    '       ! restore_file_atomically "$backup_bin" "$SB_SING_BOX_BIN" 0755; then\n'
    '        warning "回滚文件原子恢复失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '        return 1\n'
    '    fi\n',
    "_rollback_upgrade atomic pair",
)

s = replace_once(
    s,
    '        if ! cp -a "$backup_cfg" "$SB_SERVER_CONFIG"; then\n'
    '            warning "恢复 config 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '            return 1\n'
    '        fi\n'
    '        if ! cp -a "$backup_bin" "$SB_SING_BOX_BIN"; then\n'
    '            warning "恢复 binary 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '            return 1\n'
    '        fi\n',
    '        if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG" 0600; then\n'
    '            warning "恢复 config 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '            return 1\n'
    '        fi\n'
    '        if ! restore_file_atomically "$backup_bin" "$SB_SING_BOX_BIN" 0755; then\n'
    '            warning "恢复 binary 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"\n'
    '            return 1\n'
    '        fi\n',
    "mixed-state atomic pair",
)

for forbidden in (
    'cp -a "$backup_bin" "$SB_SING_BOX_BIN"',
    'cp -a "$backup_cfg" "$SB_SERVER_CONFIG"',
):
    if forbidden in s:
        raise SystemExit(f"direct Phase-D live restore remains: {forbidden}")

INSTALL.write_text(s)

t = TEST.read_text()

# Static contract: Phase D may create backups with cp, but may never restore a
# backup directly onto either live path.
needle = 'assert_no_grep \'releases/latest\' "$INSTALL_SH" "no /latest auto-crossing (1.14 selector only)"\n'
add = needle + \
    'assert_no_grep \'cp -a "\\$backup_cfg" "\\$SB_SERVER_CONFIG"\' "$INSTALL_SH" "Phase D config rollback uses atomic restore"\n' + \
    'assert_no_grep \'cp -a "\\$backup_bin" "\\$SB_SING_BOX_BIN"\' "$INSTALL_SH" "Phase D binary rollback uses atomic restore"\n' + \
    'assert_grep \'restore_file_atomically "\\$backup_bin" "\\$SB_SING_BOX_BIN" 0755\' "$INSTALL_SH" "Phase D binary restore preserves executable mode"\n'
t = replace_once(t, needle, add, "Phase D static restore assertions")

# The mv fault injector must fail ONLY the first candidate->live config rename.
# Atomic rollback itself also uses mv and must be allowed to prove recovery.
mv_start_marker = '# Simulate a failure of the CONFIG atomic replacement while the binary has\n'
mv_start = t.find(mv_start_marker)
mv_end = t.find('MOCKS\n', mv_start)
if mv_start < 0 or mv_end < 0:
    raise SystemExit("one-shot config mv fault: marker block not found")
new_mv_block = r'''# Simulate a failure of the CONFIG atomic replacement while the binary has
# already been replaced (the mixed-state scenario from the review). The fault
# fires ONCE: the later atomic rollback rename must be allowed to succeed.
mv() {
    if [ "${MV_FAIL_CONFIG:-0}" = "1" ]; then
        local last marker="${MV_FAIL_CONFIG_MARKER:-}"
        eval "last=\"\${$#}\""
        if [ "$last" = "${SB_SERVER_CONFIG:-}" ] && [ -n "$marker" ] && [ ! -e "$marker" ]; then
            : > "$marker"
            return 1
        fi
    fi
    command mv "$@"
}
'''
t = t[:mv_start] + new_mv_block + t[mv_end:]

# Every scenario resets the one-shot mv failure marker.
needle = '    export PGREP_MODE="found"\n    rm -f "$TMP/new-check-fail" "$TMP/new-api-fail"\n'
replace = '    export PGREP_MODE="found"\n    export MV_FAIL_CONFIG_MARKER="$TMP/mv-fail-config-once"\n    rm -f "$MV_FAIL_CONFIG_MARKER"\n    rm -f "$TMP/new-check-fail" "$TMP/new-api-fail"\n'
t = replace_once(t, needle, replace, "reset mv fault marker")

# Validate permissions as well as bytes after the normal rollback path.
needle = 'assert_grep \'已回滚到升级前状态\' "$TMP/d10.out" "successful rollback reported"\n'
replace = needle + \
    'assert_rc 755 "$(stat -c %a "$SB_SING_BOX_BIN")" "rollback binary mode remains 0755"\n' + \
    'assert_rc 600 "$(stat -c %a "$SB_SERVER_CONFIG")" "rollback config mode is hardened 0600"\n'
t = replace_once(t, needle, replace, "D10 permission assertions")

needle = 'assert_grep \'restart sing-box\' "$SYSTEMCTL_LOG" "recovery restart actually ran"\n'
replace = needle + \
    'assert_rc 755 "$(stat -c %a "$SB_SING_BOX_BIN")" "D18 recovered binary mode remains 0755"\n' + \
    'assert_rc 600 "$(stat -c %a "$SB_SERVER_CONFIG")" "D18 recovered config mode is 0600"\n'
t = replace_once(t, needle, replace, "D18 permission assertions")

TEST.write_text(t)
print("Phase D restore unification applied")
