#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"
LEGACY_TEST = ROOT / "tests/test-legacy-config-transactions.sh"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


s = INSTALL.read_text()

# M0/T-1: the generic single-file transaction must never cp directly over the
# live pathname during rollback. Reuse the already-reviewed atomic restore.
s = replace_once(
    s,
    '        cp -a "$backup_path" "$SB_SERVER_CONFIG"\n'
    '        # The rollback reload\'s exit code matters: a failed reload command with a\n',
    '        if ! restore_file_atomically "$backup_path" "$SB_SERVER_CONFIG"; then\n'
    '            warning "回滚恢复失败，请立即人工介入！备份: $backup_path"\n'
    '            return 1\n'
    '        fi\n'
    '        # The rollback reload\'s exit code matters: a failed reload command with a\n',
    "T-1 atomic rollback",
)

# M0/G2: make the root directory explicit so destructive-path tests can execute
# against a sandbox while production keeps /root/sbox.
s = replace_once(
    s,
    'SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"\n'
    'RESERVED_CLIENT_NAME="legacy"\n',
    'SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"\n'
    'SB_ROOT_DIR="${SB_ROOT_DIR:-$(dirname "$SB_SERVER_CONFIG")}"\n'
    'SB_SHORTCUT="${SB_SHORTCUT:-/usr/bin/mianyang}"\n'
    'SB_SYSTEMD_UNIT="${SB_SYSTEMD_UNIT:-/etc/systemd/system/sing-box.service}"\n'
    'RESERVED_CLIENT_NAME="legacy"\n',
    "sandboxable control-plane paths",
)

# M0/G2: ratify the rev5 marker location outside the uninstall target.
s = replace_once(
    s,
    'SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/root/sbox/web-management.active}"',
    'SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/var/lib/sbox-cm/management.active}"',
    "management marker path",
)

old_uninstall = '''uninstall_singbox() {
    # L5: refuse BEFORE any destructive mutation when web/E3 management is active.
    # E3 is not implemented, so this only triggers when a future E3 publishes the
    # marker; default installations behave exactly as before.
    if ! require_management_inactive "卸载"; then
        return 1
    fi
    warning "开始卸载..."
    if pgrep -x sing-box >/dev/null 2>&1 && ! systemctl is-active --quiet sing-box; then
        error "sing-box 当前由手工进程运行。为防止删除运行中的配置，已拒绝卸载。"
    fi
    disable_hy2hopping
    systemctl disable --now sing-box > /dev/null 2>&1
    rm -f /etc/systemd/system/sing-box.service
    rm -f /root/sbox/sbconfig_server.json /root/sbox/sing-box /root/sbox/mianyang.sh
    rm -f /usr/bin/mianyang /root/sbox/self-cert/private.key /root/sbox/self-cert/cert.pem /root/sbox/config
    rm -rf /root/sbox/self-cert/ /root/sbox/
    warning "卸载完成"
    return 0
}
'''

new_uninstall = '''# M0/G2 L-ANCHOR: uninstall is a destructive management transaction. The public
# entry point acquires the SAME global config.lock and delegates to a no-nesting
# helper. The lock pathname itself is a permanent control-plane anchor and is
# never unlinked, even by uninstall.
uninstall_singbox() {
    with_client_lock _uninstall_singbox_locked
}

_uninstall_singbox_locked() {
    # The activation gate MUST be evaluated while holding config.lock. This
    # closes the activate-vs-uninstall TOCTOU: either activation wins and this
    # refuses, or uninstall wins and activation later sees the missing config.
    if ! require_management_inactive "卸载"; then
        return 1
    fi

    warning "开始卸载..."
    if pgrep -x sing-box >/dev/null 2>&1 && ! systemctl is-active --quiet sing-box; then
        error "sing-box 当前由手工进程运行。为防止删除运行中的配置，已拒绝卸载。"
    fi

    # Already inside with_client_lock: call the locked hopping helper directly
    # so uninstall never nests a second flock acquisition.
    if [ -f "$SB_STATE_FILE" ]; then
        _disable_hy2hopping_locked || {
            warning "关闭 Hysteria2 端口跳跃失败，卸载已中止（控制面锚点保留）"
            return 1
        }
    else
        systemctl disable --now sing-box-hy2-hopping.service >/dev/null 2>&1 || true
        remove_hy2_hopping_rules
        rm -f "$HY_HOPPING_SERVICE" "$HY_HOPPING_HELPER"
    fi

    systemctl disable --now sing-box >/dev/null 2>&1 || true
    rm -f -- "$SB_SYSTEMD_UNIT"

    # Remove installation-owned runtime/config/credential artifacts, but DO NOT
    # rm -rf SB_ROOT_DIR. In particular, SB_LOCK_FILE must retain the same path
    # and inode for the lifetime of this critical section and afterwards.
    rm -f -- \
        "$SB_SERVER_CONFIG" \
        "$SB_SING_BOX_BIN" \
        "$SB_ROOT_DIR/mianyang.sh" \
        "$SB_SHORTCUT" \
        "$SB_SELF_CERT_KEY" \
        "$SB_SELF_CERT_CERT" \
        "$SB_STATE_FILE" \
        "$SB_API_SECRET_FILE"

    rm -rf -- "$SB_CLIENTS_DIR" "$(dirname "$SB_SELF_CERT_KEY")"

    # Generated transaction residue/backups are installation-owned too. These
    # globs deliberately target only known durable artifacts; config.lock is not
    # matched and is never unlinked.
    rm -f -- \
        "$SB_SERVER_CONFIG".candidate.* \
        "$SB_SERVER_CONFIG".restore.* \
        "$SB_SERVER_CONFIG".bak.* \
        "$SB_STATE_FILE".candidate.* \
        "$SB_STATE_FILE".restore.* \
        "$SB_STATE_FILE".bak.* 2>/dev/null || true

    systemctl daemon-reload >/dev/null 2>&1 || true

    if [ ! -e "$SB_LOCK_FILE" ]; then
        warning "控制面锚点异常消失: $SB_LOCK_FILE；需人工介入"
        return 1
    fi

    warning "卸载完成（控制面锚点已保留: $SB_LOCK_FILE）"
    return 0
}
'''

s = replace_once(s, old_uninstall, new_uninstall, "locked uninstall/L-ANCHOR")
INSTALL.write_text(s)

# Extend the existing executable regression suite rather than creating a second
# sandbox harness. These exports make uninstall's external paths harmless.
t = LEGACY_TEST.read_text()
t = replace_once(
    t,
    'export SB_LOCK_FILE="$SANDBOX/config.lock"\n'
    'export SB_HOPPING_SERVICE="$SANDBOX/sing-box-hy2-hopping.service"\n',
    'export SB_LOCK_FILE="$SANDBOX/config.lock"\n'
    'export SB_ROOT_DIR="$SANDBOX"\n'
    'export SB_SHORTCUT="$SANDBOX/usr-bin-mianyang"\n'
    'export SB_SYSTEMD_UNIT="$SANDBOX/sing-box.service"\n'
    'export SB_HOPPING_SERVICE="$SANDBOX/sing-box-hy2-hopping.service"\n',
    "sandbox exports",
)

# Static assertions for the formalized L-ANCHOR contract.
t = replace_once(
    t,
    'assert_grep \'require_management_inactive "卸载"\' "$INSTALL_SH" "uninstall checks the L5 guard"\n',
    'assert_grep \'require_management_inactive "卸载"\' "$INSTALL_SH" "uninstall checks the L5 guard"\n'
    'assert_grep \'with_client_lock _uninstall_singbox_locked\' "$INSTALL_SH" "uninstall takes the global lock"\n'
    'assert_no_grep \'rm -rf /root/sbox/self-cert/ /root/sbox/\' "$INSTALL_SH" "uninstall never removes the config.lock parent directory"\n'
    'assert_no_grep \'cp -a "\\$backup_path" "\\$SB_SERVER_CONFIG"\' "$INSTALL_SH" "generic commit rollback never directly copies onto live config"\n',
    "M0 static legacy assertions",
)

insert_before = '''section "T19: restore_file_atomically primitive"
'''

t20 = r'''section "T18b: uninstall lock anchor survives with stable inode (M0/L-ANCHOR)"
reset_sandbox
rm -f "$SB_MANAGEMENT_ACTIVE_MARKER"
: > "$SB_LOCK_FILE"
chmod 0600 "$SB_LOCK_FILE" 2>/dev/null || true
printf '#!/bin/sh\nexit 0\n' > "$SB_SING_BOX_BIN"
chmod +x "$SB_SING_BOX_BIN"
: > "$SB_SHORTCUT"
: > "$SB_SYSTEMD_UNIT"
mkdir -p "$SB_CLIENTS_DIR/test-client" "$(dirname "$SB_SELF_CERT_KEY")"
: > "$SB_API_SECRET_FILE"
: > "$SB_SELF_CERT_KEY"
: > "$SB_SELF_CERT_CERT"

inode_before="$(stat -c %i "$SB_LOCK_FILE" 2>/dev/null || stat -f %i "$SB_LOCK_FILE")"

# T18 temporarily replaced/unset systemctl; reinstall the harmless sandbox mock
# for the real inactive uninstall path.
systemctl() {
    case "${1:-}" in
        is-active) return 0 ;;
        disable|daemon-reload) return 0 ;;
        *) return 0 ;;
    esac
}

uninstall_singbox >"$TMP/t18b.out" 2>&1
assert_rc 0 $? "inactive uninstall succeeds under the global lock"

if [ -d "$SB_ROOT_DIR" ]; then pass "SB_ROOT_DIR survives uninstall"; else fail "SB_ROOT_DIR was removed"; fi
if [ -e "$SB_LOCK_FILE" ]; then pass "config.lock path survives uninstall"; else fail "config.lock path was removed"; fi
inode_after="$(stat -c %i "$SB_LOCK_FILE" 2>/dev/null || stat -f %i "$SB_LOCK_FILE")"
assert_rc "$inode_before" "$inode_after" "config.lock inode is unchanged across uninstall"
if [ ! -e "$SB_SERVER_CONFIG" ] && [ ! -e "$SB_STATE_FILE" ] && [ ! -e "$SB_SING_BOX_BIN" ]; then
    pass "runtime/config artifacts removed while anchor remains"
else
    fail "runtime/config artifacts were not fully removed"
fi
assert_grep '控制面锚点已保留' "$TMP/t18b.out" "uninstall reports preserved control-plane anchor"

'''

t = replace_once(t, insert_before, t20 + insert_before, "dynamic L-ANCHOR regression")
LEGACY_TEST.write_text(t)

print("M0 patch applied")
