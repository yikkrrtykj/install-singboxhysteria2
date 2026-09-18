#!/usr/bin/env bash
# E3 M1 -- static contracts: single transaction engine, one privileged channel,
# socket activation, systemd hardening candidate, no implicit activation.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DAEMON="$ROOT/sbox-cm/sbox-cm"
WORKER="$ROOT/sbox-cm/sbox-cm-ops"
INSTALLER="$ROOT/sbox-cm/deploy/install-sbox-cm.sh"
SOCKET_UNIT="$ROOT/sbox-cm/deploy/sbox-cm.socket.in"
SERVICE_UNIT="$ROOT/sbox-cm/deploy/sbox-cm.service.in"
LIB="$ROOT/lib/client-management.sh"
STATE_LIB="$ROOT/lib/sbox-cm-state.sh"

PASS=0; FAIL=0; SKIP=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
skip(){ SKIP=$((SKIP+1)); printf '  SKIP %s\n' "$*"; }
has(){ grep -qF -- "$2" "$1"; }
hasnt(){ ! grep -qF -- "$2" "$1"; }
want(){ has "$1" "$2" && pass "$3" || fail "$3"; }
wantnt(){ hasnt "$1" "$2" && pass "$3" || fail "$3"; }

printf '===== E3 M1 STATIC CONTRACT =====\n'

for f in "$DAEMON" "$WORKER" "$INSTALLER" "$SOCKET_UNIT" "$SERVICE_UNIT" "$STATE_LIB"; do
    [ -f "$f" ] && pass "exists: ${f#$ROOT/}" || fail "missing: ${f#$ROOT/}"
done

printf '\n== a single privileged transaction engine ==\n'
for fn in with_client_lock commit_server_config restore_file_atomically new_candidate_path \
          new_backup_path validate_client_name candidate_problems audit_client_consistency \
          get_client_credentials cm_cred_digest_of cm_render_planned_candidate; do
    c="$(grep -cE "^${fn}\\(\\)" "$WORKER" || true)"
    [ "$c" = "0" ] && pass "worker does not redefine $fn" || fail "worker redefines $fn"
done
want "$WORKER" 'cm_render_planned_candidate' 'worker uses the canonical candidate primitive'
want "$WORKER" 'commit_server_config' 'worker commits through the canonical engine'
want "$WORKER" 'with_client_lock' 'worker uses the canonical lock'

printf '\n== credential hygiene (static) ==\n'
for f in "$WORKER" "$DAEMON" "$INSTALLER"; do
    if grep -qE -- '--arg[= ]+(uuid|password)' "$f"; then
        fail "${f#$ROOT/} passes credentials through jq argv"
    else
        pass "${f#$ROOT/} carries no credential-bearing jq --arg"
    fi
done
want "$WORKER" 'cm_plan_client_credential' 'worker plans credentials in-process'
wantnt "$WORKER" 'password=' 'worker never binds a password variable'
want "$WORKER" "grep -q '^SB'" 'worker rejects SB_* environment injection (production)'

printf '\n== frame protocol invariants ==\n'
want "$DAEMON" 'MAX_FRAME = 65536' 'frame cap is 64 KiB'
want "$DAEMON" 'struct.unpack(">I"' 'length prefix is big-endian uint32'
want "$DAEMON" 'SO_PEERCRED' 'peer credentials are checked'
want "$DAEMON" 'READ_TIMEOUT = 5.0' 'read timeout is 5s'
wantnt "$DAEMON" 'AF_INET' 'daemon has no TCP/UDP address family'
wantnt "$DAEMON" 'AF_INET6' 'daemon has no IPv6 address family'
# The "no kill timer" contract is asserted with a real AST walk in
# m1-rpc-probe.py (a grep cannot distinguish code from the docstring).

printf '\n== fixed op surface (six, no extras) ==\n'
ops="$(sed -n '/^OPS = {/,/^}/p' "$DAEMON" | grep -oE '"(management|client)\.[a-z]+"' | sort -u)"
n="$(printf '%s\n' "$ops" | grep -c . || true)"
[ "$n" = "6" ] && pass 'exactly six RPC ops are declared' || fail "op surface is $n (want 6)"
for op in management.status management.activate management.deactivate \
          client.list client.add client.delete; do
    printf '%s\n' "$ops" | grep -qxF "\"$op\"" && pass "op present: $op" || fail "op missing: $op"
done
for banned in client.rotate client.export client.get run exec shell argv; do
    printf '%s\n' "$ops" | grep -qxF "\"$banned\"" && fail "banned op exposed: $banned" \
        || pass "banned op absent: $banned"
done

printf '\n== systemd socket activation ==\n'
want "$SOCKET_UNIT" 'ListenStream=/run/sbox-cm/sbox-cm.sock' 'socket path is frozen'
want "$SOCKET_UNIT" 'SocketMode=0660' 'socket mode is 0660'
want "$SOCKET_UNIT" 'SocketUser=root' 'socket owner is root'
want "$SOCKET_UNIT" 'SocketGroup=@SBXCM_GROUP@' 'socket group is the templated sboxweb group'
want "$SOCKET_UNIT" 'RemoveOnStop=yes' 'socket file is removed on stop'
want "$SERVICE_UNIT" 'Requires=sbox-cm.socket' 'service requires the socket unit'
want "$SERVICE_UNIT" 'ExecStart=@SBXCM_LIBEXEC@/sbox-cm run' 'service runs the daemon'
if grep -qE '^ListenStream=' "$SERVICE_UNIT"; then
    fail 'service unit declares a listener (must be socket-only)'
else
    pass 'service unit declares no listener'
fi

printf '\n== systemd hardening candidate (B-5) ==\n'
want "$SERVICE_UNIT" 'ProtectSystem=strict' 'ProtectSystem=strict'
want "$SERVICE_UNIT" 'ProtectHome=read-only' 'ProtectHome=read-only'
want "$SERVICE_UNIT" 'PrivateTmp=yes' 'PrivateTmp=yes'
want "$SERVICE_UNIT" 'NoNewPrivileges=yes' 'NoNewPrivileges=yes'
want "$SERVICE_UNIT" 'RestrictAddressFamilies=AF_UNIX' 'AF_UNIX only'
want "$SERVICE_UNIT" 'ReadWritePaths=/run/sbox-cm /root/sbox /var/lib/sbox-cm' \
     'exactly the three writable trees'
want "$SERVICE_UNIT" 'CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE' 'minimal capability set'
if grep -vE '^[[:space:]]*#' "$SERVICE_UNIT" | grep -qF 'CAP_CHOWN'; then
    fail 'CAP_CHOWN granted (socket activation should make it unnecessary)'
else
    pass 'CAP_CHOWN not needed (socket activation owns the socket)'
fi
want "$SERVICE_UNIT" 'User=root' 'service runs as root'

printf '\n== installer: no implicit activation ==\n'
install_body="$(awk '/^cmd_install\(\) \{/,/^\}/' "$INSTALLER")"
printf '%s\n' "$install_body" | grep -qF 'enable --now' \
    && fail 'install enables the plane implicitly' \
    || pass 'install does not enable the plane'
n_enable="$(grep -nF 'enable --now' "$INSTALLER" | grep -vcE ':[[:space:]]*#' || true)"
[ "$n_enable" = "1" ] && pass 'exactly one enable site (cmd_enable)' \
    || fail "enable sites: $n_enable (want 1)"
disable_body="$(awk '/^cmd_disable\(\) \{/,/^\}/' "$INSTALLER")"
printf '%s\n' "$disable_body" | grep -qF 'stop "$SOCKET_UNIT"' \
    && pass 'disable stops the socket' || fail 'disable does not stop the socket'
printf '%s\n' "$disable_body" | grep -qF 'stop "$SERVICE_UNIT"' \
    && pass 'disable stops the service' || fail 'disable does not stop the service'
printf '%s\n' "$disable_body" | grep -qF 'disable "$SOCKET_UNIT"' \
    && pass 'disable disables the socket' || fail 'disable does not disable the socket'
want "$INSTALLER" 'mgmt-deactivate' 'root recovery CLI is referenced'
want "$DAEMON" 'mgmt-deactivate' 'daemon exposes the root recovery CLI'

printf '\n== executable bits recorded in git ==\n'
# The deploy contract invokes the installer directly; an entry staged as 100644
# works on a Windows dev box (no exec-bit check) and fails on Linux with
# "Permission denied", so the mode itself is part of the contract.
if command -v git >/dev/null 2>&1; then
    for f in sbox-cm/sbox-cm sbox-cm/sbox-cm-ops sbox-cm/deploy/install-sbox-cm.sh; do
        mode="$(cd "$ROOT" && git ls-files -s "$f" 2>/dev/null | awk '{print $1}')"
        [ "$mode" = "100755" ] && pass "$f is committed as 100755" \
            || fail "$f is committed as ${mode:-<untracked>} (want 100755)"
    done
else
    skip 'git unavailable: exec-bit assertions skipped'
fi

printf '\n== syntax ==\n'
bash -n "$WORKER" && pass 'bash -n worker' || fail 'bash -n worker'
bash -n "$INSTALLER" && pass 'bash -n installer' || fail 'bash -n installer'
bash -n "$STATE_LIB" && pass 'bash -n state lib' || fail 'bash -n state lib'
if command -v python3 >/dev/null 2>&1; then
    if python3 -m py_compile "$DAEMON" >/dev/null 2>&1; then
        pass 'python compile daemon'
    else
        fail 'python compile daemon'
    fi
else
    skip 'python3 missing: daemon compile check skipped'
fi
if command -v shellcheck >/dev/null 2>&1; then
    for f in "$WORKER" "$INSTALLER" "$STATE_LIB"; do
        shellcheck -S warning "$f" >/dev/null 2>&1 && pass "shellcheck ${f#$ROOT/}" \
            || fail "shellcheck ${f#$ROOT/}"
    done
else
    skip 'shellcheck missing'
fi

printf '\n== M1 acceptance markers (documented, not yet enabled) ==\n'
want "$LIB" 'cm_planned_cred_digest' 'canonical planned digest primitive present'
want "$WORKER" 'reconcile' 'worker supports startup reconciliation'
want "$WORKER" 'E_MANUAL_INTERVENTION' 'degraded mutations fail closed'

printf '\n== review-blocker contracts (B1-B8) ==\n'
want "$LIB" 'cm_tx_journal_phase' 'commit engine journals each phase via the hook (B1)'
want "$WORKER" 'w_journal_hook' 'worker installs the durable phase hook (B1)'
want "$STATE_LIB" 'cm_ledger_validate' 'ledger is fully validated fail-closed (B2)'
want "$STATE_LIB" 'cm_ledger_record_ok' 'ledger records carry a frozen schema (B2)'
want "$LIB" 'cm_bounded' 'external substeps are bounded (B6)'
want "$WORKER" 'w_finalize_original' 'replay finalizes the ORIGINAL attempt (B3)'
want "$DAEMON" 'run_maintenance' 'daemon exposes the maintenance entry point (B4)'
want "$DAEMON" 'threading.Thread' 'each connection is served on its own thread (B6)'
want "$STATE_LIB" 'cm_state_ensure_root_owned' 'state ownership is fail-closed root:root (B8)'
want "$DAEMON" 'st_uid != 0' 'daemon verifies state-dir ownership (B8)'
want "$SERVICE_UNIT" '-/run/systemd' 'minimal manager-socket carve-out for systemctl (B-5)'
if has "$WORKER" 'exec 9>>'; then
    fail 'worker still probes the lock with a creating open (B7)'
else
    pass 'worker lock probe never creates the anchor (B7)'
fi
if has "$WORKER" 'exec 9<'; then
    pass 'worker lock probe opens the anchor read-only (B7)'
else
    fail 'worker lock probe is not read-only (B7)'
fi

printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || { printf 'E3_M1_STATIC=FAIL\n'; exit 1; }
printf 'E3_M1_STATIC=PASS\n'
