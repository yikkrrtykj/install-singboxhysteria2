#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL="$ROOT/install.sh"

pass=0
fail=0

ok() {
  printf '[PASS] %s\n' "$*"
  pass=$((pass + 1))
}

bad() {
  printf '[FAIL] %s\n' "$*"
  fail=$((fail + 1))
}

contains() {
  grep -Fq -- "$1" "$INSTALL"
}

not_contains() {
  ! grep -Fq -- "$1" "$INSTALL"
}

printf '===== E3 M0 STATIC CONTRACT =====\n'
printf 'install=%s\n\n' "$INSTALL"

# G1 existing global lock contract: preserve the already-reviewed fail-closed
# semantics; E3 M0 must not regress or replace this lock with a second one.
contains 'SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"' &&
  ok 'single canonical config.lock path remains' ||
  bad 'canonical config.lock declaration missing'

contains 'command -v flock' && contains 'exec 9>>"$SB_LOCK_FILE"' && contains 'flock -w "$SB_LOCK_TIMEOUT" 9' &&
  ok 'with_client_lock still fails closed around flock acquisition' ||
  bad 'with_client_lock fail-closed primitives missing'

# G1 / T-1: every single-file config rollback must use the hardened atomic
# restore primitive, never cp directly onto the live pathname.
contains 'restore_file_atomically()' && contains 'cmp -s "$backup" "$live"' &&
  ok 'restore_file_atomically primitive exists and verifies bytes' ||
  bad 'restore_file_atomically primitive incomplete'

if not_contains 'cp -a "$backup_path" "$SB_SERVER_CONFIG"'; then
  ok 'commit_server_config has no direct cp rollback onto live config'
else
  bad 'commit_server_config still directly cp-s backup onto live config (T-1 blocker)'
fi

# G2 / R5 formalized management marker. Environment override remains for test
# injection, but the production default must no longer live under /root/sbox.
if contains 'SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/var/lib/sbox-cm/management.active}"'; then
  ok 'management marker production default is /var/lib/sbox-cm/management.active'
else
  bad 'management marker still uses the provisional /root/sbox path'
fi

# G2 / L-ANCHOR: uninstall must never remove the lock pathname or the whole
# /root/sbox directory. The public entry point must acquire the same global
# lock and delegate to a no-nesting locked helper.
if contains 'uninstall_singbox()' && contains 'with_client_lock _uninstall_singbox_locked'; then
  ok 'uninstall enters the global lock through a locked helper'
else
  bad 'uninstall is not yet routed through _uninstall_singbox_locked'
fi

if not_contains 'rm -rf /root/sbox/self-cert/ /root/sbox/'; then
  ok 'uninstall no longer rm -rf-s the /root/sbox control-plane anchor'
else
  bad 'uninstall still deletes /root/sbox and therefore config.lock path'
fi

# The locked helper must perform the activation gate under the lock. This is a
# static shape assertion; dynamic inode/lifecycle behavior belongs in the M0
# sandbox regression added with the implementation.
if grep -Eq '^_uninstall_singbox_locked\(\)' "$INSTALL" &&
   awk '
     /^_uninstall_singbox_locked\(\)/ {infn=1}
     infn && /require_management_inactive/ {found=1}
     infn && /^}/ {exit found ? 0 : 1}
     END {if (!infn || !found) exit 1}
   ' "$INSTALL"; then
  ok 'management inactive check is inside _uninstall_singbox_locked'
else
  bad 'management inactive check is not yet inside locked uninstall critical section'
fi

printf '\nPASS=%d FAIL=%d\n' "$pass" "$fail"

if (( fail != 0 )); then
  printf 'E3_M0_STATIC_CONTRACT=FAIL\n'
  exit 1
fi

printf 'E3_M0_STATIC_CONTRACT=PASS\n'
