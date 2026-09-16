#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL="$ROOT/install.sh"
LIB="$ROOT/lib/client-management.sh"

pass=0
fail=0

ok()  { printf '[PASS] %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '[FAIL] %s\n' "$*"; fail=$((fail + 1)); }

has_install() { grep -Fq -- "$1" "$INSTALL"; }
no_install()  { ! grep -Fq -- "$1" "$INSTALL"; }
has_lib()     { grep -Fq -- "$1" "$LIB"; }
no_lib()      { ! grep -Fq -- "$1" "$LIB"; }

printf '===== E3 M0 STATIC CONTRACT =====\n'
printf 'install=%s\nlib=%s\n\n' "$INSTALL" "$LIB"

[ -f "$LIB" ] && ok 'canonical client-management library exists' || bad 'client-management library missing'

# One canonical lock path remains in install.sh; implementation lives only in lib.
has_install 'SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"' &&
  ok 'single canonical config.lock path remains' ||
  bad 'canonical config.lock declaration missing'

has_install 'lib/client-management.sh' &&
  ok 'install.sh loads canonical transaction library' ||
  bad 'install.sh does not load canonical transaction library'

EXPECTED_LIB_SHA="$(sed -n 's/^SB_CLIENT_MANAGEMENT_SHA256="\([0-9a-f]\{64\}\)"$/\1/p' "$INSTALL")"
ACTUAL_LIB_SHA="$(sha256sum "$LIB" | awk '{print $1}')"
if [ "$EXPECTED_LIB_SHA" = "$ACTUAL_LIB_SHA" ] && [ "$EXPECTED_LIB_SHA" = "8f16799caa6cb796575dc840659c406d3627c3cd42e42f10db6488416c3b89b6" ]; then
  ok 'install.sh digest pin matches canonical shared library bytes'
else
  bad 'install.sh digest pin does not match canonical shared library'
fi
has_install 'verify_client_management_library "$lib"' &&
has_install '. "$lib"' &&
  ok 'loader verifies selected library before source' ||
  bad 'loader digest verification/source contract missing'

has_lib 'command -v flock' && has_lib 'exec 9>>"$SB_LOCK_FILE"' && has_lib 'flock -w "$SB_LOCK_TIMEOUT" 9' &&
  ok 'shared with_client_lock is fail-closed' ||
  bad 'shared with_client_lock fail-closed primitives missing'

# No second copy of the shared primitives is permitted in install.sh.
# M1-A0 extends the uniqueness contract to the client-management semantics that
# used to live in install.sh, so the privileged worker can never drift.
for fn in with_client_lock reload_running_singbox reload_health_ok restore_file_atomically \
          new_candidate_path new_backup_path commit_server_config \
          validate_client_name client_name_exists get_reality_client_names get_hy2_client_names \
          client_structure_problems candidate_problems audit_client_consistency \
          get_client_credentials; do
  lib_count="$(grep -cE "^${fn}\\(\\)" "$LIB" || true)"
  install_count="$(grep -cE "^${fn}\\(\\)" "$INSTALL" || true)"
  if [ "$lib_count" = "1" ] && [ "$install_count" = "0" ]; then
    ok "$fn has exactly one source definition (shared lib)"
  else
    bad "$fn definition count lib=$lib_count install=$install_count"
  fi
done

# M1-A: planned-credential primitives live only in the canonical library, and
# install.sh must not build candidates with credential-bearing jq argv.
for fn in cm_cred_digest cm_cred_digest_of cm_plan_client_credential cm_cred_forget \
          cm_add_candidate_planned cm_delete_candidate cm_old_cred_digest \
          cm_add_client_candidate_planned; do
  lib_count="$(grep -cE "^${fn}\\(\\)" "$LIB" || true)"
  install_count="$(grep -cE "^${fn}\\(\\)" "$INSTALL" || true)"
  if [ "$lib_count" = "1" ] && [ "$install_count" = "0" ]; then
    ok "$fn has exactly one source definition (shared lib)"
  else
    bad "$fn definition count lib=$lib_count install=$install_count"
  fi
done

if no_install 'jq --arg name "$name" --arg uuid' && no_install '--arg password "$password"'; then
  ok 'install.sh no longer passes credentials through jq argv (M1-A)'
else
  bad 'install.sh still passes credentials through jq argv (M1-A)'
fi

# T-1/T-2: hardened restore + structured non-sensitive transaction result.
has_lib 'cmp -s "$backup" "$live"' &&
  ok 'shared restore verifies bytes after atomic replace' ||
  bad 'shared restore byte verification missing'

if no_lib 'cp -a "$backup_path" "$SB_SERVER_CONFIG"' && no_install 'cp -a "$backup_path" "$SB_SERVER_CONFIG"'; then
  ok 'generic rollback never directly cp-s backup onto live config'
else
  bad 'direct generic rollback copy still exists'
fi

has_lib 'cm_transaction_result_json()' && \
has_lib 'rollback_attempted:' && \
has_lib 'health_verified:' && \
has_lib 'backup_path:' &&
  ok 'shared transaction exposes structured result fields' ||
  bad 'structured transaction result contract incomplete'

# G2 marker + permanent control-plane anchor.
has_install 'SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/var/lib/sbox-cm/management.active}"' &&
  ok 'management marker production default is /var/lib/sbox-cm/management.active' ||
  bad 'management marker production path is wrong'

has_install 'with_client_lock _uninstall_singbox_locked' &&
  ok 'uninstall enters the global lock through locked helper' ||
  bad 'uninstall is not routed through _uninstall_singbox_locked'

no_install 'rm -rf /root/sbox/self-cert/ /root/sbox/' &&
  ok 'uninstall never removes the config.lock parent directory' ||
  bad 'uninstall still removes /root/sbox control-plane anchor'

if grep -Eq '^_uninstall_singbox_locked\(\)' "$INSTALL" &&
   awk '
     /^_uninstall_singbox_locked\(\)/ {infn=1}
     infn && /require_management_inactive/ {found=1}
     infn && /^}/ {exit found ? 0 : 1}
     END {if (!infn || !found) exit 1}
   ' "$INSTALL"; then
  ok 'management inactive check is inside locked uninstall critical section'
else
  bad 'management inactive check is outside locked uninstall critical section'
fi

printf '\nPASS=%d FAIL=%d\n' "$pass" "$fail"
if (( fail != 0 )); then
  printf 'E3_M0_STATIC_CONTRACT=FAIL\n'
  exit 1
fi
printf 'E3_M0_STATIC_CONTRACT=PASS\n'
