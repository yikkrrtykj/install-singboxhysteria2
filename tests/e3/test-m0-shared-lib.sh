#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/lib/client-management.sh"
INSTALL="$ROOT/install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
pass(){ PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
fail(){ FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
assert_rc(){ [ "$1" = "$2" ] && pass "$3" || fail "$3 (expected=$1 got=$2)"; }

printf '===== E3 M0 SHARED LIB =====\n'

EXPECTED_LIB_SHA="$(sed -n 's/^SB_CLIENT_MANAGEMENT_SHA256="\([0-9a-f]\{64\}\)"$/\1/p' "$INSTALL")"
ACTUAL_LIB_SHA="$(sha256sum "$LIB" | awk '{print $1}')"
assert_rc "$EXPECTED_LIB_SHA" "$ACTUAL_LIB_SHA" 'installer digest pin equals shared library SHA256'
cp "$LIB" "$TMP/tampered-lib.sh"
printf '\n# tampered\n' >> "$TMP/tampered-lib.sh"
TAMPERED_SHA="$(sha256sum "$TMP/tampered-lib.sh" | awk '{print $1}')"
if [ "$TAMPERED_SHA" != "$EXPECTED_LIB_SHA" ]; then pass 'one-byte/content drift changes shared-lib digest'; else fail 'tampered lib unexpectedly matches pinned digest'; fi

bash -n "$LIB" && pass 'bash -n shared lib' || fail 'bash -n shared lib'
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning "$LIB" >/dev/null 2>&1 && pass 'shellcheck shared lib' || fail 'shellcheck shared lib'
fi

for fn in with_client_lock reload_running_singbox reload_health_ok restore_file_atomically new_candidate_path new_backup_path commit_server_config; do
  lc="$(grep -cE "^${fn}\\(\\)" "$LIB" || true)"
  ic="$(grep -cE "^${fn}\\(\\)" "$INSTALL" || true)"
  [ "$lc" = 1 ] && [ "$ic" = 0 ] && pass "$fn unique in shared lib" || fail "$fn definitions lib=$lc install=$ic"
done

SANDBOX="$TMP/sandbox"
mkdir -p "$SANDBOX"
export SB_SERVER_CONFIG="$SANDBOX/sbconfig_server.json"
export SB_SING_BOX_BIN="$TMP/mock-sing-box"
export SB_LOCK_FILE="$SANDBOX/config.lock"

info(){ :; }
warning(){ printf '[warn] %s\n' "$*" >&2; }

cat > "$SB_SING_BOX_BIN" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
  check) exit 0 ;;
  *) exit 2 ;;
esac
MOCK
chmod +x "$SB_SING_BOX_BIN"

SYSTEMCTL_MODE=stopped
RELOAD_COUNT=0
systemctl(){
  case "${1:-}" in
    is-active)
      [ "$SYSTEMCTL_MODE" = stopped ] && return 3
      return 0
      ;;
    reload)
      RELOAD_COUNT=$((RELOAD_COUNT+1))
      case "$SYSTEMCTL_MODE" in
        fail-once) [ "$RELOAD_COUNT" -eq 1 ] && return 1 ;;
        fail-all) return 1 ;;
      esac
      return 0
      ;;
  esac
  return 0
}
pgrep(){ [ "$SYSTEMCTL_MODE" != stopped ]; }
sleep(){ :; }

# shellcheck source=/dev/null
. "$LIB"

# M1-A0 moved candidate_problems INTO the shared library, so this stub must be
# installed AFTER sourcing or the library's real audit would win. The M0 suite
# intentionally exercises the commit/rollback mechanics with a neutral audit.
candidate_problems(){ return 0; }

write_live(){
  printf '{"inbounds":[],"value":"old"}\n' > "$SB_SERVER_CONFIG"
}
make_candidate(){
  local value="$1" c
  c="$(new_candidate_path)" || return 1
  printf '{"inbounds":[],"value":"%s"}\n' "$value" > "$c"
  printf '%s\n' "$c"
}

printf '\n== restore primitive preserves requested binary mode ==\n'
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin.bak"
chmod 0755 "$TMP/bin.bak"
printf 'broken\n' > "$TMP/bin.live"
restore_file_atomically "$TMP/bin.bak" "$TMP/bin.live" 0755 >/dev/null 2>&1
assert_rc 0 $? '0755 atomic restore succeeds'
assert_rc "$(sha256sum "$TMP/bin.bak" | awk '{print $1}')" "$(sha256sum "$TMP/bin.live" | awk '{print $1}')" 'binary restore is byte-identical'
assert_rc 755 "$(stat -c %a "$TMP/bin.live")" 'binary restore mode remains executable'

printf '\n== success without running service ==\n'
write_live
SYSTEMCTL_MODE=stopped
cand="$(make_candidate new)"
commit_server_config "$cand" 'test-success' >/dev/null 2>&1
assert_rc 0 $? 'commit succeeds while service is stopped'
res="$(cm_transaction_result_json)"
printf '%s\n' "$res" | jq -e '
  .phase == "replace" and
  .changed == true and
  .reload_performed == false and
  .rollback_attempted == false and
  .rollback_ok == null and
  .health_verified == false and
  (.backup_path | type == "string" and length > 0)
' >/dev/null && pass 'structured success result is complete' || fail 'structured success result mismatch'

printf '\n== reload failure rolls back ==\n'
write_live
before="$(sha256sum "$SB_SERVER_CONFIG" | awk '{print $1}')"
SYSTEMCTL_MODE=fail-once
RELOAD_COUNT=0
cand="$(make_candidate rollback-me)"
commit_server_config "$cand" 'test-rollback' >/dev/null 2>&1
assert_rc 1 $? 'commit returns legacy rc=1 after rollback'
after="$(sha256sum "$SB_SERVER_CONFIG" | awk '{print $1}')"
assert_rc "$before" "$after" 'live config restored byte-for-byte'
res="$(cm_transaction_result_json)"
printf '%s\n' "$res" | jq -e '
  .phase == "rollback" and
  .changed == false and
  .reload_performed == true and
  .rollback_attempted == true and
  .rollback_ok == true and
  .health_verified == true and
  (.backup_path | type == "string" and length > 0)
' >/dev/null && pass 'structured rollback result is complete' || fail 'structured rollback result mismatch'

printf '\n== rollback runtime cannot be confirmed ==\n'
write_live
before="$(sha256sum "$SB_SERVER_CONFIG" | awk '{print $1}')"
SYSTEMCTL_MODE=fail-all
RELOAD_COUNT=0
cand="$(make_candidate manual)"
commit_server_config "$cand" 'test-manual' >/dev/null 2>&1
assert_rc 1 $? 'manual-intervention path keeps CLI rc=1'
after="$(sha256sum "$SB_SERVER_CONFIG" | awk '{print $1}')"
assert_rc "$before" "$after" 'manual-intervention path still restores disk bytes'
res="$(cm_transaction_result_json)"
printf '%s\n' "$res" | jq -e '
  .phase == "rollback_manual" and
  .changed == false and
  .reload_performed == true and
  .rollback_attempted == true and
  .rollback_ok == false and
  .health_verified == false
' >/dev/null && pass 'manual-intervention structured result does not claim rollback success' || fail 'manual-intervention structured result falsely claims success'

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
printf 'E3_M0_SHARED_LIB=PASS\n'
