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
candidate_problems(){ return 0; }

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
      if [ "$SYSTEMCTL_MODE" = fail-once ] && [ "$RELOAD_COUNT" -eq 1 ]; then return 1; fi
      return 0
      ;;
  esac
  return 0
}
pgrep(){ [ "$SYSTEMCTL_MODE" != stopped ]; }
sleep(){ :; }

# shellcheck source=/dev/null
. "$LIB"

write_live(){
  printf '{"inbounds":[],"value":"old"}\n' > "$SB_SERVER_CONFIG"
}
make_candidate(){
  local value="$1" c
  c="$(new_candidate_path)" || return 1
  printf '{"inbounds":[],"value":"%s"}\n' "$value" > "$c"
  printf '%s\n' "$c"
}

printf '\n== success without running service ==\n'
write_live
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

printf '\nPASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
printf 'E3_M0_SHARED_LIB=PASS\n'
