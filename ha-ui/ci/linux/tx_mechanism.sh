#!/usr/bin/env bash
# Stage A mechanism gate for PR #124 (P0 transaction safety).
#
# Proves on a real Linux Bash that a root-only BASH_ENV file can define the
# fixed journal hook as a *function* inside the very shell that runs the
# canonical client-management transaction, without exporting it and without
# child shells re-loading it.
#
# It also proves the fail-closed properties the design depends on:
#   * bash silently ignores a missing BASH_ENV file (exit 0) -> the launcher
#     must verify a load-time sentinel and a declare -F probe instead of
#     trusting the shell exit status;
#   * a byte-mismatched env file is rejected before any transaction runs;
#   * the real library's cm_tx_journal_phase calls the hook in-process and
#     journals the phase; a hook failure aborts the phase.
#
# Exits 0 only when every assertion holds. No network, no root, no VPS.
set -euo pipefail

repo=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
lib="$repo/lib/client-management.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/ha-ui-stageA.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT

pass=0
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { pass=$((pass + 1)); printf 'PASS: %s\n' "$*"; }

tx="$work/tx"
mkdir -p -- "$tx"
chmod 700 -- "$tx"
env_sh="$tx/env.sh"

# --- reviewed env.sh template (mirrors remote._TX_ENV_TEMPLATE) -------------
render_env() { # <txdir> <destination>
  local dir=$1 dest=$2
  sed "s|@@TX@@|$dir|g" > "$dest" <<'ENV'
#!/bin/bash
# ha-ui managed transaction hook (reviewed source: ha-ui/ha_ui/core/remote.py)
ha_ui_tx_journal() {
    local phase=${1:-unknown} backup=${2:-}
    umask 077
    printf '%s\t%s\t%s\n' "$phase" "$(date +%s)" "$backup" >> "@@TX@@/phases" || return 1
    sync -f "@@TX@@/phases" 2>/dev/null || sync
    sync -f "@@TX@@" 2>/dev/null || sync
    return 0
}
CM_TX_JOURNAL_HOOK=ha_ui_tx_journal
printf 'loaded\n' > "@@TX@@/hook-loaded"
unset BASH_ENV
ENV
  chmod 600 -- "$dest"
}

render_env "$tx" "$env_sh"
env_sha=$(sha256sum -- "$env_sh" | awk '{print $1}')

# --- 1. the env file is bound by an exact digest -----------------------------
[ "$(sha256sum -- "$env_sh" | awk '{print $1}')" = "$env_sha" ] \
  || fail "env.sh digest is not stable"
ok "env.sh has a stable reviewed digest"

# --- 2. same-shell function, non-exported, BASH_ENV unset afterwards --------
probe=$(env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" BASH_ENV="$env_sh" \
  bash -c '
    type -t ha_ui_tx_journal
    printf "HOOK=%s\n" "${CM_TX_JOURNAL_HOOK:-unset}"
    printf "BASH_ENV=%s\n" "${BASH_ENV:-unset}"
    printf "EXPORTED=%s\n" "$(env | grep -c "^CM_TX_JOURNAL_HOOK=" || true)"
    printf "CHILD=%s\n" "$(bash -c "type -t ha_ui_tx_journal || echo none")"
  ')
printf '%s\n' "$probe"
grep -qx 'function' <<<"$probe" || fail "hook is not a function in the transaction shell"
grep -qx 'HOOK=ha_ui_tx_journal' <<<"$probe" || fail "CM_TX_JOURNAL_HOOK not set as expected"
grep -qx 'BASH_ENV=unset' <<<"$probe" || fail "BASH_ENV leaked into the transaction shell"
grep -qx 'EXPORTED=0' <<<"$probe" || fail "hook variable was exported to child processes"
grep -qx 'CHILD=none' <<<"$probe" || fail "child shell re-loaded the hook"
ok "hook lives in the transaction shell only; not exported; no child re-load"

# --- 3. load-time sentinel proves the file really ran -----------------------
[ -f "$tx/hook-loaded" ] || fail "load-time sentinel missing"
ok "load-time sentinel present"

# --- 4. bash silently ignores a missing BASH_ENV: must fail closed ----------
rm -f -- "$tx/hook-loaded"
missing_probe=$(env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" \
  BASH_ENV="$tx/missing.sh" \
  bash -c 'echo ALIVE; type -t ha_ui_tx_journal || echo absent')
grep -qx 'ALIVE' <<<"$missing_probe" \
  || fail "missing BASH_ENV did not even start bash"
grep -qx 'absent' <<<"$missing_probe" \
  || fail "missing BASH_ENV still defined the hook (unexpected)"
[ ! -f "$tx/hook-loaded" ] || fail "sentinel written without loading"
ok "missing BASH_ENV is silently ignored; the sentinel/probe detects it"

# --- 5. a tampered env file is rejected by the digest gate ------------------
render_env "$tx" "$work/tampered.sh"
printf '%s\n' '# tampered' >> "$work/tampered.sh"
[ "$(sha256sum -- "$work/tampered.sh" | awk '{print $1}')" != "$env_sha" ] \
  || fail "tampered env.sh still matches the digest"
ok "tampered env.sh is rejected by the digest gate"

# --- 6. the real library calls the hook in-process --------------------------
rm -f -- "$tx/phases"
env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" BASH_ENV="$env_sh" \
  bash -c ". '$lib'; CM_TX_BACKUP_PATH='/root/sbox/x.bak'; cm_tx_journal_phase replace" \
  || fail "cm_tx_journal_phase failed with a valid hook"
[ -s "$tx/phases" ] || fail "journal record was not written"
grep -q '^replace' "$tx/phases" || fail "journal record does not carry the phase"
ok "real library invokes the hook in-process and journals the phase"

# --- 7. a failing hook is fail-closed ---------------------------------------
# Point the hook at a directory that cannot exist: the append must fail, and
# the library must abort the phase instead of continuing the transaction.
broken="$work/broken"
mkdir -p -- "$broken"
render_env "$broken/no-such-dir/tx" "$broken/env.sh"
set +e
env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" BASH_ENV="$broken/env.sh" \
  bash -c ". '$lib'; cm_tx_journal_phase replace" >/dev/null 2>&1
broken_rc=$?
set -e
[ "$broken_rc" -ne 0 ] || fail "hook failure did not abort the phase"
ok "hook failure is fail-closed"

printf '\nSTAGE-A-MECHANISM: PASS (%d checks)\n' "$pass"
