#!/usr/bin/env bash
# sbox-cm privileged runtime state: ledger, tx journal, privileged audit and the
# management activation marker.
#
# This file is function-only; sourcing it performs no mutation. It is sourced by
# the sbox-cm transaction worker (and by tests). It expects the caller to have
# already sourced lib/client-management.sh, whose cm_cred_digest() is reused as
# the single "sha256 of stdin" primitive (no second hashing implementation).
#
# Durability contract (rev5 M1): every durable record is written as
#     write -> fsync(file) -> fsync(parent directory)
# Only implementations that do this may claim power-loss durability. Records
# are JSONL where append-only, and single JSON documents where atomic.
#
# Credential hygiene: nothing in this file may ever store, echo or forward
# UUID/password/private-key material. The only credential-derived value that is
# permitted here is the IRREVERSIBLE planned/old credential digest.

SB_CM_STATE_DIR="${SB_CM_STATE_DIR:-/var/lib/sbox-cm}"

cm_now_utc() {
    date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S
}

# Reject anything that is not a plain, bounded, path-safe identifier. Every
# value that becomes part of a filename (request_id) goes through this.
cm_safe_id() { # <value> -> rc 0 when safe to embed in a path component
    local v="${1:-}"
    [ -n "$v" ] || return 1
    [ "${#v}" -le 64 ] || return 1
    case "$v" in
        *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}

# --------------------------------------------------------------- durability --
# Barrier for a file or directory. Prefers the coreutils per-file form and
# degrades to a global sync (still correct, just heavier).
cm_fsync_path() { # <path>
    local p="$1"
    [ -e "$p" ] || return 1
    if sync -f "$p" 2>/dev/null; then
        return 0
    fi
    command sync 2>/dev/null || return 1
    return 0
}

# Atomic durable write: content on stdin -> temp -> fsync(file) -> rename ->
# fsync(parent dir). Never follows a symlink at the target.
cm_durable_write() { # <path> [mode=0600]  (content on stdin)
    local path="$1" mode="${2:-0600}" dir tmp
    dir="$(dirname -- "$path")"
    if [ -L "$path" ]; then
        warning "拒绝写入符号链接目标: $path"
        return 1
    fi
    if ! mkdir -p -- "$dir" 2>/dev/null; then
        return 1
    fi
    if ! tmp="$(mktemp "$dir/.cm-tmp.XXXXXX" 2>/dev/null)"; then
        return 1
    fi
    if ! cat > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! chmod "$mode" "$tmp" 2>/dev/null; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! cm_fsync_path "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! mv -f -- "$tmp" "$path" 2>/dev/null; then
        rm -f -- "$tmp"
        return 1
    fi
    cm_fsync_path "$dir" || return 1
    return 0
}

# Durable append: content on stdin -> append -> fsync(file) -> fsync(parent dir).
cm_durable_append() { # <path> [mode=0600]  (content on stdin)
    local path="$1" mode="${2:-0600}" dir
    dir="$(dirname -- "$path")"
    if [ -L "$path" ]; then
        warning "拒绝追加到符号链接目标: $path"
        return 1
    fi
    if ! mkdir -p -- "$dir" 2>/dev/null; then
        return 1
    fi
    if [ ! -e "$path" ]; then
        : > "$path" 2>/dev/null || return 1
        chmod "$mode" "$path" 2>/dev/null || return 1
    fi
    if ! cat >> "$path"; then
        return 1
    fi
    cm_fsync_path "$path" || return 1
    cm_fsync_path "$dir" || return 1
    return 0
}

# Read a JSONL file line by line, calling <handler> with each COMPLETE line.
# A trailing partial line (crash during append) is silently dropped: it was
# never durable. FAIL-CLOSED on unreadable files.
cm_jsonl_foreach() { # <file> <handler>
    local file="$1" handler="$2" line
    [ -f "$file" ] || return 0
    [ -r "$file" ] || return 1
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        "$handler" "$line" || return 1
    done < "$file"
    return 0
}

# --------------------------------------------------------------- layout --
cm_state_layout_ok() {
    local d
    for d in "$SB_CM_STATE_DIR" "$SB_CM_STATE_DIR/ledger" \
             "$SB_CM_STATE_DIR/journal" "$SB_CM_STATE_DIR/audit"; do
        [ ! -e "$d" ] && continue
        if [ -L "$d" ] || [ ! -d "$d" ]; then
            warning "sbox-cm 运行时路径不是普通目录: $d"
            return 1
        fi
    done
    return 0
}

cm_state_init() {
    cm_state_layout_ok || return 1
    mkdir -p -- "$SB_CM_STATE_DIR" "$SB_CM_STATE_DIR/ledger" \
                "$SB_CM_STATE_DIR/journal" "$SB_CM_STATE_DIR/audit" 2>/dev/null || return 1
    chmod 0700 -- "$SB_CM_STATE_DIR" "$SB_CM_STATE_DIR/ledger" \
                  "$SB_CM_STATE_DIR/journal" "$SB_CM_STATE_DIR/audit" 2>/dev/null || return 1
    return 0
}

# --------------------------------------------------------------- ledger --
cm_ledger_path() { printf '%s/ledger/cm-ledger.jsonl\n' "$SB_CM_STATE_DIR"; }

# Append a durable intent. All values are constrained (hex digests, bounded
# identifiers, enum op names), so direct interpolation cannot break the JSON.
cm_ledger_append_intent() { # <key> <op> <name> <digest> <generation> <request_id> <cred_field> <cred_digest>
    local key="$1" op="$2" name="$3" digest="$4" generation="$5" request_id="$6"
    local cred_field="$7" cred_digest="$8"
    printf '{"v":1,"kind":"intent","key":"%s","op":"%s","name":"%s","digest":"%s","%s":"%s","generation":%s,"state":"in_flight","ts":"%s","request_id":"%s"}\n' \
        "$key" "$op" "$name" "$digest" "$cred_field" "$cred_digest" "$generation" \
        "$(cm_now_utc)" "$request_id" \
        | cm_durable_append "$(cm_ledger_path)"
}

# Append a durable outcome. It MUST carry the same identity fields as the
# intent (op/name/digest) so that a later same-key replay can verify that the
# request semantics still match before returning the stored result.
cm_ledger_append_outcome() { # <key> <op> <name> <digest> <generation> <result_json>
    local key="$1" op="$2" name="$3" digest="$4" generation="$5" result_json="$6"
    if ! printf '%s' "$result_json" | jq -e 'type == "object"' >/dev/null 2>&1; then
        return 1
    fi
    printf '{"v":1,"kind":"outcome","key":"%s","op":"%s","name":"%s","digest":"%s","generation":%s,"state":"done","ts":"%s","result":%s}\n' \
        "$key" "$op" "$name" "$digest" "$generation" "$(cm_now_utc)" "$result_json" \
        | cm_durable_append "$(cm_ledger_path)"
}

# Echo the LAST complete record for <key>, or nothing when there is none.
cm_ledger_lookup() { # <key>
    local key="$1" file="${2:-}" line last=""
    [ -n "$file" ] || file="$(cm_ledger_path)"
    [ -f "$file" ] || return 0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            *"\"key\":\"$key\""*) ;;
            *) continue ;;
        esac
        if printf '%s' "$line" | jq -e . >/dev/null 2>&1; then
            last="$line"
        fi
    done < "$file"
    [ -n "$last" ] && printf '%s\n' "$last"
    return 0
}

# Field extractors over a record produced by cm_ledger_lookup.
cm_ledger_field() { # <record-json> <jq-path>  (prints empty when absent)
    printf '%s' "$1" | jq -r "${2} // empty" 2>/dev/null
}

# Next generation for a key: 1 for a fresh key, last+1 otherwise.
cm_ledger_next_generation() { # <key>
    local key="$1" rec gen
    rec="$(cm_ledger_lookup "$key")"
    if [ -z "$rec" ]; then
        printf '1\n'
        return 0
    fi
    gen="$(cm_ledger_field "$rec" '.generation')"
    case "$gen" in
        ''|*[!0-9]*) printf '1\n' ;;
        *) printf '%s\n' "$((gen + 1))" ;;
    esac
}

# Key fingerprint for audit/log surfaces: sha256(key) first 8 hex chars.
# The FULL key only ever exists in the root-only ledger.
cm_key_fp() { # <key>
    local h=""
    h="$(printf '%s' "$1" | cm_cred_digest)" || return 1
    printf '%s\n' "${h:0:8}"
}

# --------------------------------------------------------------- journal --
cm_journal_path() { # <request_id>
    cm_safe_id "$1" || return 1
    printf '%s/journal/%s.json\n' "$SB_CM_STATE_DIR" "$1"
}

cm_journal_write() { # <request_id> <op> <phase> [backup_path] [generation]
    # Generation defaults to the caller's $GEN when not supplied (the worker
    # keeps the current ledger generation there); this keeps every journal
    # entry attributable to one audit_id.
    local rid="$1" op="$2" phase="$3" backup="${4:-}" generation="${5:-${GEN:-0}}" path
    path="$(cm_journal_path "$rid")" || return 1
    if [ -n "$backup" ]; then
        backup="\"$backup\""
    else
        backup="null"
    fi
    case "$generation" in ''|*[!0-9]*) generation=0 ;; esac
    printf '{"v":1,"request_id":"%s","op":"%s","phase":"%s","backup_path":%s,"generation":%s,"ts":"%s"}\n' \
        "$rid" "$op" "$phase" "$backup" "$generation" "$(cm_now_utc)" \
        | cm_durable_write "$path"
}

cm_journal_field() { # <request_id> <jq-path>
    local rec
    rec="$(cm_journal_read "$1")" || return 1
    printf '%s' "$rec" | jq -r "${2} // empty" 2>/dev/null
}

cm_journal_read() { # <request_id>
    local path
    path="$(cm_journal_path "$1")" || return 1
    [ -f "$path" ] || return 1
    cat "$path"
}

cm_journal_clear() { # <request_id>
    local path dir
    path="$(cm_journal_path "$1")" || return 1
    dir="$(dirname -- "$path")"
    if [ -e "$path" ]; then
        rm -f -- "$path" || return 1
    fi
    cm_fsync_path "$dir" || return 1
    return 0
}

cm_journal_list() { # prints one "<request_id>" per line, newest first
    local f base
    [ -d "$SB_CM_STATE_DIR/journal" ] || return 0
    for f in "$SB_CM_STATE_DIR/journal"/*.json; do
        [ -f "$f" ] || continue
        base="$(basename -- "$f")"
        base="${base%.json}"
        cm_safe_id "$base" && printf '%s\n' "$base"
    done
    return 0
}

# --------------------------------------------------------------- audit --
cm_audit_path() { printf '%s/audit/cm.jsonl\n' "$SB_CM_STATE_DIR"; }

# Append exactly one privileged audit record. The non-secret field OBJECT comes
# on STDIN; audit_id / ts / v are added here so every writer produces the same
# shape. Malformed input is refused (jq error) rather than half-written.
cm_audit_append() { # <audit_id>   (fields object on stdin)
    local audit_id="$1"
    jq -c --arg id "$audit_id" --arg ts "$(cm_now_utc)" '
        if (type == "object") then . + {v:1, audit_id:$id, ts:$ts}
        else error("audit fields must be an object") end
    ' | cm_durable_append "$(cm_audit_path)"
}

# rc 0 when a record with this audit_id is already durable (exactly-once guard
# for crash reconciliation).
cm_audit_has() { # <audit_id>
    local id="$1" file line
    file="$(cm_audit_path)"
    [ -f "$file" ] || return 1
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in
            *"\"audit_id\":\"$id\""*) return 0 ;;
        esac
    done < "$file"
    return 1
}

# --------------------------------------------------------------- marker --
cm_marker_path() { printf '%s/management.active\n' "$SB_CM_STATE_DIR"; }

# active | inactive | active_stale
#
#  inactive     : no marker at all -> default safe state.
#  active       : marker says active AND the live config exists and parses.
#  active_stale : marker present but unusable (corrupt state field, or the live
#                 config is missing/invalid). FAIL-CLOSED: mutations refused,
#                 status/list still answer, marker never auto-removed.
cm_management_state() { # <live_cfg>
    local cfg="${1:-}" p state
    p="$(cm_marker_path)"
    if [ ! -e "$p" ]; then
        printf 'inactive\n'
        return 0
    fi
    if [ -L "$p" ] || [ ! -f "$p" ]; then
        printf 'active_stale\n'
        return 0
    fi
    state="$(jq -r '.state // "corrupt"' "$p" 2>/dev/null)"
    if [ "$state" != "active" ]; then
        printf 'active_stale\n'
        return 0
    fi
    if [ -z "$cfg" ] || [ ! -f "$cfg" ] || ! jq empty "$cfg" >/dev/null 2>&1; then
        printf 'active_stale\n'
        return 0
    fi
    printf 'active\n'
}

cm_marker_activate() { # <session_fp> <request_id>
    local fp="${1:-}" rid="${2:-}"
    printf '{"v":1,"state":"active","activated_at":"%s","activated_by":{"session_fp":"%s","request_id":"%s"}}\n' \
        "$(cm_now_utc)" "$fp" "$rid" \
        | cm_durable_write "$(cm_marker_path)" 0644
}

cm_marker_remove() {
    local p dir
    p="$(cm_marker_path)"
    dir="$(dirname -- "$p")"
    if [ -e "$p" ]; then
        rm -f -- "$p" || return 1
    fi
    cm_fsync_path "$dir" || return 1
    return 0
}

# ------------------------------------------------------- rpc schema helpers --
# Idempotency-Key: opaque ASCII 16..128 chars from [A-Za-z0-9._:-]. The worker
# re-validates every key the daemon accepted (defence in depth). The Python RPC
# core enforces the same character set before dispatch.
cm_idempotency_key_ok() { # <key>
    local k="${1:-}"
    [ "${#k}" -ge 16 ] && [ "${#k}" -le 128 ] || return 1
    case "$k" in
        *[!A-Za-z0-9._:-]*) return 1 ;;
    esac
    return 0
}

# Semantic request digest, computed by the engine from canonicalized fields
# only (never supplied by the caller). Uses the one sha256 primitive.
cm_request_digest() { # <op> <name>
    printf '{"name":"%s","op":"%s"}' "${2:-}" "${1:-}" | cm_cred_digest
}

# ------------------------------------------------------- last transaction --
cm_last_tx_path() { printf '%s/last_transaction.json\n' "$SB_CM_STATE_DIR"; }

cm_last_tx_set() { # <generation> <op> <outcome>
    jq -cn --arg op "${2:-}" --arg outcome "${3:-}" --arg ts "$(cm_now_utc)" \
           --argjson generation "${1:-0}" \
        '{generation:$generation, op:$op, outcome:$outcome, ended_at:$ts}' \
        | cm_durable_write "$(cm_last_tx_path)" 0600
}

cm_last_tx_get() {
    local p
    p="$(cm_last_tx_path)"
    [ -f "$p" ] || { printf 'null\n'; return 0; }
    jq -c . "$p" 2>/dev/null || printf 'null\n'
}

# --------------------------------------------------------------- degraded --
# Set when startup reconciliation cannot PROVE a safe state (corrupt journal,
# restore failure, still-unhealthy runtime). While degraded is set:
#   status + client.list keep working; EVERY mutation is refused.
cm_degraded_path() { printf '%s/degraded.json\n' "$SB_CM_STATE_DIR"; }

cm_degraded_active() { # rc 0 when the degraded flag is durable
    [ -f "$(cm_degraded_path)" ]
}

cm_degraded_set() { # <reconcile-state> <reason>
    printf '{"v":1,"reconcile":"%s","reason":"%s","ts":"%s"}\n' \
        "${1:-manual_intervention}" "${2:-}" "$(cm_now_utc)" \
        | cm_durable_write "$(cm_degraded_path)" 0600
}

cm_degraded_clear() {
    local p dir
    p="$(cm_degraded_path)"
    dir="$(dirname -- "$p")"
    if [ -e "$p" ]; then
        rm -f -- "$p" || return 1
    fi
    cm_fsync_path "$dir" || return 1
    return 0
}

cm_reconcile_state() { # clean | manual_intervention
    if cm_degraded_active; then
        jq -r '.reconcile // "manual_intervention"' "$(cm_degraded_path)" 2>/dev/null \
            || printf 'manual_intervention\n'
    else
        printf 'clean\n'
    fi
}
