#!/usr/bin/env bash
# PR-2B INTEGRATION regression suite (issue #33 P2, Coding D + Coding E +
# integration lane). This is the file that proves the final goal: Monitor
# ingest + journal-reader runtime + the frozen contract + the deployment
# transaction are ONE indivisible immutable release unit -- not two lanes that
# merely coexist on a branch.
#
# Coverage (integration spec section numbers):
#   §3 HARD GATE  a formally staged release carries journal_reader.ingest_contract
#                 + .schema, the Monitor runtime import path resolves them from
#                 the INSTALLED release, journal_status() reports
#                 contract_available == true, no monkeypatch / source-tree
#                 PYTHONPATH / test-only path can fake it, and deleting or
#                 corrupting the payload makes the gate FAIL.
#   §4            Monitor live link and the reader runtime link carry the SAME
#                 release id after fresh stage, upgrade, rollback and a failed
#                 upgrade (mixed-version state is never reachable).
#   §5            retention protects BOTH live references (same release, and
#                 the temporarily-diverged Monitor=N+1 / Reader=N state), and an
#                 unverifiable reader link provenance fails the whole prune
#                 round closed with zero deletions.
#   §9            a real 0.2.0 schema-v1 database migrates to v2 through the
#                 INSTALLED release code, keeps its v1 rows, and the journal
#                 ingest it then performs stays exactly-once.
#   §11           PR #51 (Add client needs no admin-password step-up) is a
#                 regression gate of this branch, not a feature of it.
#   §12           the release probe reports Monitor release id, reader-linked
#                 release id and the module location it REALLY imported from.
#   §13           failure matrix rows reachable without a live systemd.
#
# Platform contract: everything that needs real symlink + rename(2) semantics
# (release activation, runtime link, prune chronology) is honestly SKIPped on
# platforms without them, and this suite HARD-FAILS if a Linux runner reports
# ANY skip (spec §14: a skipped gate is never a false green). The static and
# python-driven sections run everywhere.
#
# Assertion-count gate: deliberately the SAME shape as its sibling
# test-monitor-v2-jr-deploy.sh rather than an EXPECTED_PASS literal -- the
# symlink-gated sections are the ones that carry the §3 hard gate, so a
# fixed count would either be unverifiable off-Linux or silently permit a
# skipped section. The Linux no-SKIP rule below is the strict equivalent: on
# a Linux runner every section must execute AND every assertion must pass.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"
DEPLOY_DIR="$ROOT/monitor-v2/deploy"
ENV_LIB="$DEPLOY_DIR/app-bin/monitor-env.sh"
SVC="$DEPLOY_DIR/app-bin/monitor-service"
PROBE="$DEPLOY_DIR/app-bin/monitor-contract-probe"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
SERVER_PY="$ROOT/monitor-v2/web/server.py"

PASS=0
FAIL=0
SKIP=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s (platform without symlink/rename semantics; Linux CI is the gate)\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_grep() { if grep -qE "$2" "$1" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $2)"; fi; }
assert_no_grep() { if grep -qE "$2" "$1" 2>/dev/null; then fail "$3 (match: $2)"; else pass "$3"; fi; }
assert_file() { if [ -f "$1" ]; then pass "$2"; else fail "$2 (missing: $1)"; fi; }

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed (hard-fail: no interpreter) ==\n' "$PASS" "$FAIL"
    exit 1
fi

# ---------------------------------------------------------------------------
# Symlink capability probe (same semantics as the established E suite)
# ---------------------------------------------------------------------------
SYMLINK_OK=0
if ln -s . "$TMP/.symcap" 2>/dev/null && [ -L "$TMP/.symcap" ]; then
    if mv -T "$TMP/.symcap" "$TMP/.symcap2" 2>/dev/null && [ -L "$TMP/.symcap2" ]; then
        SYMLINK_OK=1
    fi
    rm -f "$TMP/.symcap" "$TMP/.symcap2"
fi
require_symlink() { # <scenario> -> rc 1 after logging the SKIP
    if [ "$SYMLINK_OK" = 1 ]; then return 0; fi
    skip "$1"
    return 1
}

# ---------------------------------------------------------------------------
# Case environment: every path under $TMP, and a systemctl TRIPWIRE -- this
# suite must never talk to a service manager at all (§6/§13 boundary).
# ---------------------------------------------------------------------------
STUB="$TMP/stub"; mkdir -p "$STUB"
SYSTEMCTL_CALLS="$TMP/systemctl-calls.log"; : > "$SYSTEMCTL_CALLS"
cat > "$STUB/systemctl" <<SME
#!/usr/bin/env bash
printf 'systemctl %s\n' "\$*" >> "$SYSTEMCTL_CALLS"
exit 1
SME
chmod +x "$STUB/systemctl"
export PATH="$STUB:$PATH"

new_case() { # new_case <name>
    CASE_DIR="$TMP/case-$1"
    rm -rf "$CASE_DIR"
    mkdir -p "$CASE_DIR/opt" "$CASE_DIR/var/lib" "$CASE_DIR/etc"
    export SBMON_APP_LINK="$CASE_DIR/opt/singbox-monitor"
    export SBMON_RELEASES_DIR="$CASE_DIR/opt/singbox-monitor-releases"
    export SBMON_STATE_ROOT="$CASE_DIR/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$CASE_DIR/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$CASE_DIR/etc/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$CASE_DIR/var/backups/singbox-monitor"
    export SBMON_LOCK_FILE="$CASE_DIR/deploy.lock"
    export SBMON_HISTORY_FILE="$SBMON_RELEASES_DIR/releases.history"
    export SBMON_KEEP_RELEASES="${SBMON_KEEP_RELEASES:-3}"
    export SBMON_REPO_MONITOR_DIR="$CASE_DIR/src"
    export SBMON_VERSION_FILE="$CASE_DIR/src/VERSION"
    export SBOXJR_DATA_ROOT="$CASE_DIR/var/lib/sbox-journal"
    export SBOXJR_STATE_DIR="$SBOXJR_DATA_ROOT/state"
    export SBOXJR_OUT_DIR="$SBOXJR_DATA_ROOT/out"
    export SBOXJR_LIB_DIR="$CASE_DIR/jr-runtime"
    export SBOXJR_UNIT_FILE="$CASE_DIR/etc/singbox-journal-reader.service"
    export SBMON_FIXTURE=1
    export SBMON_USER=sboxweb SBMON_GROUP=sboxweb
    export SBMON_PYTHON3="$PY"
    export SBMON_SYSTEMCTL="$STUB/systemctl"
    OUT="$CASE_DIR/out.log"
}

# build_src <dest> [--with-jr]
build_src() {
    local dest="$1" with_jr="${2:-}"
    mkdir -p "$dest"
    cp "$ROOT/monitor-v2/collector.py" "$dest/"
    cp "$ROOT/monitor-v2/webapp.py" "$dest/"
    cp -R "$ROOT/monitor-v2/web" "$dest/web"
    cp -R "$ROOT/monitor-v2/api_bridge" "$dest/api_bridge"
    rm -rf "$dest/api_bridge/__pycache__" "$dest/web/__pycache__"
    printf '0.1.0\n' > "$dest/VERSION"
    if [ "$with_jr" = "--with-jr" ]; then
        mkdir -p "$dest/journal_reader"
        local f
        for f in "$ROOT"/monitor-v2/journal_reader/*.py; do
            cp "$f" "$dest/journal_reader/"
        done
        rm -rf "$dest/journal_reader/__pycache__"
    fi
}

# libf <function> [args...] -- run ONE library function against the case env,
# exactly as the installer would (same code, no reimplementation).
libf() {
    bash -c '. "$0" >/dev/null 2>&1 || exit 90; f="$1"; shift; "$f" "$@"' \
        "$LIB" "$@"
}
# libf_q -- same call, library prose logs dropped (only the rc matters). The
# deploy lib writes most status lines to stdout, so an unquoted call inside
# $( ) would corrupt a captured release id.
libf_q() { libf "$@" >/dev/null 2>&1; }

# stage_activate_link <version> -> release id on stdout (rc != 0 on refusal)
stage_activate_link() {
    local ver="$1" id
    id="$(libf sbmon_stage_release "$ver")" || return 1
    libf_q sbmon_activate_release "$id" || return 1
    libf_q sbmon_sboxjr_link_runtime "$id" || return 1
    printf '%s\n' "$id"
}

monitor_release_id() {
    [ -L "$SBMON_APP_LINK" ] || return 0
    basename -- "$(readlink -- "$SBMON_APP_LINK")"
}
reader_linked_id() { # audited tri-state decoder, exactly as production uses it
    libf sbmon_sboxjr_runtime_linked_id
}
# run_probe [via-dir] -> probe JSON on stdout, rc from the probe
run_probe() {
    local link="${1:-$SBMON_APP_LINK}"
    [ -x "$link/bin/monitor-contract-probe" ] || return 9
    "$link/bin/monitor-contract-probe"
}
probe_field() { # <json> <key>
    printf '%s' "$1" | "$PY" -c 'import json,sys
print(json.load(sys.stdin).get(sys.argv[1]))' "$2" 2>/dev/null
}

# ===========================================================================
section "I0: static coupling gates (one release unit, no second source of truth)"
# ===========================================================================
assert_file "$PROBE" "shipped release probe exists"
if bash -n "$PROBE" 2>"$TMP/syn.err"; then pass "bash -n monitor-contract-probe"; else fail "bash -n monitor-contract-probe: $(cat "$TMP/syn.err")"; fi
if bash -n "$SVC" 2>"$TMP/syn.err"; then pass "bash -n monitor-service"; else fail "bash -n monitor-service: $(cat "$TMP/syn.err")"; fi
if bash -n "$ENV_LIB" 2>"$TMP/syn.err"; then pass "bash -n monitor-env.sh"; else fail "bash -n monitor-env.sh: $(cat "$TMP/syn.err")"; fi

# ONE derivation, shared by the runtime and the probe: neither may invent a
# second path rule (that is how a release and a probe start disagreeing).
assert_grep "$ENV_LIB" '^monitor_env_contract_pythonpath\(\)' "env lib owns the contract path derivation"
assert_grep "$ENV_LIB" '^monitor_env_apply_contract_pythonpath\(\)' "env lib owns the authoritative PYTHONPATH application"
assert_grep "$SVC" 'monitor_env_apply_contract_pythonpath "\$APP_DIR"' "monitor-service applies the shared derivation"
assert_grep "$PROBE" 'monitor_env_apply_contract_pythonpath "\$APP_DIR"' "probe applies the SAME derivation (no reimplementation)"
assert_eq "$(grep -c '^[[:space:]]*PYTHONPATH=' "$SVC")" "0" "monitor-service never hand-rolls PYTHONPATH (only the shared helper sets it)"
assert_no_grep "$PROBE" 'PYTHONPATH=.*\$\{?' "probe never builds a PYTHONPATH of its own"

# The libexec literal must agree between the deploy lib and the env lib: if
# one moves, staging and importing stop describing the same tree.
LIT_LIB="$(grep -o 'SBOXJR_RELEASE_LIBEXEC_REL="[^"]*"' "$LIB" | cut -d'"' -f2)"
LIT_ENV="$(grep -o 'libexec/sbox-journal-reader' "$ENV_LIB" | head -n1)"
assert_eq "$LIT_LIB" "$LIT_ENV" "release libexec relative path is the SAME literal in the deploy lib and the env lib"

# All-or-nothing payload rule: a half-shipped contract is NOT a contract.
for m in __init__.py ingest_contract.py schema.py; do
    assert_grep "$ENV_LIB" "$m" "derivation requires $m before it exports any path"
done

# The payload the Monitor needs must be inside the frozen ship manifest.
MANIFEST_LINE="$(grep -m1 'SBOXJR_MODULE_FILES=(' -A 3 "$LIB")"
assert_eq "$(printf '%s' "$MANIFEST_LINE" | grep -c 'ingest_contract.py')" "1" "ingest_contract.py is in the 12+1+1 ship manifest"
assert_eq "$(printf '%s' "$MANIFEST_LINE" | grep -c 'schema.py')" "1" "schema.py is in the 12+1+1 ship manifest"

# The probe is a release artifact: staged, executable, syntax-validated.
assert_grep "$LIB" 'app-bin/monitor-contract-probe' "sbmon_stage_release stages the probe into the release"
assert_grep "$LIB" 'staged/bin/monitor-contract-probe' "probe is chmod 0755 and syntax-checked as a staged shim"

# The Monitor's only journal edge stays confined to the two contract modules
# (Coding D's whitelist, re-asserted at integration level).
EDGE="$("$PY" - "$HIST_PY" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
bad = []
for n in ast.walk(tree):
    if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "journal_reader":
        bad += [a.name for a in n.names if a.name not in ("ingest_contract", "schema")]
    elif isinstance(n, ast.Import):
        for a in n.names:
            p = a.name.split(".")
            if p[0] == "journal_reader" and not (len(p) == 2 and p[1] in ("ingest_contract", "schema")):
                bad.append(a.name)
print(",".join(bad) or "OK")
EOF
)"
assert_eq "$EDGE" "OK" "incident_history imports ONLY ingest_contract + schema (never the reader runtime)"

# No user-facing surface may carry an absolute production path: the web layer
# still has ZERO journal references, and journal_status() keeps its fixed
# sanitized key set.
assert_eq "$(grep -c 'journal' "$SERVER_PY")" "0" "web/server.py exposes no journal surface (no path can leak through the API)"
HK="$("$PY" - "$HIST_PY" <<'EOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
body = src.split("def journal_status", 1)[1].split("def ", 1)[0]
keys = re.findall(r'"([a-z_]+)":', body)
print(",".join(k for k in keys if "path" in k or "dir" in k.split("_")[-1] and k != "exchange_dir_configured") or "CLEAN")
EOF
)"
assert_eq "$HK" "CLEAN" "journal_status() surface carries no path/dir field (sanitized; only the operator probe prints locations)"

# §11: PR #51 is part of this branch's base and must not regress.
assert_grep "$SERVER_PY" 'client\.add' "client.add keeps its dedicated route branch"
ADD_NO_STEPUP="$("$PY" - "$SERVER_PY" <<'EOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
# the add branch must NOT route through _require_step_up
m = re.search(r'if op == "client\.add":(.*?)else:', src, re.S)
body = m.group(1) if m else "MISSING"
print("OK" if "_require_csrf_actor" in body and "_require_step_up" not in body else "REGRESSED:" + ("csrf" if "_require_csrf_actor" in body else "no-csrf-actor"))
EOF
)"
assert_eq "$ADD_NO_STEPUP" "OK" "#51: Add is session+CSRF only (never step-up), other mutations still are"
assert_grep "$SERVER_PY" '_require_step_up\(self\._handle_e3_mutation, op\)' "#51: destructive mutations keep _require_step_up"
assert_grep "$SERVER_PY" '_require_step_up\(self\._handle_e3_export\)' "#51: export keeps _require_step_up"

# §13 row 13 (schema unsupported) + frozen-contract boundary: the integration
# must not have widened the accepted schema set.
assert_eq "$(grep -c 'SCHEMA_VERSION = 2' "$HIST_PY")" "1" "history schema stays exactly v2"

# ===========================================================================
section "I1: HARD GATE -- formally staged release carries and imports the contract"
# ===========================================================================
if require_symlink "I1 formal release (stage + activate + link + probe)"; then
    new_case formal
    build_src "$SBMON_REPO_MONITOR_DIR" --with-jr
    RID="$(stage_activate_link 0.1.0)"; RC=$?
    assert_eq "$RC" "0" "formal: stage+activate+link through the real library rc=$RC"
    RELEASE="$SBMON_RELEASES_DIR/$RID"

    JRD="$RELEASE/libexec/sbox-journal-reader/journal_reader"
    assert_file "$JRD/__init__.py" "formal: installed release tree carries journal_reader/__init__.py"
    assert_file "$JRD/ingest_contract.py" "formal: installed release tree carries journal_reader/ingest_contract.py"
    assert_file "$JRD/schema.py" "formal: installed release tree carries journal_reader/schema.py"
    assert_file "$RELEASE/bin/monitor-contract-probe" "formal: probe is part of the installed release"

    JSON="$(run_probe)"; PRC=$?
    assert_eq "$PRC" "0" "formal: release probe exits 0 (contract importable from the installed release)"
    assert_eq "$(probe_field "$JSON" contract_available)" "True" "formal: contract_available == true from the installed release"
    assert_eq "$(probe_field "$JSON" journal_status_contract_available)" "True" "formal: journal_status()[\"contract_available\"] == true"
    assert_eq "$(probe_field "$JSON" contract_module_in_release)" "True" "formal: the import really came from inside the release tree"
    assert_eq "$(probe_field "$JSON" contract_pythonpath_consistent)" "True" "formal: runtime PYTHONPATH is exactly the derived release path"
    assert_eq "$(probe_field "$JSON" monitor_release_id)" "$RID" "formal: probe resolved the SAME release id as the live link"
    printf '  EVIDENCE release_id=%s\n  EVIDENCE probe=%s\n' "$RID" "$JSON"

    # §4 same immutable release: monitor live link == reader runtime link.
    assert_eq "$(monitor_release_id)" "$RID" "formal: monitor live link is the staged release"
    assert_eq "$(reader_linked_id)" "$RID" "formal: reader runtime link resolves to the SAME release id"

    # §6/§13 boundary: a release transaction that touches no service manager.
    assert_eq "$(grep -c . "$SYSTEMCTL_CALLS")" "0" "formal: zero systemctl calls in the stage/activate/link transaction"

    # Real runtime entrypoint: the Monitor process itself reports the contract.
    printf 'sekret-value\n' > "$CASE_DIR/api.secret"
    mkdir -p "$CASE_DIR/state"
    printf 'SBMON_MODE=web\nSBMON_API_URL=http://127.0.0.1:19091\nSBMON_API_SECRET_FILE=%s\nSBMON_WEB_BIND=127.0.0.1:19198\n' \
        "$CASE_DIR/api.secret" > "$CASE_DIR/monitor.conf"
    timeout 8 "$RELEASE/bin/monitor-service" "$CASE_DIR/monitor.conf" "$CASE_DIR/state" \
        > "$CASE_DIR/svc.log" 2>&1 || true
    assert_grep "$CASE_DIR/svc.log" 'journal_contract=available' "formal: the real Monitor runtime entrypoint imports the contract (lifecycle evidence)"

    # -----------------------------------------------------------------------
    # §3.5 negatives: the gate must be the RELEASE, not luck.
    # -----------------------------------------------------------------------
    rm -f "$JRD/ingest_contract.py"
    JSON="$(run_probe)"; PRC=$?
    assert_eq "$PRC" "1" "negative: deleting ingest_contract.py from the installed release fails the probe"
    assert_eq "$(probe_field "$JSON" contract_available)" "False" "negative: contract_available flips to false with the payload deleted"
    printf 'def broken(:\n' > "$JRD/ingest_contract.py"
    rm -rf "$JRD/__pycache__"
    JSON="$(run_probe)"; PRC=$?
    assert_eq "$PRC" "1" "negative: an unparseable contract module still fails (real import, not a file test)"
    assert_eq "$(probe_field "$JSON" import_error)" "SyntaxError" "negative: failure is reported as a sanitized import error code"
    cp "$ROOT/monitor-v2/journal_reader/ingest_contract.py" "$JRD/ingest_contract.py"
    rm -rf "$JRD/__pycache__"
    run_probe >/dev/null; assert_eq "$?" "0" "negative: gate recovers to green once the release payload is whole again"

    # §3.4 anti-fake: neither the cwd nor an injected PYTHONPATH may answer for
    # a release that does not carry the contract.
    mv "$RELEASE/libexec" "$CASE_DIR/libexec-offline"
    ( cd "$ROOT/monitor-v2" && run_probe > "$CASE_DIR/fake1.json" ); FRC=$?
    assert_eq "$FRC" "1" "anti-fake: running the probe from a repository checkout cannot make a payload-less release pass"
    assert_eq "$(probe_field "$(cat "$CASE_DIR/fake1.json")" contract_available)" "False" "anti-fake: source-tree cwd is not an import candidate"
    ( export PYTHONPATH="$ROOT/monitor-v2"; run_probe > "$CASE_DIR/fake2.json" ); FRC=$?
    assert_eq "$FRC" "1" "anti-fake: an injected source-tree PYTHONPATH is not honored either"
    assert_eq "$(probe_field "$(cat "$CASE_DIR/fake2.json")" contract_available)" "False" "anti-fake: contract stays false under PYTHONPATH injection"
    # ... and the runtime entrypoint agrees (inert, not fake-available).
    timeout 8 "$RELEASE/bin/monitor-service" "$CASE_DIR/monitor.conf" "$CASE_DIR/state" \
        > "$CASE_DIR/svc-inert.log" 2>&1 || true
    assert_grep "$CASE_DIR/svc-inert.log" 'journal_contract=inert' "anti-fake: monitor-service reports the payload-less release as inert, never available"
    assert_no_grep "$CASE_DIR/svc-inert.log" 'journal_contract=available' "anti-fake: no available line for a payload-less release"
    mv "$CASE_DIR/libexec-offline" "$RELEASE/libexec"

    # A release with NO libexec at all (pre-PR-2B baseline) stays installable
    # and honestly reports the contract missing.
    build_src "$CASE_DIR/src-nojr"
    NOJR="$(export SBMON_REPO_MONITOR_DIR="$CASE_DIR/src-nojr"
             libf sbmon_stage_release 0.0.9)"
    libf_q sbmon_activate_release "$NOJR"
    [ -d "$SBMON_RELEASES_DIR/$NOJR" ] && pass "inert baseline: a libexec-less release stages and activates normally" \
        || fail "inert baseline: staging/activation produced no release directory (id='$NOJR')"
    assert_eq "$(cat "$SBMON_RELEASES_DIR/$NOJR/VERSION")" "0.0.9" "inert baseline: the release records exactly the version it was staged with"
    [ ! -d "$SBMON_RELEASES_DIR/$NOJR/libexec" ] && pass "inert baseline: no libexec staged from a source tree without journal_reader" \
        || fail "inert baseline: libexec appeared from a source tree that has no reader"
    run_probe "$SBMON_APP_LINK" >/dev/null 2>&1
    assert_eq "$?" "1" "inert baseline: probe HARD-FAILS against a release without the contract (never silently green)"
fi

# ===========================================================================
section "I2: §4 immutable-release coupling across fresh / upgrade / rollback / failed upgrade"
# ===========================================================================
if require_symlink "I2 transaction coupling matrix"; then
    new_case coupling
    build_src "$SBMON_REPO_MONITOR_DIR" --with-jr

    R_N="$(stage_activate_link 0.1.0)"; RC=$?
    assert_eq "$RC" "0" "coupling: fresh install of N succeeded"
    assert_eq "$(monitor_release_id)" "$(reader_linked_id)" "coupling: fresh install has monitor release id == reader release id"
    N_ID="$(monitor_release_id)"

    # --- upgrade N -> N+1
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    R_N1="$(stage_activate_link 0.1.1)"; RC=$?
    assert_eq "$RC" "0" "coupling: upgrade to N+1 succeeded"
    [ "$(monitor_release_id)" != "$N_ID" ] && pass "coupling: monitor moved to a new release" || fail "coupling: monitor did not move"
    assert_eq "$(monitor_release_id)" "$(reader_linked_id)" "coupling: after upgrade BOTH sides are N+1 (no Monitor N+1 / Reader N)"
    assert_eq "$(reader_linked_id)" "$R_N1" "coupling: reader runtime re-linked onto the N+1 release exactly"
    run_probe >/dev/null; assert_eq "$?" "0" "coupling: N+1 release still imports its own contract"
    # the OLD release stays immutable: its probe path still answers for the old id
    assert_eq "$(probe_field "$(run_probe "$SBMON_RELEASES_DIR/$N_ID")" monitor_release_id)" "$N_ID" "coupling: old release stays byte-immutable and self-identifying"

    # --- failed upgrade: N+1 runtime payload broken -> link refuses, nothing mixes
    printf '0.1.2\n' > "$SBMON_VERSION_FILE"
    BROKEN_ID="$(libf sbmon_stage_release 0.1.2)"
    rm -f "$SBMON_RELEASES_DIR/$BROKEN_ID/libexec/sbox-journal-reader/journal_reader/schema.py"
    libf sbmon_sboxjr_link_runtime "$BROKEN_ID" >/dev/null 2>&1
    assert_eq "$?" "1" "failed upgrade: reader runtime manifest breach refuses the link (fail-closed)"
    assert_eq "$(monitor_release_id)" "$R_N1" "failed upgrade: monitor live link never moved"
    assert_eq "$(reader_linked_id)" "$R_N1" "failed upgrade: reader stays on N+1 -> no mixed-version state"
    run_probe >/dev/null; assert_eq "$?" "0" "failed upgrade: the surviving release still reports contract_available"

    # --- rollback N+1 -> N (both references move together)
    libf_q sbmon_activate_release "$N_ID"
    libf_q sbmon_sboxjr_link_runtime "$N_ID"
    assert_eq "$(monitor_release_id)" "$N_ID" "rollback: monitor live link back to N"
    assert_eq "$(reader_linked_id)" "$N_ID" "rollback: reader runtime link back to the SAME N"
    assert_eq "$(probe_field "$(run_probe)" monitor_release_id)" "$N_ID" "rollback: probe resolves the rolled-back release id"
    run_probe >/dev/null; assert_eq "$?" "0" "rollback: contract still available from the rolled-back release"

    # --- rollback into a release with NO reader runtime while the reader is
    #     activated must stay fail-closed (Coding E rule, re-proved here).
    build_src "$CASE_DIR/src-pre"
    PRE_ID="$(export SBMON_REPO_MONITOR_DIR="$CASE_DIR/src-pre"
               libf sbmon_stage_release 0.0.8)"
    [ -n "$PRE_ID" ] && pass "pre-PR-2B guard: a libexec-less release still stages" \
        || fail "pre-PR-2B guard: staging the libexec-less source failed"
    libf_q sbmon_sboxjr_runtime_linked_id
    assert_eq "$?" "0" "pre-PR-2B guard: current reader link provenance is legal before the attempt"
    libf_q sbmon_sboxjr_audit_runtime "$SBMON_RELEASES_DIR/$PRE_ID/libexec/sbox-journal-reader"
    assert_eq "$?" "1" "pre-PR-2B guard: a libexec-less rollback target fails the runtime audit"
    libf_q sbmon_sboxjr_link_runtime "$PRE_ID"
    assert_eq "$?" "1" "pre-PR-2B guard: linking the reader onto a libexec-less release is refused"
    assert_eq "$(reader_linked_id)" "$N_ID" "pre-PR-2B guard: the reader link stayed on N (never mixed)"
fi

# ===========================================================================
section "I3: §5 dual-reference retention (prune protects BOTH live links)"
# ===========================================================================
if require_symlink "I3 prune chronology"; then
    new_case prune
    build_src "$SBMON_REPO_MONITOR_DIR" --with-jr
    mk_release() { # mk_release <name> <version> <age-days>
        local id; id="$(stage_activate_link "$2")" || return 1
        touch -d "$3 days ago" "$SBMON_RELEASES_DIR/$id"
        printf '%s\n' "$id" > "$CASE_DIR/id-$1"
    }
    R_OLD="$(mk_release old 0.1.0 30)"
    R_MID="$(mk_release mid 0.1.1 20)"
    R_NEW="$(mk_release new 0.1.2 10)"
    assert_eq "$([ -n "$R_OLD" ] && [ -n "$R_MID" ] && [ -n "$R_NEW" ] && echo ok)" "ok" "prune: three releases staged"

    # Monitor -> newest, Reader -> oldest: the diverged-reference state.
    libf_q sbmon_activate_release "$R_NEW"
    libf_q sbmon_sboxjr_link_runtime "$R_OLD"
    assert_eq "$(monitor_release_id)" "$R_NEW" "prune: monitor live link is the newest release"
    assert_eq "$(reader_linked_id)" "$R_OLD" "prune: reader runtime link is the OLDEST release (diverged on purpose)"
    SBMON_KEEP_RELEASES=2 libf sbmon_prune_releases >/dev/null 2>&1
    assert_eq "$?" "0" "prune: retention round completed under legal provenance"
    [ -d "$SBMON_RELEASES_DIR/$R_NEW" ] && pass "prune: the monitor-live release N+1 is protected" || fail "prune: monitor-live release was deleted"
    [ -d "$SBMON_RELEASES_DIR/$R_OLD" ] && pass "prune: the reader-referenced release N is protected TOO (dual-reference)" \
        || fail "prune: a release still referenced by the reader runtime was deleted"
    [ ! -d "$SBMON_RELEASES_DIR/$R_MID" ] && pass "prune: retention still ran (the unreferenced middle release was pruned)" \
        || fail "prune: nothing was pruned despite KEEP=2 over 3 releases"

    # Both references on the SAME release: that one is untouchable.
    libf_q sbmon_activate_release "$R_OLD"
    libf_q sbmon_sboxjr_link_runtime "$R_OLD"
    SBMON_KEEP_RELEASES=1 libf sbmon_prune_releases >/dev/null 2>&1
    assert_eq "$?" "0" "prune same-release: round completed"
    [ -d "$SBMON_RELEASES_DIR/$R_OLD" ] && pass "prune same-release: the doubly-referenced release survives any retention count" \
        || fail "prune same-release: the shared live release was deleted"

    # Illegal reader provenance: the WHOLE round fails closed, zero deletions.
    # A real victim must exist first, otherwise "nothing deleted" is vacuous.
    R_FRESH="$(libf sbmon_stage_release 0.1.3)"
    touch -d "1 days ago" "$SBMON_RELEASES_DIR/$R_FRESH"
    rm -f "$SBOXJR_LIB_DIR"; ln -s "$CASE_DIR/foreign-runtime" "$SBOXJR_LIB_DIR"
    BEFORE="$(find "$SBMON_RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    SBMON_KEEP_RELEASES=1 libf sbmon_prune_releases >/dev/null 2>&1
    PRC=$?
    [ "$PRC" != "0" ] && pass "prune provenance: an unverifiable reader link fails the round closed (rc=$PRC)" \
        || fail "prune provenance: retention succeeded despite unverifiable reader provenance"
    AFTER="$(find "$SBMON_RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    assert_eq "$AFTER" "$BEFORE" "prune provenance: ZERO releases deleted on the refused path"
    [ -d "$SBMON_RELEASES_DIR/$R_FRESH" ] && pass "prune provenance: the unreferenced victim release is still there (nothing pruned)" \
        || fail "prune provenance: retention deleted a release despite unverifiable reader provenance"
    [ -d "$SBMON_RELEASES_DIR/$R_OLD" ] && pass "prune provenance: the doubly-live release survives too" \
        || fail "prune provenance: the live release was deleted on the refused path"
    assert_eq "$(grep -c . "$SYSTEMCTL_CALLS")" "0" "prune: retention touches no service manager (sing-box unaffected)"
fi

# ===========================================================================
section "I4: §9 schema v1 -> v2 migration THROUGH the installed release"
# ===========================================================================
if require_symlink "I4 migration via installed release code"; then
    new_case migrate
    build_src "$SBMON_REPO_MONITOR_DIR" --with-jr
    RID="$(stage_activate_link 0.1.0)"
    MIG="$("$PY" - "$SBMON_RELEASES_DIR/$RID" <<'EOF'
import json, os, sqlite3, sys

release = os.path.realpath(sys.argv[1])
sys.path = [p for p in sys.path if p not in ("", ".", os.getcwd())]
sys.path.insert(0, os.path.join(release, "app", "monitor-v2"))
sys.path.insert(0, os.path.join(release, "libexec", "sbox-journal-reader"))

from journal_reader import ingest_contract as IC, schema as JR
from web import incident_history as ih

V1_DDL = """
CREATE TABLE meta ( key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta (key, value) VALUES ('schema_version','1'),
 ('created_at','2026-01-01T00:00:00+00:00'),('created_by_version','0.2.0');
CREATE TABLE timeline_samples ( epoch REAL NOT NULL, iso_utc TEXT NOT NULL,
 run_id TEXT NOT NULL, monitor_uptime_seconds REAL, snapshot_version INTEGER,
 snapshot_generated_at TEXT, last_success_at TEXT, collector_stale INTEGER NOT
 NULL, api_status TEXT, total_active_connections INTEGER NOT NULL,
 reality_active_connections INTEGER NOT NULL,
 hysteria2_active_connections INTEGER NOT NULL,
 other_active_connections INTEGER NOT NULL, uplink_rate REAL NOT NULL,
 downlink_rate REAL NOT NULL, skipped_events INTEGER NOT NULL,
 duplicate_events INTEGER NOT NULL, identity_conflicts INTEGER NOT NULL,
 abandoned_on_reset INTEGER NOT NULL);
CREATE INDEX idx_samples_epoch ON timeline_samples(epoch);
CREATE TABLE device_protocol_states ( epoch REAL NOT NULL,
 iso_utc TEXT NOT NULL, run_id TEXT NOT NULL, device TEXT NOT NULL,
 inbound TEXT NOT NULL, active_connections INTEGER NOT NULL,
 device_status TEXT, uplink_rate REAL NOT NULL, downlink_rate REAL NOT NULL,
 uplink_total REAL NOT NULL, downlink_total REAL NOT NULL, reason TEXT NOT
 NULL CHECK (reason IN ('change','heartbeat')));
CREATE INDEX idx_states_epoch ON device_protocol_states(epoch);
CREATE INDEX idx_states_device ON device_protocol_states(device, inbound,
 epoch);
"""

import tempfile
work = tempfile.mkdtemp()
diag = os.path.join(work, "diagnostics")
os.makedirs(diag)
db = os.path.join(diag, "history.sqlite3")
conn = sqlite3.connect(db)
conn.executescript(V1_DDL)
conn.execute("INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
             " collector_stale, total_active_connections,"
             " reality_active_connections, hysteria2_active_connections,"
             " other_active_connections, uplink_rate, downlink_rate,"
             " skipped_events, duplicate_events, identity_conflicts,"
             " abandoned_on_reset) VALUES (?, 'x', 'v1-run', 0, 3, 2, 1, 0,"
             " 1.5, 2.5, 0, 0, 0, 0)", (1700000000.0,))
conn.execute("INSERT INTO device_protocol_states (epoch, iso_utc, run_id,"
             " device, inbound, active_connections, device_status,"
             " uplink_rate, downlink_rate, uplink_total, downlink_total,"
             " reason) VALUES (?, 'x', 'v1-run', 'dev-a', 'vless-in', 2,"
             " 'ACTIVE', 1.0, 2.0, 3.0, 4.0, 'change')", (1700000000.0,))
conn.commit()
v1_sample = conn.execute("SELECT epoch, run_id, total_active_connections,"
                         " uplink_rate FROM timeline_samples").fetchall()
v1_state = conn.execute("SELECT epoch, device, inbound, active_connections,"
                        " reason FROM device_protocol_states").fetchall()
conn.close()

out = os.path.join(work, "out")
os.makedirs(out)
clock = [1700000100.0]
h = ih.IncidentHistory(diag, "int-run", clock=lambda: clock[0],
                       journal_exchange_dir=out)
result = {"contract_from": os.path.realpath(IC.__file__),
          "history_from": os.path.realpath(ih.__file__),
          "contract_available": bool(ih.JOURNAL_CONTRACT_AVAILABLE)}
# Provenance as a boolean (never as a path-string comparison): the loaded
# module must sit INSIDE this release tree, in the reader libexec and the
# Monitor app dir respectively. os.sep keeps the gate platform-honest.
_root = os.path.realpath(release) + os.sep
result["contract_from_release_libexec"] = result["contract_from"].startswith(
    _root + "libexec" + os.sep + "sbox-journal-reader" + os.sep)
result["history_from_release_app"] = result["history_from"].startswith(
    _root + "app" + os.sep + "monitor-v2" + os.sep)
h.open()
result["health_enabled"] = h.health()["enabled"]
result["health_degraded"] = h.health()["degraded"]
tables = sorted(r[0] for r in sqlite3.connect(db).execute(
    "SELECT name FROM sqlite_master WHERE type='table'"))
result["tables"] = tables
c2 = sqlite3.connect(db)
result["schema_version"] = dict(c2.execute("SELECT key, value FROM meta")).get("schema_version")
result["rows_preserved"] = (
    c2.execute("SELECT epoch, run_id, total_active_connections, uplink_rate"
               " FROM timeline_samples").fetchall() == [tuple(r) for r in v1_sample]
    and c2.execute("SELECT epoch, device, inbound, active_connections, reason"
                   " FROM device_protocol_states").fetchall() == [tuple(r) for r in v1_state])
c2.close()
result["journal_status_contract"] = h.journal_status()["contract_available"]

RUN = "0123456789abcdef0123456789abcdef"


def ev_path(seq, header=None, records=None, raw=None):
    if raw is not None:
        body = raw
    else:
        hdr = {"t": "h", "v": JR.FORMAT_VERSION, "cv": JR.CLASSIFIER_VERSION,
               "seq": seq, "run": RUN, "epoch": 1, "boundary": "NONE",
               "lines": 10, "eligible": 3, "info_dropped": 2,
               "nomatch_dropped": 5, "priority_unusable": 0, "pfail": 0,
               "limited": 0}
        hdr.update(header or {})
        recs = records if records is not None else [{"t": "e", "ts": 1700000000.0,
                                                    "cls": "dns", "proto": "OTHER",
                                                    "port": None, "dcls": None,
                                                    "fp": None, "n": 1}]
        lines = [json.dumps(hdr, sort_keys=True)]
        lines += [json.dumps(r, sort_keys=True) for r in recs]
        body = "\n".join(lines) + "\n"
    with open(os.path.join(out, "ev-%d.jsonl" % seq), "w", newline="\n") as fh:
        fh.write(body)


# -- terminal exactly-once ingest through the installed contract ------------
ev_path(1)
h.ingest_journal_events()
st1 = h.journal_status()
ev_path(1)                      # same file again: must settle NOTHING twice
h.ingest_journal_events()
st2 = h.journal_status()
result["ingest_terminal"] = st1["terminal_seq"]
result["ingest_idempotent"] = (st2["terminal_seq"] == st1["terminal_seq"])
c3 = sqlite3.connect(db)
result["event_rows"] = c3.execute("SELECT COUNT(*) FROM journal_events").fetchone()[0]
# a hostile file is rejected ONCE and never escapes as an exception (the
# shape + sanitized code are the frozen ones PR-2A settled on)
with open(os.path.join(out, "ev-2.jsonl"), "w", newline="\n") as fh:
    fh.write("not json at all\n")
try:
    h.ingest_journal_events()
    result["hostile_contained"] = True
except Exception as exc:
    result["hostile_contained"] = False
    result["hostile_exc"] = type(exc).__name__
result["terminal_after_hostile"] = h.journal_status()["terminal_seq"]
result["event_rows_after_hostile"] = c3.execute("SELECT COUNT(*) FROM journal_events").fetchone()[0]
_audit_row = c3.execute("SELECT code FROM journal_ingest_audit"
                        " WHERE seq = 2").fetchone()
result["hostile_code"] = _audit_row[0] if _audit_row else None
result["rejected_total"] = h.journal_status()["rejected_total"]
c3.close()
h.close()
print(json.dumps(result, sort_keys=True))
EOF
)"
    MIGRC=$?
    assert_eq "$MIGRC" "0" "migration: installed-release ingest script ran to completion"
    field() { printf '%s' "$MIG" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]))' "$1"; }
    assert_eq "$(field contract_available)" "True" "migration: the installed release's contract is what the migration used"
    assert_eq "$(field contract_from_release_libexec)" "True" "migration: contract module loaded from the release libexec ($(field contract_from))"
    assert_eq "$(field history_from_release_app)" "True" "migration: incident_history came from the release app tree ($(field history_from))"
    assert_eq "$(field health_enabled)" "True" "migration: v1 database opens healthy under v2 code"
    assert_eq "$(field health_degraded)" "False" "migration: no degraded flag after the forward migration"
    assert_eq "$(field schema_version)" "2" "migration: meta.schema_version advanced to 2"
    assert_eq "$(field rows_preserved)" "True" "migration: v1 rows preserved byte-for-byte"
    for t in journal_runs journal_events journal_ingest_audit journal_ingest_state \
             timeline_samples device_protocol_states meta; do
        printf '%s' "$MIG" | grep -q "\"$t\"" && pass "migration: v2 table $t exists in the migrated database" \
            || fail "migration: v2 table $t missing"
    done
    assert_eq "$(field journal_status_contract)" "True" "migration: journal_status() reports the contract inside the migrated runtime"
    assert_eq "$(field ingest_terminal)" "1" "migration: first ingest settles terminal_seq exactly once"
    assert_eq "$(field ingest_idempotent)" "True" "migration: re-ingesting the same file never double-settles"
    assert_eq "$(field event_rows)" "1" "migration: exactly one journal event row persisted"
    assert_eq "$(field hostile_contained)" "True" "migration: a hostile exchange file raises nothing through the release path"
    assert_eq "$(field terminal_after_hostile)" "2" "migration: the rejected file advances terminal exactly once"
    assert_eq "$(field event_rows_after_hostile)" "1" "migration: the rejected file persisted no rows"
    assert_eq "$(field hostile_code)" "exchange_bad_json" "migration: rejection is settled under the frozen sanitized code"
    assert_eq "$(field rejected_total)" "1" "migration: rejected_total counts the hostile file exactly once"
fi

# ===========================================================================
printf '\n== RESULT: %d passed, %d failed, %d skipped ==\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" != "0" ]; then
    exit 1
fi
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && [ "$SKIP" != "0" ]; then
    printf 'Linux runners must not skip ANY integration gate (spec §14: no false green)\n' >&2
    exit 1
fi
if [ "$SYMLINK_OK" = 0 ] && [ "$SKIP" = 0 ]; then
    printf 'sanity: symlink-less platform reported zero skips -- probe broken?\n' >&2
    exit 1
fi
exit 0
