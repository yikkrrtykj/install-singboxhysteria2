#!/usr/bin/env bash
# Static checks and analyzer self-test for the Phase A probe tool.
#
# Nothing here touches /root/sbox-probe, /root/sbox or sing-box itself: the
# analyzer is exercised against generated synthetic fixtures in a temp dir, and
# the guardrail lint below asserts the shipped scripts contain no destructive
# pattern. Runtime verdicts are deliberately NOT produced here.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$(cd -- "$HERE/.." && pwd)"
ANALYZE="$TOOL_DIR/lib/analyze.py"
GEN="$HERE/fixtures/make-synthetic.py"
PY="${PYTHON:-python3}"

PASS=0
FAIL=0
SKIP=0
TMP="$(mktemp -d)"
export PYTHONPYCACHEPREFIX="$TMP/pycache"
cleanup_tmp() {
  rm -rf -- "$TMP"
  find "$TOOL_DIR" -name '__pycache__' -type d -prune -exec rm -rf -- {} + 2>/dev/null || true
}
trap cleanup_tmp EXIT

pass() { PASS=$((PASS + 1)); printf '  %sPASS%s %s\n' "${C_GREEN:-}" "${C_OFF:-}" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  %sFAIL%s %s\n' "${C_RED:-}" "${C_OFF:-}" "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  %sSKIP%s %s\n' "${C_YELLOW:-}" "${C_OFF:-}" "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
expect_grep() { # expect_grep <file> <ere> <label>
  if grep -qE "$2" "$1"; then pass "$3"; else fail "$3 (no match: $2 in $(basename "$1"))"; fi
}
expect_no_grep() {
  if grep -qE "$2" "$1"; then fail "$3 (unexpected match: $2)"; else pass "$3"; fi
}

section "shell syntax"
while IFS= read -r f; do
  if bash -n "$f" 2>"$TMP/syntax.err"; then pass "bash -n $(basename "$f")"
  else fail "bash -n $(basename "$f"): $(cat "$TMP/syntax.err")"; fi
done < <(find "$TOOL_DIR" -name '*.sh' -type f | sort)

section "python syntax"
while IFS= read -r f; do
  if "$PY" -m py_compile "$f" 2>"$TMP/py.err"; then pass "py_compile $(basename "$f")"
  else fail "py_compile $(basename "$f"): $(cat "$TMP/py.err")"; fi
done < <(find "$TOOL_DIR" -name '*.py' -type f | sort)

section "guardrail lint (shipped scripts must not touch production)"
LINT_PATTERNS=(
  '\b(pkill|killall)\b'
  'systemctl[[:space:]]+(stop|restart|start|disable|enable)[[:space:]]+.*sing-box'
  '\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b'
  'rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*[[:space:]]+.*/root/sbox([^-a-z]|$)'
  'sed[[:space:]]+-i'
  '>[[:space:]]*"?\$?PROD_'
)
while IFS= read -r f; do
  clean=1
  for pattern in "${LINT_PATTERNS[@]}"; do
    if grep -nE "$pattern" "$f" >"$TMP/lint.out"; then
      clean=0
      fail "guardrail $(basename "$f"): $(head -n1 "$TMP/lint.out")"
    fi
  done
  [ "$clean" -eq 1 ] && pass "guardrail $(basename "$f")"
done < <(find "$TOOL_DIR" -name '*.sh' -type f -not -path '*/tests/*' | sort)

section "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  while IFS= read -r f; do
    if shellcheck -S warning "$f" >"$TMP/sc.out" 2>&1; then pass "shellcheck $(basename "$f")"
    else fail "shellcheck $(basename "$f"): $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"; fi
  done < <(find "$TOOL_DIR" -name '*.sh' -type f | sort)
else
  skip "shellcheck 未安装（本轮以 bash -n + guardrail lint 替代）"
fi

section "analyzer: empty evidence dir must say NOT TESTED"
mkdir -p "$TMP/ev-empty"
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-empty" >"$TMP/empty.txt" 2>&1
expect_grep "$TMP/ev-empty/SUMMARY.txt" 'NOT TESTED / WAITING FOR RUNTIME DATA' "empty dir -> NOT TESTED marker"
expect_no_grep "$TMP/ev-empty/SUMMARY.txt" 'YES - ' "empty dir -> no invented YES"
expect_no_grep "$TMP/ev-empty/SUMMARY.txt" 'VERIFIED' "empty dir -> no invented VERIFIED"

section "analyzer: synthetic fixtures are ignored without --fixture-mode"
"$PY" "$GEN" --out "$TMP/ev-nomode" >/dev/null
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-nomode" >"$TMP/nomode.txt" 2>&1
expect_grep "$TMP/ev-nomode/SUMMARY.txt" 'NOT TESTED / WAITING FOR RUNTIME DATA' "fixtures without flag -> NOT TESTED marker"
expect_no_grep "$TMP/ev-nomode/SUMMARY.txt" 'YES - ' "fixtures without flag -> no verdict from synthetic data"

section "analyzer: derivation math on synthetic fixtures (--fixture-mode)"
"$PY" "$GEN" --out "$TMP/ev-ok" --variant consistent >/dev/null
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-ok" --fixture-mode \
  --md-out "$TMP/ev-ok/report.md" --json-out "$TMP/ev-ok/analysis.json" >"$TMP/ok.txt" 2>&1
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.user_field +VERIFIED +YES' "reality user field -> YES when field carries the names"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^hy2\.user_field +NO +NO -' "hy2 user field -> NO when no field carries the names"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^reality\.source_ip +VERIFIED' "reality source ip -> VERIFIED with a public address"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^hy2\.source_ip +PARTIAL' "hy2 source ip -> PARTIAL when only loopback was seen"
expect_grep "$TMP/ev-ok/SUMMARY.txt" '^probe\.production_untouched +VERIFIED' "production baseline -> unchanged"
expect_no_grep "$TMP/ev-ok/SUMMARY.txt" 'INCONCLUSIVE' "no item degraded to INCONCLUSIVE"
expect_grep "$TMP/ev-ok/report.md" '字段命名与客户端视角一致' "consistent variant -> naming matches client view"
expect_grep "$TMP/ev-ok/report.md" '语义=客户端下行' "download test -> counter mapped to client downstream"
expect_grep "$TMP/ev-ok/report.md" '语义=客户端上行' "upload test -> counter mapped to client upstream"
expect_grep "$TMP/ev-ok/report.md" 'SYNTHETIC FIXTURE OUTPUT' "fixture mode -> report is banner-marked synthetic"

section "analyzer: inverted counter naming must be detected, not hard-coded"
"$PY" "$GEN" --out "$TMP/ev-inv" --variant inverted >/dev/null
"$PY" "$ANALYZE" analyze --evidence-dir "$TMP/ev-inv" --fixture-mode \
  --md-out "$TMP/ev-inv/report.md" >"$TMP/inv.txt" 2>&1
expect_grep "$TMP/ev-inv/report.md" '字段命名与客户端视角相反' "inverted variant -> naming flagged as opposite"
expect_grep "$TMP/ev-inv/report.md" '语义=客户端下行' "inverted variant -> direction still derived from traffic"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
