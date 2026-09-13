import io

p = "tests/test-monitor-packaging.sh"
s = io.open(p, encoding="utf-8", newline="").read()
old = '''    ( SBMON_KEEP_RELEASES=2 source "$REPO_ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"; sbmon_prune_releases ) > "$TMP/out-r413d.log" 2>&1 \\'''
new = '''    ( export SBMON_KEEP_RELEASES=2; source "$REPO_ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"; sbmon_prune_releases ) > "$TMP/out-r413d.log" 2>&1 \\'''
assert old in s, "keep export"
s = s.replace(old, new, 1)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("fixed OK")
