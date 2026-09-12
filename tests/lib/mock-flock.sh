# Test-only flock(1) shim for platforms without util-linux flock (e.g. MSYS2
# on Windows). Real flock is used whenever present (Linux/CI), so this shim is
# dead code there; it exists so the lock fail-closed and concurrency
# regressions can also run on a dev laptop.
#
# Emulated contract: flock [-w SECONDS] FD -> rc 0 while the exclusive lock is
# held, non-zero when contended past the timeout. The lock key is $SB_LOCK_FILE
# (the harness's single lock file).
#
# Atomicity: the claim is a single `mv -T` RENAME of a fully-populated staging
# directory (owner pid + fd pre-written inside) onto the well-known lock
# directory path. A contender therefore always sees the lock directory either
# absent or COMPLETE -- an earlier variant that wrote an owner file after
# mkdir had a read window that let two processes hold the lock at once, and a
# unique-per-pid mkdir variant never excluded anyone at all.
#
# Release semantics: a contender treats the lock as HELD only while its owner
# still has the recorded fd open on the lock file, detected through
# /proc/<pid>/fd. An owner file naming the caller's own pid is always the
# caller's previous, already-released scope (the installer and every harness
# scenario never nest lock scopes). Stale locks are removed by the next
# contender. The shim is NEVER defined on platforms that ship real flock.
if ! command -v flock >/dev/null 2>&1; then
flock() {
    local wait_secs=0
    if [ "${1:-}" = "-w" ]; then
        wait_secs="${2:-0}"
        shift 2
    fi
    local fd="${1:?flock: fd argument required}"
    local lock="${SB_LOCK_FILE:?SB_LOCK_FILE must be set}.mocklock"
    local staging="${lock}.incoming.$$"
    local lock_target
    lock_target="$(readlink -f -- "$SB_LOCK_FILE" 2>/dev/null || printf '%s' "$SB_LOCK_FILE")"
    local deadline=$(( ${SECONDS:-0} + wait_secs ))
    local owner owner_fd owner_pid fd_target
    while :; do
        rm -rf -- "$staging"
        if mkdir "$staging" 2>/dev/null &&
           printf '%s\n%s\n' "$$" "$fd" > "$staging/owner" &&
           mv -T "$staging" "$lock" 2>/dev/null; then
            return 0
        fi
        # Claim failed: the lock directory exists (or vanished again) -- judge
        # its owner, then either wait, clear a stale lock, or retry.
        rm -rf -- "$staging"
        owner=""; owner_fd=""
        { read -r owner; read -r owner_fd; } < "$lock/owner" 2>/dev/null
        if [ -z "$owner" ]; then
            continue    # lock vanished between mv failure and read: retry claim
        fi
        if [ "$owner" = "$$" ]; then
            rm -rf -- "$lock"    # our own previous scope: never nested, released
            continue
        fi
        fd_target="$(readlink "/proc/$owner/fd/$owner_fd" 2>/dev/null || true)"
        if [ "$fd_target" != "$lock_target" ]; then
            rm -rf -- "$lock"    # owner exited or closed the fd: stale lock
            continue
        fi
        if [ "${SECONDS:-0}" -ge "$deadline" ]; then
            return 1
        fi
        command sleep 0.1
    done
}
export -f flock
fi
