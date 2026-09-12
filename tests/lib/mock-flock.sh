# Test-only flock(1) shim for platforms without util-linux flock (e.g. MSYS2
# on Windows). Real flock is used whenever present (Linux/CI), so this shim is
# dead code there; it exists so the lock fail-closed and concurrency
# regressions can also run on a dev laptop.
#
# Emulated contract: flock [-w SECONDS] FD -> rc 0 while the exclusive lock is
# held, non-zero when contended past the timeout. The lock key is $SB_LOCK_FILE
# (the harness's single lock file) via an atomic mkdir sidecar that records the
# owning pid, the locked fd, and the normalized lock-file path.
#
# Release semantics: the lock is considered held exactly while the owner still
# has the recorded fd open on the lock file, detected through /proc/<pid>/fd.
# When the recorded owner is the caller itself, the sidecar is treated as
# released (the installer and every harness scenario never nest lock scopes,
# so a same-pid sidecar is always the caller's own previous, closed scope).
# The shim is NEVER defined on platforms that ship real flock.
if ! command -v flock >/dev/null 2>&1; then
flock() {
    local wait_secs=0
    if [ "${1:-}" = "-w" ]; then
        wait_secs="${2:-0}"
        shift 2
    fi
    local fd="${1:?flock: fd argument required}"
    local dir="${SB_LOCK_FILE:?SB_LOCK_FILE must be set}.mocklock"
    local target
    target="$(readlink -f -- "$SB_LOCK_FILE" 2>/dev/null || printf '%s' "$SB_LOCK_FILE")"
    local deadline=$(( ${SECONDS:-0} + wait_secs ))
    local owner held held_target fd_target
    while :; do
        if mkdir "$dir" 2>/dev/null; then
            printf '%s\n%s\n%s\n' "$$" "$fd" "$target" > "$dir/owner"
            return 0
        fi
        owner=""; held=""; held_target=""
        { read -r owner; read -r held; read -r held_target; } < "$dir/owner" 2>/dev/null
        if [ "$owner" = "$$" ]; then
            # Our own previous scope: never nested, therefore already released.
            rm -rf -- "$dir"
            continue
        fi
        # Held only while the owner still has that fd open on the lock file.
        fd_target="$(readlink "/proc/$owner/fd/$held" 2>/dev/null || true)"
        if [ "$fd_target" != "$held_target" ]; then
            rm -rf -- "$dir"   # owner exited or closed the fd: stale sidecar
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
