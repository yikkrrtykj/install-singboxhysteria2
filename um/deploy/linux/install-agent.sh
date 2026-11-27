#!/usr/bin/env bash
# UM-B3 Draft one-shot Linux installer template for the `linux_vps` agent.
#
# THIS FILE IS A REVIEWED TEMPLATE ONLY. It was not executed by the UM-B3
# documentation/delivery work and it does not install, enable or start anything
# by itself:
#   * dry-run is the default; --apply is required to make any change;
#   * the service is NOT enabled or started unless --start-service is given;
#   * it never creates a real credential, never contacts the center itself and
#     never modifies sing-box/Monitor/sbox-cm/HA-UI files, units or permissions.
#
# Contract: docs/um/um-a/04-node-protocol-v1.md §11 (non-root runtime user,
# /var/lib/um-agent 0700, root-only bootstrap token fed over a pipe to
# `um-agent enroll --token-stdin`, token deleted by root after success, no
# resident root process, no exec/root runtime).
#
# Planned CLI (subject to the B3 code slice): `um-agent enroll|run|rotate|status`
# with --state-dir/--center/--node-class (and --token-stdin for the frozen
# enrollment pipe). If the final CLI differs at review time, adjust this script
# and the systemd EnvironmentFile together; the reviewed contract command
# `enroll --token-stdin` must remain the token path.
#
# Usage:
#   ./install-agent.sh --binary ./um-agent --center https://ingest.example.xyz
#   sudo ./install-agent.sh --apply --binary ./um-agent --sha256 <hex> \
#        --center https://ingest.example.xyz --token-file /etc/um-agent/bootstrap.token
#
set -euo pipefail

PROG="$(basename "$0")"
APPLY=0
START_SERVICE=0
UPGRADE=0
BINARY=""
SHA256_EXPECTED=""
CENTER_URL=""
TOKEN_FILE=""
AGENT_USER="umagent"
AGENT_GROUP="umagent"
STATE_DIR="/var/lib/um-agent"
ETC_DIR="/etc/um-agent"
LIBDIR="/usr/local/libexec"
BINARY_PATH="$LIBDIR/um-agent"
UNIT_PATH="/etc/systemd/system/um-agent.service"
DROPIN_DIR="/etc/systemd/system/um-agent.service.d"
DROPIN_PATH="$DROPIN_DIR/10-noexec.conf"
ENV_FILE="$ETC_DIR/agent.env"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '[install-agent] %s\n' "$*"; }
warn() { printf '[install-agent] WARNING: %s\n' "$*" >&2; }
die()  { printf '[install-agent] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
UM-B3 Draft Linux agent installer (default: dry-run)

Options:
  --apply                 Make changes (without it nothing is written)
  --binary PATH           Reviewed static um-agent binary to install (required)
  --sha256 HEX            Expected SHA-256 of the binary (recommended)
  --center URL            Center ingest base URL (https; loopback http only in tests)
  --token-file PATH       Root-owned 0600 one-time bootstrap token; if given,
                          enrollment runs as the unprivileged user over stdin
                          and the token file is deleted on success
  --start-service         After install/enroll, enable+start um-agent.service
                          (requires --apply; off by default)
  --upgrade               Replace an existing unit/binary (service is stopped
                          first and left stopped unless --start-service)
  -h, --help              Show this help

Environment overrides: UM_AGENT_USER, UM_AGENT_STATE_DIR, UM_AGENT_ETC_DIR.

Safety boundaries:
  * never touches sing-box/Monitor/sbox-cm/HA-UI units, files or permissions;
  * never creates credentials, never prints secrets, never starts a resident
    root process;
  * does not enable/start the agent unless --start-service is explicit.
EOF
}

need_root() { [ "$(id -u)" -eq 0 ] || die "--apply requires root (run with sudo); dry-run is available as a normal user"; }

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl not found"
  [ -d /run/systemd/system ] || die "systemd is not the running init system"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --start-service) START_SERVICE=1 ;;
    --upgrade) UPGRADE=1 ;;
    --binary) shift; BINARY="${1:-}" ;;
    --sha256) shift; SHA256_EXPECTED="${1:-}" ;;
    --center) shift; CENTER_URL="${1:-}" ;;
    --token-file) shift; TOKEN_FILE="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[ -n "$BINARY" ] || die "--binary is required"
[ -f "$BINARY" ] || die "binary not found: $BINARY"
[ -x "$BINARY" ] || die "binary is not executable: $BINARY"
[ -n "$CENTER_URL" ] || die "--center is required (planned shape: https://ingest.<domain>)"

AGENT_USER="${UM_AGENT_USER:-$AGENT_USER}"
AGENT_GROUP="${UM_AGENT_GROUP:-$AGENT_GROUP}"
STATE_DIR="${UM_AGENT_STATE_DIR:-$STATE_DIR}"
ETC_DIR="${UM_AGENT_ETC_DIR:-$ETC_DIR}"
BINARY_PATH="$LIBDIR/um-agent"
ENV_FILE="$ETC_DIR/agent.env"

case "$CENTER_URL" in
  https://*) : ;;
  http://127.0.0.1:*) : ;; # test-only literal loopback IP, never production
  *) die "--center must be https:// (plain HTTP is allowed only for loopback tests)" ;;
esac

if [ -n "$SHA256_EXPECTED" ]; then
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
  ACTUAL="$(sha256sum "$BINARY" | awk '{print $1}')"
  printf '%s' "$SHA256_EXPECTED" | grep -Eq '^[0-9a-fA-F]{64}$' || die "--sha256 must be 64 hex characters"
  [ "$(printf '%s' "$SHA256_EXPECTED" | tr 'A-F' 'a-f')" = "$ACTUAL" ] || die "binary SHA-256 mismatch: expected $SHA256_EXPECTED, got $ACTUAL"
  log "binary SHA-256 verified: $ACTUAL"
else
  warn "no --sha256 given; verify the build receipt manually before applying"
fi

if [ "$APPLY" -eq 1 ]; then
  need_root
  require_systemd
  [ -d "$SCRIPT_DIR" ] || die "cannot locate installer assets directory"
  [ -f "$SCRIPT_DIR/um-agent.service" ] || die "missing $SCRIPT_DIR/um-agent.service"
  [ -f "$SCRIPT_DIR/um-agent-noexec.conf" ] || die "missing $SCRIPT_DIR/um-agent-noexec.conf"
fi

plan() { log "PLAN  $*"; }
act() {
  if [ "$APPLY" -eq 1 ]; then
    log "APPLY $*"
    "$@"
  else
    log "DRY   $*"
  fi
}

# Detect systemd major version (NoExecPaths/ExecPaths require >= 248).
SYSTEMD_MAJOR=0
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_MAJOR="$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}' | tr -dc '0-9' || true)"
  SYSTEMD_MAJOR="${SYSTEMD_MAJOR:-0}"
fi
log "target: user=$AGENT_USER group=$AGENT_GROUP state=$STATE_DIR center=$CENTER_URL"
log "systemd major detected: $SYSTEMD_MAJOR (noexec drop-in installed only on >=248)"

if [ -e "$UNIT_PATH" ] && [ "$UPGRADE" -eq 0 ]; then
  die "$UNIT_PATH already exists; rerun with --upgrade only after reviewing the change"
fi
if [ -e "$BINARY_PATH" ] && [ "$UPGRADE" -eq 0 ]; then
  die "$BINARY_PATH already exists; rerun with --upgrade only after reviewing the change"
fi

# ---------------------------------------------------------------------------
# 1. Preconditions / plan summary (no changes yet)
# ---------------------------------------------------------------------------
if [ -n "$TOKEN_FILE" ]; then
  [ -f "$TOKEN_FILE" ] || die "token file not found: $TOKEN_FILE"
  [ -L "$TOKEN_FILE" ] && die "token file must not be a symlink"
  TOKEN_META="$(stat -c '%U %a' "$TOKEN_FILE")"
  TOKEN_OWNER="${TOKEN_META%% *}"
  TOKEN_MODE="${TOKEN_META##* }"
  [ "$TOKEN_OWNER" = "root" ] || die "token file must be owned by root (got $TOKEN_OWNER)"
  case "$TOKEN_MODE" in 600|400) : ;; *) die "token file must be mode 0600/0400 (got $TOKEN_MODE)";; esac
  log "token file preconditions OK (root-owned, mode $TOKEN_MODE, content never printed)"
fi

if [ "$APPLY" -eq 0 ]; then
  log "dry-run mode: no user, directory, unit, environment file, binary or token will be changed and no service will be started"
fi

# Stop a running service before replacing its binary/unit (upgrade only).
if [ "$APPLY" -eq 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet um-agent.service 2>/dev/null; then
  log "stopping the running um-agent.service before replacing its binary/unit"
  systemctl stop um-agent.service
fi

# ---------------------------------------------------------------------------
# 2. Runtime user, directories, environment file, binary, unit, drop-in
# ---------------------------------------------------------------------------
if id "$AGENT_USER" >/dev/null 2>&1; then
  plan "reuse existing user $AGENT_USER (verify it is non-login/non-root manually)"
else
  act useradd --system --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --comment "UM agent runtime" \
      --user-group "$AGENT_USER"
fi

act install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_GROUP" "$STATE_DIR"
act install -d -m 0700 -o root -g root "$ETC_DIR"
act install -d -m 0755 -o root -g root "$LIBDIR"

ENV_CONTENT="# UM-B3 Draft environment (no secrets; token is never stored here)
UM_AGENT_STATE_DIR=$STATE_DIR
UM_AGENT_NODE_CLASS=linux_vps
UM_AGENT_CENTER_URL=$CENTER_URL
"
if [ "$APPLY" -eq 1 ]; then
  TMP_ENV="$(mktemp)"
  printf '%s' "$ENV_CONTENT" > "$TMP_ENV"
  install -m 0640 -o root -g root "$TMP_ENV" "$ENV_FILE"
  rm -f "$TMP_ENV"
else
  log "DRY   write $ENV_FILE (0640 root:root; center URL only, no secrets)"
fi

# Atomic binary replacement; the reviewed build receipt SHA-256 was verified above.
act install -m 0755 -o root -g root "$BINARY" "$BINARY_PATH"

act install -m 0644 -o root -g root "$SCRIPT_DIR/um-agent.service" "$UNIT_PATH"

# Optional operator documentation copy (the unit Documentation= points here).
RUNBOOK_SRC="$SCRIPT_DIR/../../docs/um-b3-runbook.md"
DOC_DIR="/usr/local/share/doc/um-agent"
if [ -f "$RUNBOOK_SRC" ]; then
  act install -d -m 0755 -o root -g root "$DOC_DIR"
  act install -m 0644 -o root -g root "$RUNBOOK_SRC" "$DOC_DIR/um-b3-runbook.md"
else
  warn "runbook source not found next to this checkout ($RUNBOOK_SRC); unit Documentation= will be a dangling local path"
fi

# ExecPaths=/NoExecPaths= were introduced in systemd 248 (official NEWS).
# Install the noexec drop-in only where the running systemd supports it.
if [ "$SYSTEMD_MAJOR" -ge 248 ] 2>/dev/null; then
  act install -d -m 0755 -o root -g root "$DROPIN_DIR"
  act install -m 0644 -o root -g root "$SCRIPT_DIR/um-agent-noexec.conf" "$DROPIN_PATH"
else
  warn "systemd $SYSTEMD_MAJOR does not support NoExecPaths=/; noexec drop-in is NOT installed (record the gap in the B3/UM-E acceptance notes)"
fi

act systemctl daemon-reload
if command -v systemd-analyze >/dev/null 2>&1; then
  if [ "$APPLY" -eq 1 ]; then
    if systemd-analyze verify "$UNIT_PATH" >/dev/null 2>&1; then
      log "systemd-analyze verify: OK"
    else
      systemd-analyze verify "$UNIT_PATH" 2>&1 | sed 's/^/[systemd-analyze] /' >&2 || true
      die "systemd-analyze verify failed; the unit is not installed as a working service"
    fi
  else
    log "DRY   systemd-analyze verify $UNIT_PATH"
  fi
fi

# ---------------------------------------------------------------------------
# 3. One-time enrollment as the unprivileged user over a root-opened stdin pipe
# ---------------------------------------------------------------------------
if [ -n "$TOKEN_FILE" ]; then
  command -v runuser >/dev/null 2>&1 || die "runuser (util-linux) is required for the P1-03 token pipe"
  plan "enroll as $AGENT_USER with token on stdin from root-owned $TOKEN_FILE"
  if [ "$APPLY" -eq 1 ]; then
    log "running one-time enrollment (token content is never echoed)"
    if runuser -u "$AGENT_USER" -- "$BINARY_PATH" enroll \
         --state-dir "$STATE_DIR" --center "$CENTER_URL" \
         --node-class linux_vps --token-stdin < "$TOKEN_FILE"; then
      log "enrollment succeeded; deleting the root-owned token file"
      shred -u "$TOKEN_FILE" 2>/dev/null || rm -f "$TOKEN_FILE"
    else
      warn "enrollment failed; the token file was left in place (root:root 0600) for operator retry"
      exit 1
    fi
  fi
else
  log "no --token-file given: enrollment remains an explicit operator step (see runbook)"
fi

# ---------------------------------------------------------------------------
# 4. Start only when explicitly requested
# ---------------------------------------------------------------------------
if [ "$START_SERVICE" -eq 1 ]; then
  act systemctl enable --now um-agent.service
  if [ "$APPLY" -eq 1 ]; then
    systemctl --no-pager --full status um-agent.service || true
  fi
else
  log "service installed but NOT enabled/started; next steps:"
  log "  sudo systemctl enable --now um-agent.service   # after enrollment is confirmed"
  log "  journalctl -u um-agent.service -f              # closed error codes only, no secrets"
fi

log "done (apply=$APPLY start=$START_SERVICE); review um/docs/um-b3-runbook.md for verification, upgrade, uninstall and recovery"
