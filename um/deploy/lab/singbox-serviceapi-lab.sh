#!/usr/bin/env bash
# Reproducible isolated sing-box 1.14.5 service.api lab. Downloads the official
# Linux amd64 release, starts a synthetic loopback mixed inbound + API service,
# opens a real connection, and runs the opt-in Go lab test. No production
# config, credential or network target is used.
set -euo pipefail

ROOT="${LAB_TMP:-${RUNNER_TEMP:-/tmp}/um-b3-singbox-lab}"
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERSION="${SINGBOX_VERSION:-1.14.5}"
ARCHIVE="sing-box-${VERSION}-linux-amd64.tar.gz"
URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${ARCHIVE}"
BIN="$ROOT/sing-box"
SECRET="synthetic-serviceapi-lab-secret"

cleanup() {
  set +e
  [ -n "${SINGBOX_PID:-}" ] && kill "$SINGBOX_PID" >/dev/null 2>&1
  rm -rf "$ROOT"
}
trap cleanup EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"
curl -4 -fsSL "$URL" -o "$ROOT/$ARCHIVE"
tar -xzf "$ROOT/$ARCHIVE" -C "$ROOT"
BIN="$(find "$ROOT" -type f -name sing-box | head -n 1)"
[ -x "$BIN" ] || { echo "sing-box binary not found" >&2; exit 1; }
"$BIN" version

cat >"$ROOT/config.json" <<JSON
{
  "log": {"level": "error"},
  "inbounds": [
    {"type": "mixed", "tag": "test-in", "listen": "127.0.0.1", "listen_port": 19092}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "services": [
    {"type": "api", "tag": "monitor-api", "listen": "127.0.0.1",
     "listen_port": 19091, "secret": "$SECRET"}
  ]
}
JSON
"$BIN" run -c "$ROOT/config.json" >"$ROOT/singbox.log" 2>&1 &
SINGBOX_PID=$!
for _ in $(seq 1 80); do
  if (exec 3<>/dev/tcp/127.0.0.1/19091) 2>/dev/null; then exec 3>&-; break; fi
  sleep 0.2
done
(exec 3<>/dev/tcp/127.0.0.1/19091) 2>/dev/null || { cat "$ROOT/singbox.log" >&2; exit 1; }

cd "$REPO/um"
UM_SINGBOX_SERVICEAPI_LAB=1 \
UM_SINGBOX_SERVICEAPI_URL="http://127.0.0.1:19091" \
UM_SINGBOX_SERVICEAPI_SECRET="$SECRET" \
UM_SINGBOX_SERVICEAPI_MIXED="127.0.0.1:19092" \
go test ./internal/linuxobs -run TestServiceAPIOptInLab -count=1 -v

echo "singbox-serviceapi-lab: PASS (version $VERSION; real connection stream; traffic totals stay unavailable in the frozen schema)"
