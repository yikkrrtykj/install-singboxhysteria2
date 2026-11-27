#!/usr/bin/env bash
# Isolated Linux systemd/D-Bus lab for UM-B3. Runs only on a disposable CI
# runner or disposable VM. It builds the real agent/center from this checkout,
# uses a synthetic loopback center and a synthetic sing-box unit, and performs
# install/start/stop/restart/D-Bus/no-exec/state checks.
#
# Required env: RUNNER_TEMP (or LAB_TMP) and a sudo-capable runner.
set -euxo pipefail

ROOT="${LAB_TMP:-${RUNNER_TEMP:-/tmp}/um-b3-linux-lab}"
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
EVENT="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
INGEST="127.0.0.1:18080"
ADMIN="127.0.0.1:18081"
DB="$ROOT/center.db"
TOKEN="$ROOT/token"
CENTER_LOG="$ROOT/center.log"

cleanup() {
  set +e
  sudo systemctl disable --now um-agent.service >/dev/null 2>&1
  sudo systemctl stop sing-box.service >/dev/null 2>&1
  sudo systemctl disable sing-box.service >/dev/null 2>&1
  sudo rm -f /etc/systemd/system/um-agent.service /etc/systemd/system/sing-box.service
  sudo rm -rf /etc/systemd/system/um-agent.service.d
  sudo systemctl daemon-reload >/dev/null 2>&1
  sudo userdel umagent >/dev/null 2>&1
  sudo rm -rf /var/lib/um-agent /etc/um-agent /usr/local/libexec/um-agent /usr/local/share/doc/um-agent /usr/local/libexec/sing-box
  [ -n "${CENTER_PID:-}" ] && kill "$CENTER_PID" >/dev/null 2>&1
  rm -rf "$ROOT"
}
trap cleanup EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"
cd "$REPO/um"
go build -trimpath -o "$ROOT/um-agent" ./cmd/um-agent
go build -trimpath -o "$ROOT/um-center" ./cmd/um-center
go build -trimpath -o "$ROOT/um-lab" ./cmd/um-lab
AGENT_SHA="$(sha256sum "$ROOT/um-agent" | awk '{print $1}')"

# A synthetic service is enough for the real read-only systemd D-Bus read.
sudo install -d -m 0755 /usr/local/libexec
sudo install -m 0755 /bin/sleep /usr/local/libexec/sing-box
sudo tee /etc/systemd/system/sing-box.service >/dev/null <<'UNIT'
[Unit]
Description=synthetic sing-box D-Bus lab unit
[Service]
ExecStart=/usr/local/libexec/sing-box 3600
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now sing-box.service

# Real center + real SQLite; issue a one-time token using the center binary.
"$ROOT/um-center" -contracts "$REPO/docs/um/contracts/v1" -db "$DB" \
  -issue-enroll-token -token-event "$EVENT" -token-class linux_vps > "$TOKEN"
"$ROOT/um-center" -contracts "$REPO/docs/um/contracts/v1" -db "$DB" \
  -ingest "$INGEST" -admin "$ADMIN" >"$CENTER_LOG" 2>&1 &
CENTER_PID=$!
for _ in $(seq 1 50); do
  if curl -fsS "http://$ADMIN/api/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "http://$ADMIN/api/health" >/dev/null

sudo mkdir -p /etc/um-agent
sudo install -m 0400 -o root -g root "$TOKEN" /etc/um-agent/bootstrap.token
sudo bash "$REPO/um/deploy/linux/install-agent.sh" \
  --apply --binary "$ROOT/um-agent" --sha256 "$AGENT_SHA" \
  --center "http://$INGEST" --token-file /etc/um-agent/bootstrap.token \
  --start-service

# The frozen installer verifies the unit and starts it. Collect the identity
# node id from the durable state (root-read only) and configure sources.
NODE_ID="$(sudo python3 - "$EVENT" <<'PY'
import json,sys
# identity.json holds the node id; it contains a private key, so read only the
# one field and never print the file.
with open('/var/lib/um-agent/identity.json') as f:
    print(json.load(f)['node_id'])
PY
)"
"$ROOT/um-lab" configure --db "$DB" --node-id "$NODE_ID" \
  --sources services=true,system=true,events=true --cadence 30
sudo systemctl restart um-agent.service
sleep 2

MAINPID="$(systemctl show -p MainPID --value um-agent.service)"
if [ -z "$MAINPID" ] || [ "$MAINPID" = "0" ]; then
  sudo systemctl --no-pager --full status um-agent.service || true
  sudo journalctl -u um-agent.service --no-pager -n 80 || true
  sudo systemctl show -p Result,ExecMainStatus,NRestarts um-agent.service || true
  echo "um-agent service did not stay running after config+restart" >&2
  exit 1
fi
[ "$(ps -o user= -p "$MAINPID" | tr -d ' ')" = "umagent" ]
[ "$(systemctl show -p StateDirectory --value um-agent.service)" = "um-agent" ]
[ "$(stat -c '%a %U' /var/lib/um-agent)" = "700 umagent" ]
[ -n "$(systemctl show -p NoExecPaths --value um-agent.service)" ]
command -v ss >/dev/null
if ss -ltnp | grep -q 'um-agent'; then
  echo "um-agent unexpectedly has a listening TCP socket" >&2
  exit 1
fi

# Real D-Bus read must appear in a persisted snapshot as active; the synthetic
# unit is active. Poll the center's last snapshot payload.
FOUND=0
for _ in $(seq 1 30); do
  SUMMARY="$("$ROOT/um-lab" summary --db "$DB" --node-id "$NODE_ID" --print-payload)"
  if printf '%s' "$SUMMARY" | python3 -c '
import json,sys
d=json.load(sys.stdin)
p=d.get("latest_snapshot",{}).get("payload")
if not p: sys.exit(1)
body=json.loads(p)
services=body.get("services") or []
if len(services)==1 and services[0].get("name")=="sing-box" and services[0].get("state")=="active":
    sys.exit(0)
sys.exit(1)
'; then
    FOUND=1
    break
  fi
  sleep 1
done
if [ "$FOUND" -ne 1 ]; then
  printf '%s\n' "$SUMMARY" | tail -c 4000 >&2
  echo "D-Bus service state was not persisted as active" >&2
  exit 1
fi

# Restart preserves identity/state and advances generation (restart semantics).
GEN_BEFORE="$(sudo python3 - <<'PY'
import json
print(json.load(open('/var/lib/um-agent/boot_state.json'))['generation'])
PY
)"
sudo systemctl restart um-agent.service
sleep 2
GEN_AFTER="$(sudo python3 - <<'PY'
import json
print(json.load(open('/var/lib/um-agent/boot_state.json'))['generation'])
PY
)"
[ "$GEN_AFTER" -gt "$GEN_BEFORE" ]
[ -f /var/lib/um-agent/identity.json ]

# Stop/start and verify the service remains non-root and readable.
sudo systemctl stop um-agent.service
sudo systemctl start um-agent.service
sleep 2
[ "$(systemctl show -p MainPID --value um-agent.service)" != "0" ]

sudo systemctl disable --now um-agent.service
sudo rm -f /etc/systemd/system/um-agent.service
sudo rm -rf /etc/systemd/system/um-agent.service.d
sudo systemctl daemon-reload
sudo rm -rf /var/lib/um-agent /etc/um-agent
sudo userdel umagent
sudo systemctl disable --now sing-box.service
sudo rm -f /etc/systemd/system/sing-box.service
sudo rm -f /usr/local/libexec/sing-box
sudo systemctl daemon-reload
kill "$CENTER_PID" >/dev/null 2>&1 || true
echo "linux-systemd-lab: PASS (event $EVENT, node $NODE_ID)"
