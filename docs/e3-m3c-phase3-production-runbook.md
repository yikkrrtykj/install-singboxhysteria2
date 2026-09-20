# E3 M3-C Phase 3 — Production Go-Live Enablement Runbook

Phase 3 performs one persistent `management.activate` after a separately
approved preflight. It does not add or delete clients, edit the sing-box
configuration, restart/reload sing-box, or implement a second RPC path.

```text
Phase 1 = COMPLETE (deploy-disabled)
Phase 2 = COMPLETE (one canary, ended inactive)
Phase 3 = NOT EXECUTED until a separate production approval
```

This document is an operator checklist, not execution authorization. The
operator connects to production personally, enters an interactive root shell,
and runs one command at a time. Do **not** use `set -e`: capture and inspect
every result before continuing.

## 1. Frozen inputs

After the Phase 3 PR is reviewed and merged, replace the placeholder with the
exact main merge SHA. Never approve an arbitrary descendant or the PR feature
HEAD. Phase 3 uses one new, uniquely named, detached checkout; it never reuses
the Phase 1/2 checkout or any mutable production source tree.

```bash
sudo -i

export APPROVED='<reviewed Phase 3 main merge SHA>'
[[ "$APPROVED" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'STOP: APPROVED must be the exact 40-hex Phase 3 main merge SHA' >&2
  exit 1
}
export SRC="/root/e3-m3c-phase3-${APPROVED:0:8}"

test ! -e "$SRC" || {
  echo "STOP: Phase 3 checkout already exists: $SRC" >&2
  exit 1
}

git clone https://github.com/yikkrrtykj/install-singboxhysteria2.git "$SRC" || exit 1
git -C "$SRC" checkout --detach "$APPROVED" || exit 1

test "$(git -C "$SRC" rev-parse HEAD)" = "$APPROVED" || exit 1
test -z "$(git -C "$SRC" status --porcelain)" || exit 1

export E3_PHASE3_APPROVED_HEAD="$APPROVED"
export PHASE3="$SRC/monitor-v2/deploy/e3-m3c-phase3.sh"
export PHASE2_STATE=/var/lib/e3-m3c-phase2
export PHASE3_STATE=/var/lib/e3-m3c-phase3
```

Record the frozen checkout identity:

```bash
git -C "$SRC" rev-parse HEAD
git -C "$SRC" status --short
```

Expected: HEAD is the approved merge SHA and status output is empty. Otherwise
**STOP**. Do not use `git pull`, overwrite/clean an existing checkout, switch
commits, or repair the tree inside this execution attempt.

## 2. Read-only production inventory

```bash
systemctl is-active sing-box.service
systemctl show -p ActiveEnterTimestamp -p NRestarts sing-box.service
systemctl is-active sbox-cm.socket
systemctl is-enabled sbox-cm.socket
systemctl is-active sbox-cm.service
systemctl is-enabled sbox-cm.service
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9191/api/v1/session

jq '{phase,final_status,activation,add,delete,deactivation,source_head,final_measurements}' \
  "$PHASE2_STATE/journal.json"
test ! -e /var/lib/sbox-cm/management.active
```

Expected:

```text
sing-box                       active
sbox-cm.socket                 active / enabled
sbox-cm.service                active / disabled
monitor HTTP                   200
Phase 2 phase/final_status     complete / canary_complete
Phase 2 all four stages        started=true / completed=true
activation marker              absent
```

Any mismatch: **STOP before Phase 3 preflight**. Do not manually edit evidence,
the marker, configuration, or systemd state.

## 3. Phase 3 preflight

```bash
E3_PHASE3_APPROVED_HEAD="$E3_PHASE3_APPROVED_HEAD" \
  /usr/bin/bash "$PHASE3" preflight
```

The command holds locks in this fixed order for its complete lifetime:

1. `/run/lock/e3-m3c-phase3.lock`
2. `/run/lock/singbox-monitor-deploy.lock`

Under both locks it resolves the immutable live monitor release, verifies the
live `web/e3rpc.py` hash against the approved checkout, and pins the resolved
application root for every RPC.

Expected final output:

```text
PHASE3 PREFLIGHT=PASS
HARD STOP: do not enable management without separate go-live approval
```

It creates only:

```text
/var/lib/e3-m3c-phase3/                root:root 0700
/var/lib/e3-m3c-phase3/baseline.json  root:root 0600
/var/lib/e3-m3c-phase3/journal.json   root:root 0600
```

The baseline freezes raw/semantic config digests and size, exact inventory,
sing-box timestamp/restarts, Phase 2 evidence identity, and the pinned monitor
target/hash. Writes use temp → file fsync → rename → parent-dir fsync.

If preflight does not print both lines exactly: **STOP**. It performs no
activation and must not be followed by enable.

## 4. Mandatory approval boundary

After a PASSing preflight, stop and send the complete output plus:

```bash
jq . "$PHASE3_STATE/baseline.json"
jq . "$PHASE3_STATE/journal.json"
```

Obtain an explicit, separate approval for production go-live. Preflight is
valid for 900 seconds, but enable still repeats every source, Phase 2, monitor,
closed-plane, config, inventory, transaction, lock, HTTP, and sing-box gate.

Do not proceed on silence, an expired preflight, or an approval for a different
SHA/evidence set.

## 5. Approved persistent enable

Only after explicit approval:

```bash
E3_PHASE3_APPROVED_HEAD="$E3_PHASE3_APPROVED_HEAD" \
  /usr/bin/bash "$PHASE3" enable --approve-go-live
```

The normal path executes exactly one mutation: `management.activate`. A
successful response must be `ok=true`, `management_state=active`, and
`no_op=false`. It does not call `client.add`, `client.delete`, or successful-path
`management.deactivate`.

Expected terminal output:

```text
PHASE3 GO_LIVE=PASS
E3 MANAGEMENT ENABLED = YES
management_state = active
activation_marker = present
```

The terminal journal must contain:

```text
phase=complete
activation.started=true
activation.completed=true
final_status=go_live_active
```

The script independently proves that the marker is a non-symlink regular JSON
file owned `root:root` with mode `0644`; management is active/clean; raw and
semantic config, size, and exact inventory did not change; sing-box remains
active with unchanged timestamp/restart count; monitor HTTP remains healthy;
and transaction journals remain empty.

## 6. Failure and interruption contract

Before activation starts, any failure is zero-mutation **STOP**.

After the durable `activation_started` checkpoint, any transport, RPC,
verification, or evidence failure enters fail-closed cleanup:

1. attempt `management.deactivate` through the pinned reviewed RPC;
2. if that path is unavailable, invoke the sanctioned root recovery command;
3. verify management inactive, marker absent, and production config/inventory/
   sing-box invariants unchanged;
4. record `enable_failed_closed`, or `manual_intervention` if safety cannot be
   proven.

Never manually remove or create the marker. Never edit/restore config, guess a
client identity, or reload/restart sing-box.

After shell/SSH interruption, do not resume enable from the middle. Reconnect,
freeze the same approved SHA, and run only:

```bash
E3_PHASE3_APPROVED_HEAD="$E3_PHASE3_APPROVED_HEAD" \
  /usr/bin/bash "$PHASE3" recover
```

`recover` prioritizes closing management. Missing/corrupt mutable journal,
pinned RPC loss, and monitor source drift use immutable baseline identity and
the sanctioned recovery path. Data drift is preserved for investigation; it
is never auto-reverted. A completed `go_live_active` attempt is normal
production and `recover` refuses to disable it.

## 7. Final gate

Final acceptance has two evidence layers. The `status` subcommand reports the
durable Phase 3 state machine; it does not re-measure config or inventory.

### 7.1 Terminal Phase 3 journal/status

```bash
E3_PHASE3_APPROVED_HEAD="$E3_PHASE3_APPROVED_HEAD" \
  /usr/bin/bash "$PHASE3" status
```

Required output:

```text
phase=complete
source_head=<approved Phase 3 main merge SHA>
activation_started=true completed=true
final_status=go_live_active
```

Also inspect the terminal evidence:

```bash
jq . /var/lib/e3-m3c-phase3/journal.json
```

Its terminal `final_measurements` was independently measured by the successful
`enable` command and must record unchanged raw config SHA, semantic config SHA,
config size, exact inventory, sing-box `ActiveEnterTimestamp` and `NRestarts`,
plus `management_state=active`.

### 7.2 Current read-only production checks

```bash
systemctl is-active sing-box.service

systemctl show sing-box.service \
  -p ActiveEnterTimestamp \
  -p NRestarts \
  --no-pager

test -f /var/lib/sbox-cm/management.active
test ! -L /var/lib/sbox-cm/management.active

stat -c '%U %G %a' /var/lib/sbox-cm/management.active

jq -e '
  .v == 1 and
  .state == "active"
' /var/lib/sbox-cm/management.active
```

Expected: sing-box is active; its timestamp/restart values equal the Phase 3
baseline and terminal measurements; marker metadata is `root root 644`; and
marker JSON validation returns 0.

Only after both evidence layers pass may the operator record this summary. Its
basis is **Phase 3 terminal journal + `final_measurements` + current read-only
active/marker/service checks**, not `status` alone:

```text
E3 PRODUCTION DEPLOYED   = YES
PHASE2 CANARY            = COMPLETE
E3 MANAGEMENT ENABLED    = YES
management_state         = active
activation_marker        = present
sing-box restart         = NO
config/inventory drift   = NO
```

## 8. Browser Production Acceptance

Perform this read-only UI acceptance only after `PHASE3 GO_LIVE=PASS` and the
terminal journal reports `final_status=go_live_active`.

1. Open the production Monitor Web through its normal production entry point.
2. Log in normally.
3. Open the E3 / Management area.
4. Confirm Management displays **Active**.
5. Confirm the client list loads and shows the existing production clients.
6. Confirm the `Add client` control is available for use.
7. Confirm `Deactivate management` is available for use.
8. Confirm the page shows none of: helper degraded, transport unavailable,
   stale management state, result unknown, or manual intervention.
9. Refresh the page once and confirm Management still displays **Active**.
10. End acceptance without clicking Add client, Delete client, or Deactivate
    management.

This step only proves that the real production browser/Web read path observes
the backend state already established by Phase 3. M2 CI covers the full Web
mutation path, Phase 2 covered the real production backend canary, and Phase 3
performed the persistent activation. Do not create a production test client
for browser acceptance.
