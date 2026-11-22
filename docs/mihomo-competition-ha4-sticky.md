# HA-04 Sticky Failover prototype (issue #92, DEFAULT OFF)

Status: **isolated prototype + LAB evidence only; NOT #92 acceptance, NOT
production deployment, NOT a Go-Live approval.** The controller is not enabled
by default, is not a Windows service, is not packaged, and no real Windows
profile, TUN, system proxy, VPS or application was changed by this work.

## Why this design

Native Mihomo `fallback` automatically returns to a higher-priority node when
that node recovers (measured on the exact v1.19.33 core). Setting fallback
`fixed` only suppresses failback while the fixed node is healthy; when that
node fails the core clears `fixed` and may auto-select a recovered
higher-priority node.

This prototype therefore **does not make the fallback group carry traffic**.
The existing selector group (`节点选择`) is the outer traffic selector:

- normal: outer selector = PREFERRED (`Reality` for A-first, `Backup-Reality`
  for a B-first profile after applying its physical mapping);
- the existing `自动选择` fallback group remains the **health detector** only;
- when the outer-selected node is confirmed unhealthy, the controller selects
  a confirmed-healthy candidate: first the candidates after the current one in
  original order, then already-recovered higher-priority candidates if no lower
  candidate is healthy. That is a new takeover caused by the current-path
  failure, not a failback while the current path is healthy;
- a higher-priority node recovering while the current outer node is healthy
  changes only the fallback health group's internal `now`; the outer selector
  remains on the current takeover node;
- only an explicit admin `reset` returns the outer selector to PREFERRED.

The selected outer node is persisted by Mihomo (`store-selected: true`) and by
the controller state file. This removes the native traffic failback race. It
does **not** make existing TCP/UDP sessions migrate; failures can close
existing connections and the controller never claims lossless migration.

## State machine (minimum)

| State | Meaning | Main transition |
|---|---|---|
| `PREFERRED` | outer selector on preferred node, healthy | preferred becomes unhealthy -> `TAKEOVER_PENDING` |
| `TAKEOVER_PENDING` | selected candidate, PUT in flight | verified PUT -> `TAKEOVER_LOCKED`; failure -> `UNKNOWN` |
| `TAKEOVER_LOCKED` | outer selector manually locked to takeover node | higher-priority recovery: no action; locked node unhealthy -> `RECONFIRMING`; external change -> `MANUAL_RESET` |
| `RECONFIRMING` | current node failed; lower-then-higher healthy candidate selection | verified -> `TAKEOVER_LOCKED`; none/unknown -> `DUAL_DOWN`/`UNKNOWN` |
| `UNKNOWN` | API/health/state cannot be trusted | transient API loss and incomplete health may auto-reconcile after verified refresh; auth/binding/manual/mismatch require admin |
| `DUAL_DOWN` | all four candidates are confirmed unhealthy | recovery of any confirmed-healthy candidate can take over; unknown health never becomes DOWN |
| `MANUAL_RESET` | outer selection changed outside the controller | no write; explicit admin reset required |

Sticky ordering applies only to the choice of a takeover candidate while the
current outer node is healthy: higher-priority recovery is ignored. Once the
current node is **confirmed unhealthy**, candidates after it are preferred; if
all of those are confirmed unhealthy, a confirmed-healthy higher-priority node
is eligible. `DUAL_DOWN` is entered only when all four candidates are confirmed
unhealthy; missing/null/stale/unknown health becomes `UNKNOWN`, not DOWN.

## Controller safety properties

- Python standard library only; loopback controller HTTP API; no public listener.
- Reads `/proxies` only; no extra health probes, no `/group/*/delay`, no fixed
  selection on the fallback group.
- Requires all four candidate nodes, exact `Fallback`/`Selector` group types and
  membership, boolean `alive`, and fresh parsed health history; missing, null,
  stale or unknown health becomes `UNKNOWN`, never DOWN.
- Does not modify Mihomo source/core, TUN, DNS, system proxy, VPS, HA-UI or
  existing profiles.
- Does not restart/stop core, clear connections, or install a service.
- Default off: an operator runs one foreground process; no auto-start.
- One state file per profile; profile SHA-256, config version, group names and
  node order are part of the binding. Mismatch is refused.
- Instance lock prevents two controllers writing the same state.
- State writes are atomic (temporary file, fsync, JSON re-read, replace).
- Temporary connection errors are classified separately from auth failures,
  invalid responses, group/profile mismatch and manual selection conflicts.
  Only transient connection errors and recoverable incomplete-health states are
  reconciled automatically, and only after verifying outer selection, state
  binding and complete fresh health; no blind PUT is performed.
- Auth/invalid-response/binding/manual-selection conflicts stay fail-closed
  until an explicit admin reset.
- A reset request is kept until its outer-selection write and verification
  succeed; an API failure does not consume the request.
- The controller requires an explicit admin reset after a fatal `UNKNOWN` or
  `MANUAL_RESET`; it never guesses a recovery.
- Controller crash/API loss does not cause a fallback to the preferred node
  (the outer selector stays where it was), but the controller also cannot take
  over a newly failed node until restarted. That is recorded as a fail-closed
  limitation, not a guarantee.

## Configuration

A private local JSON file, e.g. `%LOCALAPPDATA%\HAS04Sticky\config.json`:

```json
{
  "schema": "mihomo-competition-ha4-sticky-config/1",
  "controller_url": "http://127.0.0.1:9097",
  "secret": "<local controller secret>",
  "outer_group": "节点选择",
  "health_group": "自动选择",
  "order": ["Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2"],
  "profile_sha256": "<sha256 of the intended HA-04 profile>",
  "config_version": "ha4-...-sticky-r1",
  "state_path": "C:\\Users\\<user>\\AppData\\Local\\HAS04Sticky\\state.json",
  "poll_interval_ms": 50,
  "api_timeout_ms": 1000,
  "error_threshold": 3,
  "health_max_age_ms": 20000
}
```

The secret and state path stay local. The controller prints state transitions to
stdout, never the secret or YAML.

Commands (DEFAULT OFF; no auto-start):

```powershell
python tools\mihomo-competition-ha4-sticky.py run --config <config.json>
python tools\mihomo-competition-ha4-sticky.py status --config <config.json>
python tools\mihomo-competition-ha4-sticky.py reset --config <config.json>
```

`reset` is an admin request consumed by the running controller; it puts the
outer selector back on PREFERRED and clears the sticky state. It is the only
supported way to restore the initial preference. If the preferred node is
unhealthy, normal failover can take over after the reset.

## What this prototype does not provide

- No packaging, installer, Windows service, auto-start, GUI or fleet rollout.
- No real Windows/Verge/TUN/Reality/HY2/TLS/business acceptance.
- No HA-03 certificate identity conclusion; that remains #91.
- No HA-04 timing/false-positive/30-client/application acceptance.
- No cross-VPS TCP/UDP session migration.
- No protection while the controller is dead, stopped or cannot authenticate:
  traffic stays on the last outer selection; if that node fails, it has no
  automatic replacement until the controller is restarted/reconciled.
- No guarantee for a failure/recovery that happens entirely inside the health
  probe detection window or the controller's API write window. The outer
  selector is not changed by the fallback recovery, but takeover timing remains
  bounded by the probe interval/timeout and controller poll.

## Isolated LAB evidence (not acceptance)

Real-core LAB on the installed **Mihomo v1.19.33** (`verge-mihomo.exe`,
SHA-256 `0b4c7353057a78de8a09db445351aadec7d72a4f48adc7d99691f3c5ff74d3da`),
loopback synthetic four-node profile, `tun.enable=false`, `dns.enable=false`:

- Preferred failure -> outer selector moved to Hysteria2; real HTTP requests
  through the mixed port landed on Hysteria2, not only `/proxies.now`.
- High-priority Reality recovered at 0.1s / 0.5s / 1s / 3s after takeover:
  outer selector and actual new connections stayed on Hysteria2; no auto
  failback observed.
- Hysteria2 then failed: controller moved to Backup-Reality; actual new
  connections landed there. A further failure selected Backup-Hysteria2 in
  unit tests; when all four candidates were confirmed dead, state became
  `DUAL_DOWN` and actual requests failed (502), not a false success.
- Current node healthy while a higher-priority node recovered: no selector
  change; the higher-priority recovery remained health-group-only.
- Controller killed while locked: outer selection stayed on the dead node and
  requests failed; after restart the controller reconciled to the next healthy
  candidate.
- Current Hysteria2 failed while all lower candidates were down and Reality had
  recovered: controller selected Reality as a **new failure-driven takeover**
  and actual requests landed there.
- Root-API loss: state became `UNKNOWN`, no writes; explicit reset restored
  PREFERRED.
- Transient-only API failures (real core, wrapper): after threshold the state
  went `UNKNOWN`; after API recovery it auto-reconciled the persisted outer
  selection without a blind PUT. Auth/invalid responses are covered by unit
  tests and remain fail-closed.
- Health incomplete/stale/missing: unit tests require `UNKNOWN` and no switch;
  a complete fresh refresh reconciles safely.
- Reset request interrupted by a transient API failure: request was retained;
  after recovery it was applied and only then removed.
- Repeated initialize / double start: unit tests show no duplicate selector
  writes; CLI initialization failure returns non-zero.
- Core restart with `store-selected:true`: the outer manual selection survived
  and the controller reconciled.
- External/manual outer selection change while locked: controller entered
  `MANUAL_RESET`, did not overwrite the operator's selection; explicit reset
  restored PREFERRED.
- Fast failure+recovery inside one health window: no takeover occurred; outer
  selector stayed PREFERRED (no failback).
- B-first group-order run produced the same group semantics; physical VPS
  mapping was not exercised in the synthetic LAB.
- Windows reboot, real profiles/TUN/Reality/HY2, and application recovery were
  not tested.

The actual real-core LAB used local synthetic HTTP proxy nodes; it proves
controller/native selector mechanics, not protocol identity, Windows GUI
behavior or fleet suitability. The LAB health group used its own synthetic
1s/1000ms probe policy; the real HA-04 candidates (5s/2000ms and 5s/5000ms)
have different detection windows. The controller never adds its own probes, so
takeover latency is bounded by the candidate's probe interval/timeout plus the
controller poll; it is not a measured ≤10s SLA.

## Rollback

1. Stop the controller process (foreground; no service).
2. Run explicit `reset` (or use the authenticated controller/UI to select the
   original preferred node) and verify `/proxies` outer `now`.
3. Restore the original Clash Verge config/profile/backup per the HA-03
   runbook; do not hand-edit the HA-04 candidate.
4. Remove the controller state/config files if the prototype is no longer used.
5. No VPS/server rollback is needed; this tool changes no server state.

## Deployment complexity (16–30 Windows PCs)

Not approved and not tested. Each PC would need a private config/controller
secret, a per-profile state file, a process lifecycle/auto-start decision,
log/monitoring and an admin-reset procedure. That is materially more complex
than a single EXE/profile delivery and requires packaging, service/autostart
security review and an independent rollout plan. Do not deploy from this
prototype.

## Evidence boundary

This design was validated on a loopback synthetic four-node profile and with
hermetic unit tests. It may be suitable for a single authorized Windows
real-profile test after explicit approval, but it is **NOT** #92 acceptance and
must not be used to claim a 10-second SLA, application recovery, certificate
identity, fleet capacity or Go-Live.
