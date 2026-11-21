# HA-04 fast-probe LAB evidence (loopback, issue #92)

Status: **LAB EVIDENCE ONLY — not acceptance, not a fleet/VPS/ISP/Windows/application result.**
Harness: `tests/mihomo-competition-ha4-lab.py`
Profile tool: [`tools/mihomo-competition-ha4-fastprobe.py`](mihomo-competition-ha4-fastprobe.md)
Design/measurement contract: [fast-probe variants](mihomo-competition-ha4-fastprobe.md).

All numbers below were measured on one Windows host in a **loopback-only**
synthetic fixture. The fixture is built end-to-end through the three repo tools
(HA-02 batch → HA-03 competition profile → HA-04 fast-probe variant) and runs
real pinned `sing-box` listeners and pinned Mihomo clients; nothing is
simulated at the protocol level. Loopback RTT is ~1-7 ms, so the numbers
describe **mechanics**, not WAN/VPS/ISP behaviour, and a loopback "recovery
time" is not a 10 s acceptance measurement.

## Environment and pinned binaries

- Host: Windows 11 amd64 (single host); all sockets bound to `127.0.0.1` /
  `127.0.0.2` loopback only; no TUN, no external network, synthetic throwaway
  credentials; health/upload origin is a local HTTP server.
- Mihomo: `Mihomo Meta v1.19.31 windows amd64`, SHA-256
  `532ed88b3a37d72f6b5ee5d24a45ce5d8799f3ba34931d6a167d4345f7ebca50`.
- sing-box: `1.14.3 windows amd64`, SHA-256
  `5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf`.
- The harness verifies both hashes before running and refuses a mismatch.
- Run metadata: primary run (`--scenario all`) started 2026-11-21T08:24:29Z,
  duration 536.8 s, Python 3.12.14; the separate clean B-first matrix run took
  234.3 s. Both runs finished with `ports_free: true`,
  `processes_stopped: true` and no leftover listeners.
- Fixture: two logical VPSes (A=`127.0.0.1`, B=`127.0.0.2`), each with an
  independent REALITY TCP listener and Hysteria2 UDP listener, plus the A-side
  Hysteria2 hopping range; one pinned Mihomo client per measured run; per
  terminal UUID/password as required by the HA-02 batch gate.
- The **delivered variants are the actual HA-04 tool outputs**; `--check` is
  recorded per generated variant (`ha4-fastprobe: OK`).

### Declared LAB-only deviations (applied to the copied runtime profile)

These are recorded in `results.json.environment.declared_lab_deviations` and
are the only edits made to a verified HA-04 variant before it is given to the
loopback client (the on-disk variant/manifest evidence is not modified):

1. health URL rewritten from the delivered 204 URL to the local loopback origin;
2. `mixed-port`, `external-controller` and debug log are local;
3. `dns.enable=false`, `dns.fallback-filter.geoip=false` and `tun.enable=false`
   (no TUN/admin/resolver/GeoIP database on the LAB host);
4. the delivered `GEOIP,LAN,DIRECT` / `GEOIP,CN,DIRECT` rules are removed so
   the loopback origin is forced through `节点选择` instead of DIRECT.

Everything else — the four nodes and their order, the probe policy under test,
`lazy:false`, the HY2 pins / `skip-cert-verify:false`, listeners and
`allow-lan:false` — is exactly the verified HA-04 variant.

## Measurement definitions used by the harness

- **T0**: the listener kill ack **plus an independent effect check** (TCP
  connect refused / UDP port bindable after the process exited). The SUT
  `/proxies` state is not used as fault proof.
- **T1**: first client-side failure evidence after T0: earliest timestamped
  per-node `alive:false` health evidence and/or the first selection change. A
  `null` T1 means no qualifying observation was captured in the window
  (UNKNOWN), not "no fault".
- **T2**: first **fresh** end-to-end SOCKS probe (HTTP 204 from the loopback
  origin) whose request was both started and completed after T0, with chain
  attribution from `/connections`. An in-flight or reused attempt is not T2.
- **Dead-node window**: time the selected `自动选择` member was a T0-dead node.
- **Switch count**: distinct selection changes observed in the observation
  window.
- **T3 (application)**: NOT MEASURED — vMix/TikTok LIVE Studio/Google Drive are
  real-Windows-PC HA-05 evidence; loopback has no application hook.
- Each matrix cell below is one repetition unless stated; these are not
  p95/percentile measurements.

## Matrix: T0→T1 / T0→T2 (ms), dead-node window, switches

Two measured runs are reported (same host/fixture/tool build; raw evidence in the
lab directories named in the reproduction section):

- run 4, `--scenario all`, `results.json`: 19 client runs (18 OK, 1 harness
  error), 32 trials, 536.8 s. The single harness error was a **baseline setup
  flake** in `matrix-b i10/t5000` (client baseline chain not healthy before the
  fault; no fault trial was measured). No measured trial failed.
- run b, `--scenario matrix-b`, `results.json`: 3 runs OK, 9 trials, 234.3 s.
  This clean separate run supplies the complete B-first matrix that run 4 could
  not finish. It is the same harness build and fixture; do not compare cell
  values across runs as if they were one sample.

`—` in T0→T1 means no qualifying client-side detection evidence was captured in
the observation window (**UNKNOWN**, not "no fault"); a `—` T2 means no fresh
post-T0 success was measured (only the both-VPS-down row). Every T2 listed has a
`/connections` chain unless noted.

**A-first** (run 4, 9 policies × {Reality-TCP-only failure, whole-VPS-A outage}):

| Row | interval | timeout | T0→T1 | T0→T2 | T2 node | dead-node | switches | verdict |
|---|---|---|---|---|---|---|---|---|
| A-first A-Reality TCP | 3s | 1000ms | — | 203.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 3s | 1000ms | — | 282.0 ms | Backup-Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first A-Reality TCP | 3s | 2000ms | — | 375.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 3s | 2000ms | — | 406.0 ms | Backup-Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first A-Reality TCP | 3s | 5000ms | — | 391.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 3s | 5000ms | 2020.8 ms | 3562.0 ms | Backup-Reality | 2031.0 ms | 1 | FRESH_SUCCESS |
| A-first A-Reality TCP | 5s | 1000ms | — | 313.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 5s | 1000ms | 1094.0 ms | 2703.0 ms | Backup-Reality | 2109.0 ms | 2 | FRESH_SUCCESS |
| A-first A-Reality TCP | 5s | 2000ms | — | 234.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 5s | 2000ms | 938.0 ms | 4266.0 ms | Backup-Reality | 2937.0 ms | 2 | FRESH_SUCCESS |
| A-first A-Reality TCP | 5s | 5000ms | — | 375.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 5s | 5000ms | 968.0 ms | 7500.0 ms | Backup-Reality | 5875.0 ms | 2 | FRESH_SUCCESS |
| A-first A-Reality TCP | 10s | 1000ms | — | 172.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 10s | 1000ms | 1094.0 ms | 2703.0 ms | Backup-Reality | 2110.0 ms | 2 | FRESH_SUCCESS |
| A-first A-Reality TCP | 10s | 2000ms | — | 219.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 10s | 2000ms | 922.0 ms | 4297.0 ms | Backup-Reality | 2938.0 ms | 2 | FRESH_SUCCESS |
| A-first A-Reality TCP | 10s | 5000ms | — | 266.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| A-first whole VPS A | 10s | 5000ms | 953.0 ms | 7469.0 ms | Backup-Reality | 5922.0 ms | 2 | FRESH_SUCCESS |

**B-first** (clean run b, 3 policies × {primary B-Reality-TCP failure, idle
backup A-Reality failure, whole-backup-VPS-A outage}):

| Row | interval | timeout | T0→T1 | T0→T2 | T2 node | dead-node | switches | verdict |
|---|---|---|---|---|---|---|---|---|
| B-first B-Reality TCP | 3s | 1000ms | — | 375.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first A-Reality (backup) | 3s | 1000ms | — | 250.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first whole VPS A (backup) | 3s | 1000ms | 3694.8 ms | 344.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first B-Reality TCP | 5s | 2000ms | — | 343.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first A-Reality (backup) | 5s | 2000ms | — | 265.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first whole VPS A (backup) | 5s | 2000ms | 5738.4 ms | 390.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first B-Reality TCP | 10s | 5000ms | — | 250.0 ms | Hysteria2 | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first A-Reality (backup) | 10s | 5000ms | — | 250.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |
| B-first whole VPS A (backup) | 10s | 5000ms | 8729.8 ms | 235.0 ms | Reality | 0.0 ms | 0 | FRESH_SUCCESS |

The shipped `60 s / 5000 ms` reference was **not** re-measured in this run (it is
the HA-03 artifact, byte-verified but left untouched); its mechanics are
NOT MEASURED here.

## Hysteria2 rows

Policy i3/t1000, A-first terminal (run 4):

| Row | Measured result |
|---|---|
| Idle-HY2 negative control (kill A-HY2 while Reality/selected is healthy) | first health evidence T1 = 2946.9 ms; **switches = 0**; final selection `Reality`; the dead HY2 was never selected/carried |
| HY2 actually selected, then killed (first kill A-Reality, then A-HY2) | T1 = 922.0 ms; T2 = 1687.0 ms through `Backup-Reality`; switches = 1 |
| HY2 restart recovery (kill only A-HY2, restart it) | recovered = yes; **fault→recovered-candidate = 32453.0 ms**, **restart→usable = 22390.0 ms**, a second fault→fresh-route = 18890.0 ms |
| Second fault injected during the HY2 recovery window | T1 = 586.4 ms; fresh route T2 = 328.0 ms through `Backup-Reality`; switches = 0; dead-node window 0 ms |

The ~32 s fault→usable window is the known stale-QUIC-session effect (client
keeps the old Hysteria2 QUIC connection until its idle timeout), **not** a
business outage: the new-route T2 values above are sub-2 s and the second fault
was routed around in 328 ms. The 22.4 s restart→usable interval shows the
listener being up is not the same as the candidate being usable.

## UDP hopping

Policy i3/t1000, hopping terminal with the A-side HY2 `ports: 24010-24019`
range (run 4):

| Row | Measured result |
|---|---|
| Kill one hop port (`A-HY2-hop-24018`) | 19 fresh successes / 2 failures; the client continued to reach the HY2 node over the remaining hop ports (`hop-continued`); no complete business interruption was needed to move away from the single blocked port |
| Kill the whole A-HY2 listener set (11 processes: base + hop range) | T2 = 250.0 ms through `Backup-Reality`; switches = 0 (the fresh connection moved in-dial; no group-selection change was recorded in this single run) |

The single-port row is the intended "port hopping hides a single blocked port"
negative control. The whole-HY2 row is the "global UDP impairment must not be
hidden by hopping" row. Real WAN hopping, real ISP/UDP filtering and real
port-block behaviour are NOT MEASURED in loopback.

## Whole-VPS outage / both VPSes unavailable

Run 4:

| Row | Measured result |
|---|---|
| Whole VPS A outage (both A listeners) | A-first rows above: fresh route to `Backup-Reality` in 2.70-7.50 s with a dead-node selected window of 2.03-5.92 s and 1-2 switches; B-first rows: business traffic stayed on `Reality` (B, the live primary) with fresh successes at 235-390 ms and detection evidence at 3.69-8.73 s |
| Both VPSes unavailable simultaneously | 8 fresh attempts, 0 successes; observed selections included `Backup-Hysteria2`, `Backup-Reality`, `Reality` while all candidates were T0-dead; verdict `NO_USABLE_ROUTE_no_false_recovery` |

No false recovery or invented success is reported for the common outage: a
green node, a cached 204 or a stale selection was not accepted as recovery.

## Failback and second interruption

Run 4:

| Row | Measured result |
|---|---|
| First interruption (whole VPS A) | T1 UNKNOWN (not captured); T2 = 250.0 ms through `Backup-Reality`; switches = 0 in the sampled window (in-dial move) |
| Failback after A restore | failback observed = yes in 515.0 ms; switches in the post-restore window = 0; fresh-probe failures in the window = 0 |
| Second interruption (fail the actually-current path after failback) | T1 = 1235.0 ms; T2 = 1485.0 ms; **chain attribution for that T2 was unavailable (UNKNOWN)**; switches = 1; final selection `Hysteria2`; no T0-dead node was selected at the end |

The second fault did not leave a dead node selected and did not create a
recovery claim; the missing chain attribution on that one T2 is reported as
UNKNOWN rather than asserted. A >=10 min failback stability window is NOT
MEASURED (one 30 s observation window only).

## N02: 204 healthy while upload is degraded

Run 4, policy i3/t1000, A-first terminal:

| Field | Measured result |
|---|---|
| Native selection switches during the stalled upload | **0** |
| Health probe successes while the upload was stalled | 18/18 (`204`) |
| Upload path | POST through the selected path; the origin accepted headers/body and then never responded (`response_wait` stall) |
| Verdict / disposition | `204_STAYS_GREEN_UPLOAD_STALLED`; native liveness did not detect the upload degradation and made no switch. Disposition: manual/application contingency or an explicit scope exclusion, handed to HA-06 as a measured gap; **no quality FAIL/PASS is claimed and no automatic quality controller is added**. Quality Failover stays opt-in and off. |

This reproduces the N02 class in LAB mechanics only: a real application
(vMix/TikTok/Drive) impact and any automatic quality recovery are out of scope
and NOT MEASURED.

## Interpretations (bounded to LAB)

- **TCP-refused primary failure moved new connections in-dial, not by group
  polling.** Across all nine A-first policies, a fresh connection reached
  `Hysteria2` in 172-391 ms after the A-Reality kill without a recorded
  `自动选择` selection change, and no health-check `alive:false` evidence was
  captured inside the observation window (T1 UNKNOWN). This matrix therefore
  measures **new-route latency**, not detection latency, for the
  connection-refused class. It must not be read as "detection in <400 ms".
- **Whole-VPS outage keeps a dead node selectable for a timeout-dependent
  window.** The measured dead-node selected window was ~2.03-2.11 s at
  `timeout=1000`, ~2.94 s at `2000` and ~5.88-5.92 s at `5000`; total T0→T2 was
  2.70-7.50 s and a typical row recorded 2 switches (transient selection of the
  also-dead same-VPS HY2, then the live backup). Longer timeout trades a longer
  dead-node window for fewer premature failures; this single-repetition LAB does
  not quantify the real-WAN false-positive trade.
- **Interval effect is not separable from these single repetitions.** Whole-VPS
  T1 was 0.9-2.0 s (A-first) and 3.7-8.7 s (B-first, detection of an idle
  backup death), dominated by in-flight check completion and timeout rather than
  a clean interval difference. The effective check cadence when
  `timeout > interval` (tick coalescing/single-flight) is **NOT MEASURED** per
  cell; it must be measured on the real core, not assumed from the config.
- **B-first symmetry:** when the current primary (B) dies, fresh connections
  move to B's HY2 in 235-375 ms; when only the idle backup VPS A dies, the
  business path is unaffected (fresh success 235-390 ms, 0 switches, 0 dead-node
  window) while detection evidence appears 3.7-8.7 s later. An alarm for a
  non-impacting backup failure is possible; real alarms/false positives need the
  authorized WAN run.
- **HY2 restart recovery is dominated by the stale QUIC session:** fault→usable
  ~32.4 s and restart→usable ~22.4 s at i3/t1000, matching the ~30 s QUIC idle
  timeout mechanism, while a fault during that window was routed around in
  328 ms. The listener being up is not candidate usability; the ~30 s window is
  not automatically a ~30 s business outage. No Mihomo patch and no automatic
  client restart was used; a client restart is only a documented operator action
  row for the real run.
- **UDP hopping hid a single blocked port** (19 successes / 2 failures while one
  hop port was dead) and did not hide a whole-HY2 loss (fresh route in 250 ms).
- **Common outage:** both VPSes down produced no false recovery (0/8 fresh
  attempts); stale selections were not accepted as success.
- **Failback** took 515 ms with 0 switches and 0 probe failures in the sampled
  window; the second interruption rerouted in ~1.5 s with no T0-dead node
  selected at the end, but chain attribution for that one T2 was UNKNOWN. A
  >=10 min stability window is not measured.
- **N02 is invisible to native liveness** (18/18 health 204s, 0 switches while
  the upload stalled), which is the measured gap to hand to HA-06; it is not a
  quality verdict.

### Confidence and uncertainty

- One repetition per cell (B-first matrix is a separate clean run after the
  run-4 baseline flake); no p95/percentile claim is made. Values vary with
  fault phase relative to the health tick; the contract's phase-covering
  repetitions remain NOT MEASURED.
- Timestamps use one monotonic clock plus a wall↔mono offset; T1/T2 resolution
  is bounded by the ~50 ms controller poller and ~250 ms fresh-probe cadence.
  One B-first whole-backup row reported T1 ≈ -0.25 s relative to T0 (a
  health-check completion during the injector's own effect verification) —
  treated as pre-T0 fault evidence, not as negative recovery time.
- Loopback has ~1-7 ms RTT, no ISP/GFW/loss, one host and one client core:
  these numbers are host/CPU dependent and are **not** a 10 s acceptance
  measurement. The shipped 60 s/5000 ms reference was not re-measured; its
  mechanics stay NOT MEASURED in this run.

## What this LAB does not establish (NOT MEASURED / BLOCKED)

- T3 application recovery for vMix Call, TikTok LIVE Studio and Google Drive;
- real WAN/VPS RTT, ISP/GFW behaviour, real UDP port hopping on a WAN;
- real 10 s recovery claim (loopback is not a WAN measurement);
- 30-client false-positive rate, probe load, CPU/connection bursts;
- the real Windows PC + Clash Verge Rev bundle (`v2.5.10` + bundled Mihomo
  `v1.19.33`) and its on-disk core identity;
- TUN/DNS/Fake-IP/IPv4/IPv6 effective paths and remote-management behaviour;
- real HY2 certificate identity/rotation/expiry acceptance (LAB uses throwaway
  self-signed certifications);
- real failback observation >=10 min and 16-30 terminal fleet behaviour;
- any HA-04 acceptance verdict. HA-04 formal acceptance still requires the
  HA-03 real-environment pass and the authorized real-resource run.

## Reproduction

```sh
export HA04_MIHOMO=/path/to/mihomo          # pinned v1.19.31, SHA-256 above
export HA04_SINGBOX=/path/to/sing-box       # pinned v1.14.3, SHA-256 above
python3 tests/mihomo-competition-ha4-lab.py --scenario all \
  --lab-dir .scratch/ha04-lab
```

Raw evidence (`results.json`, JSONL event logs, runtime configs and logs, all
loopback/synthetic) is written under the lab directory by the harness; the
summary tables above are taken from that run. The harness refuses busy ports,
missing/wrong binaries and non-loopback bindings.
