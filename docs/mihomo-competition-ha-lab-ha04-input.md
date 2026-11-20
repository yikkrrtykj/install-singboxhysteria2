# HA-04 technical input — isolated Reality/HY2 failover lab

Status: **LAB evidence only; not acceptance, not Shanghai network, not a
fleet, not an application result.** This note preserves the measured HA-02-side
protocol-lab findings so HA-04 [#92](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/92)
can reuse them instead of rebuilding an experiment framework.
Parent: [competition HA contract](mihomo-competition-ha-contract.md) /
[acceptance contract](mihomo-competition-ha-acceptance.md).
Full local report (not committed, no secrets): `lab-report.md` next to its raw
`results.json` and `run_lab.py` under the operator scratch directory.

## What ran

One Windows 11 host, loopback only. Four real `sing-box` 1.14.3 listeners stood
in for the two VPSes (A-Reality TCP, A-HY2 UDP, B-Reality TCP, B-HY2 UDP) with a
local REALITY handshake target and a self-signed HY2 certificate; one real
Mihomo v1.19.31 loaded the canonical four-node profile
(`Reality, Hysteria2, Backup-Reality, Backup-Hysteria2`, `节点选择` select,
`自动选择` fallback). The lab used `http://127.0.0.1/generate_204`,
`interval 3`, `timeout 1000`; the shipped delivery still carries the #42
defaults (`interval: 60`, `timeout: 5000`, `lazy: false`,
`expected-status: "204"`). Wall clock per run: 175.6 s, processes and listeners
cleaned up, exit 0.

Pinned binaries:

| Binary | Version | SHA-256 |
| --- | --- | --- |
| `sing-box.exe` (Windows amd64) | 1.14.3, go1.26.8, revision `7054cac5…` | `5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf` |
| `mihomo.exe` (Windows amd64) | Mist/Mihomo v1.19.31, go1.26.8 | `532ed88b3a37d72f6b5ee5d24a45ce5d8799f3ba34931d6a167d4345f7ebca50` |

## Observations (labelled LAB)

T0 = injector action plus independent effect check; T1 = first health evidence;
T2 = first fresh successful response through a surviving node.

| Scenario | Observed selection | T0→T1 | T0→T2 |
| --- | --- | --- | --- |
| Baseline, all four healthy (3 runs) | `自动选择=Reality`, chain `Reality → 自动选择 → 节点选择` | — | 200 in 15/16/16 ms |
| Stop only A-Reality, scheduled check only | → Hysteria2 | ≤344 ms | **359 ms** |
| Stop only A-Reality, active retry (2 runs) | → Hysteria2 | 2047/1953 ms | **2078/1969 ms** |
| Stop whole VPS A, scheduled check | transient Hysteria2, then Backup-Reality | 2657 ms | **4266 ms** |
| Stop whole VPS A, active retry (2 runs) | transient Hysteria2 (~1 s), then Backup-Reality | 2078/2156 ms | **3485/3469 ms** |
| Restore A-Reality, then A-HY2; 30 s window | Backup-Reality → Reality 2000 ms after the first restore, **0 switches** | — | — |
| Health URL green while upload blackholed (3 runs) | Reality unchanged, **0 switches**, all four "alive" | — | 204 in 0–32 ms |

Notable behaviours worth an HA-04 test row:

- **HY2 restart recovery is slow.** After the A-HY2 process restarted, Mihomo
  kept that member unhealthy for **27.7–30.1 s** in 3/3 runs. Do not read "the
  server is listening again" as "the candidate is usable again".
- **Transient selection of an already-dead node.** During whole-VPS-A failure
  the fallback briefly selected the also-dead A-HY2 before moving to
  Backup-Reality, adding roughly one second of outage. HA-04 must count this,
  not just the final selection.
- **Probe HTTP semantics matter.** `unified-delay: true` issues a second HEAD on
  the same keep-alive connection. A 204 endpoint that answers HEAD with
  `501`/`Connection: close` makes every health check fail; the production probe
  target must support repeated HEAD on a kept-alive connection.
- **204 does not see upload degradation.** In all three N02 runs the GET stayed
  204 while the upload did not complete; native liveness is blind to this class
  of failure, consistent with the #48 quality gap.

## What this does and does not establish

- It establishes that the canonical four-node profile really fails over and
  fails back between real Reality and real Hysteria2 transports on one host,
  and gives HA-04 a working T0/T1/T2 measurement method with one real core.
- It does **not** establish any Shanghai-network, real-VPS, Windows-fleet,
  application or ≤10 s result. T3 was not measurable (no vMix/TikTok/Drive);
  the loopback timings include no WAN RTT, no ISP/GFW behaviour, no real
  port hopping and no 30-client probe load. The 3 s/1000 ms lab settings are
  not the shipped policy and are not a recovery guarantee.
- No timing row here may be copied into HA-04/HA-05 acceptance, and no node
  switch may be reported as application recovery.

## Handling decision

- Native Mihomo remains the competition baseline; the PR-48B **Quality
  Failover EXE stays in the repository, opt-in and disabled** — not retired and
  not enabled by this evidence.
- The N02 result is an input to HA-04/HA-06, not a quality PASS: any scope that
  relies on automatic upload-degradation recovery is still NOT MET/BLOCKED
  unless separately tested and approved.
- HA-04 should reuse this harness shape (two independent sing-box stand-ins,
  four real listeners, one pinned Mihomo, local 204 origin) for the lab rows
  and reserve real VPS/Windows/application runs for the acceptance rows.
