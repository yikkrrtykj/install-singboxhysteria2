# UM-B4 read-only investigation: existing VPS Monitor traffic statistics

Status: **investigation only**. It does not modify `monitor-v2`, does not broaden
permissions, does not enable `singbox_api`, and does not claim a production
traffic capability. Linux Reality/Hysteria2 real traffic collection remains a
**pre-production functional blocker** on #127.

## 1. What the existing Monitor has

The existing Monitor's only per-inbound byte data comes from the same sing-box
`1.14 service.api` connection stream that UM-B3 audited:

- `monitor-v2/api_bridge/singbox_stream.py:28,42-62` consumes
  `daemon.StartedService/SubscribeConnections` on loopback with the
  single `service.api` bearer secret.
- `monitor-v2/collector.py:39-48,436-512` keeps per-connection active totals
  and banks finalized CLOSED totals once; on stream reset it refreshes active
  IDs and banks missing IDs as ABANDONED lower bounds (`:271-311`).
- Per-inbound aggregates (`uplink_total`, `downlink_total`, active connections,
  rates) are at `collector.py:545-555`; the design explicitly labels them
  **"Since monitor start"**, not daemon-lifetime/all-time (`README.md:809-810`).
- The stream/process is in-memory; a monitor restart loses the accumulator and
  can reduce the published cumulative values (`web/broker.py:1-7`;
  `collector.py:15`; `webapp.py:262-272` exposes a run id).

The monitor is a non-root hardened service (`sboxweb`) but it **holds the
write-capable service.api secret** (`deploy/singbox-monitor.service.in:11-69`;
`deploy/README.md:122-132`; `deploy/lib/monitor-deploy-lib.sh:642-653`). Its
local web snapshot/auth is an admin-password session, not a read-only machine
interface; the snapshot also includes raw source/destination addresses and
connection ids (`web/server.py` snapshot/stream; `incident_history.py:488-580`
excludes them only from the sanitized history DB).

## 2. Local read-only surfaces evaluated

| Surface | Per-inbound bytes? | Access / limitation |
| --- | --- | --- |
| loopback `/api/v1/snapshot`/SSE | yes, since-monitor-start lower bounds | admin password/session; raw client data; not a machine contract |
| `/api/v1/diagnostics/timeline` | yes, lower bounds; 7 d sparse | admin session; sanitized but internal |
| `diagnostics/history.sqlite3` | yes, lower bounds | sboxweb/root only; internal 7-day schema; would need permission expansion |
| `state/snapshot.json` | yes | sboxweb; only written in compatibility collector-loop mode (production web mode does not write it) |
| `state/health.json` | no | only schema/age flags |
| host-evidence / remote-probes / journal reader | no | no bytes; journal reuse is forbidden by UM-A review |
| sing-box `service.api` / `sing-box api` | per-connection only | same write-capable secret; P1-10 audit FAIL |
| `sbox-cm` | no stats | privileged mutation plane; must not be used |

There is **no existing read-only machine credential, UNIX stats socket, stable
export file or Prometheus endpoint** that exposes accurate per-inbound
daemon-lifetime total bytes.

## 3. Gap against the frozen UM contract

1. **Authorization:** v1.14.5 `service.api` secret authorizes the whole
   `StartedService` RPC surface (write/control calls). P1-10 failed; the frozen
   UM source switch remains `singbox_api=false` and must stay disabled. Monitor
   reuse does not make the credential read-only.
2. **Exactness:** monitor and B3 both observe a **lower bound** (active
   authoritative + finalized CLOSED once), not a daemon-lifetime exact total. The
   frozen `traffic` schema has no lower-bound/exactness representation; B3
   therefore reports `traffic=unavailable` rather than misrepresenting a lower
   bound as a total.
3. **Epoch/reset:** monitor counters reset on monitor restart, while UM's
   `counter_epoch` is host-boot-derived and does not model a monitor restart.
4. **Attribution/privacy:** monitor aggregates per device/inbound tag and its
   raw snapshot contains client addresses/ids; UM needs node/inbound tags from
   `expected_inbound_tags`, no raw client data, integer byte semantics, and
   bounded freshness (`ok/partial/unavailable`).
5. **Deployment coupling:** monitor-v2 is a separately deployed optional product
   (repo 0.10.0; documented production 0.3.0); its internal interfaces are not
   frozen for UM consumers.

## 4. Future options (not implemented in B4)

- **Preferred if traffic is reprioritized:** a separately reviewed monitor-v2
  change that makes the existing non-root monitor write a versioned, sanitized,
  read-only export (per-inbound active count + cumulative up/down bytes +
  explicit `lower_bound`/epoch/`stale` markers; no IPs/ids), served as a file or
  loopback GET behind a read-only scoped token. UM would need a **contract
  amendment** for a new source (`local_readonly`/`monitor`) and lower-bound
  semantics before submitting traffic; the service.api secret stays inside the
  monitor and no new write-credential process is introduced.
- systemd `LoadCredential` could deliver a monitor export token to `umagent`
  without changing existing file permissions, but credential delivery is not
  authorization and a versioned source audit would still be required.
- Rejected now: monitor admin password/session reuse; reading sboxweb/root
  files via permission expansion; collector-loop mode (drops production
  dashboard); direct/write-capable service.api; journal reader (no bytes);
  `sbox-cm`.

## 5. Current decision / work items on #127

- Keep Linux `singbox_api` **disabled/unavailable** and traffic `unavailable`;
  do not display UNKNOWN/UNAVAILABLE as zero/healthy in UM-D.
- Keep Linux Reality/Hysteria2 real traffic collection as a **pre-production
  functional blocker**.
- Future work, only after a new Owner decision: read-only export contract,
  source authorization proof, protocol attribution, cumulative/lower-bound
  semantics, real Reality/Hysteria2 inbound acceptance, and no security-gate
  reduction. No `monitor-v2` modification or permission broadening is authorized
  by B4.

## 6. Evidence references

`monitor-v2/collector.py`, `api_bridge/singbox_stream.py`,
`web/incident_history.py`, `web/server.py`, `deploy/singbox-monitor.service.in`,
`deploy/README.md`; UM `docs/um/um-b3-singbox-serviceapi-audit.md`,
`docs/um/um-127/10-owner-decisions-rev6.md`, `docs/um/um-a/04-node-protocol-v1.md`
and the frozen traffic/config schemas. The investigation was static/read-only.
