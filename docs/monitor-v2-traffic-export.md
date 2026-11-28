# Restricted read-only traffic export (UM-LT, monitor-v2)

Status: OPTIONAL, **default DISABLED**. Implemented in the existing production
web-mode runtime (`webapp.py serve` → `Collector` → `SnapshotBroker`) for the
local Linux Go Agent of UM-LT. It publishes a bounded, sanitized, atomically
replaced JSON file; it is **not** an HTTP API and it never exposes the sing-box
`service.api` secret or raw Monitor state.

Related contract: rev-7 `traffic_observation` (consumer side:
`um/internal/linuxobs/monitor_export.go`, `um/internal/contract/traffic.go`).

## 1. Enablement (operator-only, restart-only)

```bash
# monitor-v2/webapp.py serve ...
--traffic-export-file /run/singbox-monitor-export/traffic.json \
--traffic-export-inbound vless-in:reality \
--traffic-export-inbound hy2-in:hysteria2
```

- `--traffic-export-file PATH`: **absolute** path only. Relative paths are
  refused; there is NO `/tmp` or cwd fallback. The parent directory must
  already exist and must not be a symlink; an existing final path must be a
  regular non-symlink file. This is the ONLY accepted source of the path
  (never center/agent/HTTP supplied).
- `--traffic-export-inbound TAG:KIND`: repeatable operator allow-list pair.
  At least 1 and at most 8; `KIND` is exactly `reality`, `hysteria2` or
  `other`; tag grammar `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; duplicate tags are
  refused. ONLY these configured tags can ever appear in the file.
- Flags absent ⇒ feature completely dark: no writer object, no thread, no
  queue, no file read/write/create. Nothing in the dashboard, collector or
  broker behavior changes.
- Misconfiguration (file without inbound list, relative path, symlinked
  directory/final path, non-regular existing file, missing parent, unwritable
  parent on POSIX) is a **startup failure** (`exit 2`, explicit stderr
  message). The monitor never silently runs with the feature off when asked.
- Enable/disable is restart-only; there is no runtime toggle and no env-var
  path. Production packaging: see §6.

With the feature enabled the monitor removes any leftover export file from a
previous process **before serving**, then generates a **new random
`source_epoch`** (32 lowercase hex) for this process.

## 2. Exported document (`schema_version` 1)

Exactly these top-level members (no others; the consumer rejects unknown
members):

| field | type | meaning |
| --- | --- | --- |
| `schema` | string | always `singbox-monitor-traffic-export` |
| `schema_version` | int | always `1` |
| `source` | string | always `monitor-v2` |
| `source_epoch` | string | new 32-lowercase-hex token **per monitor process**; a change means counters restarted at a new observation epoch |
| `sequence` | int | monotonic per process, first publication `0`, `+1` per successful publication |
| `generated_at` | int unix s | publication time |
| `observed_at` | int unix s | observation time; always `<= generated_at` |
| `monitor_stale` | bool | monitor itself declares the counters stale; the agent marks freshness stale |
| `monitor_last_success_at` | int unix s \| null | last successful service.api batch; **non-null whenever `monitor_stale` is false** |
| `counter_scope` | string | always `observation_epoch` (NOT daemon lifetime) |
| `exactness` | string | always `lower_bound` (observed bytes are lower bounds) |
| `active_connections` | int \| null | sum over the configured inbounds only |
| `rate_window_seconds` | number \| null | nominal window behind the rate samples; non-null whenever any rate is non-null |
| `inbounds` | array | one entry per **operator-configured** pair, in configured order |

Each `inbounds[]` entry has exactly:

| field | type | meaning |
| --- | --- | --- |
| `inbound_tag` | string | configured inbound tag (allow-list only) |
| `kind` | string | configured `reality` / `hysteria2` / `other` |
| `observed_uplink_bytes` | int \| null | exact safe integer (`0..9007199254740991`) or null |
| `observed_downlink_bytes` | int \| null | same |
| `uplink_observed_rate_bps` | number \| null | observed rate estimate, null when unavailable/stale |
| `downlink_observed_rate_bps` | number \| null | same |
| `active_connections` | int | active lifecycles for that configured tag |
| `observed_at` | int unix s | `<= generated_at` |
| `quality` | string | `lower_bound`, `partial` or `unavailable` |

Rules pinned by tests and by the consumer:

- **No raw data**: no IP addresses, ports, UUIDs, connection ids, user/device
  names, proxy names, inbound types beyond the operator-declared `kind`,
  config, error strings or secrets. The wire shape is an allow-list, not a
  serialization of Monitor state.
- **Null means unavailable, never zero.** A tag that has not produced traffic
  since the process started appears with null counters, `active_connections: 0`
  and `quality: "unavailable"`.
- **Exact safe integers only.** Counters are exact Python integers internally
  (protobuf int64/uint64). A counter outside `0..2**53-1` is published as null
  (`quality: "partial"`); it is never rounded through float64 and never
  clamped. The legacy dashboard snapshot keeps its historical float formatting
  independently.
- **Stale monitor**: counters may be kept, but every observed row becomes
  `quality: "partial"` and all rates are null; configured tags with NO
  observation at all are **omitted** while stale (a stale monitor cannot vouch
  for an "unavailable" reading either; the consumer fills any missing expected
  tag as unavailable). Before the collector's first successful batch the
  export declares itself stale (a monitor that never succeeded cannot claim
  freshness).
- **Rates** are observed per-stream estimates summed over active lifecycles;
  they are null when there is no valid rate window (stream interval outside
  `(0s, 3600s]`), when stale, or when no UPDATE sample was observed. Null
  rates are never fabricated as zero.
- `observed_at <= generated_at` for the document and every row.

## 3. Publication / file semantics

- Single writer thread (`monitor-traffic-export`), fed by the SnapshotBroker
  publisher with a **sanitized projection** from the tracker's single
  accumulator (no second collector, no duplicate accounting). Publisher side
  is non-blocking: a bounded queue holds at most ONE pending projection; a
  newer projection drops the older one. Export I/O can never stall the
  dashboard/collector.
- The temp file is created in the **same directory** as the final path,
  mode `0640`, `fsync`ed, then atomically `os.replace()`d over the final path.
  Readers therefore always see a complete JSON document (previous complete
  file or new complete file, never partial). A failed write keeps the previous
  complete file and is rate-limited on stderr (one generic line per 60 s, no
  path/payload) — the writer thread keeps running and the dashboard is
  unaffected.
- Document is bounded: at most 8 inbounds, at most 64 KiB serialized.
- **Durability tradeoff**: the file itself is fsynced before the rename, so
  its contents survive a crash. The directory is fsynced best-effort only; a
  power loss in the tiny rename→dir-flush window may lose the latest
  publication (previous complete file remains, or the file is absent on the
  first publication). Partial JSON can never be exposed.

## 4. Permissions, user and group (Linux)

The monitor publishes as the `singbox-monitor` service user (packaged:
`sboxweb`). The local agent must be able to read the file but nothing else:

```bash
# One-time operator setup, NOT performed by the installer or the monitor:
groupadd --system sboxmon-export
usermod -aG sboxmon-export <local-agent-service-user>
install -d -m 2750 -o sboxweb -g sboxmon-export /run/singbox-monitor-export
```

- `2750` (setgid) makes the published file group `sboxmon-export`; the monitor
  opens the temp file with mode `0640`, so owner (`sboxweb`) writes and
  `sboxmon-export` reads. No world/other access.
- The dedicated `sboxmon-export` group contains ONLY the local agent's service
  user (never root, never interactive/login users). The agent reads the file
  read-only; it never gets shell access to the monitor user.
- The directory is created by the operator, not by the installer/monitor. If
  it is absent, no export path exists and the unit stays valid (see §6).
- `/run` is tmpfs: after a host reboot the operator must recreate the
  directory (systemd-tmpfiles drop-in or install script); an absent path means
  the export is disabled/unavailable, never silently unsafe.

## 5. Consumer contract for the local Go agent

- Accept exactly `schema == "singbox-monitor-traffic-export"` and
  `schema_version == 1`; reject the file (freshness `unavailable`) otherwise.
- Validate all 14 top-level members and all 9 inbound members as required
  (closed object; unknown members are rejected).
- Treat a changed `source_epoch` as a counter restart; within one epoch require
  a strictly increasing `sequence` (or a newer `observed_at`).
- Treat `monitor_stale: true` as "not fresh"; freshness is stale at best, and
  rates are null. A file older than the agent's freshness bound is stale, and
  beyond its max age it is unusable (never reused as fresh).
- A missing/partial/invalid file degrades to an honest `unavailable`
  observation with null counters — never a zero/total claim.
- Counters are observed **lower bounds** in the monitor observation epoch, not
  daemon-lifetime totals.

## 6. Packaging / systemd (existing unit)

`monitor-v2/deploy/singbox-monitor.service.in` re-opens exactly one additional
writable path, prefixed with `-` so a default install with no export directory
is untouched:

```ini
ReadWritePaths=-/run/singbox-monitor-export
```

The packaged unit does NOT pass the export flags; enabling the feature is a
deliberate operator act (e.g. an explicit `monitor-service` override or a
future reviewed packaging ticket) that names both the absolute file path and
the full inbound allow-list. `monitor-v2/deploy/lib/monitor-deploy-lib.sh`
stages the `export/` payload from a frozen 3-file manifest as part of the
monitor runtime (webapp imports it), and packaging tests assert the staged set.

## 7. Limits / non-goals

- No runtime toggle, no config hot-reload, no export while monitor is stopped.
- No second collector, no REST/HTTP export surface, no service.api/secret for
  the agent, no mutation of sing-box.
- Counters reset when the monitor process restarts (new `source_epoch`);
  consumers must treat the reset as a new observation epoch, not as traffic
  loss.
- Dashboard/collector/broker behavior is byte-for-byte unchanged when the
  flags are absent; existing E1/E2 regressions remain the gate.

## 8. Tests

`tests/test-monitor-v2-traffic-export.py` (stdlib unittest) covers the exact
integer precision path, null-vs-zero, stale behavior, allow-list/tag/kind
rejection, duplicate and max-8 enforcement, sanitization sentinels, atomic
replacement under concurrent readers, mode `0640` (POSIX), symlink/path
rejection, startup stale-file removal, new `source_epoch`, sequence
monotonicity, disabled = no file, bounded document, concurrent-reader
atomicity, broker containment (export failure cannot kill the publisher) and
a rev-7 consumer-compatibility projection check.
