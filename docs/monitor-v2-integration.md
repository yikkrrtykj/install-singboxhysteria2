# Monitor v2 Integration — Round 0 Record

Status: **DRAFT — awaiting Round 0 review.** This document records verified
code facts of the integration tree only. No runtime wiring, no VPS run, no
production change happened in Round 0.

## Inputs (verified before any merge)

| Ref | SHA | Verified |
|---|---|---|
| main (base) | `3c6120441ee99c74faeb41a8122897395b2d7c94` | yes |
| S0 `origin/feature/security-baseline-hardening` | `544f7e52930e2f721e692e39f593289e24f3c6cf` | yes |
| E2 `origin/feature/proxy-monitor-web` | `b52b42c1b42eec2b799b49e1c79e73922ea6b339` | yes |
| E4 `origin/feature/proxy-monitor-mihomo` | `5540723ece311917bb0d9e7b824048927137eb1b` | yes |
| Packaging `origin/feature/monitor-packaging` | `29538c6db03dcc05033c7d4287bc8a664690d072` | yes |
| E3 design `origin/feature/monitor-v2-e3-design` | `beb915a9c948c37d369d701fbfff21b68efb1c98` | yes (not merged — design only) |

Merge order (fixed): main → S0 → E2 → E4 → Packaging. All merges `--no-ff`.

## Merge log

| Step | Integration head | Conflicts |
|---|---|---|
| after S0 | `5472f5180c92dc938919b9db177f34d52dd06ddc` | none |
| after E2 | `b230671a12338cefe956068c13ead95a0f23246f` | none |
| after E4 | `05d561973453fce863ff3d3bda9d51908e739306` | 1: `monitor-v2/README.md` |
| after Packaging | see `git log -1` on the branch | none |

E4 README conflict resolution (per-hunk rationale): the "已知未实现" list had
diverged — E2 added the bullet「可信反代（trusted proxy）场景下的白名单来源设计」;
both sides kept the「expected source IP 机械比对」bullet with different
punctuation. Resolution keeps **both** E2 bullets (they are E2 facts) and
appends E4's Phase E4 section unchanged. No code conflict; all four tracks'
files merged byte-identical to their branch heads (verified by
`git diff <branch-head> HEAD` per track: `install.sh` == S0, `monitor-v2/mihomo` == E4,
`monitor-v2/deploy` + packaging test == Packaging).

## Regression results

Test environment note: these gates were executed on a Windows Git Bash host
(no WSL, no systemd, no `/root/sbox`). `test-phase-c.sh`,
`test-phase-d.sh` and `test-security-baseline.sh` depend on POSIX runtime
semantics that this host cannot provide; the identical failure sets reproduce
on the **frozen, already-reviewed branch worktrees** (control runs), so the
counts below are environment baselines, not integration regressions. The
monitor-v2 gates (E1/E2/E4/Packaging) are self-contained and fully green.

| Gate | Integration tree | Frozen-branch control | Verdict |
|---|---|---|---|
| Phase C | pass=71 fail=47 | S0 control: pass=71 fail=47 | match — 0 regression |
| Phase D | pass=55 fail=49 | S0 control: pass=55 fail=49 | match — 0 regression |
| S0 baseline | pass=85 fail=31 | S0 control: pass=85 fail=31 | match — 0 regression |
| E1 | **pass=188 fail=0** | 188/0 on every track | GREEN |
| E2 | **pass=252 fail=0** | E2 control: 252/0 | GREEN |
| E4 | **pass=161 fail=0** | E4 control: 161/0 | GREEN |
| Packaging | **129 passed 0 failed** | Packaging control: 129/0 | GREEN |

`bash -n install.sh`: PASS. shellcheck: PASS (see PR checks; no new findings
introduced by integration).

S0 spot checks confirmed in code: `/root/sbox/config.lock` fail-closed;
`service.api` listen `127.0.0.1:9091` with nonempty secret
(`install.sh:3118`); `/root/sbox/monitor-api.secret` written root:root 0600
(`install.sh:3138`); derived-file repair is fail-closed with config as truth
(`install.sh:1493-1512`); Reality/HY2 credentials untouched by integration.

---

## Cross-track contract audit (I0-1 … I0-7)

### I0-1 — S0 secret → Packaging → E2 secret bridge

Implemented chain (verified in code):

```
sbconfig_server.json  service.api.secret      (runtime truth)
        │  root installer derives
        ▼
/root/sbox/monitor-api.secret               root:root 0600   (install.sh:3138)
        │  root installer derives (sbmon_sync_api_secret,
        ▼  monitor-deploy-lib.sh:365, fail-closed drift repair)
/etc/singbox-monitor/api.secret             root:sboxweb 0640
        │
        ▼
E2 webapp.py serve --secret-file ...
        │
        ▼
127.0.0.1:9091  (service.api, loopback-only)
```

Rules held: config = runtime truth, both secret files = derived copies
(enforced in `install.sh` and `monitor-deploy-lib.sh` drift repair);
E2 never reads `/root/sbox` (it only receives `--secret-file`);
no auth fallback exists in E2 auth code.

### I0-2 — E2 entrypoint vs Packaging placeholder  ⚠ ROUND 1

Packaging's `monitor-service` (line 122-129) execs `$APP_DIR/app/web/serve`
when present, else exits 21 with "no app/web/serve entry deployed (E2
pending)". The real E2 entrypoint is `monitor-v2/webapp.py serve`
(subcommands `setup` / `serve`; `serve` runs ONE E1 `Collector` →
`SnapshotBroker` → HTTP/SSE, `webapp.py:248`).

Round 1 MUST wire `monitor-service`'s web mode to the real entrypoint
(`exec python3 webapp.py serve ...`). No fake `app/web/serve` server logic
may be created; a release-tree wrapper that only execs the real webapp is
acceptable. Round 0 deliberately leaves `web` fail-closed (exit 21).

### I0-3 — E2 persistence layout vs Packaging layout  ⚠ ROUND 1

Verified mismatch:

- E2: `<data-dir>/auth.json`, `<data-dir>/access.json`
  (`webapp.py:11`, `auth.py:194`, `access.py:74`), default data-dir
  `/var/lib/singbox-monitor` (`webapp.py:42`), and
  `ensure_private_dir(data_dir)` tightens the data-dir itself to 0700
  (`storage.py:16`).
- Packaging: `mkdir -p $SBMON_STATE_ROOT/{state,auth,access}`
  (`monitor-deploy-lib.sh:270`).

Round 1 must pick ONE truth. Recommendation (migration-safe convergence):
adopt E2's flat model —

```
/var/lib/singbox-monitor/   sboxweb:sboxweb 0700
  auth.json                 0600
  access.json               0600
  state/                    0700
```

Packaging stops creating new `auth/` / `access/` dirs; existing empty dirs on
old installs are left in place (not a destructive cleanup). Round 0: record
only, no code change.

### I0-4 — Web health vs snapshot-file health  ⚠ ROUND 1

- Packaging `monitor-health` reports `service_active` / `api` /
  `snapshot` (file age + staleness) from the collector-loop's
  `state/snapshot.json`; README documents `web_http` as
  `not-applicable` in collector-loop mode.
- E2 keeps everything in memory: one `Collector` thread →
  `SnapshotBroker` publishes a decorated snapshot per poll tick;
  **no snapshot file** (`broker.py:75-132`).

Round 1 must keep exactly ONE collector and bridge health via either
(A) a minimal private health state file written by the E2 broker, or
(B) a dedicated loopback internal health surface. Choice pending a fresh
review of broker/server code at wiring time. Forbidden: a second E1
collector for health; feeding authenticated `/api/v1/snapshot` from a
systemd probe with a stored admin session/token. The health path must not
depend on browser admin credentials.

### I0-5 — Web exposure boundary

Held: web binds `127.0.0.1:9191` only (`monitor-deploy-lib.sh:42`
`SBMON_WEB_BIND_DEFAULT=127.0.0.1:9191`; packaging test T13 asserts the conf
and unit never reference `0.0.0.0`). Round 0: no public listener, no firewall
mutation, no reverse proxy. Future canary via SSH tunnel / local curl only.

### I0-6 — E4 placement

Fact: `sbmon_stage_release` (`monitor-deploy-lib.sh:408-431`) stages ONLY
`collector.py` + `api_bridge/` (plus deploy shims). E4's
`monitor-v2/mihomo/` is repo-only / optional client component; it is NOT in
the server release, and must NOT be mechanically added in Round 1. E4 is
client-side, optional, loopback-only, read-only enrichment; it is not server
Device identity, not lifecycle source, not fallback identity. Identity stays:
Device = `Connection.user`, Protocol = inbound, Lifecycle = `Connection.id`.
E4 integration boundary in Round 0: code coexists, tests pass (161/0), and it
cannot mutate E1 server truth (fixed enrichment-key whitelist,
`model.ENRICHMENT_KEYS`; GET-only transport). Final client delivery/packaging
is a later integration decision — define the actual consumer first.

### I0-7 — Pre-E3 config mutation blocker  🛑 BLOCKER BEFORE E3 ENABLEMENT

Verified: `modify_singbox` (`install.sh:2259`), `process_doko` (2373),
`process_dokoko` (2430), `process_ssko` (2485) all read and write
`/root/sbox/sbconfig_server.json` directly via `jq` and contain **zero**
`with_config_lock` calls — they can bypass `/root/sbox/config.lock`.
Before E3 (Web Client Manager) enablement, choose:

- **A (recommended):** migrate all of these flows into the same fail-closed
  `with_config_lock` used by Phase C / Phase D, so that CLI Phase C, legacy
  mutation, Phase D migration and the future E3 helper share one
  `/root/sbox/config.lock`; or
- B: disable these legacy mutation flows while web management is active.

Round 0 changes nothing here; status is BLOCKER BEFORE E3 ENABLEMENT.

---

## Cross-track invariants (post-merge audit)

| Invariant | Result |
|---|---|
| Device identity still API USER | PASS (E1 untouched; E4 whitelist) |
| Browser cannot reach 9091 | PASS (no 9091 in `web/static`; only server-side Collector connects) |
| E4 cannot provide Device identity | PASS (fixed key whitelist; display-only `selected_proxy`) |
| E2 does not write sbconfig_server.json | PASS (zero `sbconfig` references in `webapp.py`/`web/`) |
| Packaging does not restart sing-box | PASS (packaging test: mocked systemctl log contains no sing-box operation) |
| Packaging reads /root/sbox only via secret anchor | PASS (`SBMON_API_SECRET_SOURCE` only; lib header forbids touching /root/sbox) |
| service.api loopback-only | PASS (`127.0.0.1:9091`) |
| 9191 loopback-only | PASS (test T13) |
| No firewall mutation | PASS |
| No credential rotation | PASS — Reality UUID / HY2 password / Reality private key / ports / cert paths untouched: `install.sh` byte-identical to S0 head; no other track touches them |
| No new database | PASS (E2 persistence is auth.json/access.json only) |

## Round 0 non-goals (status)

- VPS canary: **NOT RUN** — Round 1 must first resolve I0-2/I0-3/I0-4 and the
  final systemd `ExecStart`; a VPS run before that has no value.
- Production: **UNCHANGED**. Public 9191: **CLOSED**.
- E3: design only (`beb915a9`), not merged, not implemented.
- Round 1 blockers: I0-2 entrypoint wiring, I0-3 persistence convergence,
  I0-4 health bridge (one-collector rule), final `ExecStart`; I0-7 stays a
  hard blocker in front of E3 enablement.
