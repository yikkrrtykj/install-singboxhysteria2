# Monitor v2 Integration — Round 0 Record

Status: **DRAFT — Round 1 runtime wiring + Round 1.1 hardening implemented, awaiting review.**
This document records verified code facts of the integration tree. Round 0 /
0.1 assembled the four frozen tracks and closed Linux CI; Round 1 wired the
reviewed E2 web runtime into the reviewed Packaging runtime (I0-2/I0-3/I0-4
and the secret runtime contract); Round 1.1 added five fail-closed
integration-hardening fixes (service-owned state tree boundary, no root
mutation of `auth.json`/`access.json`, web health identity check, strict poll
contract, clean `web-setup` environment). No VPS run, no production change,
no E3.

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

**Authoritative gate: GitHub Actions Ubuntu (`ubuntu-latest`), run on this
branch.** Local Windows Git Bash numbers are a development baseline only:
Windows cannot represent the flock / systemd / POSIX-metadata semantics these
suites assert, so its Phase C/D/S0 failures are an environment artifact. The
frozen-branch control comparison there showed zero local integration
regression (kept as a development record, not a verdict).

Linux CI (PR #16 checks) — **Round 1 head, all green**:

| Gate | Linux CI result | vs Round 0.1 |
|---|---|---|
| Phase C | **121/121 PASS** | unchanged |
| Phase D | **105/105 PASS** | unchanged |
| S0 baseline | **133/133 PASS** | unchanged |
| E1 | **188/188 PASS** | unchanged |
| E2 | **272/272 PASS** | +20 new R1 assertions (health export) |
| E4 | **161/161 PASS** | unchanged |
| Packaging fixture | **381/381 PASS** | +74 new R1 assertions |
| Packaging root metadata | **385/385 PASS** | +76 new R1 assertions |

No existing assertion was removed or weakened; every change is additive. The
E2 suite's `EXPECTED_PASS` moved 252 → 272 and the packaging suite grew with
the Round 1 coverage in R1-9 (staging, persistence, web runtime, secret
matrix, bind contract, health probe, web-setup).

Round 0.1 adds E1/E2/E4 as mandatory steps of the `shell-tests` workflow (no
`continue-on-error`), so every future push of this PR re-proves them on
Linux alongside Phase C/D/S0.

Local Windows development baseline (supplementary, non-authoritative):
Phase C pass=72 fail=47, Phase D pass=56 fail=49, S0 pass=86 fail=31 —
failure sets byte-identical to frozen-branch control runs (only random
tmpdir names differ); E1 188/0, E2 252/0, E4 161/0, Packaging 130/0 all
green locally as well.

`bash -n install.sh`: PASS. `shellcheck -S warning` (install.sh, gateway,
all deploy scripts): PASS; also asserted inside the suites and re-run on
Linux CI.

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
E2 never reads `/root/sbox` (it only receives `--secret-file`).

Secret-resolution truth (code, not aspiration): `resolve_secret()`
(`monitor-v2/collector.py:698`) resolves in precedence order
`BOX_API_SECRET` env → `--secret-file` → `""`. It returns the empty string
— it does not fatal — when both are absent. Therefore:

- **At code level**, the E1/E2 collector supports unauthenticated API
  operation, for compatibility with a secret-less `service.api`.
- **The integrated production runtime DOES NOT permit that mode.**
  Packaging owns the fail-closed deployment gate: a configured
  `api.secret` must exist, be a regular file, and be readable, and
  **integrated web mode MUST NOT invoke `webapp.py serve` without an
  explicit `--secret-file`** (Round 1 hard invariant).
- **`BOX_API_SECRET` must not be injected via the systemd environment.**
  File-based delivery is the production contract: the secret never enters
  the unit file, never appears as a literal in process arguments, and
  never reaches the journal — only the secret *file path* is passed.
  Full chain:

```
sbconfig_server.json  service.api.secret
        ↓
/root/sbox/monitor-api.secret
        ↓
/etc/singbox-monitor/api.secret
        ↓
Packaging preflight verifies (regular file, readable, group-readable)
        ↓
ExecStart / monitor-service passes:
    --secret-file /etc/singbox-monitor/api.secret
        ↓
E2 webapp.py serve
```

### I0-2 — E2 entrypoint vs Packaging placeholder  ✅ RESOLVED (R1-1/R1-3)

The fake `app/web/serve` hook is **gone**. `monitor-service`'s `web` mode now
execs the real, already-reviewed entrypoint inside the immutable release:

```
exec env -u BOX_API_SECRET python3 <release>/app/monitor-v2/webapp.py serve \
    --listen <validated loopback host>  --port <validated port>  \
    --url "$SBMON_API_URL"  --secret-file "$SBMON_API_SECRET_FILE"  \
    --data-dir "$DATA_ROOT"  --health-file "$DATA_ROOT/state/health.json"  \
    --poll "$SBMON_WEB_POLL_SECONDS"
```

There is exactly ONE `Collector`, ONE `SnapshotBroker` and ONE service.api
stream consumer in the runtime. No second collector exists for health or
packaging. The staged release layout (R1-1) is one coherent tree:

```
app/monitor-v2/{collector.py, webapp.py, api_bridge/, web/{*.py, static/*}}
bin/{monitor-service, monitor-health}
lib/monitor-env.sh
```

`collector.py` exists exactly once (no duplicate independently-maintained
runtime tree); `collector-loop` compatibility mode points at the same file.
Staged Python validation now compiles `collector.py`, `api_bridge/*.py`,
`webapp.py` and `web/*.py`. Node.js is never a production installer
dependency (JS syntax stays a CI/development gate). `monitor-v2/mihomo` (E4)
is NOT staged.

### I0-3 — E2 persistence layout vs Packaging layout  ✅ RESOLVED (R1-2)

E2's model is now the single truth:

```
/var/lib/singbox-monitor/   sboxweb:sboxweb 0700   (E2 DATA ROOT)
  auth.json                 0600   admin hash + recovery hash
  access.json               0600   IP/CIDR whitelist
  state/                    0700
    health.json                    broker health export (minimal, R1-6)
    snapshot.json                  collector-loop compatibility only
```

Fresh installs create the data root and `state/` only — the legacy `auth/`
and `access/` **directories are no longer created**. Migration safety: a
pre-existing `auth/` or `access/` directory is preserved untouched (its
contents are never deleted, chown'ed, chmod'ed or repurposed), and
`auth.json` / `access.json` are never overwritten by
install/upgrade/repair/rollback (asserted byte-identical in the suite).

The deployed shim contract changed from `monitor-service <conf> <state-dir>`
to `monitor-service <conf> <data-root>`, and the systemd unit now passes
`/var/lib/singbox-monitor` explicitly (`ExecStart=... monitor-service <conf>
@SBMON_STATE_ROOT@`). `monitor-health` takes the same `<conf> <data-root>`
contract. No cwd/path inference anywhere.

### I0-4 — Web health vs snapshot-file health  ✅ RESOLVED via option (A) (R1-6/R1-7)

Chosen: **(A) a minimal private health state file written by the E2 broker.**
No second collector, no loopback-only internal surface, no stored admin
credential anywhere in the health path.

`SnapshotBroker` gained an OPTIONAL `health_file` parameter (default `None`;
standalone E2 without `--health-file` behaves exactly as before). On every
successful publisher tick it atomically rewrites a minimal record with
EXACTLY these keys:

```json
{"schema_version": 1, "snapshot_version": <int>,
 "published_at": "<UTC ISO>", "collector_stale": <bool>,
 "consumer_alive": <bool>}
```

Implementation contract: same-directory temp file + `fsync` +
`os.replace` (mode 0600); a failed write never leaves a partial JSON file
and **never kills the serving dashboard** (the external probe then observes
the file going missing/stale). The record carries no client/runtime payload
(no devices, connections, user, source, destination, `last_error`,
credentials or bearer material) and is never logged. This is asserted in the
E2 suite including a forced-failure case.

`monitor-health` in web mode reads ONLY this file (never `auth.json` /
`access.json`) and adds an **unauthenticated loopback identity probe**:

```
GET /api/v1/session      (no password, no cookie, no CSRF token,
                          no recovery key, no service.api bearer)
```

Round 1.1 hardened this from "any answer below 500 proves the dashboard is
alive" to a real **identity** check: the probe requires **HTTP 200** AND a
decodable **JSON object** carrying the minimal stable E2 session shape
(`authenticated` bool, `whitelist_allowed` bool, `version` non-empty string;
optional `password_configured`/`recovery_configured`/`remote_mode` bools). An
unrelated program on the port (404/401/403/500, or a foreign 200 body) is no
longer mistaken for the dashboard, and the response body is never emitted.
Signals reported: `service_active`, `api_url_valid`,
`api_reachable`, `broker_health{present,wellformed,age_seconds,age_stale,
collector_stale,consumer_alive,stale}`, `web_http`, `mode`, `overall`.
Exit: 0 healthy / 1 unhealthy (service inactive) / 2 degraded (bad API URL,
API unreachable, health missing/malformed/too old, `collector_stale`,
`consumer_alive=false`, or web endpoint unavailable). `collector-loop`
mode retains the original `snapshot` behavior unchanged.

### I0-5 — Web exposure boundary

Held: web binds `127.0.0.1:9191` only (`monitor-deploy-lib.sh:42`
`SBMON_WEB_BIND_DEFAULT=127.0.0.1:9191`; packaging test T13 asserts the conf
and unit never reference `0.0.0.0`). Round 0: no public listener, no firewall
mutation, no reverse proxy. Future canary via SSH tunnel / local curl only.

### I0-6 — E4 placement

Fact: `sbmon_stage_release` now stages the E1 collector **and** the E2 web
runtime (`app/monitor-v2/{collector.py, webapp.py, api_bridge/, web/}`,
asserted by the packaging suite) — but it still copies no E4 code. E4's
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

## Round 1 — runtime wiring (implemented)

Contracts closed: **I0-2** (real `webapp.py serve` entrypoint, no fake
`app/web/serve`), **I0-3** (E2 flat persistence model is the single truth;
data-root/`state/` only on fresh installs, legacy dirs preserved), **I0-4**
(one collector + minimal broker health export + unauthenticated loopback
liveness probe), and the **secret runtime contract** below.

### R1-5 secret contract (production)

`resolve_secret()` (`monitor-v2/collector.py:698`) is deliberately
**unchanged**: `BOX_API_SECRET` → `--secret-file` → `""`, no fatal. That is
the standalone E1/E2 API contract. Packaging owns the fail-closed
deployment gate instead:

- web mode REQUIRES `SBMON_API_SECRET_FILE` configured, and the file must be
  **present, a regular file (symlink rejected), readable and non-empty**;
- before exec, `BOX_API_SECRET` is **unset** (`exec env -u BOX_API_SECRET`)
  so the environment can never override or rescue the file contract;
- the secret value never enters argv, the environment, the unit file, stdout
  /stderr or the journal — only the secret **file path** is passed:

```
config service.api.secret
  -> /root/sbox/monitor-api.secret    root:root 0600
  -> /etc/singbox-monitor/api.secret  root:sboxweb 0640
  -> Packaging preflight (regular, readable, non-empty)
  -> ExecStart / monitor-service:  --secret-file /etc/singbox-monitor/api.secret
  -> E2 webapp.py serve
```

`ProtectHome` is not weakened and E2 never reads `/root/sbox`.

### R1-4 bind contract

`monitor-env.sh` validates the web bind with Python `ipaddress` (never Bash
colon-splitting). Accepted: `127.0.0.1:9191`, `localhost:9191`, `[::1]:9191`.
Rejected: `0.0.0.0`, private LAN and public addresses, malformed/overflowing
ports, userinfo, path/query/fragment, wildcard (`::`) and missing host/port.
Packaging does not use E2 remote/TLS mode.

### R1-8 web-setup

`install-monitor.sh web-setup` runs the reviewed `webapp.py setup
--data-dir /var/lib/singbox-monitor` **as the service identity** (under the
deployment lock), so `auth.json` / `access.json` are never root-owned. It
never auto-adds a whitelist entry, never accepts/generates a plaintext
password non-interactively, never logs the password or recovery key, and if
the service was active it restarts **only** `singbox-monitor` afterwards
(never sing-box). It is never run automatically by unattended install.
Round 1.1 tightened the environment and postcondition (see below).

### Round 1.1 — integration hardening (implemented)

Round 1.1 is a small integration-hardening round (no new architecture): five
fail-closed fixes with additive regressions. No existing assertion was
removed or weakened.

| # | Fix | Contract |
|---|---|---|
| **A** | Service-owned state tree privilege boundary | Root creates/confirms only the **top-level** data root (a real directory, never a symlink/non-directory) and converges it to `sboxweb:sboxweb 0700`. `state/` is created and mode-converged **as the service user** (`sbmon_ensure_state_tree_as_service_user`), never by root. A `state/` symlink or wrong-type entry fails closed, and a symlink race after the check cannot escalate because the mutation itself runs with `sboxweb` privileges. No recursive chown/chmod of the data root. `auth.json`/`access.json`/legacy `auth//access/` stay migration-safe. |
| **B** | No root mutation of `auth.json`/`access.json` | The post-`web-setup` root `chown`/`chmod` of the data root and flat access files was **removed**. The installer only runs a **non-destructive** postcondition (`sbmon_verify_service_owned_tree`); drift fails closed with a manual-fix hint (never auto-rescued). A setup failure reports honestly that partial persistence may have happened and never restarts the monitor. |
| **C** | Web health identity check | `monitor-health` web mode requires **HTTP 200 + a JSON object** with the minimal E2 session shape (`authenticated`/`whitelist_allowed` bool, `version` non-empty string); 404/401/403/500 or a foreign 200 body is **degraded**. No credential, no login dependency, body never emitted. |
| **D** | Strict poll contract | `SBMON_WEB_POLL_SECONDS` must be a **finite float > 0** (Python `float` parse in `monitor-env.sh`), shared by `monitor-service` (fail-closed before `exec webapp`) and `monitor-health`. `0`/`0.0`/negative/`NaN`/`inf`/`Infinity`/`.`/`1..2`/garbage/empty are rejected; absent defaults to `1`. Freshness uses `ceil(5 * poll + 15)` (no `${VAR%%.*}` truncation). |
| **E** | Clean setup environment | Production `web-setup` resolves the python binary as root (`command -v`) and runs the reviewed setup under an **explicit clean env** (`env -i`): only `HOME` (data root), a fixed approved `PATH` and `SSH_CONNECTION` are forwarded. `BOX_API_SECRET`, tokens/cookies and any arbitrary caller env are never inherited; password/recovery key never enter argv, env or logs. |

### Round 1 non-goals (status)

- VPS canary: **NOT RUN**.
- Production: **UNCHANGED**. Public 9191: **CLOSED**. TLS: not used by
  Packaging. Reverse proxy / firewall: untouched.
- E3: design only (`beb915a9`), not merged, not implemented.
- E4: still repo-only (not staged, not deployed); unchanged boundary.
- **I0-7 remains a hard PRE-E3 BLOCKER** (legacy `modify_singbox` /
  `process_doko` / `process_dokoko` / `process_ssko` still bypass
  `/root/sbox/config.lock`). Not addressed in Round 1 by design.
