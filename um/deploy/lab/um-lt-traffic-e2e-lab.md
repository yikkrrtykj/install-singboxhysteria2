# UM-LT real-protocol traffic E2E lab

Real-protocol end-to-end proof of the UM-LT Linux traffic-export data path.
This lab uses a **real sing-box server with a real Reality (VLESS) inbound and a
real Hysteria2 inbound**, **real sing-box clients**, the **real monitor-v2 web
runtime**, the **real Linux Go agent**, the **real Go center** and **real
SQLite**. Credentials, certificates and test services are synthetic; every
listener is loopback; the only external network operation is downloading the
pinned official sing-box release with SHA-256 verification.

## Files

| Path | Purpose |
| --- | --- |
| `um/deploy/lab/linux-traffic-e2e-lab.sh` | CI/local entrypoint wrapper (bash `-n` clean). |
| `um/deploy/lab/linux_traffic_e2e_lab.py` | Orchestrator: pinned download, config generation, process management, all stages, assertions, artifacts, cleanup. |
| `um/deploy/lab/um_lt_lab_lib.py` | Pure-stdlib helpers: synthetic credentials, sing-box config builders, closed contract validators, privacy scanners, read-only SQLite helpers, loopback payload/TLS capture servers, capture proxy. |
| `tests/um-lt/test_lab_contract.py` | 58 stateless unit/static tests: SHA pinning, config invariants, export/report validators, privacy scanners, RFC 7748 x25519 fallback, SQLite aggregation, capture proxy, no-production-resource guards. Runs without sing-box/network/Go. |
| `.github/workflows/um-lt-traffic-lab.yml` | Ubuntu 24.04 workflow: Go 1.27.4, Python 3.12, static tests, self-check, pinned sing-box download+SHA, explicit Go build, full lab, artifact upload. |

## Exact commands

```bash
# Static self-check: config generation, `sing-box check` when a binary is
# available, closed-contract validators, privacy/no-production guards.
python3 um/deploy/lab/linux_traffic_e2e_lab.py --self-check

# Local layout check against a non-pinned local sing-box binary (NEVER real
# lab evidence -- version mismatch is reported, not hidden):
UM_LT_LAB_SELFCHECK_UNPINNED=1 \
  python3 um/deploy/lab/linux_traffic_e2e_lab.py --self-check \
  --singbox-bin /path/to/sing-box

# Stateless tests (no sing-box, no Go, no network):
python3 tests/um-lt/test_lab_contract.py

# Full real-protocol lab (Linux x86_64, Go, Python >= 3.10, curl):
bash um/deploy/lab/linux-traffic-e2e-lab.sh \
  --workdir "$RUNNER_TEMP/um-lt-lab-work" \
  --artifacts "$RUNNER_TEMP/um-lt-artifacts"

# Run a subset (setup/infrastructure still boots):
python3 um/deploy/lab/linux_traffic_e2e_lab.py --stage main-path --stage replay-duplicate
python3 um/deploy/lab/linux_traffic_e2e_lab.py --list-stages
```

Exit codes: `0` PASS, `1` failed assertion, `2` precondition/failure-before-run,
`3` SKIPPED. A skip is only possible with `UM_LT_LAB_ALLOW_SKIP=1` and prints
`SKIPPED (not a PASS)`; missing binaries/flags/rev-7 schemas otherwise fail with
an actionable message.

## Pinned real protocol binary

* `sing-box 1.14.5` `sing-box-1.14.5-linux-amd64.tar.gz`
* URL: `https://github.com/SagerNet/sing-box/releases/download/v1.14.5/sing-box-1.14.5-linux-amd64.tar.gz`
* SHA-256: `ca57e405be6b7dc79a0efa91823a0cc4d81138cbe4a9aacbfd749c65e6fca3b2`
  (cross-checked against the GitHub release API asset `digest`).
* A user-supplied `--singbox-bin`/`SINGBOX_BIN` must report exactly 1.14.5; a
  different protocol build is never substituted silently.

## Lab topology (all loopback, synthetic credentials)

```
localhost HTTP fixture (known payload bytes)          local TLS camouflage target
        |                                                    ^ Reality handshake
        v                                                    |
curl --socks5-hostname --> real sing-box client (Reality) --+
curl --socks5-hostname --> real sing-box client (Hysteria2) --+
                                             |
                          real sing-box server: vless-in [reality] tcp,
                          hy2-in [hysteria2] udp, official service.api tcp
                                             |
                          real monitor-v2 `webapp.py serve`
                          (--traffic-export-file/--traffic-export-inbound,
                           atomic restricted JSON export, loopback dashboard)
                                             |
                          real Linux `um-agent` (--monitor-export-file,
                          center source `monitor_export`)
                                             |
                          capture proxy (records signed report requests)
                                             |
                          real `um-center` ingest/admin/web + real SQLite
```

## Stages and key assertions

| Stage | Asserts |
| --- | --- |
| `default-disabled` | monitor started without export flags creates no export file; dashboard/session/snapshot healthy. |
| `agent-version-gate` | OD-LT-14: the center stores `monitor_export=true` but only emits the optional key after the first authenticated rev-7 agent snapshot; the real agent first emits a rev-5 body, then a rev-7 unavailable observation (honest, not zero-filled). |
| `main-path` | 6 MiB+1 MiB via Reality and 8 MiB+2 MiB via Hysteria2; curl-measured payload vs export/report/DB lower bounds; upload→uplink, download→downlink; per-inbound attribution and no cross-attribution; active=0 after settle; freshness=fresh, availability=ok, `counter_scope=observation_epoch`, `exactness=lower_bound`, base `traffic: []`, `contract_revision=7`. |
| `center-query` | rev-7 SQLite tables exist with normalized allow-list columns; per-epoch series (never summed across epochs); no raw export JSON / secret / IP in rows; admin `node show` returns the rev-7 snapshot; `/web/api/traffic/*` exists and fails closed 401/403 without Cloudflare Access credentials. |
| `monitor-restart` | new `source_epoch`, sequence restarts, leftover file removed, both epochs stored separately, no cross-epoch fabricated total. |
| `singbox-reset` | server stop ⇒ `monitor_stale`, rows `quality=partial`, no fabricated rates, agent declines to fresh; server restart ⇒ fresh recovery, no fake peak, real business traffic still works; client restart covered. |
| `export-tamper` | truncated/missing export ⇒ all-zero sentinel epoch, `freshness/availability=unavailable`, empty observation, no invented rows; old structurally valid export ⇒ `stale`, lower-bound counters retained, never fresh. |
| `replay-duplicate` | verbatim replay of a captured signed report returns `result=duplicate`, stores no duplicate report/observation rows, second replay still duplicate. |
| `agent-center-spool` | center outage: agent spools durably; center restart: exactly-once drain and unique report IDs; agent restart: generation advances, no duplicates. |
| `config-source` | center `collect.monitor_export=false` ⇒ rev-5 body (no `contract_revision`, empty traffic, traffic unavailable) and no traffic rows; re-enable resumes fresh observed rows. |
| `allowlist-change` | restricted monitor allow-list ⇒ missing center-authorized tag is unavailable/null (never zero) and availability partial; center expected-tag shrink ⇒ only authorized rows; restore resumes hy2 lower bound; no cross-attribution. |
| `connection-shapes` | short/long/idle/multi connections: plausible active counts (in-flight ≥1, idle held ≥1, bounded multi, settle to 0), all business connections succeed, counters bounded by measured payload. |
| `concurrent-protocols` | simultaneous both-protocol transfers: each direction reaches its measured payload, deltas bounded (no cross-attribution), uplink path covered. |
| `monitor-after-traffic` | monitor started after traffic: new epoch, observation-epoch scoped counters (no lifetime total), fresh/ok after new traffic, no fabricated peak. |
| `final-verification` | every saved export + captured report is privacy-clean and closed; `singbox_api` stays disabled; expected tags are the real inbounds; unique report rows; dashboard alive; sanitized summary written. |

## Measurement layer (documented honestly)

* Independent expected payload: `curl` writes `%{http_code} %{size_download}
  %{size_upload}` through the real socks inbound. This is the **HTTP payload**
  measurement.
* Direction names are the official service.api names: **uplink** = client→server
  (upload), **downlink** = server→client (download). The lab proves this mapping
  explicitly by measuring download and upload separately.
* Observed counters include real protocol framing overhead (measured ~100-120
  bytes per MiB-scale transfer) and may lag until a connection is finalized, so
  assertions use: observed ≥ measured payload (after settling) and observed ≤
  measured payload + `max(128 KiB, 2%)` overhead tolerance. This still catches
  cross-attribution and double counting.
* The official service.api exposes **no per-inbound daemon-lifetime counter**.
  All counters are **observed lower bounds scoped to the monitor observation
  epoch** (`counter_scope=observation_epoch`, `exactness=lower_bound`); they are
  never rendered or summed as lifetime totals. Cross-epoch sums are refused by
  the lab's assertions.

## Interface assumptions (reconciled rev-7)

Verified against the shared-worktree implementation during development:

* monitor-v2 export file: `schema="singbox-monitor-traffic-export"`,
  `schema_version=1`, `source="monitor-v2"`, `source_epoch` 32hex,
  `sequence`, `generated_at`≥`observed_at`, `monitor_stale`,
  `monitor_last_success_at`, `counter_scope="observation_epoch"`,
  `exactness="lower_bound"`, `active_connections`, `rate_window_seconds`,
  `inbounds[]` with `observed_uplink_bytes`/`observed_downlink_bytes`,
  observed rates, `active_connections`, `observed_at`, `quality`. Closed
  allow-list; null means unavailable, never zero. The superseded
  `export_version` draft shape is rejected with an actionable message.
* monitor-v2 argv: `--traffic-export-file ABS_PATH` plus repeatable
  `--traffic-export-inbound TAG:KIND` (fatal when the file is set without at
  least one pair; default disabled creates no writer/thread/file).
  Producer-final stale rule: while `monitor_stale=true` every emitted row is
  `quality=partial` with counters kept and rates null, and configured tags
  never observed in the epoch are omitted (the agent fills missing expected
  tags as unavailable); fresh exports list never-observed tags with
  `quality=unavailable` and null counters.
* Agent: `um-agent run` flag `--monitor-export-file` (env
  `UM_AGENT_MONITOR_EXPORT_FILE`); center source key
  `collect.monitor_export`; expected tags `vless-in/reality` and
  `hy2-in/hysteria2`; report `traffic_observation` uses the report-only token
  `monitor_readonly_export`, `contract_revision=7`, lower-bound member names.
* Center: rev-7 schema files `docs/um/contracts/v1/rev7/report-snapshot.rev7.schema.json`
  and `docs/um/contracts/v1/rev7/agent-config.rev7.schema.json`; normalized tables
  `traffic_observation_reports` / `traffic_observations`; query routes under
  `/web/api/traffic/*` on the loopback Web listener.
* Authenticated `/web/api/traffic/*` RBAC query behavior requires Cloudflare
  Access and is covered by the Go web tests; this offline lab asserts the route
  exists and fails closed without credentials, and verifies normalized
  attribution through read-only SQLite plus the admin `node show` query surface.
  This limitation is stated in `summary.json`.

## Local results (Windows dev host; NOT full-lab evidence)

* `python tests/um-lt/test_lab_contract.py` → 58 tests OK (no sing-box/Go/network).
* `python um/deploy/lab/linux_traffic_e2e_lab.py --self-check` → PASS (19 checks,
  2 skips: no sing-box on PATH, rev-7 contract example not in this worktree).
* Self-check with a local sing-box 1.14.3 binary (explicitly marked
  layout-only, never evidence) → PASS including real `sing-box check` for the
  generated real-protocol server + both real client configs.
* Manual Windows prototype (not part of the harness): real sing-box 1.14.3
  server with Reality + Hysteria2 inbounds and real clients, real monitor-v2
  web runtime with the restricted export flags, 2 MiB/3 MiB loopback transfers
  through each protocol observed by the export as lower bounds
  (downlink 2,097,270 / 3,145,846 bytes for 2,097,152 / 3,145,728 payload
  bytes; upload 94 bytes for a 94-byte request overhead demonstration), and
  `monitor_stale=true` after the real server was stopped.
* Untested locally (Linux-only): Go center/agent execution, rev-7 storage/query
  integration, spool/replay after center restart, and the full Linux lab itself.
  Those are what the new CI workflow runs.
