# UM-LT — Evidence record (contract PR only; implementation/lab evidence NOT RUN)

Status: **CANDIDATE contract-PR evidence template for the rev-7 package —
docs/schema/fixtures plus test-only schema conformance. NOT published/frozen,
NOT merged, NOT implemented.** This file records what the contract PR can
actually prove and explicitly marks everything that requires the implementation
PR or real labs as **NOT RUN**. No PASS is claimed for a NOT RUN item.

- Branch / PR: `docs/um-127-linux-traffic-rev7`, PR #135 (Draft).
- Base: `main` `3bf1fadf32f84aead0433b1534619cb9820d2e44` (UM-C closure).
- Independently reviewed HEAD: `1aa71abedc782e69b1cfcb5d3efe63d1cbc4ed3e`
  (tree `29bd804c5f305fc405f921130aaa69828d8d964c`, 6 commits from base).
  Its exact-head **Unified Monitor Go** workflow run `46156909313` completed all
  five jobs success (`native` ubuntu-24.04 + windows-2022, `linux-race`,
  `coverage`, `govulncheck`). This review-fix commit follows that head; its own
  exact-head CI and PR head/tree/commit count are recorded in the PR body after
  the commit and are not self-referenced here. Quality-owned workflows are not
  claimed green by this contract PR (the Windows EXE/quality job was rerun and is
  outside this package's claim).
- Normative texts: [`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md),
  [`contracts/v1/rev7/`](contracts/v1/rev7/),
  [`um-lt-architecture.md`](um-lt-architecture.md),
  [`um-lt-data-semantics.md`](um-lt-data-semantics.md),
  [`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md),
  [`um-lt-compatibility.md`](um-lt-compatibility.md),
  [`um-lt-capacity.md`](um-lt-capacity.md), [`um-lt-runbook.md`](um-lt-runbook.md),
  [`um-lt-scope-and-acceptance.md`](um-lt-scope-and-acceptance.md),
  [`um-lt-owner-decisions.md`](um-lt-owner-decisions.md).

## 1. Artifacts added by this contract PR (docs/schema/fixtures + test-only conformance)

| Artifact | Purpose |
| --- | --- |
| `docs/um/contracts/v1/rev7/report-snapshot.rev7.schema.json` | rev-7 snapshot body: frozen rev-5 shape + required `contract_revision`/`traffic_observation` |
| `docs/um/contracts/v1/rev7/agent-config.rev7.schema.json` | rev-5 config + optional `collect.monitor_export` (CFG-REV7 gated) |
| `docs/um/contracts/v1/rev7/traffic-export.schema.json` | monitor-v2 export file: closed 14 top-level / 9 per-entry members, safe integers, rates/window and stale/quality coherence expressible in JSON Schema |
| `docs/um/contracts/v1/rev7/examples/report-snapshot.json` | synthetic rev-7 Linux positive fixture (`agent.version` `1.1.0`) |
| `docs/um/contracts/v1/rev7/examples/agent-config.json` | synthetic rev-7 config positive fixture |
| `docs/um/contracts/v1/rev7/examples/traffic-export.json` | synthetic monitor export positive fixture |
| `docs/um/contracts/v1/rev7/negative-vectors.json` | 55 machine-readable negative/gating vectors: 31 `json_schema`, 18 `implementation_semantic`, 1 `platform_isolation`, 5 `config_generation`; includes 18 export-file vectors and 5 `CFG-REV7` mappings |
| `docs/um/um-a/04-node-protocol-v1.rev7.md` | candidate normative overlay (source, export transport, report semantics, numeric/epoch/freshness rules, center sentinel/storage/query rules, compatibility, no-weakening, conformance, provenance) |
| `docs/um/um-lt-*.md` (architecture, data semantics, source audit, compatibility, capacity, runbook, scope/acceptance, owner decisions, this file) | design/audit/operations/acceptance/decision records |
| `um/internal/schema/rev7_schema_test.go` | **test-only** contract conformance: compiles the rev-7 overlay and validates all three positive fixtures |
| `um/internal/schema/rev7_negative_vectors_test.go` | **test-only** contract conformance: executes every `json_schema`-stage vector (report/config/export), pins unique ids/stage split/CFG rule mapping and the two raw-body lexical cases |

No Go production code, monitor-v2 code, frontend, workflow or unrelated test is
touched by this contract PR. The two Go files are test-only contract conformance
for the overlay artifacts; the implementation parser/agent/center tests remain
the implementation PR's evidence.

## 2. Validation actually performed at contract-PR time

| # | Command / check | Result |
| --- | --- | --- |
| V-01 | `python -c "json.load(...)"` on the three rev-7 schemas, three fixtures and `negative-vectors.json` | **PASS** — all parse as UTF-8 JSON |
| V-02 | `cd um && go test ./internal/schema -run 'TestRev7' -v` | **PASS** — both tests pass against the real schema engine (`TestRev7OverlayCompilesAndValidatesFixtures`, `TestRev7SchemaStageNegativeVectors`) |
| V-03 | Overlay compile + positive fixtures: report-snapshot/config/traffic-export schemas are loaded, all three committed fixtures validate, and the frozen rev-5 top-level schema set/count is unchanged (overlay lives in `rev7/`) | **PASS** |
| V-04 | Schema-stage vector execution: all 31 `json_schema` vectors are rejected by the real schema (report/config/export), including unknown/missing/bounds/float/coherence cases; the 2 `raw_body` lexical vectors are schema-**accepted** (proving the JSON-Schema limitation, so the implementation must reject the exact bytes) | **PASS** (`31 executed, 2 raw lexical schema-accepted`) |
| V-05 | Vector structure/stage split: 55 unique ids; stages `json_schema 31 / implementation_semantic 18 / platform_isolation 1 / config_generation 5`; `expected.stage == stage`; every CFG-REV7 rule `01..05` has exactly one vector mapping (`NEG7-CFG-01,04,05,06,07`) | **PASS** |
| V-06 | Frozen rev-5 base shape preserved: every rev-5 report/config property (except the documented additions) deep-equal to rev-5; required base fields still required; only `contract_revision`+`traffic_observation` added to report required; only optional `monitor_export` added to collect | **PASS** |
| V-07 | Permission-model consistency: no `root-owned`, `/var/lib/um-lt-export`, `um-lt-export` or `traffic-export.json` residual references; overlay/architecture/audit/runbook describe the same `/run/singbox-monitor-export/`, owner `<monitor-user>`, group `sboxmon-export` (agent only), `2750` setgid dir / `0640` file, no ACL | **PASS** |
| V-08 | Epoch/staleness consistency: overlay §7.1/§7.3 and the report schema description state the epoch reset and the pre-epoch lifecycle caveat (observed lower bound on observed lifecycles, not a pure epoch delta and not daemon-lifetime total); `EXPORT_MAX_AGE_SECONDS = 86400` defined and age is measured from `observed_at`; monitor-stale ⇒ stale-at-best | **PASS** |
| V-09 | Sentinel/status-only storage/query rules present in overlay §7.4/§7.6/§11 and architecture §7.3–§7.4, including no zero-epoch keying, no bucket/epoch rows, previous-latest invalidation, and the all-unavailable real-epoch form | **PASS** (documented; real storage execution **NOT RUN**) |
| V-10 | `CFG-REV7` gate consistency: minimum `agent.version` `1.1.0` defined and referenced by overlay §11.1, config schema, `gating_rules`/vectors, compatibility, architecture and runbook; key omitted entirely (not `false`) for unknown/older; `>=1.1.0` effective on the next pull; later older version omits again; `CFG-REV7-05` mapped to `NEG7-CFG-01` | **PASS** (real center config-generation test **NOT RUN**, E-16) |
| V-11 | Artifact/path consistency: fixture links point to `contracts/v1/rev7/examples/`; no stale `contracts/v1/examples/` pointer; `traffic.json` and export-file tokens are consistent across docs/schema/fixtures | **PASS** |
| V-12 | Git boundary: the contract PR changes only new `docs/um/**` artifacts plus the two test-only `um/internal/schema/rev7_*_test.go` files; no production code, monitor-v2, frontend, workflow, existing rev-5/rev-6 schema/example/vector/doc edit; no merge/push/force-push | **PASS** (exact commit/tree recorded in the PR) |
| V-13 | rev-5/rev-6 frozen files byte-unchanged against `3bf1fadf` (top-level schemas, examples, v1/rev-6 vectors, protocol docs 04 rev5/rev6, um-127 docs) | **PASS** — empty `git diff` |
| V-14 | PR body updated after the review-fix commit with the exact new HEAD, tree and commit count (no green claim for the new exact head; Unified Go run `46156909313` cited for the reviewed head `1aa71abe`) | **PASS** (recorded in PR #135) |
| V-15 | Full Unified Monitor Go regression on the review-fix tree: `cd um && go test -count=1 ./...` (all packages, incl. `internal/schema`) and `cd um && go vet ./...` | **PASS** — `go test` exit 0 with every package `ok` (no failures); `go vet` produced no findings |

Exact commands/results for this package:

```text
$ cd um && go test -count=1 ./...
PASS  (all packages ok; internal/schema, contract, store, center, web, agent,
       linuxobs, management, conformance, ... no failures; exit 0)
$ cd um && go vet ./...
(no output; exit 0)
$ cd um && go test -count=1 ./internal/schema -run 'TestRev7' -v
PASS  TestRev7OverlayCompilesAndValidatesFixtures
PASS  TestRev7SchemaStageNegativeVectors (55 vectors: 31 schema-stage executed,
      2 raw lexical schema-accepted; stages json_schema:31,
      implementation_semantic:18, platform_isolation:1, config_generation:5)
$ python validate2.py   # local non-committed contract-consistency checks
PASS  (226 checks: JSON parse, schema ids/closed objects, frozen rev-5 base
      shape, export 14/9 shape, fixtures/vectors/stage split/CFG mapping, docs
      permission-model/CFG/epoch/sentinel consistency, 74 doc links)
$ git diff --check
(no whitespace errors)
```

Contract-side limits: these checks compile the overlay and execute schema-stage
vectors; they do **not** execute implementation-semantic/platform/config vectors,
real HTTP/agent/center behavior, file-ACL/atomicity, privacy scans, capacity or
lab protocol traffic. Those remain the implementation PR / UM-E work below.

## 3. Implementation-pr and lab evidence — **NOT RUN**

Every row below is **NOT RUN** for this contract PR; it is the required evidence
for the implementation PR (and UM-E where noted). It must be replaced with real,
exact-command evidence before any production claim.

| ID | Required evidence | Status |
| --- | --- | --- |
| E-01 | Monitor writer: real Linux run; atomic temp+fsync+rename; no partial file under concurrent reads; startup stale-file deletion; ≤64 KiB output; `TAG:KIND` allow-list only (no `inbound_type` heuristic) | **NOT RUN** |
| E-02 | Export permissions: operator-created `/run/singbox-monitor-export/` owned by the non-root monitor user, group `sboxmon-export` containing exactly the non-root agent user, `2750` setgid dir / `0640` file, no ACL, no world access; symlink/FIFO/wrong-owner/oversized rejection; agent read-only (cannot write/delete); unit `ReadWritePaths=-…` diff; tmpfs recreate after reboot | **NOT RUN** |
| E-03 | Export privacy scan: sentinel values (IP/hostname/device/user/connection-id/UUID/proxy/URL/YAML/secret) absent from file, agent logs, report, center storage/query/backups | **NOT RUN** |
| E-04 | Agent: reads fixed read-only path; rejects invalid/stale/absent with the documented sentinel/status-only form; applies expected tag/kind allow-list; derives age/freshness/availability using the effective-dated cadence; no new listener/exec; no monitor/secret access (EACCES proven) | **NOT RUN** |
| E-05 | Report: rev-7 body signed under the unchanged rev-5 signing string; accepted/deduped/replayed; retry/restart semantics unchanged; `singbox_api=false` assertion; P1-10 FAIL retained | **NOT RUN** |
| E-06 | Center: rev-7 schema/semantic validation before storage; platform/config gating; rev-7 snapshot accepted in the same durable transaction; structured storage/query shows lower-bound label + freshness/availability/age + epoch boundary; no TOTAL rendering | **NOT RUN** |
| E-07 | Compatibility matrix: A5/C5, A7/C5, A7/C7-disabled, A7+/C7, direct C5 rev-7 rejection, A5 receives 7-key config → fail-closed/immediate config retry/no new snapshots, Windows untouched | **NOT RUN** |
| E-08 | Downgrade/rollback: queued rev-7 quarantine preserves `report_id`/body bytes; rev-5 spool drains; old-center rejection handling; center DB schema fail-closed rollback / restore path | **NOT RUN** |
| E-09 | Storage migration: additive schema migration (current store v13 → next), no data loss, STRICT/CHECK bounds, retention/delete batches, no full-observation raw copy | **NOT RUN** |
| E-10 | Capacity/perf: measured row/byte ratio, 150-node/30-day accelerated retention, query p95, disk-pressure/backup interplay | **NOT RUN** (production acceptance = **UM-E**) |
| E-11 | End-to-end real protocol lab (synthetic local): monitor → export → agent → center → query, including epoch reset and stale/unavailable/status-only paths (`um/deploy/lab/**`, `tests/um-lt/**` planned by the lab workstream) | **NOT RUN** |
| E-12 | Real Reality/Hysteria2 inbound acceptance (Issue #127 blocker) | **NOT RUN** — must not be claimed until executed |
| E-13 | Independent review of the rev-7 contract and of the implementation security/semantics | **PENDING** (contract PR) / NOT RUN (implementation) |
| E-14 | Exact-head CI for the review-fix commit of this contract PR (all required checks) | **PENDING** — recorded in PR #135 after the commit, not claimed here; reviewed head `1aa71abe` Unified Go run `46156909313` is the last green Unified run cited |
| E-15 | Owner conditional merge authorization exercised by the normal Merge Commit | **PENDING** — author does not merge; pre-merge is not publication |
| E-16 | `CFG-REV7` real center config-generation test: unknown/`<1.1.0` ⇒ `monitor_export` key absent entirely; signed `>=1.1.0` ⇒ included on the next pull; later older version ⇒ absent again; key never emitted for Windows/unknown class; comparator boundary cases (`1.0.999`, `1.1.0`, `2.0.0`, suffix handling) | **NOT RUN** (contract-PR documents/vectors only) |
| E-17 | Sentinel/status-only storage/query: sentinel stores status metadata only and zero epoch never keyed in `traffic_epoch`/bucket rows; status-only real-epoch form creates no value/bucket rows; both supersede previous latest as unavailable; query renders UNKNOWN/UNAVAILABLE; all-unavailable valid export path | **NOT RUN** (documented rules only) |

## 4. Evidence rules

- A PASS requires a real, reproducible execution at a named head/commit in a
  synthetic/local environment with the command and result recorded; schema
  compile/validation is conformance for schema-stage vectors only.
- A NOT RUN item stays explicitly NOT RUN; a missing check is not "assumed
  green". UM-E owns production acceptance.
- No real credentials, private keys, tokens, VPS addresses, hostnames, UUIDs or
  production data may appear in evidence. Fixtures are synthetic only.
- Evidence must keep the frozen holds visible: PRODUCTION HOLD, R1 production
  HOLD, `singbox_api` DISABLED, P1-10 FAIL, UM-F DEFERRED.
- Any future change to headers, signing strings, endpoints, enums, numeric
  bounds, dedupe/sequence/boot/rotation rules, node classes, export tokens or
  vectors is a frozen-contract revision requiring independent review before
  implementation.

## 5. Evidence template for the implementation PR (fill in, do not pre-fill)

```text
Implementation PR: <link/number>
Reviewed HEAD: <sha>   Tree: <tree>   Commits from base: <n>
Base center/monitor/agent versions: center=<v> monitor=<v> agent=<v>
Source audit version: UM-LT-SOURCE-AUDIT-v1
Labs: <run ids/links>  Environment: synthetic/local only
E-01..E-17: <command> => <result> <artifact path/log hash>
Schema/vector runner: cd um && go test ./internal/schema -run 'TestRev7' -v => PASS/FAIL
Static/unit/regression: <commands> => PASS/FAIL
Full vector execution (schema + semantic): <runner path/test id> => PASS/FAIL
Capacity measurement: rows=<n> bytes/row=<n> total=<n> db=<n> p95=<n> => PASS/FAIL
Known NOT RUN / residual: <list>
Exact-head CI: <checks> PASS/FAIL (quality-owned workflows separately)
Independent review: <reviewer> verdict
Rollback drill: <result>
Holds: PRODUCTION HOLD / R1 HOLD / singbox_api DISABLED / P1-10 FAIL / UM-F DEFERRED
```

## 6. Contract-PR conclusion

- The rev-7 contract package is internally consistent, JSON-valid, additive and
  preserves the frozen rev-5/rev-6 base shape and the no-weakening rules. The
  schema-stage vectors and positive fixtures are **executed** by the test-only
  contract conformance tests (`go test ./internal/schema -run 'TestRev7'`), and
  the reviewed head's Unified Monitor Go CI run `46156909313` is green.
- It is a **candidate formal overlay pending review/CI**, not published/frozen;
  the implementation-semantic evidence and every real lab remain **NOT RUN**.
- The contract author does not merge, does not enable the source in any
  environment, and makes no production claim.
