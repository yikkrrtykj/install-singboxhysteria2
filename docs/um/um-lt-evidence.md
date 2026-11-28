# UM-LT — Evidence record (contract PR only; implementation/lab evidence NOT RUN)

Status: **CANDIDATE contract-PR evidence template for the rev-7 package —
docs-only. NOT published/frozen, NOT merged, NOT implemented.** This file records
what the contract PR can actually prove and explicitly marks everything that
requires the implementation PR or real labs as **NOT RUN**. No PASS is claimed
for a NOT RUN item.

- Branch: `docs/um-127-linux-traffic-rev7`
- Base: `main` `3bf1fadf32f84aead0433b1534619cb9820d2e44` (UM-C closure)
- Contract commit: recorded in the PR/final report; this file deliberately does
  not self-reference its own SHA (a commit cannot contain its own hash).
- Normative texts: [`um-a/04-node-protocol-v1.rev7.md`](um-a/04-node-protocol-v1.rev7.md),
  [`contracts/v1/`](contracts/v1/), [`um-lt-architecture.md`](um-lt-architecture.md),
  [`um-lt-data-semantics.md`](um-lt-data-semantics.md),
  [`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md),
  [`um-lt-compatibility.md`](um-lt-compatibility.md),
  [`um-lt-capacity.md`](um-lt-capacity.md), [`um-lt-runbook.md`](um-lt-runbook.md),
  [`um-lt-scope-and-acceptance.md`](um-lt-scope-and-acceptance.md),
  [`um-lt-owner-decisions.md`](um-lt-owner-decisions.md).

## 1. Artifacts added by this contract PR (docs/schema/fixtures only)

| Artifact | Purpose |
| --- | --- |
| `docs/um/contracts/v1/report-snapshot.rev7.schema.json` | rev-7 snapshot body: frozen rev-5 shape + required `contract_revision`/`traffic_observation` |
| `docs/um/contracts/v1/agent-config.rev7.schema.json` | rev-5 config + optional `collect.monitor_export` |
| `docs/um/contracts/v1/examples/report-snapshot.rev7.json` | synthetic rev-7 Linux positive fixture |
| `docs/um/contracts/v1/examples/agent-config.rev7.json` | synthetic rev-7 config positive fixture |
| `docs/um/contracts/v1/negative-vectors.rev7.json` | 37 machine-readable negative/gating vectors (schema/semantic/platform/config stages, incl. four `CFG-REV7` agent-version gate cases) |
| `docs/um/um-a/04-node-protocol-v1.rev7.md` | candidate normative overlay (source, export transport, report semantics, bounds, epoch/freshness, compatibility, no-weakening, conformance, provenance) |
| `docs/um/um-lt-*.md` (architecture, data semantics, source audit, compatibility, capacity, runbook, scope/acceptance, owner decisions, this file) | design/audit/operations/acceptance/decision records |

No existing rev-5/rev-6 schema, example, vector or protocol document is edited;
no Go/Python/frontend/monitor/test/workflow file is touched.

## 2. Validation actually performed at contract-PR time

Command environment: bundled Python 3 (no third-party JSON-Schema package
available). A local, non-committed consistency script was used; it is evidence
of internal consistency, **not** a conformance runner.

| # | Command / check | Result |
| --- | --- | --- |
| V-01 | `python -c "json.load(...)"` on all five new JSON artifacts | **PASS** — all parse as UTF-8 JSON |
| V-02 | Schema sanity: `$schema` draft 2020-12, `$id` prefix `https://um.invalid/contracts/v1/`, title contains "rev-7", every new object schema closed (`additionalProperties: false`) | **PASS** |
| V-03 | `$id` uniqueness across all `docs/um/contracts/v1/*.schema.json` | **PASS** — 12 unique ids |
| V-04 | Frozen rev-5 base shape preserved: every rev-5 report/config property (except the documented additions) deep-equal to rev-5; required base fields still required; only `contract_revision`+`traffic_observation` added to report required; only optional `monitor_export` added to collect | **PASS** |
| V-05 | Positive fixtures validate against the rev-7 schemas | **PASS** |
| V-06 | Negative/gating vectors: 37 ids unique, ≥15 total, 18 schema-stage vectors invalid after their patch, 13 implementation-semantic + 1 platform + 5 config-generation vectors schema-valid (as declared) | **PASS** |
| V-07 | Required negative categories present: exact/lower-bound ambiguity, float bytes, negative bytes, >2^53−1, bad epoch, negative sequence, stale-with-ok availability, unknown tag, wrong kind, duplicate tag, rate-without-window, unknown field, Windows class, `contract_revision:6`, bad freshness/quality | **PASS** |
| V-08 | Export-file shape cross-check: lead-reconciled `singbox-monitor-traffic-export` v1 field set/consts/observability fields/mapping; report body keeps `monitor_readonly_export` and never forwards file-only fields; old `export_version` draft shape absent from all rev-7 docs | **PASS** (4 462 consistency checks total incl. V-09) |
| V-09 | `CFG-REV7` agent-version gate consistency: minimum `agent.version` `1.1.0` defined once and referenced by overlay §11.1, config schema description, `gating_rules`/`NEG7-CFG-04..07`, compatibility §2/§3/§8 and runbook §0/§3/§5/§8; unknown/older ⇒ key omitted entirely; `>=1.1.0` ⇒ effective next pull; later older ⇒ omitted again | **PASS** (documented rule + vectors; real center config-generation test remains **NOT RUN**, see E-16) |
| V-10 | Git boundary: only new `docs/um/**` files; no modifications to existing rev-5/rev-6 artifacts or code; no merge/push/force-push | **PASS** (see the final report/PR for the exact commit/tree; verified after committing the single docs commit) |
| V-11 | rev-5/rev-6 files byte-unchanged: compare `docs/um/contracts/v1/{report-snapshot.schema.json,agent-config.schema.json,negative-vectors.v1.json,test-vectors.v1.json,power-loss-generation.rev6.json}`, `docs/um/um-a/04-node-protocol-v1.md`, `docs/um/um-a/04-node-protocol-v1.rev6.md` against `3bf1fadf` | **PASS** (not in the changed-file list; no content edit) |

Not claimed: this is not a JSON-Schema-conformance harness, does not execute the
negative vectors at HTTP/agent/center level, and does not prove any runtime
behavior. The implementation PR must add a real runner.

## 3. Implementation-pr and lab evidence — **NOT RUN**

Every row below is **NOT RUN** for this contract PR; it is the required evidence
for the implementation PR (and UM-E where noted). It must be replaced with real,
exact-command evidence before any production claim.

| ID | Required evidence | Status |
| --- | --- | --- |
| E-01 | Monitor writer: real Linux run; atomic temp+fsync+rename; no partial file under concurrent reads; startup stale-file deletion; ≤64 KiB output | **NOT RUN** |
| E-02 | Export ACL/group: owner/group/mode, no world access, exactly two group members, symlink/FIFO/wrong-owner/oversized rejection, agent read-only (cannot write/delete), unit `ReadWritePaths` diff | **NOT RUN** |
| E-03 | Export privacy scan: sentinel values (IP/hostname/device/user/connection-id/UUID/proxy/URL/YAML/secret) absent from file, agent logs, report, center storage/query/backups | **NOT RUN** |
| E-04 | Agent: reads fixed read-only path, rejects invalid/stale/absent with the documented sentinel, applies expected tag/kind allow-list, derives freshness/availability; no new listener/exec; no monitor/secret access (EACCES proven) | **NOT RUN** |
| E-05 | Report: rev-7 body signed under the unchanged rev-5 signing string; accepted/deduped/replayed; retry/restart semantics unchanged; `singbox_api=false` assertion; P1-10 FAIL retained | **NOT RUN** |
| E-06 | Center: rev-7 schema/semantic validation before storage; platform/config gating; rev-7 snapshot accepted in the same durable transaction; structured storage/query shows lower-bound label + freshness/availability/age + epoch boundary; no TOTAL rendering | **NOT RUN** |
| E-07 | Compatibility matrix: A5/C5, A7/C5, A7/C7-disabled, A7+/C7, direct C5 rev-7 rejection, A5 receives 7-key config → fail-closed, Windows untouched | **NOT RUN** |
| E-08 | Downgrade/rollback: queued rev-7 quarantine preserves `report_id`/body bytes; rev-5 spool drains; old-center rejection handling; center DB schema fail-closed rollback / restore path | **NOT RUN** |
| E-09 | Storage migration: additive schema migration (current store v13 → next), no data loss, STRICT/CHECK bounds, retention/delete batches, no full-observation raw copy | **NOT RUN** |
| E-10 | Capacity/perf: measured row/byte ratio, 150-node/30-day accelerated retention, query p95, disk-pressure/backup interplay | **NOT RUN** (production acceptance = **UM-E**) |
| E-11 | End-to-end real protocol lab (synthetic local): monitor → export → agent → center → query, including epoch reset and stale/unavailable paths (`um/deploy/lab/**`, `tests/um-lt/**` planned by the lab workstream) | **NOT RUN** |
| E-12 | Real Reality/Hysteria2 inbound acceptance (Issue #127 blocker) | **NOT RUN** — must not be claimed until executed |
| E-13 | Independent review of the rev-7 contract and of the implementation security/semantics | **PENDING** (contract PR) / NOT RUN (implementation) |
| E-14 | Exact-head CI for this contract PR (all required checks) | **PENDING** — recorded in the PR/final report, not claimed here |
| E-15 | Owner conditional merge authorization exercised by the normal Merge Commit | **PENDING** — author does not merge; pre-merge is not publication |
| E-16 | `CFG-REV7` real center config-generation test: unknown/`<1.1.0` ⇒ `monitor_export` key absent entirely; signed `>=1.1.0` ⇒ included on the next pull; later older version ⇒ absent again; key never emitted for Windows/unknown class; comparator boundary cases (`1.0.999`, `1.1.0`, `2.0.0`, suffix handling) | **NOT RUN** (contract-PR documents/vectors only) |

## 4. Evidence rules

- A PASS requires a real, reproducible execution at a named head/commit in a
  synthetic/local environment with the command and result recorded; JSON parsing
  alone is not conformance.
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
Reviewed HEAD: <sha>   Tree: <tree>
Base center/monitor/agent versions: center=<v> monitor=<v> agent=<v>
Source audit version: UM-LT-SOURCE-AUDIT-v1
Labs: <run ids/links>  Environment: synthetic/local only
E-01..E-12: <command> => <result> <artifact path/log hash>
Static/unit/regression: <commands> => PASS/FAIL
Negative vectors executed by: <runner path/test id> => PASS/FAIL
Capacity measurement: rows=<n> bytes/row=<n> total=<n> db=<n> p95=<n> => PASS/FAIL
Known NOT RUN / residual: <list>
Exact-head CI: <checks> PASS/FAIL
Independent review: <reviewer> verdict
Rollback drill: <result>
Holds: PRODUCTION HOLD / R1 HOLD / singbox_api DISABLED / P1-10 FAIL / UM-F DEFERRED
```

## 6. Contract-PR conclusion

- The rev-7 contract package is internally consistent, JSON-valid, additive and
  preserves the frozen rev-5/rev-6 base shape and the no-weakening rules, as far
  as static validation can prove.
- It is a **candidate formal overlay pending review/CI**, not published/frozen;
  the implementation and every real lab remain **NOT RUN**.
- The contract author does not merge, does not enable the source in any
  environment, and makes no production claim.
