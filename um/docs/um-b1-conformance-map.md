# UM-B1 contract conformance map (Draft PR)

- Contract: UM-A rev-5, PR #126 HEAD `048fc170`, merged to main as `8f1b9ac1`.
- Plan/conformance source: `docs/um/um-127/conformance/transport-recovery.cases.json`
  (revision 5, 30 REC cases).
- This map is intentionally strict: **only executed B1 checks are reported as
  passing**. UM-B2/UM-B3-owned cases are deferred and must not be counted as PASS.
- P1-07 correction: the conformance test reads the normative `setup`/`attempt`/
  `expected` fields from the JSON fixture; it is not a separate hard-coded copy.
  A mutation to the fixture expected/input makes the harness fail
  (`TestConformanceHarnessDetectsFixtureMutation`).

## Execution summary (B1 review HEAD)

| Bucket | Count | Status |
| --- | --- | --- |
| REC total in fixture | 30 | parsed and ownership-checked |
| B1-owned in fixture | 12 | 11 executed, **REC-29 deferred in whole to B2** |
| B2-owned | 15 | deferred, not PASS |
| B3-owned | 3 | deferred, not PASS |

`REC-29` is **not** half-executed: B1 has no snapshot data-apply/ordering stage,
so neither a transport half nor a data half is claimed. It is skipped with the
reason in `TestB1RECCases/REC-29` and listed as B2-deferred below.

## Executable evidence in the module

| Evidence | Location | Executed in B1 |
| --- | --- | --- |
| rev-5 signed positive vectors (report, Windows terminal, enroll, rotate, config) | `internal/wire/signing_test.go` | yes |
| rev-5 cryptographic negatives (body/key/boot-gen/rotate tamper, cross-endpoint) | `internal/wire/signing_test.go` | yes |
| 10 JSON schemas + positive/negative examples; strict JSON duplicate/trailing-data rejection | `internal/schema/schema_test.go` | yes |
| platform isolation / Windows terminal runtime / privacy-by-path | `internal/contract/*_test.go` | yes |
| A-1..A-5 recovery ordering + ACK exhaustion + rotate validation order | `internal/protocol/recovery_test.go` | yes |
| SQLite STRICT numeric storage, raw-SQL negative tests, migration fail-closed/legacy upgrade, per-connection PRAGMAs after replacement, transaction/rollback/dedupe/mapping/ledger/retention | `internal/store/store_test.go`, `internal/store/store_p1_test.go` | yes |
| 11 B1-owned REC cases + B1 negative subset, read from the normative JSON | `internal/conformance/conformance_test.go` | yes |
| REC cases owned by UM-B2/UM-B3 (18) | this document + `conformance_test.go` registry | **deferred, not PASS** |

## REC-01..REC-30 ownership and B1 status

| ID | Owner | B1 execution status |
| --- | --- | --- |
| REC-01 | UM-B1 | executed in `TestB1RECCases` from fixture `setup/attempt/expected` |
| REC-02 | UM-B1 | executed from fixture (first attempt lost, seq=2 accepted) |
| REC-03 | UM-B2 | deferred (lost ACK + report dedupe ingest path) |
| REC-04 | UM-B2 | deferred (duplicate first report new generation ingest path) |
| REC-05 | UM-B2 | deferred (offline restart matrix is transport-level; B2 harness) |
| REC-06 | UM-B2 | deferred (spool replay harness) |
| REC-07 | UM-B1 | executed (gap > MAX_BOOT_GAP rejected; impossible assertion removed) |
| REC-08 | UM-B1 | executed (same generation, different boot id) |
| REC-09 | UM-B1 | executed (retired generation) |
| REC-10 | UM-B2 | deferred (delayed superseded attempt over HTTP) |
| REC-11 | UM-B1 | executed (exact retry duplicate) |
| REC-12 | UM-B1 | executed (seq conflict) |
| REC-13 | UM-B2 | deferred (HTTP ACK next_seq reconciliation) |
| REC-14 | UM-B1 | executed: fixture state seeded through `ApplyTransport`, DB closed/reopened, persisted `node_boot` asserted, **real post-reopen retry** accepted + report duplicate asserted, then exact transport retry duplicate |
| REC-15 | UM-B2 | deferred (503/failure injection at ingest) |
| REC-16 | UM-B2 | deferred (quarantine policy at ingest) |
| REC-17 | UM-B3 | deferred (agent boot-state fail-closed) |
| REC-18 | UM-B3 | deferred (agent restored snapshot) |
| REC-19 | UM-B2 | deferred (rotate intent over HTTP state machine; B1 validates ordering only) |
| REC-20 | UM-B2 | deferred (rotation expired path) |
| REC-21 | UM-B2 | deferred (revocation during backlog) |
| REC-22 | UM-B2 | deferred (config pull as first contact) |
| REC-23 | UM-B2 | deferred (rotate as first contact) |
| REC-24 | UM-B2 | deferred (enrollment response loss) |
| REC-25 | UM-B1 | executed (65535 gap boundary accepted) |
| REC-26 | UM-B1 | executed (MAX_NUMERIC + ACK next_seq null) |
| REC-27 | UM-B3 | deferred (agent power-loss seq persistence) |
| REC-28 | UM-B1 | executed: committed/uncommitted/reopen boundary — committed state survives restart, failed payload transaction leaves high-water unchanged, retry applies once, exact retry is duplicate, report survives final reopen |
| REC-29 | UM-B1 (fixture) → **entire case deferred to UM-B2** | **not executed, not PASS**: no snapshot data-apply/ordering in B1 |
| REC-30 | UM-B2 | deferred (interleaved spool replay) |

## Rev-5 behavioural negative cases

B1 executes these pure transport/grammar cases through
`internal/conformance.TestNegativeVectorB1Subset`. The fixture has prose
`mutation` fields rather than a machine-readable setup, so the inputs are kept in
an explicit, documented fixture-to-test mapping; the expected HTTP/ACK/error/
next_seq/audit values are read from the normative JSON and a changed fixture
expectation makes the test fail (`TestNegativeVectorB1Subset` mutation check).

`NEG-BOOT-06`, `NEG-BOOT-07`, `NEG-BOOT-08`, `NEG-BOOT-09`, `NEG-BOOT-10`,
`NEG-ROT-12`, `NEG-ROT-13`, `NEG-ROT-14`, `NEG-ROT-15`.

All other behavioural cases (HTTP headers/encoding/tokens/rotation state machine/
enrollment/orphan/listener isolation/platform HTTP negatives) are owned by
UM-B2/UM-B3 and are **not** executed or marked PASS in B1. Schema-shape runtime
negatives that are pure body validation (e.g. six-token/sum/mapping/privacy) are
covered by `internal/contract` tests.

## Mapping semantics used by B1 (clarification proposal, not a frozen-contract edit)

The rev-5 contract requires append-only effective-dated mapping versions but does
not spell out backdating, future versions or unmapping. B1 implements the
conservative semantics below and records them here for independent review. The
frozen contract files are unchanged; this is a minimal clarification proposal.

- Only the four A/B protocol tokens (`a_reality`, `a_hy2`, `b_reality`, `b_hy2`)
  may map to a `linux_vps` target. `direct`/`unknown` are reserved display tokens
  and are never mapping targets.
- `windows_node_id` must exist, have class `windows_terminal`, and belong to the
  same event. Every target must exist, have class `linux_vps`, and belong to the
  same event.
- First version must be `1`; every later version must be the immediate next
  integer and `effective_from` must be strictly later than the latest version's
  effective time. Duplicate effective times and backdated inserts are rejected
  so already-attributed history cannot change.
- Future-effective versions are allowed and become visible to `ResolveMapping`
  only when `at >= effective_from`.
- An empty/subset entry map is the unmapping representation: omitted tokens are
  unmapped from that version onward (UI renders UNKNOWN); the previous version
  remains the historical attribution before the new effective time.
- Versions and entries are immutable: SQL triggers reject raw UPDATE/DELETE, and
  the typed API only appends. Historical queries are tested to be unchanged
  after appending.

## Known B1 limitations / deferred ownership (not PASS)

- No HTTP listener, center process, enrollment endpoint, rotation state machine
  persistence beyond the pure ordering helper, or agent spool.
- `seq_dedupe`/`boot_registry` physical pruning and the full policy-B archive
  engine are **deferred to UM-B2**, with a capacity upper-bound validation
  required before the center is put into operation. Retention only deletes the
  basic replay/dedupe rows it owns today.
- `security_ledger` is a basic hash chain only. It is **not** a signed
  checkpoint, has no offsite/recovery guarantee and cannot detect or prevent
  tail truncation. `VerifyChain` must never be used as recovery authorization.
- Windows telemetry is schema/contract-level only; no real Mihomo read,
  service, R2/R1 source decision or real-build validation (UM-B3).
- `windowsobs`/CLI remain experimental; no service wiring.

These limitations are tracked in the Draft PR body and must be closed by the
owning later slices, not silently marked as verified.
