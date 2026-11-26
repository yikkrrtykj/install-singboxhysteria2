# UM-B1 contract conformance map (Draft PR)

- Contract: UM-A rev-5, PR #126 HEAD `048fc170`, merged to main as `8f1b9ac1`.
- Plan/conformance source: `docs/um/um-127/conformance/transport-recovery.cases.json`
  (revision 5, 30 REC cases).
- This map is intentionally strict: **only executed B1 checks are reported as
  passing**. UM-B2/UM-B3-owned cases are deferred and must not be counted as PASS.

## Executable evidence in the module

| Evidence | Location | Executed in B1 |
| --- | --- | --- |
| rev-5 signed positive vectors (report, Windows terminal, enroll, rotate, config) | `internal/wire/signing_test.go` | yes |
| rev-5 cryptographic negatives (body/key/boot-gen/rotate tamper, cross-endpoint) | `internal/wire/signing_test.go` | yes |
| 10 JSON schemas + 10 positive/7 schema-negative examples | `internal/schema/schema_test.go` | yes |
| platform isolation / Windows terminal runtime / privacy sentinels | `internal/contract/*_test.go` | yes |
| A-1..A-5 recovery ordering + ACK exhaustion + rotate validation order | `internal/protocol/recovery_test.go` | yes |
| SQLite schema, PRAGMAs, high-water transaction/rollback, dedupe, mapping history, ledger chain, retention | `internal/store/store_test.go` | yes |
| 12 B1-owned REC cases + B1 negative subset | `internal/conformance/conformance_test.go` | yes |
| REC cases owned by UM-B2/UM-B3 | this document + `conformance_test.go` registry | **deferred, not PASS** |

## REC-01..REC-30 ownership and B1 status

| ID | Owner | B1 execution status |
| --- | --- | --- |
| REC-01 | UM-B1 | executed in `TestB1RECCases` (normal restart) |
| REC-02 | UM-B1 | executed (first attempt lost, accepted seq=2) |
| REC-03 | UM-B2 | deferred (lost ACK + report dedupe ingest path) |
| REC-04 | UM-B2 | deferred (duplicate first report new generation ingest path) |
| REC-05 | UM-B2 | deferred (offline restart matrix is transport-level; B2 harness) |
| REC-06 | UM-B2 | deferred (spool replay harness) |
| REC-07 | UM-B1 | executed (gap > MAX_BOOT_GAP rejected) |
| REC-08 | UM-B1 | executed (same generation, different boot id) |
| REC-09 | UM-B1 | executed (retired generation) |
| REC-10 | UM-B2 | deferred (delayed superseded attempt over HTTP) |
| REC-11 | UM-B1 | executed (exact retry duplicate) |
| REC-12 | UM-B1 | executed (seq conflict) |
| REC-13 | UM-B2 | deferred (HTTP ACK next_seq reconciliation) |
| REC-14 | UM-B1 | executed (center restart persistence for `node_boot`) |
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
| REC-28 | UM-B1 | executed (storage-rollback / no high-water advance; B2 owns the HTTP 503 mapping) |
| REC-29 | UM-B1/B2 | **transport half executed; `stale_ignored` data apply deferred to UM-B2** — not marked PASS |
| REC-30 | UM-B2 | deferred (interleaved spool replay) |

## Rev-5 behavioural negative cases

B1 executes these pure transport/grammar cases through
`internal/conformance.TestNegativeVectorB1Subset`:

`NEG-BOOT-06`, `NEG-BOOT-07`, `NEG-BOOT-08`, `NEG-BOOT-09`, `NEG-BOOT-10`,
`NEG-ROT-12`, `NEG-ROT-13`, `NEG-ROT-14`, `NEG-ROT-15`.

All other behavioural cases (HTTP headers/encoding/tokens/rotation state machine/
enrollment/orphan/listener isolation/platform HTTP negatives) are owned by
UM-B2/UM-B3 and are **not** executed or marked PASS in B1. Schema-shape runtime
negatives that are pure body validation (e.g. six-token/sum/mapping/privacy) are
covered by `internal/contract` tests.

## Known B1 limitations (not PASS)

- No HTTP listener, center process, enrollment endpoint, rotation state machine
  persistence beyond the pure ordering helper, or agent spool.
- REC-29 data-apply ordering (`stale_ignored`) is deferred to UM-B2.
- Windows telemetry is schema/contract-level only; no real Mihomo read,
  service, R2/R1 source decision or real-build validation (UM-B3).
- Retention pruning of `seq_dedupe`/`boot_registry` and full policy-B archive
  engine are simplified/deferred; see `internal/store` comments and ADR.
- `windowsobs`/CLI remain experimental; no service wiring.

These limitations are tracked in the Draft PR body and must be closed by the
owning later slices, not silently marked as verified.
