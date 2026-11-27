# UM-A 04 — Node protocol v1, revision 6 normative overlay

Status: **REVISION 6 — NORMATIVE OVERLAY, APPROVED / FROZEN by the rev-6
contract-release merge.** This file is the normative revision-6 overlay on
revision 5. It does not rewrite or delete revision-5 history; the revision-5
document remains the base contract and historical evidence.

- Base contract: [`04-node-protocol-v1.md`](04-node-protocol-v1.md), revision 5,
  contract commit `048fc170685da5b7140bebd9e3347616cb3ec656`.
- Source amendment: PR #132, branch `docs/um-127-power-loss-generation`.
- Owner decision record: [`../um-127/10-owner-decisions-rev6.md`](../um-127/10-owner-decisions-rev6.md).
- Machine-readable normative fixture:
  [`../contracts/v1/power-loss-generation.rev6.json`](../contracts/v1/power-loss-generation.rev6.json).
- Contract-update path: the normal docs/fixture-only contract PR path, including
  independent review and the Owner's conditional merge authorization; this
  overlay is not normative in a pre-merge draft.

## 0. Precedence and compatibility

1. For the subjects covered here, **this overlay controls** where revision-5 text
   is ambiguous, inconsistent or contradicted by the rules below.
2. Every revision-5 requirement not explicitly clarified/superseded here remains
   in force unchanged.
3. Revision-5 files, schemas, signed vectors, examples and historical review
   evidence are **not edited or deleted** by this revision.
4. Revision-6 does not change headers, signing strings, JSON schemas, endpoint
   bodies, numeric bounds, `MAX_BOOT_GAP`, node classes, route tokens or the
   center transaction ordering.
5. An incompatible future change requires a new explicit design revision; this
   overlay only resolves the restart/power-loss generation semantics.

## 1. Problem resolved

Revision 5 simultaneously said that generation increments on a "normal restart",
that power loss increments the persisted generation on restart, and that REC-27
resends from the persisted sequence after power loss. The last two are not
compatible with "same generation" when a process restart happened. Revision-6
makes the restart boundary explicit and separates:

- a **transport retry inside the same running process/generation**, which may be
  an exact attempt replay; from
- a **process restart**, which always begins a new generation, and therefore a
  new attempt and boot identity.

## 2. Normative restart rule

### 2.1 Restart definition

A **restart** is a successful process start that opens an already-enrolled
runtime state and can perform network operations.

`status`, inspection and other read-only local CLI operations are **not**
restarts. Merely opening a state for read-only inspection must not mutate it.

### 2.2 Every restart increments generation

On every restart, including a clean stop/start, an unclean exit, or recovery
after power loss, the agent MUST, before any network request:

- increment the persisted generation by **exactly one**;
- generate a new random 32-hex `boot_id` that differs from every prior boot id
  for the node;
- fsync the new `{generation, boot_id}`;
- allocate a fresh transport attempt under the new generation (new `seq`,
  `nonce`, `sent_at` and signature as required by the base contract);
- continue to preserve the payload identity of fsynced spool records;
- if no representable next generation exists, fail closed into operator
  recovery; never wrap, reset or reuse a generation.

The clean-shutdown marker is diagnostic only. Its presence/absence MUST NOT
decide whether generation advances.

### 2.3 Same-runtime exact retry

Within one process runtime/generation, an exact retry MUST replay the exact
persisted attempt: same `generation`, `boot_id`, `seq`, `sent_at`, nonce and
therefore the same request fingerprint. The center may classify it as
`duplicate`. `sent_at` is part of the fingerprint, so a changed `sent_at`
cannot be asserted as an exact fingerprint; the nonce is separately covered by
the frozen nonce-dedupe rule.

### 2.4 Restart replay

After a restart, a fsynced payload MUST be replayed with:

- the same `report_id`, `collected_at`, type and decoded body identity;
- the new generation and new `boot_id`;
- a fresh valid attempt; no retired generation's sequence/attempt is reused as
  an authorization token;
- the current active key; if a rotation proof is pending, proof recovery runs
  first under the frozen rotation rules.

The center dedupes by `report_id` as in revision 5. The first replay of a
report already stored under the previous generation MAY be `duplicate`, but it
MUST atomically:

- commit the new generation/boot high-water;
- commit the record's transport state with dedupe;
- avoid writing a second stored copy of the report data.

No fsynced payload may be lost merely because it was already stored under the
previous generation.

### 2.5 Boot/sequence validation remains

The base revision-5 rules continue unchanged:

- `gen < highest_gen` → `409 stale_boot_generation`, no state change;
- same generation with a different `boot_id` → `409 boot_identity_conflict`;
- `1 <= gen - highest_gen <= MAX_BOOT_GAP` accepted as new-generation first
  contact; larger gaps → `409 boot_identity_conflict`;
- first accepted request of a new generation may have `seq > 1`;
- unsynced/retired sequences are never reused;
- `next_seq` exhaustion remains terminal (new generation or operator recovery);
- signature, nonce, fingerprint, dedupe, rotation, revocation and fsync rules are
  untouched.

## 3. REC mapping and supersession

The old REC-27 center exact-duplicate rule is retained. Its old agent-side
power-loss same-generation action is superseded.

| ID | Scenario | Normative rev-6 expectation |
| --- | --- | --- |
| AMEND-REC-27-A | Same runtime, committed report, ACK lost; exact retry (old REC-27 center case) | `200 duplicate`; exact fingerprint; no generation advance; no second data copy |
| AMEND-REC-27-B | Process restart/power loss after a committed report whose ACK was lost (old REC-27 agent action superseded) | new generation exactly `old+1`, new boot id, fresh attempt; same payload identity; `200 duplicate`; new-generation high-water and dedupe committed atomically; no data loss/second copy |
| AMEND-REC-27-C | Late retired-generation request after the new high-water | `409 stale_boot_generation`; no state change; no sequence reuse |
| AMEND-REC-27-D | `status`/read-only inspection | no generation/boot/spool/quarantine mutation; no network request required |
| AMEND-REC-27-E | Same generation, different `boot_id` | `409 boot_identity_conflict`; no state change |
| AMEND-REC-27-F | Multiple consecutive offline restarts, bounded forward gap | accepted/duplicate as appropriate; new generation high-water committed; `boot_generation_gap` audit when gap > 1; gap ≤ `MAX_BOOT_GAP` |

Old REC-27 center exact-duplicate remains valid as AMEND-REC-27-A. REC-04 and
REC-30 remain compatible: a new-generation first duplicate and oldest-first
spool replay are explicitly expected.

## 4. Revision-5 clauses clarified/superseded

Where this table conflicts with revision-5 text, this overlay controls.

| Revision-5 location | Revision-5 ambiguity | Revision-6 read |
| --- | --- | --- |
| §2 `X-UM-Boot-Gen`; §6.1 | "normal restart" | every enrolled runtime start, clean or unclean |
| §6.3 restart row | "persisted generation +1 and new boot id" | unchanged and confirmed |
| §6.3 ACK-exhaustion row | "new generation on clean restart" | new generation on the next runtime start, including after power loss |
| §6.4 power-loss row | "persisted generation increments on restart" | confirmed; same-generation agent resend is not the restart rule |
| REC-27 setup gen 3/boot b3/seq 4, agent action "resume from persisted seq" | same-generation power-loss replay | **agent action superseded**; AMEND-REC-27-A covers the retained center exact-duplicate rule, AMEND-REC-27-B covers restart |
| §13 ACK exhaustion "clean restart" | clean-only | next runtime start, including unclean |
| `status`/read-only local inspection | not explicitly a restart | non-mutating; never advances generation |

## 5. Impact by slice

### B1 center

- No new endpoint or state field is required.
- A first new-generation request may be `duplicate`; the existing transaction
  must advance boot/gen/seq high-water with the dedupe result.
- AMEND-REC-27-A/C/E/F must be executable against real HTTP/SQLite.
- Existing REC-01..REC-30 expectations remain valid except the REC-27
  agent-side action noted above; revision-5 history is retained.

### B2 storage

- The first new-generation duplicate must commit `node_boot`/sequence high-water
  and report dedupe in one transaction.
- No second report row/data write for an already-stored report.
- Existing SQLite bounds/CHECK/durability rules are unchanged.

### B3 agent

- Every enrolled runtime start advances generation and boot id before network
  activity, including unclean/power-loss restart.
- `status`/read-only inspection is non-mutating.
- Same-process retry may replay the exact persisted attempt; restart replay
  preserves payload identity and refreshes the transport attempt.
- Rotation proof recovery runs before config/report after restart.
- Existing spool/ACK, OS lock, privacy, fail-closed and service behavior remain
  unchanged.

## 6. Executable conformance requirements

The normative fixture is
`docs/um/contracts/v1/power-loss-generation.rev6.json`. It MUST be executed by
real tests, not merely parsed:

- AMEND-REC-27-A: real center HTTP + SQLite + agent same-runtime exact retry.
- AMEND-REC-27-B: real agent persistence/restart (process-level crash harness)
  + real center, new generation/boot, same report identity, duplicate,
  high-water, no second stored copy.
- AMEND-REC-27-C: real center request from the retired generation after the new
  high-water → stale rejection.
- AMEND-REC-27-D: real `status`/read-only CLI execution against a persisted
  state; byte/tree/mtime or equivalent state comparison; no mutation.
- AMEND-REC-27-E: real center same-generation/different-boot request.
- AMEND-REC-27-F: real bounded-gap request after consecutive offline restarts,
  with gap audit.

Existing revision-5 tests for REC-17/18, REC-04/30, rotation, generation
exhaustion, crash recovery and repeated unclean restarts remain mandatory.

## 7. Approval and provenance

- Owner decision record: `docs/um/um-127/10-owner-decisions-rev6.md`
  (2026-11-27, limited scope; no PR #131 merge or production authorization).
- Independent review: recorded on PR #132 before merge.
- Publication: normal Merge Commit of PR #132; merge commit, parents, tree and
  main CI are recorded in the final PR/Issue evidence and the B3 release record.
- Pre-merge draft status is not a publication claim. Only the merged main state
  is **REV-6 PUBLISHED / FROZEN / VERIFIED**.
