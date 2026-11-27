# UM-127 amendment draft — power-loss / process-restart generation semantics

- Status: **DRAFT AMENDMENT, NOT FROZEN, NOT APPROVED.**
- Base: `docs/um/um-a/04-node-protocol-v1.md` revision 5 (frozen), especially
  §5, §6.1, §6.4, the recovery-case table, and REC-27.
- Scope: only the ambiguity between "normal restart increments generation" and
  the power-loss row / REC-27 exact-duplicate wording.
- Tracking: issue #127, B3 implementation Draft PR #131, and this amendment
  Draft PR #132. This amendment is intentionally a separate docs/fixture-only
  Draft PR and does not modify any frozen rev-5 file, schema or existing vector.
- Destination if approved: a new contract revision (proposed **rev-6**) on the
  normal contract-update path; no rev-5 file is edited in this PR.
- The B3 code may implement and test the proposed rule, but must label the
  acceptance as **dependent on this amendment being approved**. Until then the
  amendment is not normative and no test may be changed merely to make the
  current contract look green.
- Merge hold: both this amendment PR and B3 PR #131 remain Draft until the
  approval path in §5 is completed. Neither merge is authorized by this file.

## 1. Problem statement

Rev-5 contains three statements that cannot all be read literally at the same
time for an unclean restart:

1. `X-UM-Boot-Gen` is "monotonically increased by exactly 1 per normal agent
   restart" (§2 headers).
2. The recovery table says "Power loss on agent: ... persisted generation
   increments on restart" (§6.4).
3. REC-27 says "Agent power loss, seq persistence edge: resend committed seq ->
   duplicate; unsynced seq never reused". Its normative setup is a power-loss
   after agent generation 3/boot b3/seq 4 and its agent action says "resume from
   persisted seq" (same generation). REC-04, however, already says a lost ACK +
   restart is a **new-generation first duplicate**. REC-27's center
   exact-duplicate expectation and its agent-side same-generation action
   therefore cannot both remain literal.

This draft does not invent new duplicate semantics (REC-04 already defines the
new-generation duplicate); it resolves which agent restart behavior and which
piece of REC-27 are normatively retained, and records the supersession
explicitly. The historical B3 implementation interpreted only a clean marker as
a restart; that is the reason the current candidate needs the amendment.

## 2. Proposed normative rule

### 2.1 Definition of restart

A restart is a successful process start that opens an already-enrolled runtime
state and can perform network operations. `status`/inspection and other
read-only local CLI operations are **not** restarts and must not advance the
generation. Merely opening a state for inspection must not mutate it.

### 2.2 Every restart enters a new generation

On every such restart, including an unclean exit or power loss:

- increment the persisted `generation` by exactly one;
- generate a new random 32-hex `boot_id`;
- start `seq` at 1 for the new generation (or otherwise allocate a valid new
  attempt; the first accepted request may have `seq > 1` only under the existing
  bounded rules);
- fsync the new `{generation, boot_id}` before any request;
- if the generation is numerically exhausted, fail closed (operator recovery).

The clean-shutdown marker is no longer the authority for whether a restart
happened. It may remain as a diagnostic/attribution aid only.

### 2.3 Same-runtime transport retry is different

A retry inside the same process generation can be classified by the center as
an exact duplicate only when it replays the **exact persisted attempt** (same
`generation`, `boot_id`, `seq`, `sent_at`, nonce and therefore the same
fingerprint). `sent_at` is part of the fingerprint; changing it while claiming
an exact retry is invalid. A new `sent_at`/nonce means a new attempt, which is a
different duplicate path (same report_id, possibly new generation after a
restart).

### 2.4 Restart replay

After a restart, a fsynced payload must be replayed with:

- the same `report_id`, `collected_at`, type and decoded body identity;
- a new generation and new `boot_id`;
- a fresh valid attempt (new seq/nonce/sent_at as required; no reuse of the
  retired generation's seq as an authorization token);
- the current active key (if rotation is pending, proof recovery runs first).

The center dedupes by `report_id`. The first new-generation replay may be a
`duplicate`; it must still commit the new generation high-water and the record's
transport state atomically with dedupe. A late request from the retired
generation is rejected as `stale_boot_generation`; a same-generation different
boot id is `boot_identity_conflict`. No fsynced payload may be lost merely
because it was already stored under the previous generation.

### 2.5 No weakening

This amendment does not weaken: signature binding, nonce uniqueness, request
fingerprint, report_id dedupe, boot high-water, generation gap bounds, identity
revocation, fsync-before-send, bounded spool, or rotation proof. It only
clarifies when a new generation is mandatory and how a post-restart replay is
classified.

## 3. REC mapping

- **REC-27-0 (old center rule retained):** the center's exact duplicate rule
  for a repeated committed attempt remains valid; unsynced seq is never reused.
  The old fixture's same-generation center expectation maps to
  **AMEND-REC-27-A**.
- **REC-27-A (same-process exact retry):** same-runtime loss of an ACK; replay
  the exact persisted attempt (same generation/boot/seq/sent_at/nonce/
  fingerprint); center returns `duplicate`.
- **REC-27-B (power-loss remap):** process crash/power loss after a committed
  report with lost ACK. On restart the agent uses a new generation/new boot id
  and a fresh new-generation attempt for the same `report_id`/body; the first
  new-generation report is `duplicate` and center high-water advances. This
  **supersedes the old REC-27 agent-side "resume from persisted seq" action**
  (same generation) while retaining its center duplicate expectation.
- **REC-27-C:** a late old-generation request after the new high-water is
  `stale_boot_generation`; the retired seq/fingerprint is never reused.
- **REC-27-D (companion clarification):** `status`/read-only inspection does not
  count as a restart and does not change generation. This is a non-mutating-CLI
  rule, not an expansion of the duplicate rule.
- REC-04 and REC-30 remain consistent: new-generation first duplicate and
  oldest-first replay are explicitly supported; this amendment removes their
  apparent conflict with the older REC-27 agent action.

## 3a. Rev-5 clauses clarified or superseded

If this amendment is approved, the following reads are fixed (rev-5 text is not
edited by this PR; the amendment records precedence):

| Rev-5 location | Current ambiguous read | Proposed read / status |
| --- | --- | --- |
| §2 `X-UM-Boot-Gen` / §6.1 "normal restart" | only clean restart increments | every enrolled runtime start, clean or unclean, increments once; **clarified** |
| §6.4 power-loss row "persisted generation increments on restart" | conflicts with clean-only rule | confirmed for all restarts; **clarified** |
| §6.3 seq exhaustion "new generation on a clean restart" | clean-only | next runtime start, including after power loss; **clarified** |
| REC-27 setup gen3/b3/seq4, agent action "resume from persisted seq" | same-generation agent replay after power loss | **agent action superseded** by REC-27-B; center duplicate expectation retained as REC-27-A/B |
| REC-04 lost-ACK + restart | already new-generation duplicate | unchanged and consistent |
| `status`/read-only inspection | not explicitly a restart | does not advance generation; **companion clarification** |

If the amendment is **not** approved, rev-5 remains the governing text and the
B3 restart implementation must be labeled non-normative/pending; no test may
silently convert this table into a PASS.

## 4. Impact

- **B1 center:** the existing transactional rule already advances boot/seq
  high-water on an accepted or duplicate first new-generation request; no new
  endpoint or state is required. Add/retain tests for duplicate + high-water.
- **B2 storage:** ensure the first new-generation duplicate commits
  `node_boot`/`seq_dedupe` with report dedupe in one transaction; no data write
  for the already-stored report.
- **B3 agent:** every enrolled runtime start advances generation before network
  activity; status/inspection is non-mutating; spool replay refreshes attempts
  while preserving payload identity; recovery tests cover same-runtime and
  restart cases separately.
- **Migration:** existing local state opens as a restart and advances; no
  in-place generation reset, no identity re-enrollment, no old seq reuse.

## 5. Approval, review and merge path (normative gate)

This file is a proposal only. It becomes normative only after **all** of:

1. an Owner-authored/approved decision record in
   `docs/um/um-127/05-owner-decisions.md` (or a linked Owner record) explicitly
   accepts this amendment, its destination revision and its merge;
2. an **independent review PASS** of this docs/fixture amendment, recorded on
   PR #132, covering the security no-weakening table and REC supersession;
3. the amendment PR itself is merged through the normal contract-update path and
   the destination contract revision is published;
4. B3 PR #131 is then re-run/re-reviewed against the approved revision, with
   exact-HEAD CI and no unresolved review threads.

Until all four are done:

- **PR #132 and PR #131 remain Draft; MERGE HOLD and PRODUCTION HOLD apply.**
- B3 may implement/test the proposed behavior, but tests/docs must name the
  amendment dependency and must not call the behavior frozen.
- old rev-5 vectors remain untouched; the old exact-duplicate center case stays
  valid, while the old REC-27 agent power-loss same-generation action is marked
  superseded.
- no production/B4+ use is authorized; no auto-merge, no force-push, no frozen
  rev-5 edit in #131.

The draft cases are in
`docs/um/um-127/conformance/power-loss-generation.amendment.v1.json`. They are
**illustrative draft cases**, not a frozen machine-readable contract; no
consumer exists yet. If approved, they should be normalized alongside the
destination schema/vectors.
