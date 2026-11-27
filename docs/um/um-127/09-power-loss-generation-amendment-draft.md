# UM-127 amendment draft — power-loss / process-restart generation semantics

- Status: **DRAFT AMENDMENT, NOT FROZEN, NOT APPROVED.**
- Base: `docs/um/um-a/04-node-protocol-v1.md` revision 5 (frozen), especially
  §5, §6.1, §6.4, the recovery-case table, and REC-27.
- Scope: only the ambiguity between "normal restart increments generation" and
  the power-loss row / REC-27 exact-duplicate wording.
- Tracking: issue #127 and Draft PR #131 (B3 implementation). This amendment is
  intentionally a separate docs/fixture-only Draft PR and does not modify any
  frozen rev-5 file, schema or existing vector.
- The B3 code may implement and test the proposed rule, but must label the
  acceptance as **dependent on this amendment being approved**. Until then the
  amendment is not normative and no test may be changed merely to make the
  current contract look green.

## 1. Problem statement

Rev-5 contains three statements that cannot all be read literally at the same
time for an unclean restart:

1. `X-UM-Boot-Gen` is "monotonically increased by exactly 1 per normal agent
   restart" (§2 headers).
2. The recovery table says "Power loss on agent: ... persisted generation
   increments on restart" (§6.4).
3. REC-27 says "Agent power loss, seq persistence edge: resend committed seq ->
   duplicate; unsynced seq never reused", and REC-04 already covers "lost ACK +
   restart; first new-gen report is a duplicate".

The current B3 implementation historically interpreted only a *clean* shutdown
marker as a restart, preserving generation/boot/seq after an unclean exit and
resending the exact persisted attempt. That satisfies one reading of REC-27 but
contradicts the power-loss row and the security intent of a fresh boot
generation. The ambiguity must be resolved explicitly, not deferred to hardware
acceptance.

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

A retry inside the same process generation (same `generation`, `boot_id`,
`seq`, fingerprint, fresh `sent_at`/nonce only where the contract permits) can
be classified by the center as an exact duplicate. This preserves the existing
ACK-loss semantics and the old REC-27 exact-sequence consistency case.

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

- **REC-27-A (existing reading retained):** same-runtime loss of an ACK; retain
  the exact persisted seq/fingerprint and retry; center returns `duplicate`.
- **REC-27-B (new clarification):** process crash/power loss after a committed
  report with lost ACK. On restart the agent uses a new generation/boot id and
  a fresh attempt for the same `report_id`/body; the first new-generation report
  is `duplicate`, but center high-water advances to the new generation.
- **REC-27-C:** a late old-generation request after the new high-water is
  `stale_boot_generation`.
- **REC-27-D:** `status`/read-only inspection does not count as a restart and
  does not change generation.
- REC-04 and REC-30 remain consistent: new-generation first duplicate and
  oldest-first replay are explicitly supported; this amendment removes their
  apparent conflict with the older REC-27 wording.

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

## 5. Approval and transition

This file is a proposal only. It becomes normative only after Owner approval and
an amendment merge; until then:

- B3 may implement/test the proposed behavior;
- tests and docs must name the dependency;
- old rev-5 vectors remain untouched and valid for their own cases;
- no code may claim the amendment is already frozen;
- any production/B4+ use requires the normal independent review and Owner
  authorization.

The machine-readable draft cases are in
`docs/um/um-127/conformance/power-loss-generation.amendment.v1.json`.
