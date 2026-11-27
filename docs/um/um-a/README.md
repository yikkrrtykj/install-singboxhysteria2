# UM-A — Investigation, selection and frozen design

Status: **revision 5 final targeted amendment + revision 6 approved normative
overlay (power-loss/restart generation)**. The overlay becomes frozen only when
the rev-6 contract-release PR is merged; see
[04-node-protocol-v1.rev6.md](04-node-protocol-v1.rev6.md). UM-B and later phases remain HOLD until this phase receives an
independent review PASS and the owner merge authorization (see
[07-um-b-entry-and-review.md](07-um-b-entry-and-review.md)). The owner's Round-2
review conclusions are recorded in 07 §3 / 08; they do not replace the independent
review or authorize a merge.

## Scope

UM-A answers the planning questions in the project brief and freezes the design
inputs needed to start UM-B:

1. Baseline and existing-capability audit: latest main, relevant issues/PRs,
   deployment boundaries; what may be reused, adapted or must never be reused.
2. Technology selection for center, agent, web frontend, database and
   deployment, with rejected alternatives and dependency constraints.
3. Architecture, data flow, trust boundaries, threat surface, permission
   matrix, `node_class` isolation and event-isolation rules.
4. Frozen node registration / authentication / reporting / rotation /
   revocation / protocol-version / compatibility contract (v1) with
   machine-readable schemas and signed test vectors, including the owner-accepted
   A-1..A-5 recovery semantics, numeric/SQLite bounds and the Windows terminal
   six-token telemetry.
5. Frozen 30-day history retention, capacity limits, deletion rules and
   backup/restore targets.
6. Threat model, security test plan and performance budget that later phases
   must satisfy.

## Non-goals (explicitly out of scope for this PR)

- No center, agent, frontend or database implementation.
- No new runtime dependencies committed to the repository; no CI/workflow
  change; no new service, container or database provisioning.
- No change to `monitor-v2`, `sbox-cm`, Remote Probe (#67), HA-UI, installers,
  existing Issues or their recorded verdicts.
- No production deployment, no release, no remote write capability, no merge.

## Deliverables

- [01 — Existing-capability review](01-existing-capability-review.md)
- [02 — Technology selection ADRs](02-technology-selection-adr.md)
- [03 — Architecture and trust boundaries](03-architecture-and-trust-boundaries.md)
- [04 — Node protocol v1 (frozen, revision 5)](04-node-protocol-v1.md)
- [04 rev-6 normative overlay — power-loss/restart generation](04-node-protocol-v1.rev6.md)
- [05 — Retention, capacity and backup](05-retention-capacity-backup.md)
- [06 — Threat model, security tests and performance](06-threat-model-security-tests-performance.md)
- [07 — UM-B entry criteria and review](07-um-b-entry-and-review.md)
- [08 — PR #126 review response matrix (rev 2, rev 3 and rev-5 targeted amendment; owner Round-2 record)](08-review-response-matrix.md)
- [../contracts/v1/](../contracts/v1/) — schemas, positive/negative examples, signed report/Windows-terminal/enrollment/rotate/config vectors, behavioural negative contract (revision 5), plus the revision-6 normative power-loss/restart fixture

## How this phase was investigated

Read-only review of main `885171c0…` (historical rev-5 investigation basis):

- repository modules and documentation for `monitor-v2`, `sbox-cm`, Remote
  Probe (#67), HA-UI, Windows client, deployment tooling and CI workflows;
- GitHub issues #33 / #48 / #67 and the open/closed PR inventory, including the
  merged HA-UI 0.2.0 (PR #124) and the quality-receiver CI hotfix (PR #125);
- deployment/rollout boundary documents and the existing security contracts;
- existing retention, spool, auth and rate-limit implementations, with their
  measured evidence, as inputs for the UM design.

No repository file outside `docs/um/` is changed by this phase.

## Review gate (UM-A → UM-B)

The independent reviewer must confirm all of:

- [ ] Capability boundaries: no forbidden reuse/duplication; existing systems
      unchanged and their contracts preserved.
- [ ] Technology selections are justified; rejected/alternative options and
      dependency additions are explicit and acceptable.
- [ ] Architecture/trust boundaries/permission matrix resolve the brief's
      security principles (no localhost trust, no header-only trust, separate
      ingress, read-only agent, center not in business path).
- [ ] Node protocol v1 is unambiguous, replay-resistant, rotation/revocation
      capable, version-compatible, and testable from the committed schemas and
      signed vectors; the rev-5 recovery/numeric/node-class/Windows-terminal
      additions and revoked-vector history are coherent.
- [ ] Retention/capacity/backup rules are implementable within the 2C4G/40GB
      assumption and the 30-day history requirement, including the database
      decision gate.
- [ ] Threat model, security test plan and performance budget are complete
      enough to drive UM-B..UM-E.
- [ ] Open questions are resolved or explicitly accepted by the owner.
- [ ] No implementation was started and no merge/deployment authorization is
      implied.

## Local validation performed for this deliverable (revision 5)

- Every JSON schema/example under `docs/um/contracts/v1/` parses as JSON; all 10
  schemas are valid JSON Schema 2020-12; 10 positive examples validate; the 7
  schema-negative examples are rejected and the 2 runtime-only negatives are
  schema-valid as intended.
- Signed vectors verify with Ed25519: retained rev-4 report, rev-5 Windows
  terminal report, rev-5 enrollment, rotate and config; body bytes/hashes match
  the committed examples; the historical rev-4 enrollment vector remains
  verifiable and is explicitly not a current positive. Tampered-body (Linux and
  Windows), wrong-key, cross-endpoint, boot-generation and rotate-body negatives
  fail as required.
- The behavioural contract is revision 5 with 67 unique cases, all error codes in
  the closed enum, retained `superseded_rev4_expectations`, and the REC-01..REC-30
  mapping in `04` §6.4.
- Cross-document checks: no normative leftover `seq == 1`/generation-skip/
  `uint64`/"Mihomo disabled in v1" contradiction, no stale node-table naming, relative
  links resolve, and no private keys/tokens are committed.
- Markdown/Mermaid was reviewed manually; no repository test or CI job reads
  `docs/um/`, so CI for this PR is regression-only (existing suites must stay
  green). The known Windows acceptance-harness flake is recorded separately and
  was not hidden by any test change.

Exact commands/results are recorded in the PR body and in `08` (rev-5 section),
not in this directory, so the committed design stays stable.
