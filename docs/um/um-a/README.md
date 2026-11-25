# UM-A — Investigation, selection and frozen design

Status: **deliverable for independent review**. UM-B and later phases remain
HOLD until this phase receives an independent review PASS (see
[07-um-b-entry-and-review.md](07-um-b-entry-and-review.md)).

## Scope

UM-A answers the planning questions in the project brief and freezes the design
inputs needed to start UM-B:

1. Baseline and existing-capability audit: latest main, relevant issues/PRs,
   deployment boundaries; what may be reused, adapted or must never be reused.
2. Technology selection for center, agent, web frontend, database and
   deployment, with rejected alternatives and dependency constraints.
3. Architecture, data flow, trust boundaries, threat surface, permission
   matrix and event-isolation rules.
4. Frozen node registration / authentication / reporting / rotation /
   revocation / protocol-version / compatibility contract (v1) with
   machine-readable schemas and a signed test vector.
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
- [04 — Node protocol v1 (frozen)](04-node-protocol-v1.md)
- [05 — Retention, capacity and backup](05-retention-capacity-backup.md)
- [06 — Threat model, security tests and performance](06-threat-model-security-tests-performance.md)
- [07 — UM-B entry criteria and review](07-um-b-entry-and-review.md)
- [../contracts/v1/](../contracts/v1/) — schemas, examples, signed test vector

## How this phase was investigated

Read-only review of main `885171c0…`:

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
      signed vector.
- [ ] Retention/capacity/backup rules are implementable within the 2C4G/40GB
      assumption and the 30-day history requirement, including the database
      decision gate.
- [ ] Threat model, security test plan and performance budget are complete
      enough to drive UM-B..UM-E.
- [ ] Open questions are resolved or explicitly accepted by the owner.
- [ ] No implementation was started and no merge/deployment authorization is
      implied.

## Local validation performed for this deliverable

- Every JSON schema/example under `docs/um/contracts/v1/` parses as JSON; the
  schemas declare JSON Schema 2020-12 and the frozen key sets.
- The committed example report payload is signed with an ephemeral Ed25519 key;
  the committed signature/pubkey test vector is verified with OpenSSL
  (verification command recorded in the contracts README).
- Markdown/Mermaid was reviewed manually; no repository test or CI job reads
  `docs/um/`, so CI for this PR is regression-only (existing suites must stay
  green).

Exact evidence (commands, hashes, CI run) is recorded in the PR body, not in
this directory, so the committed design stays stable.
