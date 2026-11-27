# Unified Monitor (UM)

Long-lived, independent management-plane platform for monitoring multiple
competitions/events and their VPS nodes from one public web entry, with history,
security isolation and (later, separately authorized) controlled remote client
management.

This program is **separate** from the existing per-VPS `monitor-v2` Monitor, the
Windows HA-UI and the frozen Remote Probe (#67). Those systems keep their
existing scope, contracts and deployment status; UM neither replaces nor
reconfigures them.

## Phase state

| Phase | Scope | State |
| --- | --- | --- |
| **UM-A** | Existing-capability review, technology selection, architecture/trust boundaries, frozen contracts, retention/capacity/backup rules, threat model/security tests/performance budget | **REVISION 5 PUBLISHED + REVISION 6 POWER-LOSS OVERLAY PENDING RELEASE MERGE** (PR #132) |
| UM-B | Center service + node infrastructure (enrollment, identity, reporting, revocation, storage, retention) | **HOLD** (preparation may start only after the merge gates) |
| UM-C | Public web entry + authentication (Cloudflare Tunnel/Access, password, TOTP, sessions) | **HOLD** |
| UM-D | Dashboard + history features | **HOLD** |
| UM-E | Security/deployment/acceptance (load, fault injection, backup/restore, independent review) | **HOLD** |
| UM-F | Controlled remote client management | **DEFERRED** (requires separate approval after the read-only platform passes UM-E) |
| Production deployment | — | **HOLD** |

The authoritative product requirements, boundaries and phase gates are the
Unified Monitor project brief supplied by the owner. This repository only
records the UM-A investigation/design artefacts and must not be read as an
implementation or deployment authorization. Revision 5 integrates the owner's
Round-2 review directions (see [um-a/08](um-a/08-review-response-matrix.md));
merge authorization and independent review remain separate.

## Hard boundaries (apply to every phase)

- The center is a management plane: it does not proxy client traffic, does not
  participate in client failover decisions and is never in the data path of a
  competition connection.
- The web admin entry and the machine data entry are isolated (different
  hostnames, listeners and authentication stacks).
- Localhost is not an administrator credential; an unverified Cloudflare header
  is never an administrator credential.
- Every node has its own rotatable, revocable machine identity. Event ownership
  and node class are decided by the center only (`node_class` is bound by the
  admin-issued enrollment token scope); an agent cannot move itself between
  events or classes.
- The center never stores root SSH passwords for VPSes. Agents are read-only and
  have no access to the `sbox-cm` privileged socket.
- Windows terminal collection is read-only: it never edits Mihomo/Clash Verge
  Rev configuration, never switches nodes, never closes connections and never
  changes HA-UI/P6/#67 behavior. Local proxy names, private YAML and controller
  secrets are never uploaded; only the six bounded route tokens, aggregate
  counts and sampling timestamps are reported.
- Remote write is a separate future design (UM-F) with operation-level
  authorization; browser session/CSRF/UID are not sufficient authorization.
- Real UUIDs, passwords, private keys, tokens, full private YAML and raw
  sensitive connection data never enter monitoring history, CI or public
  issues.
- Center outage must not affect any sing-box, Mihomo or existing HA service.
- Existing `monitor-v2`, Komari, the single-VPS Monitor, issue #33/#48/#67
  contracts and HA-UI 0.2.0 stay independent and keep their recorded verdicts.

## UM-A documents

| Document | Contents |
| --- | --- |
| [um-a/README.md](um-a/README.md) | UM-A scope, method, review gate, deliverables |
| [um-a/01-existing-capability-review.md](um-a/01-existing-capability-review.md) | Baseline/main, issues/PR inventory, audit of `monitor-v2`, `sbox-cm`, Remote Probe #67, HA-UI; reuse/adapt/forbid matrix; forbidden duplication |
| [um-a/02-technology-selection-adr.md](um-a/02-technology-selection-adr.md) | Center/agent/frontend/database/deployment/crypto selections, rejected options, dependency policy |
| [um-a/03-architecture-and-trust-boundaries.md](um-a/03-architecture-and-trust-boundaries.md) | Context/component/data-flow/deployment diagrams, trust boundaries, permission matrix, isolation rules, data model overview (including `node_class`/terminal/mapping versions) |
| [um-a/04-node-protocol-v1.md](um-a/04-node-protocol-v1.md) | **Frozen** node registration/auth/report/rotation/revocation, recovery semantics A-1..A-5, numeric/SQLite rules, node classes/platform isolation, Windows terminal telemetry and protocol-version compatibility contract (revision 5) |
| [um-a/04-node-protocol-v1.rev6.md](um-a/04-node-protocol-v1.rev6.md) | **Revision 6 normative overlay** for power-loss/process-restart generation, REC-27 remap and executable conformance requirements (effective on PR #132 release merge) |
| [um-a/05-retention-capacity-backup.md](um-a/05-retention-capacity-backup.md) | 30-day history retention, deletion rules, capacity model/limits, SQLite→PostgreSQL gate, backup/restore (RPO/RTO) |
| [um-a/06-threat-model-security-tests-performance.md](um-a/06-threat-model-security-tests-performance.md) | Threat model, abuse cases, security test plan, performance budgets and UM-E measurement plan (rev-5 platform/mapping/privacy cases added) |
| [um-a/07-um-b-entry-and-review.md](um-a/07-um-b-entry-and-review.md) | UM-A rev-5 review checklist, historical owner-decision record (superseded for rev-6 by um-127/10), UM-B entry criteria, authorization record |
| [um-a/08-review-response-matrix.md](um-a/08-review-response-matrix.md) | PR #126 review response matrix (P0-01, P1-01..P1-11, rev-5 targeted amendment, owner Round-2 review record) and validation summary |
| [contracts/v1/](contracts/v1/) | Machine-readable v1 JSON schemas, positive/negative examples, signed test vectors (report, Windows terminal, enrollment, rotate, config), behavioural negative contract (revision 5) and revision-6 power-loss fixture |

## Authorization record

- Authorized now: UM-A investigation/design (revision 5 published) and the
  rev-6 contract-release package under its conditional Owner merge authorization.
- Not authorized by the rev-6 release: B3 PR #131 merge, production deployment,
  real R1 enablement, or an unauthorized `singbox_api`.
- B1/B2 are already merged; the B3 implementation (#131) remains a separate
  Draft candidate and does not become released by the rev-6 contract merge.
- The rev-6 PR is a **Draft** until independent review PASS, exact-head CI green
  and the normal Merge Commit gate complete. Merge/release/production remain
  explicitly withheld until then.

## Versioning

UM-A design baseline: rev-5 was based on main `885171c08210ad0f4e91f0fed0243460d294b15e`
(merge commit of PR #125); the rev-6 release base is `54efc81c`. Contract v1
**revision 5** is the published base. The approved rev-6 overlay resolves only
the power-loss/restart generation semantics; it becomes effective on its release
merge. Revision-5 content includes:
signatures are transport headers only and bind endpoint/method/path/encoding/
identity/time/sequence/nonce/body hash; enrollment is active-on-commit and binds
`node_class` through the admin token scope; rotation is a persistent state
machine where the old key is revoked only after new-key proof and every retry
runs full boot/seq/identity validation; replay is closed by `(node_id, nonce)`
+ full request fingerprint, bounded generation forward jumps (`MAX_BOOT_GAP`),
first-contact `seq>1`, current-boot acceptance, `report_id` dedupe and
`synchronous=FULL`; numeric fields are bounded to `MAX_NUMERIC` and stored as
SQLite INTEGER; Linux/Windows node classes are isolated; Windows reports six
route tokens (`a_reality`, `a_hy2`, `b_reality`, `b_hy2`, `direct`, `unknown`)
with independent selection/connection sampling; center-managed versioned
mapping keeps historical attribution; source switches are fail-closed and
authorization-gated (R2-preferred, R1 later owner risk acceptance only); signed
monotonic boot generations, quotas and security-ledger rules are frozen (restore
through an unverifiable ledger stays quarantined). The 2026-11-27 limited Owner
decisions are recorded in [um-127/10](um-127/10-owner-decisions-rev6.md); other
Owner decisions/run-time parameters remain pending. Any incompatible change
requires an explicit UM-A design revision review before further implementation.
