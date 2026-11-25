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
| **UM-A** | Existing-capability review, technology selection, architecture/trust boundaries, frozen contracts, retention/capacity/backup rules, threat model/security tests/performance budget | **READY FOR PLANNING — this directory is the UM-A deliverable, pending independent review** |
| UM-B | Center service + node infrastructure (enrollment, identity, reporting, revocation, storage, retention) | **HOLD** |
| UM-C | Public web entry + authentication (Cloudflare Tunnel/Access, password, TOTP, sessions) | **HOLD** |
| UM-D | Dashboard + history features | **HOLD** |
| UM-E | Security/deployment/acceptance (load, fault injection, backup/restore, independent review) | **HOLD** |
| UM-F | Controlled remote client management | **DEFERRED** (requires separate approval after the read-only platform passes UM-E) |
| Production deployment | — | **HOLD** |

The authoritative product requirements, boundaries and phase gates are the
Unified Monitor project brief supplied by the owner. This repository only
records the UM-A investigation/design artefacts and must not be read as an
implementation or deployment authorization.

## Hard boundaries (apply to every phase)

- The center is a management plane: it does not proxy client traffic, does not
  participate in client failover decisions and is never in the data path of a
  competition connection.
- The web admin entry and the machine data entry are isolated (different
  hostnames, listeners and authentication stacks).
- Localhost is not an administrator credential; an unverified Cloudflare header
  is never an administrator credential.
- Every node has its own rotatable, revocable machine identity. Event ownership
  is decided by the center only; an agent cannot move itself between events.
- The center never stores root SSH passwords for VPSes. Agents are read-only and
  have no access to the `sbox-cm` privileged socket.
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
| [um-a/03-architecture-and-trust-boundaries.md](um-a/03-architecture-and-trust-boundaries.md) | Context/component/data-flow/deployment diagrams, trust boundaries, permission matrix, isolation rules, data model overview |
| [um-a/04-node-protocol-v1.md](um-a/04-node-protocol-v1.md) | **Frozen** node registration/auth/report/rotation/revocation and protocol-version compatibility contract |
| [um-a/05-retention-capacity-backup.md](um-a/05-retention-capacity-backup.md) | 30-day history retention, deletion rules, capacity model/limits, SQLite→PostgreSQL gate, backup/restore (RPO/RTO) |
| [um-a/06-threat-model-security-tests-performance.md](um-a/06-threat-model-security-tests-performance.md) | Threat model, abuse cases, security test plan, performance budgets and UM-E measurement plan |
| [um-a/07-um-b-entry-and-review.md](um-a/07-um-b-entry-and-review.md) | UM-A review checklist, owner decisions (pending), UM-B entry criteria, authorization record |
| [um-a/08-review-response-matrix.md](um-a/08-review-response-matrix.md) | PR #126 review response matrix (P0-01, P1-01..P1-06) and revision-2 validation summary |
| [contracts/v1/](contracts/v1/) | Machine-readable v1 JSON schemas, positive/negative examples, signed test vectors (report + enrollment), behavioural negative contract |

## Authorization record

- Authorized now: UM-A investigation and design only (documentation, schemas,
  diagrams, local validation).
- Not authorized: UM-B/C/D/E/F implementation, any production deployment,
  remote writes, merging this PR without independent review approval.
- This PR is a **Draft**; merging, release and production remain explicitly
  withheld.

## Versioning

UM-A design baseline: main `885171c08210ad0f4e91f0fed0243460d294b15e`
(merge commit of PR #125). Contract v1 **revision 2** is frozen by
[04-node-protocol-v1.md](um-a/04-node-protocol-v1.md) after the PR #126 review
(response matrix: [08](um-a/08-review-response-matrix.md)): signatures are
transport headers only and bind endpoint/method/path/encoding/identity/time/
sequence/nonce/body hash; replay/dedupe is `report_id`-based with persistent
center state and `synchronous=FULL`; owner decisions remain pending. Any
incompatible change requires an explicit UM-A design revision review before UM-B
implementation.
