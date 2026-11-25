# UM-A 07 — UM-B entry criteria, owner decisions and authorization record (revision 3)

Status: hand-off gate between UM-A (investigation/design) and UM-B. Revision after
PR #126 rev-3 review. Owner decisions below are **NOT approved** by this revision;
the review's recommendations are recorded as recommendations only.

## 1. UM-A review checklist (revision 3 final)

| # | Requirement | Evidence |
| --- | --- | --- |
| 1 | Latest main, Issues/PRs/deployment boundaries reviewed | [01](01-existing-capability-review.md) |
| 2 | monitor-v2 / sbox-cm / Remote Probe #67 / HA-UI audited; reuse vs forbidden explicit | [01](01-existing-capability-review.md) §6–§7 |
| 3 | Architecture, data flow, trust boundaries, permission matrix | [03](03-architecture-and-trust-boundaries.md) |
| 4 | Technology selection with rejected options | [02](02-technology-selection-adr.md), review PASS kept |
| 5 | Frozen node protocol with header-only signatures, operation binding, replay/durability, per-endpoint semantics | [04](04-node-protocol-v1.md), [contracts/v1](../contracts/v1/) |
| 6 | 30-day retention policies A/B compared, capacity/backup/restore rules | [05](05-retention-capacity-backup.md) |
| 7 | Threat model, security tests, performance budget aligned with the real architecture | [06](06-threat-model-security-tests-performance.md) |
| 8 | Review issues P0-01, P1-01..P1-06 addressed item by item | [08](08-review-response-matrix.md) |
| 9 | All signed vectors/schemas revalidated (positive and negative) | PR validation evidence |
| 10 | No implementation, product/workflow change or deployment authorization | PR scope `docs/um/` |

## 2. Owner decisions (pending; recommendations from the review recorded, not approved)

| ID | Question | Recommendation (reviewer) | Status |
| --- | --- | --- | --- |
| Q-TRACK | Single long-term UM tracking issue? | Create one owner-authorized UM tracking Issue; coding AI must not create it | PENDING |
| Q-HOST | Center host/spec/OS | Independent 2C4G/40 GB Ubuntu 24.04 LTS, new VPS; final size by UM-E load test | PENDING |
| Q-SIZE | Disk/policy-B quota | 40 GB + policy B supports ~150 active nodes with VACUUM/backup scheduling; 200 active nodes with policy B needs a larger disk (or policy A). Quotas in doc 05 §4.1 | PENDING |
| Q-INGRESS | Machine-entry transport | Evaluate dual-entry Cloudflare Tunnel (web+Access; ingest tunnel hostname without Access) **and** compare with direct TLS 8443; choose after comparison; protocol identical | PENDING (Option A/B in ADR-UM-005) |
| Q-DNS | Domain/Cloudflare/Access | `monitor.132431.xyz` tunnel+Access; `ingest.132431.xyz` according to Q-INGRESS; owner owns zone, Access IdP, `aud`, tunnel tokens | PENDING |
| Q-AGENT-OS | Agent OS matrix/install | Debian/Ubuntu systemd; static binary + reviewed installer; one-time root orchestration, unprivileged runtime | PENDING |
| Q-COEXIST | Coexistence with per-VPS Monitor | Agent and existing Monitor may coexist read-only; no changes to existing Monitor deployments | PENDING |
| Q-DATA | Authorized local data sources | sing-box service.api (LoadCredential), `/proc`, read-only systemd D-Bus; no journald/root; Mihomo optional | PENDING |
| Q-RET | Retention policy | Policy **B** (active rolling 30 d; archived keeps remaining history until T+30 d) with overlap cap; owner must confirm | PENDING |
| Q-AUD | Audit retention | 180 d, size-bounded, configurable down but never below 30 d | PENDING |
| Q-BACKUP | Backup / RPO / RTO | Local failure RPO ≤24 h; whole-VPS-loss RPO requires a **daily encrypted off-host copy** if ≤24 h is promised (owner daily pull or write-only push credential); otherwise state whole-VPS RPO = last off-host copy. RTO ≤2 h local, ≤1 business day whole-VPS | PENDING |
| Q-LEDGER | Security ledger off-host handling | Include the hash-chained ledger + signed checkpoint in every backup/offsite copy; restore starts quarantined and requires ledger reconciliation; incomplete/unverifiable ledger stays quarantined (no auto ingest) | PENDING |
| Q-HA | Availability | Single center, no HA; admin plane best-effort; business unaffected | PENDING |
| Q-ADMIN | Admin policy | Mandatory TOTP for every admin; first phase single platform admin; one-time recovery codes; offline reset via OS access | PENDING |
| Q-TECH | Tech stack | Go center+agent, Vue 3+TS+Vite+uPlot, SQLite WAL first (synchronous=FULL) | PENDING (review PASS on direction) |
| Q-ALIAS | Client summary presentation | Pseudonymous `device_ref` + center-side admin display alias; no raw proxy credentials/connection data | PENDING |
| Q-UMF | UM-F boundary | Read-only platform only; UM-F needs separate approval/design with operation-level authorization | PENDING |
| Q-ISSUE | Existing issues | #33/#67 untouched; **#48 is Closed/Completed** with its fault-injection evidence retained and unfinished event-level acceptance limits preserved; no new issues/PRs without owner approval | PENDING |

**No real token, password, private key, VPS purchase or Cloudflare application may
be requested from the owner at this stage.** These questions are decision inputs
for UM-B, not provisioning actions; the design uses placeholders.

## 3. UM-B entry criteria

- [ ] Independent UM-A review PASS for revision 3 final (all P0/P1 and final-correction items closed).
- [ ] Owner answers §2 (or explicitly accepts recommendations).
- [ ] Contract v1 revision 3 final frozen; committed positive/negative vectors reproduced
      by the first UM-B conformance tests before any feature merge.
- [ ] Tech selections accepted; dependency register/review plan agreed.
- [ ] UM-B split into reviewable Draft PRs with write scopes, tests and evidence.
- [ ] Existing systems unmodified; no `sbox-cm`/#67/remote-write activation;
      production deployment remains HOLD.

## 4. Proposed UM-B slices (for owner approval)

| Slice | Scope | Must prove |
| --- | --- | --- |
| UM-B1 | Go module skeleton; storage interface + SQLite schema/migrations; retention engine; contract conformance tests (schemas, positive/negative vectors) | schema/retention/durability tests, 30 d accelerated retention, signed vectors |
| UM-B2 | Ingest listener; enrollment (active-on-commit) / rotation state machine / revocation; header/signing binding; replay/boot/seq/report_id dedupe; storage transactions; synthetic agent harness | SEC-11..15, SEC-29..31, SEC-36..38, contract negatives, load smoke |
| UM-B3 | `um-agent`; provisioning orchestration (root one-shot → unprivileged enroll); read-only collectors; D-Bus/no-exec; durable spool; install/runbook | SEC-21/31/32/33, agent budgets, offline replay/restart/revocation transitions, no-exec proof |
| UM-B4 | Admin API/CLI for events, nodes, tokens, revocation, retention, aliases (web UI is UM-C) | RBAC foundations, audit, cross-event isolation, data-honesty APIs |

UM-B does not build the public web entry (UM-C), dashboard (UM-D) or remote
management (UM-F). Each slice is a separate Draft PR; production deployment is
authorized only in UM-E.

## 5. Change control

- Contract v1 revision 3 final (`04` + `contracts/v1/`) is frozen. Any change requires a
  written proposal, threat-model impact, compatibility statement, updated vectors
  (positive and negative) and independent review before implementation.
- Retention policy A/B, RPO/RTO, backup/off-host handling and machine-ingress
  option are owner decisions; they may be decided but not silently changed by
  UM-B. The 30-day retention and privacy allowlist are not tunable down.
- New dependency/service/write path requires a new ADR and review.
- The security ledger and restore-quarantine procedure are mandatory; weakening
  them requires owner approval and a new threat-model review.

## 6. Authorization record

| Item | State |
| --- | --- |
| Current authorization | UM-A investigation/design only (revision 3 final) |
| Implementation (UM-B..UM-E) | **HOLD** |
| UM-F remote write | **DEFERRED** |
| Production deployment/release | **HOLD** |
| Merge of the UM-A PR | Requires independent review PASS and owner merge authorization; coding AI does not merge |
| Existing systems (#33/#67/Monitor/HA-UI) | Unchanged; verdicts/deployment states preserved. #48 is Closed/Completed and its record is preserved (not reopened or reset) |
| Center/agent/VPS/Cloudflare resources | Not created, not deployed; no credentials, configs or production state touched |
| Related existing CI flake | Recorded; a separate owner-authorized hotfix is suggested; no test/workflow change in this PR |

Any deviation must be requested explicitly by the owner and recorded in the
tracking issue/PR; it is not inferred by coding AI.
