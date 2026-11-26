# UM-A 07 — UM-B entry criteria, owner decisions and authorization record (revision 5)

Status: hand-off gate between UM-A (investigation/design) and UM-B. This is the
**revision 5 final targeted amendment**, incorporating the owner-accepted
A-1..A-5 recovery semantics, numeric/storage rules, node classes/platform
isolation and the Windows terminal contract from the #128 planning package. The
owner's Round-2 review conclusions are recorded in §3; they are not a merge or
deployment authorization and do not approve the pending decisions in §2.
Owner decisions below remain **NOT approved** unless the owner explicitly
answers them.

## 1. UM-A review checklist (revision 5)

| # | Requirement | Evidence |
| --- | --- | --- |
| 1 | Latest main, Issues/PRs/deployment boundaries reviewed | [01](01-existing-capability-review.md) |
| 2 | monitor-v2 / sbox-cm / Remote Probe #67 / HA-UI audited; reuse vs forbidden explicit | [01](01-existing-capability-review.md) §6–§7 |
| 3 | Architecture, data flow, trust boundaries, permission matrix, `node_class` isolation | [03](03-architecture-and-trust-boundaries.md) |
| 4 | Technology selection with rejected options | [02](02-technology-selection-adr.md), review PASS kept |
| 5 | Frozen node protocol with header-only signatures, operation binding, replay/durability, per-endpoint semantics | [04](04-node-protocol-v1.md), [contracts/v1](../contracts/v1/) |
| 6 | 30-day retention policies A/B compared; capacity/backup/restore rules (including mapping-version retention) | [05](05-retention-capacity-backup.md) |
| 7 | Threat model, security tests, performance budget aligned with the real architecture | [06](06-threat-model-security-tests-performance.md) |
| 8 | Review issues P0-01, P1-01..P1-11 addressed item by item; rev-5 amendment items recorded | [08](08-review-response-matrix.md) |
| 9 | All signed vectors/schemas revalidated (positive and negative), rev-5 vectors added, historical vectors retained | `test-vectors.v1.json`, `negative-vectors.v1.json`, validation record in 08 |
| 10 | No implementation, product/workflow change or deployment authorization | PR scope `docs/um/` |
| 11 | #128 plan review (owner Round-2) recorded and folded into this contract; no separate PR-A2 | §3, [08](08-review-response-matrix.md) |
| 12 | Owner decisions still PENDING; no Coding-AI approval inferred | §2, §7 |

## 2. Owner decisions (pending; recommendations recorded, not approved)

| ID | Question | Recommendation (reviewer/owner direction) | Status |
| --- | --- | --- | --- |
| Q-TRACK | Single long-term UM tracking issue? | One owner-authorized UM tracking Issue (#127 exists); coding AI must not create duplicates | PENDING |
| Q-HOST | Center host/spec/OS | Independent 2C4G/40 GB Ubuntu 24.04 LTS, new VPS; final size by UM-E load test | PENDING |
| Q-SIZE | Disk/policy-B quota | 40 GB + policy B supports ~150 active nodes; 200 active nodes need larger disk or policy A | PENDING |
| Q-INGRESS | Machine-entry transport | Evaluate dual-entry Cloudflare Tunnel and direct TLS 8443; protocol identical | PENDING |
| Q-DNS | Domain/Cloudflare/Access | `monitor.132431.xyz` tunnel+Access; `ingest.132431.xyz` per Q-INGRESS; owner holds zone/IdP/`aud`/tunnel tokens | PENDING |
| Q-AGENT-OS | Agent OS matrix/install | Debian/Ubuntu systemd for linux_vps; rev-5 adds windows_terminal as a class, but the Windows OS support/install matrix still needs an explicit decision; one-time root orchestration, unprivileged runtime | PENDING |
| Q-COEXIST | Coexistence with per-VPS Monitor | Read-only coexistence; no changes to existing Monitor deployments | PENDING |
| Q-DATA | Authorized local data sources | sing-box `service.api` (LoadCredential), `/proc`, read-only systemd D-Bus; no journald/root. Windows terminal: R2 truly-read-only source preferred; R1 write-capable controller credential requires separate owner risk acceptance and is never auto-enabled | PENDING |
| Q-RET | Retention policy | Policy B (active rolling 30 d; archived keeps remaining history until T+30 d) with overlap cap | PENDING |
| Q-AUD | Audit retention | 180 d, size-bounded, configurable down but never below 30 d | PENDING |
| Q-BACKUP | Backup / RPO / RTO | Local failure RPO ≤24 h; whole-VPS-loss RPO requires daily encrypted off-host copy; RTO ≤2 h local, ≤1 business day whole-VPS | PENDING |
| Q-LEDGER | Security ledger off-host handling | Ledger + signed checkpoint in every backup/offsite; restore quarantined and reconciled; incomplete ledger stays quarantined | PENDING |
| Q-HA | Availability | Single center, no HA; admin plane best-effort; business unaffected | PENDING |
| Q-ADMIN | Admin policy | Mandatory TOTP for every admin; first phase single platform admin; one-time recovery codes; offline OS reset | PENDING |
| Q-TECH | Tech stack | Go center+agent, Vue 3+TS+Vite+uPlot, SQLite WAL first (`synchronous=FULL`) | PENDING |
| Q-ALIAS | Client summary presentation | Pseudonymous `device_ref` + center-side display alias (plus rev-5 terminal route aliases); no raw proxy credentials/connection data | PENDING |
| Q-UMF | UM-F boundary | Read-only platform only; UM-F needs separate approval/design with operation-level authorization | PENDING |
| Q-ISSUE | Existing issues | #33/#67 untouched; #48 is Closed/Completed (verified live 2026-11-25) with evidence retained; no new issues/PRs without owner approval | PENDING |

**No real token, password, private key, VPS purchase or Cloudflare application may
be requested from the owner at this stage.** R2 source evaluation is UM-B3 work;
R1 is a separate later owner risk decision.

## 3. Owner Round-2 review record (2026-11-26)

The owner recorded these review conclusions for the #128 planning package. They
are recorded verbatim in substance; the Coding AI did not perform or approve
them:

| Item | Owner conclusion | Rev-5 action |
| --- | --- | --- |
| #128 overall implementation plan | PASS | planning package kept; gates updated |
| Recovery design A-1..A-5 | ACCEPTED DIRECTION | folded into this revision (§5/§6 of 04) |
| Dual-platform architecture | PASS | folded into node_class/platform/terminal contract |
| Go migration roadmap | PASS | kept in #128 plan; UM-B1 preparation gated |
| Final contract | TARGETED UPDATE REQUIRED | this revision 5 is that targeted update |
| CI | PASS WITH RECORDED RERUN | recorded; no test weakening |
| Merge / deployment | Separate owner authorization required | not granted by this record |

**Independent review is still required** by the UM-B entry criteria; the
Round-2 record is an owner review, not the independent review object on GitHub.

## 4. UM-B entry criteria

- [ ] Independent UM-A review PASS for revision 5 final (all P0/P1, rev-5
      targeted items and the owner Round-2 directions closed).
- [ ] Owner answers §2 or explicitly accepts recommendations; owner gives merge
      authorization; #126 is merged via a normal Merge Commit and main CI is
      green.
- [ ] Contract v1 revision 5 frozen; committed positive/negative vectors and
      REC-01..REC-30 reproduced by the first UM-B conformance tests before any
      feature merge.
- [ ] Tech selections accepted; dependency register/review plan agreed
      (including the Go toolchain/SQLite dependency decision).
- [ ] UM-B split into reviewable Draft PRs with write scopes, tests and evidence.
- [ ] Existing systems unmodified; no `sbox-cm`/#67/remote-write activation;
      production deployment remains HOLD.
- [ ] UM-B1 CI plan covers contract-file changes, pinned toolchain, dependency
      audit, build/test/vet/race, with no simplified schema validation,
      tautological tests or JSON-parse-only conformance.

## 5. Proposed UM-B slices (for owner approval)

| Slice | Scope | Must prove |
| --- | --- | --- |
| UM-B1 | Go module skeleton; rev-5 signing library extension; storage interface + SQLite schema/migrations (numeric bounds, dedupe/boot tables, mapping-version tables); retention engine; contract conformance tests (schemas, rev-5 positive/negative vectors, REC-01..REC-30 protocol-level cases) | schema/retention/durability tests, 30 d accelerated retention, signed vectors, no simplified validation |
| UM-B2 | Ingest listener; enrollment (token-scope class/event binding, active-on-commit) / rotation state machine with full validation / revocation; header/signing binding; replay/boot/seq/report_id dedupe; A-1..A-5 recovery; platform isolation; storage transactions; synthetic agent harness | SEC-11..15, SEC-29..31, SEC-36..38, SEC-42..47, contract negatives, REC cases, load smoke |
| UM-B3 | `um-agent`; provisioning orchestration (root one-shot → unprivileged enroll); Linux read-only collectors; Windows terminal collector after R2 evaluation (six tokens, independent sampling, read-only proof; R1 only after separate owner acceptance); durable spool; install/runbook | SEC-21/31/32/33, agent budgets, offline replay/restart/revocation transitions, no-exec proof, Windows read-only/HA assertions |
| UM-B4 | Admin API/CLI for events, nodes, tokens, revocation, retention, aliases, node_class and versioned route mappings (web UI is UM-C) | RBAC foundations, audit, cross-event isolation, mapping-history immutability |

UM-B does not build the public web entry (UM-C), dashboard (UM-D) or remote
management (UM-F). Each slice is a separate Draft PR; production deployment is
authorized only in UM-E.

## 6. Change control

- Contract v1 **revision 5** (`04` + `contracts/v1/`) is the final targeted
  amendment. Any further change requires a written proposal, threat-model
  impact, compatibility statement, updated vectors (positive and negative) and
  independent review before implementation.
- Rev-4 expectations that rev-5 supersedes are retained in
  `negative-vectors.v1.json` (`superseded_rev4_expectations`) and git history;
  they must not be silently deleted.
- Retention policy A/B, RPO/RTO, backup/off-host handling and machine-ingress
  option are owner decisions; they may be decided but not silently changed by
  UM-B. The 30-day retention and privacy allowlist are not tunable down.
- R2/R1: R2 truly-read-only Windows source is preferred; R1 residual risk is a
  separate later owner acceptance, not a default or implied approval.
- New dependency/service/write path requires a new ADR and review.
- The security ledger and restore-quarantine procedure are mandatory; weakening
  them requires owner approval and a new threat-model review.

## 7. Authorization record

| Item | State |
| --- | --- |
| Current authorization | UM-A investigation/design only (revision 5 final targeted amendment) |
| Implementation (UM-B..UM-E) | **HOLD** until entry criteria and owner authorization |
| UM-F remote write | **DEFERRED** |
| Production deployment/release | **HOLD** |
| Merge of the UM-A PR | Requires independent review PASS and owner merge authorization; coding AI does not merge |
| #128 plan PR | Kept; syncs its baseline to this revision after #126 stabilizes; independent review and owner merge gate still required |
| Existing systems (#33/#67/Monitor/HA-UI) | Unchanged; verdicts/deployment states preserved. #48 is Closed/Completed and its record is preserved |
| Center/agent/VPS/Cloudflare resources | Not created, not deployed; no credentials, configs or production state touched |
| Related existing CI flake | Recorded; a separate owner-authorized hotfix is suggested; no test/workflow change in this PR |

Any deviation must be requested explicitly by the owner and recorded in the
tracking issue/PR; it is not inferred by coding AI.
