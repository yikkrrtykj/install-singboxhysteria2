# UM-A 07 — UM-B entry criteria, open questions and authorization record

Status: this document is the hand-off gate between UM-A (investigation/design)
and UM-B (implementation). Nothing here authorizes implementation by itself; the
independent review PASS plus owner answers are required.

## 1. UM-A review checklist

| # | Requirement from the brief | Evidence in this deliverable |
| --- | --- | --- |
| 1 | Latest main, Issues, PRs and deployment boundaries reviewed | [01](01-existing-capability-review.md) §1, §8 |
| 2 | `monitor-v2`, `sbox-cm`, Remote Probe #67 and HA-UI audited | [01](01-existing-capability-review.md) §2–§5 |
| 3 | Reusable vs forbidden capabilities explicit | [01](01-existing-capability-review.md) §6, §7 |
| 4 | Center/agent/frontend/database technology evaluated | [02](02-technology-selection-adr.md) ADR-UM-001..008 |
| 5 | Architecture, data flow, trust boundaries | [03](03-architecture-and-trust-boundaries.md) §1–§6 |
| 6 | Permission matrix and event isolation | [03](03-architecture-and-trust-boundaries.md) §7–§8 |
| 7 | Node registration/auth/report/revoke/version/compatibility frozen | [04](04-node-protocol-v1.md), [contracts/v1](../contracts/v1/) |
| 8 | 30-day retention, capacity, backup and deletion rules frozen | [05](05-retention-capacity-backup.md) |
| 9 | Threat model, security test plan, performance budget | [06](06-threat-model-security-tests-performance.md) |
| 10 | No implementation, no product/workflow change, no deployment | PR change scope is `docs/um/` only; UM-B..E HOLD |

Reviewer should reject if: a forbidden reuse remains; a contract is ambiguous or
untestable; a trust boundary is missing; the 30-day/40 GB sizing is inconsistent;
or any implementation/deployment authorization is implied.

## 2. Open questions for the owner (UM-B cannot start until answered)

Recommended defaults are provided; the owner may accept or override each.

1. **Tracking issue.** There is no Unified Monitor GitHub issue (only #33, #48,
   #67 are open). Recommended: owner creates one long-term UM tracking issue and
   links this PR; coding AI must not create it unilaterally.
2. **Center host.** Confirm a new independent VPS (new host, not an existing
   production VPS), 2C4G/40 GB SSD planning size, Linux x86_64, Debian 12 or
   Ubuntu 24.04 LTS, IPv4 (+IPv6 if available). Final size by UM-E load test.
3. **DNS/Cloudflare.** Confirm control of `132431.xyz`: `monitor.132431.xyz`
   proxied through Cloudflare Tunnel + Access; `ingest.132431.xyz` DNS-only
   (no proxy) on TCP 8443; confirm Cloudflare Access identity provider and the
   application `aud` tag, and that the owner will provision the tunnel token.
4. **Agent OS matrix and installation.** Confirm supported event-VPS OS
   (Debian/Ubuntu systemd), install method (signed/static binary + reviewed
   install script/unit, operator-run with root once, then unprivileged service),
   and that the center never gets SSH/root access to install it.
5. **Authorized data sources per event VPS.** Confirm the agent may read:
   sing-box `service.api` over loopback with its existing 0600 secret file,
   `/proc`, and `systemctl is-active` for the sing-box unit; optionally the
   Mihomo controller over loopback for client summaries. Confirm journald/root
   collection is **not** required (it stays #33/Monitor scope).
6. **Coexistence.** If a VPS already runs the per-VPS `monitor-v2` Monitor, is
   running the UM agent alongside it acceptable (read-only duplicate load), or
   should events use one collector? Recommended: events may run the UM agent
   only; no change to existing Monitor deployments.
7. **Retention/audit/backup.** Accept 30-day telemetry history, 180-day audit
   (configurable), RPO ≤24 h, RTO ≤2 h, encrypted owner-initiated off-host
   backup, and the SQLite→PostgreSQL gate in [05](05-retention-capacity-backup.md) §4.
8. **Availability.** Accept a single center host (admin plane best-effort; center
   outage does not affect business) as the v1 availability model; no HA in
   UM-B..UM-E.
9. **Admin policy.** Accept password + mandatory TOTP for every admin account,
   one-time recovery codes, offline reset requiring OS-level access on the center
   host, and Argon2id parameters specified in UM-B.
10. **Tech stack.** Accept Go (center + agent), Vue 3 + TypeScript + Vite +
    uPlot (frontend), SQLite WAL first, no containers/microservices, and the
    dependency policy in [02](02-technology-selection-adr.md) ADR-UM-007.
11. **Privacy of client summaries.** Confirm pseudonymous `device_ref`
    (HMAC-SHA256 with per-event salt; no client names/UUIDs) is sufficient for
    "客户端摘要" and that no raw connection metadata may be collected.
12. **UM-F.** Confirm the read-only platform (UM-A..UM-E) must not add write
    capability, and that UM-F starts only after a separate approval and design.

## 3. UM-B entry criteria

UM-B may start only when all are true:

- [ ] UM-A independent review recorded **PASS** (requested changes closed).
- [ ] Owner resolved/answered all §2 questions (or accepted recommendations).
- [ ] Contract v1 frozen; the committed test vector is reproduced by the first
      UM-B contract test (before any feature work merges).
- [ ] Tech selections accepted; dependency register/review plan agreed.
- [ ] UM-B scope split into reviewable Draft PRs with write scopes and test
      evidence, each independently reviewed.
- [ ] No existing system is modified; UM-B does not enable `sbox-cm`, #67, or any
      remote write path; production deployment remains HOLD.

## 4. Proposed UM-B delivery slices (for owner approval)

| Slice | Scope | Must prove |
| --- | --- | --- |
| UM-B1 | Go module skeleton; storage interface + SQLite schema/migrations; retention engine; contract conformance tests (schemas + signed test vector) | schema/retention/backup-shape tests, 30-day accelerated retention, vector verification |
| UM-B2 | Ingest listener, enrollment/rotation/revocation, report auth/replay/schema/allowlist, storage transactions, synthetic agent harness | SEC-11..SEC-15, SEC-17, SEC-19, SEC-23, contract tests, load smoke |
| UM-B3 | `um-agent` binary, read-only collectors, durable spool, enrollment flow, systemd/unit and operator runbook | agent budget, spool replay/outage, no-listener/no-write proofs, privacy allowlist |
| UM-B4 | Admin CLI/API for events, nodes, enroll tokens, revocation, retention status (web UI is UM-C) | RBAC foundations, audit, cross-event isolation at API layer |

UM-B does not build the public web entry (UM-C), dashboard (UM-D) or remote
management (UM-F). Each slice is a separate Draft PR, merged only after its own
review; production deployment is still separately authorized in UM-E.

## 5. Change control for the frozen design

- Contract v1 (`04-node-protocol-v1.md` + `contracts/v1/`) is frozen. Any change
  requires: documented proposal, threat-model impact, backward-compatibility
  statement, test-vector update and independent review before implementation.
- Capacity/retention/backup values in [05](05-retention-capacity-backup.md) may
  be tuned only by owner-approved revision; the 30-day retention and
  private-data allowlist are not tunable down.
- Architecture/trust-boundary changes (new ingress, new write path, new
  dependency/service) require a new ADR and review.

## 6. Authorization record

| Item | State |
| --- | --- |
| Current authorization | UM-A investigation/design only |
| Implementation (UM-B..UM-E) | **HOLD** |
| UM-F remote write | **DEFERRED** |
| Production deployment/release | **HOLD** |
| Merge of the UM-A PR | Requires independent review PASS and owner merge authorization; coding AI does not merge |
| Existing systems (#33/#48/#67/Monitor/HA-UI) | Unchanged; their verdicts and deployment statuses preserved |
| Unified Monitor center/agent/VPS | Not created, not deployed; no credentials, configs or VPS state touched |

Any deviation from this record must be requested explicitly by the owner and
recorded in the tracking issue/PR, not inferred by coding AI.
