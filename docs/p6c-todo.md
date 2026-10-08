# P6C — incident remote evidence

Authorized by the operator on 2026-10-08 after PR #70 merge and existing-test-VPS update. Base: `7c20a8251392d61f7f954292d0fe1ff9e4dbe056`.
Monitor version: **0.8.0**. P6C reviewed and merged in PR #71 on 2026-10-08 (`79b9aecda9cb7ee6706e339d443c28e8f2323474`). History stays v5; remote store stays v1.

- [x] Separate session-gated GET `/api/v1/incidents/<incident_id>/remote-probes`.
- [x] Strict bounded positive canonical incident ID; missing incident 404, unreadable History 503.
- [x] Server-derived `analysis_start_epoch` → `last_classified_end_epoch`; URL bounds, limits and filters cannot change it.
- [x] Bounded retained sample projection: 255 records and one extra truncation witness. No receipts as evidence, run/sequence/test identifiers, keys, endpoints or raw request bytes.
- [x] Current reporting status separated from historical incident records; no inference of a stopped Windows service or path failure from silence.
- [x] Operator position/path labels, retired mapping uncertainty, egress changes, stale/unavailable and retention/budget limits visible.
- [x] DOM-safe Chinese incident presentation with explicit refresh, technical identifiers behind details, passive cache labelled non-independent.
- [x] P5 list/detail keys, History/classifier/runtime/presenter and collection/ingest/storage implementations unchanged.
- [x] Local 23 P6C SQLite/HTTP tests, 129 DOM checks, 148 P5 behavior checks and 230 Agent behavior checks passed.
- [x] Exact-head CI acceptance: all 15 checks and all three workflows passed on `9c8e69a46d2cad80db88935fe903f3a13666f570`; track PR checks (Linux route/framing and full packaging regressions). The first run exposed an obsolete pre-P6C static reference allowlist; the P6C session dispatch and closed module-set gates now restate the authorized scope without removing History/classifier isolation checks.
- [x] PR review and merge decision: PR #71 merged; scope, schema, session dispatch and protected-path isolation reviewed.
- [ ] Update the existing VPS with P6C plus the retired-device display fix (PR #72); no Windows reinstall needed for this server/UI-only change.

The existing P6B route group was attempted on Windows and aborted with WinError 10053 during a deliberately rejected chunked request. The other 143 P6B checks passed locally. Keep this limitation; Linux CI remains required, not a fabricated local full-suite PASS.

This phase is incident supporting-fact presentation only. It adds no standalone live device overview, arbitrary time-window browser, classifier consumption, ISP lookup, failover or P6D. Position/path labels are current operator assertions, not incident-time routing proof; different labels do not establish independent uplinks. No source silence is reported as network down. History byte/schema/prune and classifier contracts remain unchanged.

The combined PR #72 candidate retains both UI test groups: 135 DOM checks and all 23 P6C SQLite/HTTP tests passed locally after integrating main. PR #72 final CI and merge are tracked separately; a successful code merge is not a VPS deployment receipt.

No local operator helpers, machine records, keys, downloaded ZIPs or temporary preview files are part of the PR.
