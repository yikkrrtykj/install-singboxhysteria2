# UM-LT — Owner decisions, assumptions and requests

Status: **CANDIDATE record for the rev-7 contract package — docs-only, pending
independent review/CI and the Owner's conditional merge authorization. NOT
published/frozen, NOT merged, NOT implemented. This file does not grant any
deployment, merge or permission authorization.**

## 1. Decisions already made / carried into this revision

| ID | Decision | Source / scope |
| --- | --- | --- |
| OD-LT-01 | Linux traffic capability is delivered through a new **read-only local monitor-v2 file export** consumed by the unprivileged agent, not through `service.api` | UM-LT goal brief; B4 read-only investigation follow-up; existing `docs/um/um-b4-data-source-investigation.md` |
| OD-LT-02 | The rev-7 source is a **lower bound from the monitor observation epoch**, never a daemon-lifetime total or exact counter | goal brief; [`um-lt-data-semantics.md`](um-lt-data-semantics.md) |
| OD-LT-03 | `singbox_api` stays **DISABLED**; P1-10 remains **FAIL**; no `service.api` credential is accepted/delivered by the agent or center and no security gate is weakened | owner decision `docs/um/um-127/10-owner-decisions-rev6.md` §3, retained |
| OD-LT-04 | No new write-capable credential holder; the monitor keeps its existing secret internally and exports none; the agent gets only read access to one aggregate file | goal brief; [`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md) |
| OD-LT-05 | The export file shape is the cross-agent reconciled format `schema: singbox-monitor-traffic-export`, `schema_version: 1`, `source: monitor-v2`, with file-only observability (`generated_at`, `monitor_stale`, `monitor_last_success_at`); the report source token remains `monitor_readonly_export` | lead reconciliation (umlt-monitor/umlt-go/umlt-e2e), recorded in overlay §4.3 |
| OD-LT-06 | Rev-7 is an **additive, default-disabled** overlay: no new endpoint/header/signing string/error code; base `v` stays 1; `contract_revision: 7` is the discriminator | goal brief; overlay §0 |
| OD-LT-07 | The contract PR is **conditionally mergeable but not merged by its author**; independent review PASS + exact-head CI + Owner conditional authorization + normal Merge Commit only | goal brief; §4 below |
| OD-LT-08 | The implementation PR is a separate deliverable and is **not merged/authorized** by this contract PR; real labs and production remain unauthorized | goal brief; [`um-lt-scope-and-acceptance.md`](um-lt-scope-and-acceptance.md) |

## 2. Decisions requested (review/owner confirmation)

| ID | Request | Why needed / impact if rejected |
| --- | --- | --- |
| OD-LT-09 | Approve the narrow rev-5 coherence exception for rev-7 Linux bodies: base `traffic` MUST stay `[]` while `availability.traffic` may be `partial` (observation available but not a total), and MUST NOT be `ok` | the frozen rev-5 rule says `partial` requires a non-empty traffic array; rev-7 sets the array empty honestly. If rejected, the only alternative is `availability.traffic=unavailable` for all rev-7 bodies, which under-describes available lower bounds. Negative vector `NEG7-SNAP-24` covers the forbidden direction |
| OD-LT-10 | Approve the rev-7 numeric bound `MAX_SAFE_BYTES = 2^53−1` for byte counters (stricter than rev-5 `MAX_NUMERIC=2^63−2`), with truncation/capping rules | keeps values exact for JSON/JS consumers and keeps a lower bound from rounding up; deliberately stricter, not weaker |
| OD-LT-11 | Approve the freshness derivation (`fresh iff age ≤ max(2×cadence,120)s`; `stale` up to 86400 s; else unavailable) and the documented no-observation sentinel | needed for deterministic agent/center behavior and negative vectors |
| OD-LT-12 | Approve the storage requirement: extract the observation into bounded structured latest/5-minute-bucket rows; do **not** retain a second 30-day raw copy of `traffic_observation` per report | at 150 nodes/30 s cadence, full-body retention adds ~13 GB and breaches the frozen 5 GiB planning basis; the form is capacity-driven, exact table/bucket choice is implementation-reviewable |
| OD-LT-13 | Approve the minimal permission model: one new system group `um-lt-export` containing only the monitor writer user and agent reader user; dedicated root-owned export directory; one monitor `ReadWritePaths=` addition; no other permission change | implementation installer needs a concrete audited model; alternative ACLs are possible but must be equally audited |
| OD-LT-14 | Approve the compatibility/rollback semantics: a rev-5 agent's strict config validator rejects a seventh `collect` key (fail-closed), so the center must not emit `monitor_export` to non-rev-7 agents; queued rev-7 records are quarantined byte-identically on downgrade and not auto-resent in v1 | prevents a silent availability/rollback defect and avoids rewriting fsynced identities |
| OD-LT-15 | Confirm the goal-gate labels: this package uses **H-LT-01…H-LT-12** restated from the UM-LT goal brief; if the brief uses different H labels, the lead maps them to this matrix | no gate is claimed PASS; labeling only |
| OD-LT-16 | Confirm that modifying the existing `monitor-v2` writer is authorized **only in the implementation PR**, while this contract PR stays docs/schema/fixtures-only | keeps the contract PR boundary as required by the goal |
| OD-LT-17 | Confirm reference names (`/var/lib/um-lt-export/`, `traffic-export.json`, group `um-lt-export`, 2750/0640) may be fixed by the implementation PR provided the audit invariants are preserved | runbook/installer need exact names; the contract fixes invariants, not package names |

## 3. Assumptions (recorded, not approvals)

1. The goal brief's field list for `traffic_observation` is authoritative; the
   report schema follows it exactly (source token `monitor_readonly_export`,
   `exactness=lower_bound`, `counter_scope=observation_epoch`, byte/rate bounds,
   ≤8 inbounds, frozen tag grammar).
2. The export file shape is the lead-reconciled format in OD-LT-05; if the
   implementation diverges, the normative overlay and lab must be updated through
   the same review, not silently.
3. Labs for the implementation PR are synthetic/local only (`um/deploy/lab/**`,
   `tests/um-lt/**`); no real production, Cloudflare/DNS/certificates, VPS/SSH or
   paid resources.
4. Production capacity acceptance is UM-E; the contract PR provides only
   parameterized estimates.
5. The frozen rev-5/rev-6 files are not edited; new rev-7 artifacts are additive
   and the existing schemas/examples/vectors stay byte-unchanged.
6. Windows terminal, rev-5 Linux base telemetry, metrics/events, enrollment,
   rotation, revocation, RBAC/session/TOTP/CSRF and UM-C behavior are unchanged.
7. `monitor_stale`/`monitor_last_success_at` are monitor-side observability only
   and are never forwarded; the agent derives freshness from its own clock.

## 4. Conditional contract merge authorization (as understood; not exercised)

- The Owner conditionally authorizes merging **this contract PR only**, as the
  rev-7 contract-release package, after: independent review PASS, no blocking
  findings, exact baseline/branch match, all required checks green, and only
  after the implementation evidence path is understood.
- Normal Merge Commit only; no squash/rebase/force-push; no protected-branch
  bypass. **The contract author does not perform the merge.**
- This authorization does **not** approve: the implementation PR merge, any
  production deployment, real R1, `singbox_api` enablement, monitor permission
  expansion beyond OD-LT-13, UM-B4/C/D/E/F/G scope changes, or paid/cloud/VPS
  resources.
- Pre-merge status is not a publication claim. Only the merged `main` state makes
  rev-7 **PUBLISHED / FROZEN**; until then it is a **candidate formal overlay
  pending review/CI**.

## 5. Explicit non-approvals / retained holds

- PRODUCTION HOLD, R1 PRODUCTION HOLD, `singbox_api` DISABLED, UM-F DEFERRED,
  issue #127 remains OPEN.
- No permission expansion: no widening of sing-box/Monitor/`sbox-cm`/HA
  permissions, no new root process, no setuid, no new listener, no new
  write-capable credential holder, no center→agent command channel.
- P1-10 remains FAIL; real Reality/Hysteria2 traffic acceptance remains
  **NOT RUN** until the implementation/lab proves it.
