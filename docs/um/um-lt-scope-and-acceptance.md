# UM-LT — Scope and acceptance-gate matrix

Status: **CANDIDATE acceptance boundary for the rev-7 contract package —
docs-only, pending independent review/CI and the Owner's conditional merge
authorization. NOT published/frozen, NOT merged, NOT implemented. No gate below
is claimed PASS by this contract PR.** Gate labels H-LT-01… are restated from the
UM-LT goal brief; if the goal uses different labels, the lead maps them to this
matrix without changing the content.

## 1. Scope of the contract PR (this package)

In scope, docs/schema/fixtures only:

- rev-7 additive contract artifacts under `docs/um/` (overlay, schemas, positive
  fixtures, negative vectors, architecture, data semantics, source audit,
  compatibility, capacity, runbook, this matrix, owner decisions, evidence);
- no Go/Python/frontend/monitor code, no workflow change, no production resource,
  no merge.

Out of scope (not authorized by this PR):

- implementation in `um/`, `monitor-v2/`, `tests/`, tools or workflows;
- production deployment, real R1, Cloudflare/DNS/TLS/certificates, VPS/SSH/paid
  resources, real lab infrastructure;
- `service.api` enablement or any change to P1-10 / `singbox_api=false`;
- merging the contract PR (the author does not merge);
- UM-B1/B2/B3/B4/C/D/E/F/G scope changes.

## 2. Acceptance gates

Legend for "contract PR" evidence: **EXISTS** = artifact produced and locally
validated (parse/consistency); **NOT RUN** = no execution claimed; **N/A** = not
this PR's scope.

| Gate | Requirement | Contract PR proves | Implementation PR must prove | Status / owner boundary |
| --- | --- | --- | --- | --- |
| **H-LT-01** Contract overlay | Formal minimal additive rev-7 overlay exists, standalone, no rev-5/6 weakening | schemas/fixtures/vectors + normative overlay + this matrix; JSON parse/consistency validation (no runner) | runner for schema+semantic vectors; conformance mapping | contract: **EXISTS**; independent review/CI/owner merge pending |
| **H-LT-02** Frozen baseline preserved | rev-5/rev-6 files byte-unchanged; B1–B4/UM-C guarantees intact; no code touched | git diff shows only new `docs/um/**` files; no edits to existing schemas/examples/vectors/docs 04 rev5/rev6 | regression suite unchanged + byte diff on rev-5/6 contract files | contract: **EXISTS** (diff only); implementation: must keep |
| **H-LT-03** Monitor read-only export | Non-root monitor writes restricted, sanitized, atomic JSON export; no new credential/listener; minimal ACL | file shape/ACL/atomic-replace/privacy rules normative; audit v1 | real writer + ACL/symlink/atomicity/privacy tests on Linux; monitor release carries it | contract: **EXISTS**; implementation/lab: **NOT RUN** |
| **H-LT-04** Agent read + report | Linux agent reads export read-only, maps/allow-lists, signs/queues rev-7 snapshot under unchanged rev-5 transport | report schema, mapping/coherence rules, sentinel, failure modes | real agent file-read/ACL/EACCES tests; rev-7 snapshots accepted by real center; spool/replay regression | contract: **EXISTS**; implementation/lab: **NOT RUN** |
| **H-LT-05** Center validate/store/query | Center validates schema+semantics, stores bounded, queries with lower-bound/freshness/epoch labels | additive storage/query design + capacity constraints | real ingest/storage/query tests; migration; query labelling; no raw observation copy | contract: **EXISTS**; implementation: **NOT RUN** |
| **H-LT-06** Data semantics | Observed observation-epoch lower bound vs daemon-lifetime exact; active bytes/deltas/rates/window; restart/source_epoch; pre-subscription/abandoned/short/replay/ID-reuse/counter-decrease/overflow; no cross-epoch differencing; no fabricated zero; float→integer; 2^53−1; unavailable cases | [`um-lt-data-semantics.md`](um-lt-data-semantics.md) normative definitions | real monitor/agent/center semantic tests incl. restart/epoch reset, stale/unavailable, no-total rendering; UI labelling where applicable | contract: **EXISTS**; implementation/lab: **NOT RUN**; real Reality/Hy2 acceptance **NOT RUN** |
| **H-LT-07** Source authorization | Versioned audit proves agent cannot read service.api secret/raw data or write export; no new write-capable credential holder; no URL/command/path from center; no public listener; `singbox_api` DISABLED; P1-10 remains FAIL | [`um-lt-source-authorization-audit.md`](um-lt-source-authorization-audit.md) v1 + threat scenarios + evidence template | real EACCES/no-read/no-write/permission-diff tests; `singbox_api` disabled assertion; P1-10 FAIL retained | contract: **EXISTS**; implementation/lab: **NOT RUN** |
| **H-LT-08** Compatibility/rollback | Old/new agent/center matrix; disabled/unsupported/queued payload/mixed fleet/rollback; rev-5 agent 7-key config rejection; queued rev-7 quarantine without rewriting report_id/body; drain rules | [`um-lt-compatibility.md`](um-lt-compatibility.md) matrix + rules | real A5/A7/C5/C7 matrix tests, direct C5 rev-7 rejection, downgrade quarantine/drain test, DB schema fail-closed rollback test | contract: **EXISTS**; implementation/lab: **NOT RUN** |
| **H-LT-09** Privacy allow-list | No raw IP/IDs/UUIDs/names/destinations/secrets/URLs/YAML/free text in export/report/storage/logs/backups | allow-list normative in overlay/audit/data semantics; fixtures synthetic only | sentinel/privacy scan over writer+agent+center+query+backups; negative examples | contract: **EXISTS** (rules); implementation/lab: **NOT RUN** |
| **H-LT-10** Capacity | Parameterized estimates inside 150 nodes / 100 per event / 30 d / 30–300 s / 8 inbounds / 5 GiB active / 10 GiB overlap; formula/index plan; no full-body retention | [`um-lt-capacity.md`](um-lt-capacity.md) estimates + requirement | measured rows/byte ratio/p95; accelerated retention/load; disk-pressure/backup interplay | contract: **EXISTS**; implementation measurement **NOT RUN**; production capacity acceptance = **UM-E** |
| **H-LT-11** Evidence/review/merge gate | Evidence template, exact-head CI, independent review, conditional owner merge authorization, no self-merge, no publication claim pre-merge | [`um-lt-evidence.md`](um-lt-evidence.md), [`um-lt-owner-decisions.md`](um-lt-owner-decisions.md); candidate status stated everywhere | exact-head CI + evidence for the implementation PR; independent review; separate merge authorization | contract: evidence template **EXISTS**, CI/review/merge **PENDING**; author does not merge |
| **H-LT-12** No production/unauthorized resources | No production, no real R1, no Cloudflare/DNS/certificates/VPS/SSH/paid resources, no `singbox_api`, PRODUCTION HOLD/R1 HOLD/UM-F DEFERRED | scope statements, no code/resources in diff | labs must remain synthetic/local; no production execution | contract: **EXISTS** (boundary); any deployment needs separate authorization |

## 3. Inherited gates that must stay green (no weakening)

| Inherited guarantee | Contract PR stance | Evidence required by implementation |
| --- | --- | --- |
| Ed25519 transport-header signing + 15-line signing strings | unchanged (no new header/string) | existing crypto vectors still pass; rev-7 body signed under the same string |
| boot generation / `MAX_BOOT_GAP` / `X-UM-Boot-Gen` | unchanged | rev-6 conformance suites unchanged |
| sequence high-water / exact retry / ACK `next_seq` | unchanged | existing B1/B2 tests + rev-7 retries |
| nonce uniqueness / request fingerprint | unchanged | existing tests |
| `report_id` dedupe / report conflict | unchanged; body now contains the observation | dedupe of rev-7 reports; same report_id different observation hash → conflict |
| rotation proof / revocation | unchanged | existing tests; revoked node rev-7 rejected |
| fsync / durable transaction ordering | unchanged | existing durability tests + rev-7 stored in same transaction |
| node class / platform isolation | unchanged; rev-7 Linux-only | Windows rev-7 reject; Linux terminal-object reject |
| event isolation / RBAC | unchanged | event-scoped query tests |
| Windows terminal telemetry (R1/R2 rules) | unchanged | Windows regression |
| privacy allow-list | extended only additively | sentinel tests |
| TOTP/session/CSRF/Access web security | untouched | UM-C regression |
| `singbox_api` DISABLED / P1-10 FAIL | explicitly retained, never weakened | assertion test that no enablement/credential path exists |

## 4. What this contract PR explicitly does NOT prove

- no runtime behavior, no real monitor/agent/center execution, no real traffic;
- no schema/negative-vector runner (JSON parse/consistency only);
- no real file ACL/atomicity/privacy symlink tests;
- no center migration/storage/query execution;
- no capacity measurement, no 30-day/150-node load, no UM-E acceptance;
- no real Reality/Hysteria2 inbound acceptance (Issue #127 blocker);
- no independent review/CI/merge/publication; rev-7 is a **candidate** until the
  normal merge gates complete.

## 5. Owner boundaries

- The contract author prepares this package and **does not merge it**; merge
  requires independent review PASS, exact-head CI green and the Owner's
  conditional merge authorization, with a normal Merge Commit only.
- The implementation PR is a separate deliverable/authorization; this contract PR
  does not authorize it, its merge, real labs, production, R1, Cloudflare/DNS/TLS,
  VPS/SSH/paid resources, or any `service.api` enablement.
- Any gate miss is reported, not waived; no PASS is claimed for a NOT RUN item.
