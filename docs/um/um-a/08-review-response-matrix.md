# UM-A 08 — PR #126 review response matrix (rev 2 and rev 3)

Input reviews: PR #126 independent architecture review at HEAD
`d2818a7823304f1ef9f2aab7781a7755afb839c7` (rev 2) and the targeted rev-3 review
at HEAD `2886619c01d1f5249b77af5fe9e10431cb2eeac6`. This matrix is the record that
each finding is addressed; normative text is in the listed documents. Nothing here
marks an owner decision as approved.

| ID | Review requirement | Resolution | Primary files |
| --- | --- | --- | --- |
| **P0-01** | Remove enrollment signing circular dependency: signature out of the signed JSON body into an independent header; revise schema, signing string, request example, verification order; provide full enrollment positive + tampered/wrong-key/expired/wrong-token negative contracts | Signature is header-only for **every** endpoint; enrollment uses the dedicated `um-enroll-v1` signing string (protocol/endpoint/method/path/encoding/pubkey/sent-at/nonce/body-hash). Body no longer contains signature/nonce/key/time/token. Positive enrollment vector + cryptographic negatives committed; behavioural token/expiry/reuse negatives frozen | `04` §2–§4, `contracts/v1/enroll-request.schema.json`, `examples/enroll-request.v1.json`, `test-vectors.v1.json`, `negative-vectors.v1.json` (NEG-ENROLL-*) |
| **P1-01** | Bind HTTP operation: version/method/path/content-encoding/identity/time/seq/nonce/body hash; freeze per-endpoint semantics; cross-endpoint reuse, duplicate header, encoding ambiguity, signature tamper rejection; enrollment/rotation response-loss/duplicate/recovery; add response schemas/error vocabulary | Two frozen signing strings (enroll, node-auth) bind all listed fields; endpoint table with request/response schemas; duplicate-header/unknown-header/encoding rules; `rotate-response.schema.json` added; error enum expanded; response-loss state tables for enroll/rotate | `04` §1–§4, §7–§8; `contracts/v1/` (all schemas, `rotate-response.schema.json`), `negative-vectors.v1.json` |
| **P1-02** | Separate payload identity/time from transport auth; historical >300 s re-authentication; agent restart spool order; historical boot rejection; center-restart dedupe/sequence; nonce reuse with different content; rotation/revocation during backlog; old snapshot must not overwrite newer; ACK loss/transaction/power-loss persistence; define what must be durable before accepted; review SQLite `synchronous=NORMAL` | `report_id`+`collected_at` vs `sent_at`/`nonce`/`seq`; payload age ≤7 d independent of ±300 s transport freshness; persistent `report_dedupe`/`nonce_dedupe`/`boot_registry`/`node_seq`; center restart-safe; `nonce_reuse`/`report_conflict`; later final correction adds signed boot-generation codes (`stale_boot_generation`/`boot_identity_conflict`); snapshot apply only if newer, otherwise `stale_ignored`; ACK only after durable transaction; SQLite switched to **`synchronous=FULL`** (NORMAL rejected); full 11-row state-transition test table | `04` §5–§6; `05` §4, §6; `02` ADR-UM-004 |
| **P1-03** | Agent least privilege: non-root cannot read root:umagent 0600 token or delete root-owned provisioning file; safe install-time credential delivery/ownership/cleanup; `systemctl` vs no-exec; restricted read-only interface; audit real sing-box `service.api` and credential write capability; do not loosen existing permissions; no resident root collector; real data sources with unavailable/unknown instead of fake zeros | One-time **root installer orchestration** feeds a root-only token to `um-agent enroll --token-stdin` running as `umagent` via a pipe; agent owns key/state; root deletes token; no resident root process. Runtime `umagent`, seccomp denies exec/`NoExecPaths`, no `systemctl`; systemd state via read-only D-Bus `ActiveState` (unknown when unavailable). sing-box/Mihomo credentials via `LoadCredential` (source perms unchanged); client method allowlist and UM-B audit requirement. Snapshot/metrics availability + nullable fields and honest unknown states. | `04` §11, §9; `03` §11–§12; `02` ADR-UM-002; schemas `report-snapshot`/`report-metrics` |
| **P1-04** | Center trust boundary: distinguish route isolation from same-process memory/DB permissions; revise SEC-18/19/20 to the real architecture; do not claim process isolation via different handlers; evaluate process-level split separately; bind Cloudflare JWT identity to local session and define invalidation | Explicit "process isolation NOT claimed" statement; SEC-18/19/20 rewritten with honest blast radius; optional process split recorded as a future decision; session bound to verified Access subject and revalidated per request, mismatch/expiry → 403/revoked | `03` §6 + §3, §6; `06` §1, §4 SEC-18/19/20, SEC-35; `07` Q-HA |
| **P1-05** | Compare retention A vs B (recommend B, recompute archive overlap/extreme events/backup/disk); consistent exceptions for open incidents, revocations, audit, backups; split local-failure vs whole-VPS RPO/RTO; daily recoverable offsite if ≤24 h promised; restore must not revive revoked/purged data | Policy A/B table + recommendation B with overlap cap and worst-case 2× sizing; single normative data-class table; RPO/RTO split table and explicit owner decision for whole-VPS RPO/daily off-host; restore quarantine + security ledger replay + owner-confirmed purge restore | `05` §1–§4, §6; `03` §9; `07` Q-RET/Q-AUD/Q-BACKUP |
| **P1-06** | Closed per-event-type detail fields; no arbitrary keys/text; fix oneOf integer/number overlap; audit timestamps/duplicate fields/units/missing state/version compat/config switches; sensitive-data sentinel negatives; keep device pseudonyms + admin display alias design | `report-events` if/then closed `detail` per kind (additionalProperties false), `agent_error` uses closed code enum; integer/number overlap removed via explicit nullable variants; time fields distinguished (`collected_at`/`sent_at`/`server_time`); duplicated boot/config fields removed from body; availability/nullable semantics; negative schema examples; sentinel test contract SEC-14; center-side alias design (bounded label on `node_id`/`device_ref`, never sent to agent) | `contracts/v1/report-events.schema.json`, `report-snapshot.schema.json`, `report-metrics.schema.json`, `examples/negative/`; `04` §9–§10; `03` §7, §9; `06` SEC-14/SEC-33 |
| **CI boundary** | Record attempt-1 `QueryFullProcessImageNameW winerror=5` and same-HEAD attempt-2 success; do not fix by skipping/ignoring/weakening identity checks; no test/workflow change in this PR; keep failure record and propose separate hotfix pending owner authorization | First-attempt evidence preserved; no test/workflow change; recommended follow-up in PR body and local evidence; final CI status reported with rerun | PR body + recorded run/log evidence |

## Validation performed for revision 2

- All schemas/examples parse; schemas are valid JSON Schema 2020-12; positive
  examples validate and the committed negative examples are rejected
  (local `jsonschema`, not a repository dependency).
- Positive report **and** enrollment signed vectors verify (Ed25519 via OpenSSL);
  tampered-body, wrong-key and cross-endpoint-reuse vectors fail as required.
- `negative-vectors.v1.json` freezes the behavioural HTTP negative expectations.
- Local links checked; secret-pattern scan over `docs/um/` has no hits; frozen
  contract files are pinned to LF.
- Documentation consistency re-checked across `03`/`04`/`05`/`06`/`07` and
  `contracts/v1/README.md` (no body-signature, no dedupe-table
  naming inconsistency, no 300 s payload-age confusion).

## Owner decisions explicitly **not** approved here

`07` §2 (Q-TRACK/Q-HOST/Q-SIZE/Q-INGRESS/Q-DNS/Q-AGENT-OS/Q-COEXIST/Q-DATA/
Q-RET/Q-AUD/Q-BACKUP/Q-LEDGER/Q-HA/Q-ADMIN/Q-TECH/Q-ALIAS/Q-UMF/Q-ISSUE) remain
PENDING.

# Revision 3 response matrix (targeted)

Input: rev-3 review at HEAD `2886619c01d1f5249b77af5fe9e10431cb2eeac6`.
No architecture/selection redesign; only the listed contract/security boundaries.

| ID | Requirement | Resolution | Files |
| --- | --- | --- | --- |
| **P1-07** | Eliminate the `pending_activation` contradiction; prefer simple "active on durable commit, orphan identified/revoked/re-enrolled by admin"; if kept, require an executable activation protocol not inferred from unobservable HTTP response state | Removed `pending_activation` from node/key states and error vocabulary. Enrollment commit makes the node **active immediately**; a lost response leaves a normal active orphan, admin revokes it (audited) and reissues a token; a node with reports is never treated as orphan. Negative contract NEG-ENROLL-11 records the recovery | `04` §4, §7; `03` §10; `07`; `negative-vectors.v1.json` |
| **P1-08** | Resolve old-key-grace/revocation contradiction; define rotation transaction, key/rotation state, persisted intent, response loss, agent restart/retry; secure recovery stops reporting for operator recovery, never bypasses revocation | Rewrote rotation as a persistent state machine: old key stays **active** until a report signed by the new key proves possession; expiry aborts only the provisional key; same-nonce replay is idempotent; different nonce → `rotation_in_progress`; retry after abort → `rotation_expired`; agent restart/response-loss/revocation transitions frozen; admin revocation always wins and unprovable state stops reporting | `04` §7, §8; `error.schema.json` (+rotation codes); `negative-vectors.v1.json` NEG-ROT-03..06; `03` §10; `06` SEC-38 |
| **P1-09** | Nonce dedupe unique key + full request fingerprint (cross-endpoint rejection); exact `seq == last_seq` duplicate vs conflict; prove bounded `boot_registry` cannot re-accept still-signature-valid old boots; clarify transaction ordering of report_id duplicate vs new boot/seq persistence; positive/negative cases + state tables | `nonce_dedupe` unique `(node_id, nonce)` + full `fingerprint_hash` (endpoint/method/path/key/boot/seq/sent-at/encoding/body); `seq_dedupe` exact-retry table; boot acceptance uses only `node_seq.current_boot_id` (registry is diagnostics, therefore eviction cannot re-accept); single transaction order frozen (nonce → boot/seq → report_id → data → persist dedupe+high-water → commit → ACK); duplicate under new boot/seq updates transport state without data write; cases NEG-REPORT-11..14 | `04` §5–§6; `03` §9; `06` SEC-13; `negative-vectors.v1.json` |
| **P1-10** | Separate credential delivery from server-side authorization; Mihomo controller disabled by default unless proven non-write access; audit sing-box service.api versions/server authorization (client allowlist alone insufficient); no permission changes or root collector; freeze fail-closed source disabling now | Source switches default `false`; `singbox_api` requires a versioned server-side authorization audit in UM-B3 before enabling; `mihomo_api` disabled in v1; unproven/mismatched source stays disabled with `availability=unavailable` + `agent_error code=source_authorization_unproven`; client allowlist labeled defense-in-depth only; no file-permission changes; no resident root collector | `04` §11, §9; `agent-config.schema.json` (source switches + expected tags); `03` §11; `06` SEC-39; negative NEG-REPORT-15 |
| **P1-11** | Global active/archived/overlap quotas; capacity includes dedupe/audit/ledger/backup/WAL/VACUUM temp; ledger durability/order/latest-version/offsite rules; incomplete ledger quarantine with no automatic ingest restore | Added global/per-event/archived/overlap quotas and hard-limit behavior; capacity table now includes `report_dedupe`, `nonce_dedupe`, `seq_dedupe`, audit, ledger, WAL, VACUUM temp, backups; 40 GB + policy B consequence stated honestly (~150 nodes; 200 needs larger disk or policy A); ledger is hash-chained, fsynced before DB commit/ACK, includes signed checkpoints, latest-version via `(seq,hash,checkpoint)`, included in every backup/offsite copy, restore quarantined until reconciliation | `05` §4–§6; `03` §9; `06` SEC-34; `07` Q-SIZE/Q-LEDGER |
| Consistency-1 | Config request body: two-byte `{}` vs zero bytes; sign/schema/vector/Content-Type aligned | Fixed to **exactly two bytes `{}`**, `Content-Type: application/json`; signing string always `sha256("{}")`; zero-byte/whitespace body → `invalid_request`; added to contract docs | `04` §1, §7; `contracts/v1/README.md` |
| Consistency-2 | Standard `Content-Encoding` vs `X-UM-Content-Encoding` consistency | HTTP header and signed header must agree (or signed `identity` when HTTP header absent); duplicate/mismatch/unknown → `unsupported_encoding`/`duplicate_header` | `04` §1–§2; `contracts/v1/README.md`; negative vectors |
| Consistency-3 | Unify Cloudflare Tunnel and direct TLS ingress failure models | Added a unified failure matrix: agent retry/spool behavior identical; only failure domain/confidentiality differs (CF outage takes both entries in Option A; Option B keeps machine ingress independent; flood/confidentiality differences) | `03` §13; `06` §3/§7; `02` ADR-UM-005 |
| Consistency-4 | #48 Closed/Completed, keep passed fault-injection evidence and unfinished event-level acceptance limits | Updated baseline/issue records: #48 Closed/Completed (2026-11-25), record preserved, not reopened; #33/#67 unchanged | `01` §1, §9; `README`; `07` Q-ISSUE |
| Consistency-5 | Runtime semantics for service name/inbound_tag/timestamps/availability (schema shape is not truth/privacy proof) | Frozen runtime validation: `services[].name` v1 allowlist `sing-box`; inbound tag/kind must match center `expected_inbound_tags`; temporal bounds for observed_at/sample at/event at/collected_at; availability coherence (ok ⇒ non-null, unavailable ⇒ null); `up` only with evidence; privacy sentinel scan; reject/quarantine, never render | `04` §9; `agent-config.schema.json`; `06` SEC-39 |

## Revision-3 validation (performed)

- All schemas/examples revalidated: positive examples pass (including updated
  agent-config source switches + `expected_inbound_tags`), negative examples are
  rejected.
- Signed report/enrollment vectors re-verified (Ed25519, OpenSSL); body hashes and
  signing strings unchanged except no body/signing change was required for rev 3;
  tampered/wrong-key/cross-endpoint negatives still fail as required.
- Behavioural negative contract extended to 35 cases; every expected code is in
  the frozen `error` enum (cases with no error are explicit duplicate/recovery
  expectations).
- Cross-document consistency: no `pending_activation` state/error; rotation
  expiry never revokes the old key; source switches default false; config body
  `{}`; Content-Encoding consistency; quotas and ledger rules consistent across
  `03`/`04`/`05`/`06`/`07`.

# Final contract corrections (rev-3 follow-up)

Input: final PR #126 review at HEAD `089f27a5…` (minor targeted correction).

| ID | Requirement | Resolution | Files |
| --- | --- | --- | --- |
| **A. Boot lifecycle** | Fix §5/§6 contradiction on new-boot acceptance; use persistent, signature-bound monotonic boot generation; old generation cannot re-activate; same generation + different boot id rejected; new-generation first report (even duplicate) updates transport state; local state loss must not reset generation; keep report_id vs transport separation | `X-UM-Boot-Gen` added to signed headers/signing strings; authoritative `node_boot{highest_gen,boot_id,last_seq,last_fingerprint}`; rules: gen==highest requires same boot id (`boot_identity_conflict`), gen==highest+1 (first seq=1) accepted, gen<highest → `stale_boot_generation`, skip → `boot_identity_conflict`; duplicate first new-gen report commits transport high-water without data; agent persists generation/boot id and fails closed on boot-state loss (no reset; operator revoke + re-enroll); canonical transaction order updated; positive vector re-signed and boot-gen-tamper negative added | `04` §2–§6; `03` §10; `test-vectors.v1.json`; `negative-vectors.v1.json` NEG-BOOT-01..05; `error.schema.json` |
| **B. Rotation retry consistency** | Define same-nonce retry vs fingerprint/freshness; agent recovery of persisted intent; ACK loss after new-key proof; confirmed vs aborted vs admin-revoked; unprovable → operator recovery; keep old-key-revoked-only-after-proof | Rotate nonce is a persisted intent key: same nonce/body may refresh `sent_at`/`seq`/`boot_gen` for 300 s freshness and gets an idempotent response; changed body/key/endpoint → `nonce_reuse`; agent persists intent and retries after restart; 2xx new-key report marks confirmed/delete old key; `rotation_expired`/`revoked_key` → aborted fallback; both keys rejected/admin revoked → stop + operator recovery | `04` §7; `negative-vectors.v1.json` NEG-ROT-07..11; `06` SEC-41 |
| **C. Ledger restore** | A verifiable copy must not be assumed latest; whole-machine loss with unproven completeness stays quarantined; old signature-valid backup cannot restore all node permissions; off-host storage/restore drills in UM-E | Doc 05 §6.3 now states verifiable ≠ latest, incomplete/unverifiable latest ledger ⇒ quarantine/no permission restore; storage selection and drills scheduled in UM-E | `05` §6.3; `06` SEC-34; `07` Q-LEDGER |
| **D. Documentation consistency** | Fix revision-2 admission/authorization/change-control references; sync lifecycle diagram with rotation state machine and delete timer-revocation wording; unify nonce/seq/boot/report_id transaction order; 18 owner decisions stay PENDING | Revision labels updated to revision 3 final; lifecycle diagram rewritten (active-on-commit, rotation confirmed/aborted, boot generation); old-key timer revocation wording removed; one canonical transaction order in `04` §5; 18 decision rows remain PENDING | `03` §10; `04` §5–§6; `07`; `08`; READMEs |

Final validation: schemas/examples/negative examples revalidated; both signed
vectors verify (report vector now includes `X-UM-Boot-Gen`); boot-generation tamper
negative fails verification; 45 behavioural/recovery cases with all error codes in
the frozen enum; cross-document consistency and link/secret checks pass.

# Revision 5 targeted amendment (owner Round-2)

Input: owner Round-2 review (2026-11-26) of the #128 planning package. Owner
conclusions recorded: #128 implementation plan PASS; recovery design A-1..A-5
**ACCEPTED DIRECTION**; dual-platform architecture PASS; Go migration roadmap
PASS; final contract **TARGETED UPDATE REQUIRED**; CI PASS with recorded rerun;
merge/deployment require separate owner authorization. This section records our
response; it is not an independent review and does not approve the pending owner
decisions or authorize a merge.

| ID | Owner direction | Resolution in revision 5 | Files |
| --- | --- | --- | --- |
| **R5-A** Recovery A-1..A-5 | Integrate bounded generation forward jumps and first-contact `seq>1`; keep stale generation/identity conflict/revocation/unsafe recovery fail-closed; ACK `next_seq` reconciliation; superseded-attempt handling; no special rotation retry path around high-water | `04` §5, §6 (rules + 13 state-transition tests), §6.4 REC-01..REC-30 mapping; `03` §10; `test-vectors.v1.json` rev-5; `negative-vectors.v1.json` NEG-BOOT-06..10, NEG-ROT-12..15, NEG-REPORT history | `04`; `03`; `contracts/v1` |
| **R5-B** Numeric/storage | Bounded generation jump; uint64 boundary; ACK `next_seq` exhaustion; SQLite storage semantics | `MAX_NUMERIC=2^63−2`, canonical decimals, `MAX_BOOT_GAP=65535`; ACK `next_seq` nullable on exhaustion; all protocol numbers stored as SQLite signed INTEGER with CHECK constraints; no TEXT/BLOB/REAL/wrap | `04` §2, §5, §13; `ack.schema.json`; `negative-vectors.v1.json` NEG-BOOT-09/10 |
| **R5-C** Rotation retry | Must execute full boot/seq/nonce/identity validation; no retry path bypassing high-water | Explicit 6-step validation order; intent match only replaces identical-fingerprint matching; replay + high-water in one transaction; stale/seq failure returns error without replay | `04` §7; `negative-vectors.v1.json` NEG-ROT-12..15 |
| **R5-D** Node classes/platform isolation | Add Linux/Windows `node_class`; center registration binds event+class; platform isolation rules | Enrollment body `node_class`, token scope `{event_id,node_class}`, OS consistency, immutable class; per-class payload/kind/source allowlists with `platform_mismatch`; `enroll-response` includes class | `04` §4, §9.1; `enroll-request`/`enroll-response` schemas; `agent-config`; `negative-vectors.v1.json` NEG-PLAT-* |
| **R5-E** Windows telemetry | Six route tokens aligned with windowsobs; independent selection/connection sampling; unmapped never DIRECT; center-managed versioned A/B mapping without rewriting history; no proxy names/profile upload; R2 first, R1 later owner acceptance only | Six-token `terminal` object/events; independent `sampled_at`; six-token by_route sum; direct only with explicit operator-local binding; append-only `route_mapping_versions` with `effective_from`; privacy negatives; `terminal_v1`; R2/R1 policy; read-only/no-HA rules | `04` §9.2, §11; `report-snapshot`/`report-events`/`agent-config` schemas; `terminal-snapshot` + negative examples; `06` SEC-42..47; `05` retention |
| **R5-F** History/vector traceability | Update conflicting old behavioural vectors; retain history | Rev-4 report vector retained valid; rev-4 enrollment retained as `historical_rev4_enroll_vector`; `superseded_rev4_expectations` in negative vectors; revision history in `test-vectors.v1.json`; no deletion of old expectations | `test-vectors.v1.json`; `negative-vectors.v1.json`; `contracts/v1/README.md` |
| **R5-G** #128 plan closure | No independent PR-A2; keep #128, sync its baseline after #126 stabilizes; keep REC cases/register/roadmap/reuse/migration gates | #128 branch receives a docs-only sync to rev-5 (no PR-A2); gates now #126 independent review → owner merge auth → normal Merge Commit → main CI → #128 review/merge gate → latest main CI → owner-authorized Go branch sync (preserve 3 commits, no rebase/force, docs/um must match main) → UM-B1 | #128 `docs/um/um-127/**` (separate PR) |

Validation performed for revision 5 (docs-only; owner-independent checks):

- All 10 JSON schemas parse and are valid JSON Schema 2020-12.
- 10 positive example bodies validate (including `terminal-snapshot.v1.json`); 7
  schema-negative examples are rejected; 2 runtime-only negatives are schema-valid
  as intended (`report-snapshot-tampered`, `terminal-by-route-sum-mismatch`).
- Targeted rules: node_class/host consistency, missing/extra class rejected,
  six-token completeness, extra-field/raw-proxy-name rejection, reason_code
  requirement, ACK `next_seq` null/max/over-max, platform-isolation schema shape.
- Signed vectors: report (retained rev-4), Windows terminal, enrollment (rev-5),
  rotate, config verify Ed25519; body lengths/hashes match; historical rev-4
  enrollment signature verifies. Crypto negatives (tampered Linux/Windows body,
  wrong key, cross-endpoint reuse, boot-gen tamper, rotate-body tamper) all fail
  as required.
- Behavioural contract: 67 unique cases, all error codes in the closed enum,
  `superseded_rev4_expectations` retained, REC-01..REC-30 mapped in `04` §6.4.
- Doc checks: no normative `seq == 1`/generation-skip/`uint64`/`Mihomo disabled
  in v1` contradictions remain; no `node_seq` in normative docs; relative links
  resolve; no private keys/tokens found.
- CI: existing suites are regression-only (no job reads `docs/um`); the known
  Windows harness flake is recorded separately and was not hidden by any test
  change. Full PR CI is reported in the PR body.

**No independent review or owner approval is claimed here.** Owner decisions
remain PENDING; merge and deployment require separate owner authorization.
