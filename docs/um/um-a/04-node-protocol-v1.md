# UM-A 04 — Node protocol v1 (FROZEN contract, revision 2)

Status: **FROZEN for UM-B implementation**, revision after the PR #126 architecture
review (P0-01, P1-01, P1-02, P1-03, P1-04, P1-06). The machine-readable schemas
and vectors in [`../contracts/v1/`](../contracts/v1/) are normative parts of this
contract. An incompatible change requires an explicit design-revision review.

Related: trust boundaries [03](03-architecture-and-trust-boundaries.md), privacy
and retention [05](05-retention-capacity-backup.md), threat/tests
[06](06-threat-model-security-tests-performance.md), review response matrix
[08](08-review-response-matrix.md).

## 0. Fixed design decisions for this revision

| Review item | Resolution in this contract |
| --- | --- |
| P0-01 enrollment signature circular dependency | Signature is a **transport header**; no signed body contains a signature field. Enrollment has its own signing string. Full positive and negative vectors are committed. |
| P1-01 HTTP operation binding | Signing input binds endpoint, method, path, protocol version, identity, key, boot, sequence, sent time, nonce, content encoding and SHA-256 of the decoded body. Per-endpoint request/response semantics and error vocabulary are frozen. |
| P1-02 offline replay/durability | Payload identity (`report_id`, `collected_at`) is separated from per-attempt authentication (`sent_at`, `nonce`, `seq`, key); dedupe/sequence/boot state is persistent in SQLite with `synchronous=FULL`; ACK only after a durable commit; historical snapshot cannot overwrite newer latest state; state-transition and test tables included. |
| P1-03 agent least privilege | One-shot root installer orchestrates enrollment without running agent logic as root; token crosses a pipe, never a non-root-readable file; agent runs unprivileged with `LoadCredential`, D-Bus read-only queries and no exec; data-source availability is explicit; unknown data is never faked. |
| P1-04 center trust boundary | Single-process center is stated honestly: route/network isolation, **not** process isolation; DB and admin memory are shared. Security acceptance targets are revised accordingly; process-level split is an optional later decision. |
| P1-06 privacy/schema | Closed per-kind event details, no arbitrary keys/text, nullable/unknown values, explicit availability, fixed integer/number overlap, sentinel negative contract, admin-side device aliases. |
| P1-07 enrollment lifecycle (rev 3) | No `pending_activation`: the node is `active` when the enrollment transaction commits; response loss leaves a normal orphan identity that the admin revokes and re-issues. |
| P1-08 rotation recovery (rev 3) | Persistent rotation state machine: old key is **never revoked on a timer**, only after proof of new-key use; grace expiry aborts the new key and keeps the old active; response loss/restart/retry/revocation transitions defined; unprovable recovery stops reporting for operator recovery, never bypasses revocation. |
| P1-09 replay closure (rev 3) | Unique `(node_id, nonce)` + full request fingerprint; seq-equal exact-retry vs conflict rules; bounded boot registry is not an authorization source (only current boot accepted); single-transaction ordering of report dedupe + boot/seq high-water + data; recovery cases added. |
| P1-10 read-only authority (rev 3) | Source switches default **false**; sing-box `service.api` requires a server-side authorization audit before enabling; Mihomo controller disabled in v1; unproven authorization disables the source with `unavailable`/`source_authorization_unproven`, never fake data; no permission changes, no root collector. |
| P1-11 capacity/ledger (rev 3) | Global active/archived/overlap quotas; capacity includes dedupe/audit/ledger/backup/WAL/VACUUM temp; security ledger durability/order/latest-version/offsite rules; incomplete ledger ⇒ quarantine, no automatic ingest restore. |

## 1. Transport, endpoints and machine-ingress options

- Application protocol: HTTPS, HTTP/1.1 with keep-alive, JSON UTF-8, Ed25519
  signatures over transport headers + decoded body bytes.
- **Machine-ingress transport is a deployment choice, not a protocol change**:
  - Option A (preferred evaluation): a second Cloudflare Tunnel hostname
    (`ingest.132431.xyz`) without Access, forwarded to a loopback ingest listener.
    No public inbound port; Cloudflare terminates TLS, so monitoring payload is
    readable by the Cloudflare edge (privacy trade-off) while the node signature
    still provides end-to-end authenticity/integrity.
  - Option B: direct TLS 1.3 listener on `ingest.132431.xyz:8443` (DNS-only, no
    proxy; public inbound port). Payload stays end-to-end encrypted to the center;
    exposed listener must absorb unauthenticated traffic.
  - The protocol below is identical for both; the center must bind the listener
    to loopback for Option A and to the public interface for Option B. Owner
    decides ([07](07-um-b-entry-and-review.md)); the security test plan covers
    both.

| Method | Path | Auth | Request body | Success response |
| --- | --- | --- | --- | --- |
| POST | `/v1/agent/enroll` | one-time bootstrap token + new-key signature headers | `enroll-request.schema.json` | `enroll-response.schema.json` (200) |
| POST | `/v1/agent/report` | current node key signature headers | snapshot / metrics / events schema (by `type`) | `ack.schema.json` (200) |
| POST | `/v1/agent/rotate` | **old** node key signature headers | `rotate-request.schema.json` | `rotate-response.schema.json` (200) |
| POST | `/v1/agent/config` | current node key signature headers | **exactly the two bytes `{}`**, `Content-Type: application/json` | `agent-config.schema.json` (200) |
| — | anything else | — | — | `error.schema.json` with `endpoint_not_found`/`method_not_allowed` |

The config request body is **fixed to `{}` (U+007B U+007D, 2 bytes)**, not an empty
body and not a JSON object with any members; the signing string therefore always
uses `sha256("{}")`. A zero-byte or whitespace/other JSON body is
`invalid_request`. For every request, the standard HTTP `Content-Encoding` header
and the signed `X-UM-Content-Encoding` header must be **consistent**: both absent
is invalid; if the HTTP header is absent, the signed value must be `identity`
(uncompressed); if present, the HTTP header value must be byte-identical to the
signed header value. Any duplicate/mismatched/unknown coding is
`400 unsupported_encoding` (or `duplicate_header` for repeated headers).

No `/v1/agent/revoke` endpoint exists (admin-only web action). The ingest
listener has no `/api/*` routes and no cookie/session/CSRF/HTML semantics; the web
listener has no `/v1/agent/*` routes.

TLS: server certificate validated against the system CA store with hostname
checking; no plaintext fallback, no redirects. Optional strict-mode SPKI pin
recorded at enrollment. Body limits: compressed ≤256 KiB, decoded ≤128 KiB,
enroll ≤8 KiB, config response ≤16 KiB; header timeouts 5 s, body 10 s, handler
10 s.

## 2. Headers, duplicate-header rules and content encoding

Every request must send exactly one of each listed header. Any duplicated
`X-UM-*`, `Content-Encoding` or `Authorization` header, or an unknown `X-UM-*`
header, is rejected with `400 duplicate_header` / `400 invalid_header`; the
center inspects the raw header list, not a joined value.

| Header | Endpoints | Grammar | Meaning |
| --- | --- | --- | --- |
| `X-UM-Protocol` | all | `1` | wire protocol major |
| `X-UM-Pubkey` | enroll only | base64url raw 32 B (43 chars) | new node key being enrolled |
| `X-UM-Node-Id` | report/rotate/config | lowercase UUIDv4 | node identity |
| `X-UM-Key-Id` | report/rotate/config | `key-[0-9a-f]{8}` | signing key id (`rotate` uses the old key) |
| `X-UM-Boot-Id` | report/rotate/config | 32 lowercase hex | agent process generation |
| `X-UM-Seq` | report/rotate/config | decimal uint64 ≥1 | monotonic per boot, per request attempt |
| `X-UM-Sent-At` | all | decimal Unix seconds | **authentication time** (not payload age) |
| `X-UM-Nonce` | all | base64url exactly 16 B (22 chars) | unique per request attempt |
| `X-UM-Content-Encoding` | all | `identity` or `gzip` | **must be explicit**, even for identity |
| `X-UM-Signature` | all | base64url 64 B (86 chars) | Ed25519 over the signing string |
| `Content-Type` | all | `application/json` | required |
| `Authorization` | enroll only | `Bearer <bootstrap-token>` | one-time enrollment token |

Content-encoding rules: exactly one coding token, `identity` or `gzip`; the HTTP
`Content-Encoding` and signed `X-UM-Content-Encoding` must agree (see §1); no
stacked/`x-gzip`/`deflate`/transfer-encoding ambiguity; gzip must be a single
member with no trailing data; decoding failure or a cap violation is
`400 unsupported_encoding` / `413 payload_too_large` **before** parsing. The
signature covers the **decoded body bytes**; the declared coding is bound in the
signing string so a downgrade or label mismatch is rejected.

## 3. Signing strings (normative)

All strings are UTF-8 with LF separators and **no trailing newline**; each field
is the exact header value. `sha256(body)` is the lowercase hex SHA-256 of the
decoded body bytes.

Enrollment (signed with the key whose public part is in `X-UM-Pubkey`):

```text
um-enroll-v1
POST
/v1/agent/enroll
1
<content-encoding>
<pubkey-b64url>
<sent-at>
<nonce>
<sha256-hex(body)>
```

Node-authenticated endpoints (signed with the key named by `X-UM-Key-Id`;
`endpoint` is exactly `report`, `rotate` or `config`):

```text
um-v1
<endpoint>
<method>
<path>
1
<node-id>
<key-id>
<boot-id>
<seq>
<sent-at>
<nonce>
<content-encoding>
<sha256-hex(body)>
```

Binding: protocol major + endpoint + HTTP method + path + identity + key id +
boot id + sequence + authentication time + nonce + content encoding + exact
decoded body hash. A signature for one endpoint/identity/encoding/body cannot be
reused for another (cross-endpoint replay is `bad_signature`); the body hash
prevents body substitution; the time window and nonce prevent network replay;
the boot/sequence prevent reordering after a restart.

## 4. Enrollment (P0-01)

### Request

Headers: `X-UM-Protocol`, `X-UM-Pubkey`, `X-UM-Sent-At`, `X-UM-Nonce`,
`X-UM-Content-Encoding`, `X-UM-Signature`, `Authorization`, `Content-Type`.
Body: [`enroll-request.schema.json`](../contracts/v1/enroll-request.schema.json) —
`{v, agent_version, host{os,kernel,arch}, capabilities[]}`. **No signature,
nonce, key, time or token fields exist in the body**; duplicate representations
are rejected (`invalid_request`).

Signed vector: [`test-vectors.v1.json`](../contracts/v1/test-vectors.v1.json)
`enroll_vector` (exact body `examples/enroll-request.v1.json`, signing string,
Ed25519 public key and signature). Cryptographic negatives: wrong key, tampered
body, cross-endpoint reuse. Behavioural negatives: unknown/expired/reused token,
missing/duplicate headers, unsupported encoding, stale timestamp, body containing
a signature field (`negative-vectors.v1.json` NEG-ENROLL-*).

### Response and response-loss recovery (P1-07: no pending activation state)

Body: [`enroll-response.schema.json`](../contracts/v1/enroll-response.schema.json)
(`node_id`, `event_id`, `key_id`, `config_version`, `device_salt`,
`cadence_seconds`, `server_time`, optional `center_spki_sha256`).

Enrollment commits node + key + token-consumption atomically and the node is
**`active` immediately when that transaction commits**. There is no
`pending_activation` state and no activation confirmation protocol: the center
cannot observe whether the agent received the HTTP response, so it must not infer
activation from it.

If the response is lost, the token is already consumed: the agent retries and
receives `401 token_used`. The committed node is a normal active identity that the
admin can see; because the agent never learned its `node_id`/key assignment, the
admin identifies the orphan (never-used node with a recent creation time and no
reports), **revokes it** (audited) and issues a new one-time token; the agent
generates a new key and enrolls as a new node id. A normal active node that has
received reports is never treated as an orphan; an operator must not revoke a
node merely because a response was lost before its first report.

## 5. Report semantics: payload identity vs transport authentication (P1-02)

Every report body carries `report_id` (uuidv4, generated once when the record is
created/spooled) and `collected_at` (epoch seconds when the data was collected).
Transport authentication fields are per attempt (fresh `sent_at`, `nonce`,
increasing `seq`), and the **payload age does not gate transport acceptance**:
spooled data collected hours or days earlier is re-authenticated at send time.
Accepted payload age is bounded by the agent spool contract (≤7 days) and by
`collected_at ≤ sent_at + 60 s`; older-than-retention data is rejected/accepted as
stale-ignored per §6.

Center processing (single transaction, `synchronous=FULL`):

1. Verify headers/encoding/size/grammar; 2. node + event binding; 3. key state;
4. `|server_time − sent_at| ≤ 300 s`; 5. signature over decoded bytes;
6. nonce dedupe; 7. report_id dedupe/conflict; 8. boot/sequence rules;
9. schema + privacy allowlist; 10. apply data; 11. persist dedupe + sequence +
data; 12. ACK. Nothing is acknowledged before step 11 commits; a failed commit is
`503 storage_unavailable` (retryable) with no partial state.

Dedupe/durability tables (persistent, bounded):

| Table | Key | Purpose | Retention |
| --- | --- | --- | --- |
| `report_dedupe` | `(node_id, report_id)` → body SHA-256, first/last received | idempotency across retries/restarts; same report_id different hash → `409 report_conflict` | 8 days (spool 7 d + margin) |
| `nonce_dedupe` | **unique `(node_id, nonce)`** → `fingerprint_hash` + received_at | network replay and cross-endpoint nonce reuse; a nonce has exactly one request fingerprint | 24 h |
| `seq_dedupe` | `(node_id, boot_id, seq)` → `fingerprint_hash` | exact-retry classification when `seq <= last_seq` (ack loss/duplicate) | current boot, bounded last 256 seq entries |
| `boot_registry` | `(node_id, boot_id)` → first/last seen, last seq, state | diagnostics/history only; **acceptance is decided by `node_seq.current_boot_id`, never by registry presence** | with node identity, bounded last 8 boots |
| `node_seq` | node_id → current boot_id, last_seq, last fingerprint | monotonic ordering per boot; gaps allowed and counted | current |

`fingerprint_hash = SHA-256(endpoint | method | path | key_id | boot_id | seq |
sent_at | content-encoding | decoded-body-sha256)` with LF separators and no
trailing newline. A request is "exactly the same attempt" only when its nonce
matches and the fingerprint matches; any change with a reused nonce is
`nonce_reuse`, even across endpoints.

`seq` semantics (P1-09):

- `seq == last_seq` **and** the fingerprint equals `node_seq.last_fingerprint` →
  `200 duplicate` (the previous attempt committed but its ACK was lost).
- `seq == last_seq` and fingerprint differs → `409 sequence_conflict`.
- `seq < last_seq`: if `seq_dedupe` holds the exact fingerprint for that
  `(boot_id, seq)` → `200 duplicate`; otherwise `409 sequence_conflict`.
- `seq > last_seq`: accepted (gap counted), current boot continues.

Boot rule and bounded registry proof: a report is accepted only if its `boot_id`
equals `node_seq.current_boot_id` at transaction time. Any other boot id is
`409 stale_boot` regardless of whether it is still in `boot_registry`. Bounded
registry retention (last 8 boots) therefore can never re-accept an evicted old
boot within any signature window: acceptance does not consult the registry list at
all; the registry exists only for diagnostics and is not an authorization source.
A new boot becomes current only in the same transaction that persists its first
accepted report; before that the old boot remains current. This also closes the
race between a new-boot first report and a retried old-boot request: whichever
commits first becomes current; the other is classified duplicate/stale
deterministically.

Transaction order (single SQLite transaction, `synchronous=FULL`):

1. nonce fingerprint check/insert; 2. boot/seq validation; 3. report_id lookup;
4. data apply (or duplicate/stale-ignore decision); 5. persist transport high-water
(`node_seq`/`seq_dedupe`) **and** report dedupe **and** data; 6. commit; 7. ACK.
A duplicate report arriving under a **new boot/seq** still updates the transport
high-water in the same transaction (the new boot is genuine transport evidence),
but performs no data write and returns `duplicate`; if the transaction aborts,
none of the three state changes persist and the agent retries.

- Snapshot: applied to `node_latest` only when `collected_at` is newer than the
  currently applied snapshot; an authenticated but older snapshot is acknowledged
  as `stale_ignored` (authenticated, deduped, **not applied**, never overwrites
  newer state).
- Metrics/events: inserted idempotently by `(node_id, report_id)`; historical
  data is written under its `collected_at` buckets (within the allowed payload
  age) and remains visible as a late-arrival gap; no overwriting of newer rows.
- Duplicate: `result: duplicate` (same report_id + same hash) or `stale_ignored`
  (older snapshot); in both cases the agent removes the spool record on receipt.
- A lost ACK causes a resend with a **new nonce/sent_at/seq**: the center finds
  the existing `report_id` and answers `duplicate` (or `stale_ignored`), so the
  agent can drop the spool record safely.

### ACK

[`ack.schema.json`](../contracts/v1/ack.schema.json): `report_id`, `result`
(`accepted|duplicate|stale_ignored`), `server_time`, `next_seq`, `config_version`,
`retry_after_s`. The ACK echoes the report_id so a late/duplicated response cannot
be confused with another report.

## 6. Replay, sequence, boot and recovery state tables

### 6.1 Rules

- `nonce`: first use executes; exact replay (same endpoint + same body hash)
  inside 24 h is idempotent (`duplicate`/replay-safe); same nonce with different
  body/endpoint is `409 nonce_reuse` (permanent; security event).
- `seq`: per current boot strictly increasing; `seq < last` → `409
  sequence_conflict`; `seq > last` accepted (gap recorded); a report with a new
  `boot_id` is accepted and retires the previous boot; a report from a retired
  boot is `409 stale_boot` (permanent), because the agent's new boot resends the
  same spooled `report_id`s under the new boot.
- Agent restart: a **new** `boot_id` is generated; the spool contains payload
  records only (report_id + collected_at + type + body). The agent replays the
  oldest spool record first under the new boot/seq with fresh nonce/sent_at; the
  center dedupes by `report_id`, so records already stored before the crash are
  `duplicate` and are dropped from the spool. A late request from the previous
  boot after the new boot is `stale_boot`.
- Center restart: all dedupe/sequence/boot state is in SQLite and survives
  restarts; agents retry and receive `duplicate` for already-committed reports.
- Single-agent rule: the agent holds a single-writer spool lock so two agent
  instances cannot produce an ambiguous boot history for one node.
- Rotation: a spool record is not tied to a key. After rotation the agent signs
  retransmissions with the new key; the center accepts them under the same node
  identity (grace rules in §7). Revocation: reports are rejected with
  `401 revoked_key`; the agent stops sending and keeps the bounded spool intact
  for operator decision (no silent deletion, no auto re-enrollment).
- Snapshot ordering is by `collected_at`, never by arrival time; an old spooled
  snapshot cannot overwrite the current live snapshot (`stale_ignored`).
- Payload age: allowed while within the 7-day spool bound; `collected_at` in the
  future (> sent_at + 60 s) is `invalid_request`; `sent_at` outside ±300 s is
  `stale_timestamp` (retryable after clock calibration from `server_time`).

### 6.2 Durability and acknowledgement semantics

- Center: `PRAGMA journal_mode=WAL`, `synchronous=FULL` (fsync on commit) — the
  previously considered `synchronous=NORMAL` is **rejected** because it does not
  guarantee the durability implied by `accepted` across OS/power loss. A report
  is acknowledged only after the transaction (data + dedupe + sequence/boot)
  has committed durably. Commit failure → 503, no ACK, agent retries.
- Agent: the spool record is fsynced (file + directory) **before** the first
  send attempt; it is removed only after a terminal success/semantic disposition.
  A crash between commit and ACK therefore resends the same `report_id` and
  receives `duplicate`.
- A terminal non-retryable payload error (`invalid_request`, `report_conflict`)
  quarantines that record (bounded) and continues with later records; auth/sequence
  errors stop the queue and require operator action. No silent drops.

### 6.3 Required state-transition tests (UM-B)

| Scenario | Expected |
| --- | --- |
| 1 h network outage | records spool durably; after reconnection oldest-first replay with fresh sent_at/nonce/seq; center ACKs accepted; no duplicates stored |
| Agent restart mid-spool | new boot_id; old spool replayed; already-stored report_ids → `duplicate`; data loss only for records that were never fsynced (none by contract) |
| Center restart | dedupe/seq/boot survive; in-flight/spooled retries → `duplicate`/accepted; no reordering errors |
| Lost ACK (commit succeeded) | resend with new nonce/seq → `duplicate`; spool dropped |
| Lost ACK (commit failed/503) | resend → accepted; no duplicate |
| Power loss on agent | fsynced records survive; older boot → center rejects late old-boot request as `stale_boot`, new-boot resend wins; unsynced tail may be lost and is reported via spool_retention diagnostics |
| Power loss on center | committed reports survive (FULL); uncommitted → agent retries; dedupe prevents double apply |
| Revocation during backlog | backlog stays bounded/spooled; reports rejected `revoked_key`; operator re-enroll creates new node; old spool must be discarded (documented) |
| Rotation during backlog | backlog retransmits under new key after rotation; same node identity; accepted |
| Historical boot replay | old boot_id after new boot accepted → `stale_boot`; same report_id under new boot is idempotent |
| Old snapshot after newer live snapshot | authenticated, `stale_ignored`, never applied to latest |

## 7. Rotation, configuration and revocation (P1-08 state machine)

Key states: `active`, `provisional` (new key accepted only for rotation proof),
`revoked`; rotation states: `awaiting_proof`, `confirmed`, `aborted`. State is
persistent (`key_rotations` table); timers are evaluated on request and by a
background job.

| Step | Actor | Persisted state / action | Old key | New key |
| --- | --- | --- | --- | --- |
| 1 | agent | generate new key; persist `{rotation_nonce, new_priv, new_pub}` before sending | active | — |
| 2 | agent → center | `POST /v1/agent/rotate` signed by old key, body `{v,new_pubkey}`, nonce N | active | — |
| 3 | center | one transaction: create `rotation{node, old_key_id, new_pubkey, N, state=awaiting_proof, expires_at=now+300s}`, key new=`provisional` | active | provisional |
| 4 | center → agent | `rotate-response {previous_key_id,new_key_id,config_version,server_time}` | active | provisional |
| 5 | agent | persist new key id + rotation state; send the next report **signed with the new key** (proof) | active | provisional |
| 6 | center | first accepted request signed by provisional key: one transaction → new=`active`, old=`revoked`, rotation=`confirmed` | revoked | active |
| 7 | center | if `expires_at` passes with no proof: rotation=`aborted`, new=`revoked`; **old remains `active`** (never revoked on a timer) | active | revoked |
| 8 | agent | on `401 revoked_key` for the provisional key: delete provisional key, resume old-key reporting (old is active unless separately revoked); if the old key is also rejected → stop and operator recovery | — | — |

Response-loss and retry semantics:

- Same `(nonce, body)` retry while `awaiting_proof` → **identical
  `rotate-response`** (idempotent replay from the persisted rotation record).
- A different nonce while a rotation is `awaiting_proof` →
  `409 rotation_in_progress` (no second concurrent rotation); the agent keeps
  retrying its persisted nonce.
- A retry after the rotation was `aborted` (`expires_at` passed) →
  `409 rotation_expired`; the agent deletes the provisional key, resumes old-key
  reporting, and may start a new rotation with a fresh nonce later.
- Agent restart with a persisted pending rotation: it retries the rotate request
  with the same persisted nonce; idempotent replay gives the same response, or
  `rotation_expired` triggers the abort path. It never sends new-key reports
  before it has received/recorded a response; once recorded, it prefers the new
  key for the proof report.
- Center restart: `key_rotations` is persistent; an expired `awaiting_proof`
  rotation is aborted lazily/on the background job; the old key stays active.
- Admin revocation always wins: it revokes all keys and aborts pending rotations;
  later requests are `401 revoked_key` and the agent stops for operator recovery.
  There is **no automatic bypass of a revocation** by rotation retries.
- Revocation during a backlog: old-key and new-key authentication is checked per
  request; an aborted rotation never invalidates the old key, so spool replay
  continues under the old key; a confirmed rotation requires replay under the new
  key (the agent uses the new key after confirmation).

Config pull: `POST /v1/agent/config`, signed with the current active key, body
exactly `{}` (2 bytes, §1); response
[`agent-config.schema.json`](../contracts/v1/agent-config.schema.json) with
`cadence_seconds` 30–300, **source switches** `{system, services, singbox_api,
mihomo_api, events}` (all default `false` until the center enables them),
`expected_inbound_tags` (the runtime tag/kind allowlist used in §9),
`device_salt`, `config_version`. No command/URL/host/target fields exist; the
center has no push channel.

## 8. Errors (closed vocabulary)

HTTP status + [`error.schema.json`](../contracts/v1/error.schema.json).

| HTTP | error | Retryable | Notes |
| --- | --- | --- | --- |
| 400 | `invalid_request` | no | schema/body/duplicate representation |
| 400 | `missing_header` / `invalid_header` | no | header grammar |
| 400 | `duplicate_header` | no | repeated/unknown `X-UM-*` header |
| 400 | `unsupported_encoding` | no | encoding token/gzip malformed/stacked |
| 401 | `unauthorized` | no | generic auth failure |
| 401 | `unknown_node` / `revoked_key` | no | identity/key state |
| 401 | `bad_signature` | no | signature/endpoint/body binding failed |
| 401 | `stale_timestamp` | yes (once) | recalibrate from `server_time` |
| 401 | `token_invalid` / `token_expired` / `token_used` | no | enrollment only |
| 404 | `endpoint_not_found` | no | wrong listener plane/wrong path |
| 405 | `method_not_allowed` | no | non-POST on agent paths |
| 409 | `replay` | yes | duplicate transport attempt; treat as duplicate |
| 409 | `nonce_reuse` / `sequence_conflict` / `stale_boot` / `report_conflict` / `identity_mismatch` | no | replay/ordering conflicts |
| 409 | `rotation_in_progress` / `rotation_expired` | no | rotation recovery states (doc 04 §7) |
| 413 | `payload_too_large` | no | decoded/compressed caps |
| 426 | `unsupported_version` / `upgrade_required` | no | protocol major/agent policy |
| 429 | `rate_limited` | yes | honor `Retry-After` |
| 503 | `storage_unavailable` | yes | retry; no state changed |

Every error response carries `server_time` for clock recalibration and never
contains exception text, paths, bodies or secrets.

## 9. Payload schemas, availability honesty and privacy

Bodies: snapshot, metrics, events ([schemas](../contracts/v1/)). All report bodies
carry `v`, `type`, `report_id`, `collected_at`; timestamps are epoch seconds UTC.

- **Availability**: `availability{system,services,protocols,traffic,clients}` ∈
  `ok|partial|unavailable`. Missing metrics are `null`, protocol/service state may
  be `unknown`, arrays may be empty when a source is unavailable. The center
  stores NULL and never converts missing data into zero/healthy state; the UI
  (UM-D) must render UNKNOWN/STALE. No fake zeros, no "up" without evidence.
- **Closed event details**: per-kind closed detail schemas are enforced
  (`report-events.schema.json` if/then + `additionalProperties:false`). No
  arbitrary keys, no free-text error messages, no paths/exception text.
- **Privacy allowlist** (center MUST reject/strip before storage): no UUIDs,
  passwords, private keys, tokens, full YAML, client names, raw source/destination
  IPs or hostnames, URLs, command lines, journal text, free text, or connection
  records. Allowed: aggregate counters, protocol state tokens, `device_ref`
  (HMAC-SHA256 with per-event salt of the local client identity, truncated to 32
  bytes), bounded counters, node-provided agent version/host class.
- **Admin-side aliases**: display labels are center-owned metadata attached to
  `node_id` or `device_ref` by an authorized admin (bounded, free-text UI label,
  never sent to agents, never containing credentials). Aliases do not change the
  machine identity and are audited.
- **Runtime semantic validation (P1-06 follow-up)** — schema shape/string length
  is not proof of privacy or truth; the center MUST enforce these semantics and
  reject/quarantine violations (test IDs SEC-39):
  - `services[].name` v1 runtime allowlist is exactly `sing-box` (schema enum);
    any other service name is rejected, never stored as text.
  - `inbound_tag` must exactly equal one of the center-configured
    `expected_inbound_tags` for that node/event (agent-config), with matching
    `kind`; unknown tags are rejected/quarantined rather than displayed.
  - `observed_at` must be within `[collected_at - 900 s, collected_at + 60 s]`;
    `metrics.samples[].at` must be minute-aligned, strictly increasing, unique,
    and within `[collected_at - 600 s, collected_at + 60 s]`;
    `events[].at` must be within `[collected_at - 3600 s, collected_at + 60 s]`.
    `collected_at` must not be in the future (`> sent_at + 60 s`).
  - Availability coherence: `system=ok` ⇒ all system fields non-null;
    `system=unavailable` ⇒ all null; `partial` ⇒ at least one null; services/
    protocols/traffic/clients follow the same rule for their fields; `up` state
    requires service `active` and a positive reason; `unknown` requires
    `source_unavailable`/`unknown`; `down` requires a non-ok reason. Up without
    evidence is rejected, never rendered.
  - Privacy runtime: `device_ref` must be the only client identifier (43-char
    base64url), no UUID/IP/YAML/password-shaped values in any string field; a
    sentinel hit rejects the report and is audited (no value logged).
  - Unknown enum tokens are rejected; additional closed-set runtime checks are
    listed in UM-B tests. The center stores only validated values.
- **Sentinel negative contract**: UM-B must include tests that plant
  UUID/password/private-key/YAML/source-IP sentinel values in agent payloads and
  assert they are rejected at the boundary, absent from stored rows, logs, HTTP
  responses and backups (SEC-14 extension).

## 10. Versioning and compatibility

- Wire major is in the path namespace (`/v1/`), `X-UM-Protocol` and body `v`.
  Body `v` is the payload-schema version (currently 1); the header is the wire
  major. They are intentionally separate and both validated.
- Unknown fields are ignored only in objects documented as extensible (none in
  v1 except the future ack/error additive fields noted below); closed enums reject
  unknown tokens (`invalid_request`).
- Adding an optional response field is compatible; adding a required request
  field, changing units/enums/signing strings or tightening a bound that old
  agents violate is a major revision.
- Deprecation ≥90 days and one agent minor release before removal; unknown major
  → `426 unsupported_version`.
- Agent capabilities in enrollment are advisory for optional features; v1
  mandatory set is snapshot+metrics+events.

## 11. Agent runtime, provisioning and least privilege (P1-03)

- **Install/provision (one-time root orchestration, reviewed installer)**:
  - root-owned token file `/etc/um-agent/bootstrap.token` (root:root 0600) is
    never readable by the agent user; it is **not** moved into the agent's
    directory.
  - the reviewed installer runs enrollment as the unprivileged `umagent` via
    `runuser`/equivalent with the token fed on **stdin from a root-opened pipe**
    (`um-agent enroll --token-stdin`); the agent process generates its own
    Ed25519 key and writes its state (`/var/lib/um-agent/` 0700 umagent, key
    0600 umagent).
  - after successful enrollment the root installer deletes the token file; on
    failure it leaves it in place (0600 root) only for operator retry and records
    a closed error code. No resident process runs as root.
  - no file permission is loosened on sing-box, Mihomo, Monitor or `sbox-cm`.
- **Runtime identity**: `umagent` non-login user; `um-agent.service` has
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `ReadWritePaths=/var/lib/um-agent`, `UMask=0077`, memory/task caps, and **no
  fork/exec** (`SystemCallFilter` denies `execve/execveat`, `NoExecPaths=/` where
  supported; enforced by a runtime/static test).
- **Data sources are fail-closed and authorization-gated (P1-10)** — credential
  delivery (LoadCredential) is not authorization; the center must not claim an
  API credential is read-only just because the client code only calls read
  methods:
  - **sing-box `service.api`** (`singbox_api` switch): disabled by default. Before
    any environment enables it, UM-B3 must record a versioned audit of the
    supported sing-box version(s) and the **server-side** API authorization model
    proving the credential cannot invoke configuration-mutating operations. If
    that proof is absent/partial/version-mismatched at runtime, the source stays
    disabled, reports `availability.*=unavailable` and `agent_error`
    `code=source_authorization_unproven`; there is no fallback credential or
    alternative transport. No sing-box/Monitor/`sbox-cm` file permissions are
    changed; the credential is delivered by `LoadCredential` only.
    The client additionally implements only a fixed allowlist of read-only
    started-service subscription methods (no generic/dynamic RPC surface), and
    UM-B must add a negative test that no other RPC path exists in the binary —
    but this is defense-in-depth, **not** the authorization proof.
  - **Mihomo controller** (`mihomo_api` switch): **disabled by default in v1 and
    not part of v1 acceptance**. The external controller credential is generally
    read/write; enabling it requires an owner-approved design that proves a
    read-only access mode without granting business write permission. Until then
    client summaries come only from the sing-box API stream (pseudonymous
    `device_ref`), and the source reports `unavailable` — never fabricated data.
  - `/proc`/syscalls for CPU, memory, disk and network counters (no subprocess).
  - systemd unit state via **read-only D-Bus property reads** on
    `org.freedesktop.systemd1` (`ActiveState` only); no start/stop/enable/exec
    calls. Unavailable → `unknown`; no `systemctl` exec fallback.
  - protocol state: derived only from available evidence (service state + allowed
    API activity/optional loopback dial); absence of traffic is never reported as
    down or up — it is `unknown`.
- **Spool**: durable, ordered, bounded 32 MiB/7 days, single-writer lock,
  fsync-before-send, bounded retry/backoff (1 s→60 s with jitter), bounded
  quarantine, fail-closed retention at startup.
- No listening socket; only the configured center origin is contacted; no shell,
  no package management, no remote command channel.

## 12. Frozen vectors and validation

Committed under [`../contracts/v1/`](../contracts/v1/):

- `test-vectors.v1.json`: positive report and enrollment vectors (exact body
  files, decoded-body hashes, signing strings, Ed25519 public keys/signatures,
  expected result) plus cryptographic negatives (tampered body, wrong key,
  cross-endpoint reuse) with expected verification failure.
- `negative-vectors.v1.json`: behavioural HTTP/recovery contracts (35 cases):
  enrollment token/expired/used/recovery, header duplication/missing/encoding/
  config-body, tampered body, cross-endpoint replay, nonce/report/boot/sequence
  conflicts, size caps, rotation in-progress/expired/confirmed/revocation, source
  authorization-unproven, listener-plane separation, and the exact-retry
  duplicate/conflict rules for `seq == last_seq`.
- `examples/`: positive snapshot/metrics/events/enroll/ack/enroll-response/
  rotate/config bodies and negative examples used by schema negative tests
  (extra body signature field, arbitrary detail, free-text detail, impossible
  units, unknown error code).

Config body fixed to `{}` (2 bytes); standard `Content-Encoding` must match the
signed `X-UM-Content-Encoding`; rotation and enrollment state machines are frozen
above. Any change to headers, signing strings, endpoint semantics, dedupe/
sequence/rotation rules, enums or vectors is a frozen-contract revision requiring
independent review before implementation.
