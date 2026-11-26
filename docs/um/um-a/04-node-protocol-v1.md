# UM-A 04 — Node protocol v1 (final targeted amendment, revision 5)

Status: **revision 5 final targeted amendment** for UM-B implementation. Revision 5
integrates the owner-accepted A-1..A-5 recovery semantics from the #128 planning
package, bounded numeric/storage rules, `node_class` registration/platform
isolation and the Windows terminal telemetry extension. The machine-readable
schemas and vectors in [`../contracts/v1/`](../contracts/v1/) are normative parts
of this contract. An incompatible change requires an explicit design-revision
review; independent review and owner merge authorization are still required
before merge, and this document does not grant them.

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
| P1-10 read-only authority (rev 3) | Source switches default **false**; sing-box `service.api` requires a server-side authorization audit before enabling; unproven authorization disables the source with `unavailable`/`source_authorization_unproven`, never fake data; no permission changes, no root collector. Revision 5: the Windows terminal Mihomo source is class-specific, defaults to disabled, and requires the R2 truly-read-only source if proven; R1 (write-capable controller credential) needs a separate later owner risk acceptance and is never auto-enabled. |
| P1-11 capacity/ledger (rev 3) | Global active/archived/overlap quotas; capacity includes dedupe/audit/ledger/backup/WAL/VACUUM temp; security ledger durability/order/latest-version/offsite rules; incomplete ledger ⇒ quarantine, no automatic ingest restore. |
| Final A — boot lifecycle (rev 4) | Signed monotonic `X-UM-Boot-Gen` generation: lower generation never re-activates (`stale_boot_generation`), same generation with different boot id rejected (`boot_identity_conflict`), new-generation first report (even duplicate) commits transport high-water, local boot-state loss is fail-closed operator recovery (no reset). |
| Final B/C — rotation retry & ledger (rev 4) | Rotate nonce is a persisted intent (fresh transport fields allowed within 300 s, idempotent replay), confirmed/aborted/admin-revoked states and ACK-loss recovery defined, unprovable state → operator recovery; a verifiable ledger/backup is not assumed latest — incomplete proof keeps restore quarantined (drills in UM-E). |
| **Rev-5 A-1..A-5 recovery** | Bounded generation forward jumps are accepted (`MAX_BOOT_GAP=65535`); the first **accepted** request of a new generation may have `seq>1`; ACK `next_seq` is adopted; superseded attempts are ignored by the agent; rotate intent replay runs the full boot/seq/nonce/identity validation and never bypasses high-water. Lower generations, identity conflicts, revocation and unsafe recovery stay fail-closed. |
| **Rev-5 numeric/storage** | `boot_gen`/`seq` are canonical decimal in `[1, 9223372036854775806]`; values are validated before conversion and stored as SQLite signed INTEGER (never TEXT/BLOB/float); ACK `next_seq` is the next usable seq or `null` on generation exhaustion. |
| **Rev-5 node classes/platform isolation** | Enrollment carries immutable `node_class` (`linux_vps`/`windows_terminal`); the admin-issued bootstrap token binds event+class; the center enforces per-class payload/source/kinds allowlists (`platform_mismatch`). Windows terminal telemetry uses exactly six route tokens aligned with the existing `windowsobs` enum. |

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
| `X-UM-Boot-Gen` | report/rotate/config | canonical decimal `1..9223372036854775806` | **persistent boot generation**, monotonically increased by exactly 1 per normal agent restart; forward gaps are accepted only within `MAX_BOOT_GAP` (§5) |
| `X-UM-Boot-Id` | report/rotate/config | 32 lowercase hex | random id of this boot **within the generation** |
| `X-UM-Seq` | report/rotate/config | canonical decimal `1..9223372036854775806` | monotonic per boot, per request attempt |
| `X-UM-Sent-At` | all | canonical decimal Unix seconds `0..9223372036854775807` | **authentication time** (not payload age) |
| `X-UM-Nonce` | all | base64url exactly 16 B (22 chars) | unique per request attempt |
| `X-UM-Content-Encoding` | all | `identity` or `gzip` | **must be explicit**, even for identity |
| `X-UM-Signature` | all | base64url 64 B (86 chars) | Ed25519 over the signing string |
| `Content-Type` | all | `application/json` | required |
| `Authorization` | enroll only | `Bearer <bootstrap-token>` | one-time enrollment token bound to an admin-issued event+node_class scope |

Numeric grammar and storage binding (rev 5): `boot-gen`, `seq` and `sent-at`
headers are **canonical decimal** (no leading zeros, no `+`, no whitespace); the
signed header value is the exact text used in the signing string. `boot-gen` and
`seq` are bounded to `[1, MAX_NUMERIC]` with
`MAX_NUMERIC = 9223372036854775806 (2^63−2)`, which fits a SQLite signed 64-bit
INTEGER and leaves `next_seq = last_seq + 1` representable. Values above the
bound, non-canonical decimals, or nonzero-but-leading-zero forms are
`400 invalid_header`; the center validates before any `uint64→int64` conversion
and never wraps. See §13 for the complete SQLite storage and exhaustion rules.

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
<boot-gen>
<boot-id>
<seq>
<sent-at>
<nonce>
<content-encoding>
<sha256-hex(body)>
```

Binding: protocol major + endpoint + HTTP method + path + identity + key id +
boot **generation** + boot id + sequence + authentication time + nonce + content
encoding + exact decoded body hash. A signature for one endpoint/identity/
generation/encoding/body cannot be reused for another (cross-endpoint replay is
`bad_signature`); the body hash prevents body substitution; the time window and
nonce prevent network replay; the generation/boot/sequence prevent reordering or
re-activation after a restart.

## 4. Enrollment (P0-01)

### Request

Headers: `X-UM-Protocol`, `X-UM-Pubkey`, `X-UM-Sent-At`, `X-UM-Nonce`,
`X-UM-Content-Encoding`, `X-UM-Signature`, `Authorization`, `Content-Type`.
Body: [`enroll-request.schema.json`](../contracts/v1/enroll-request.schema.json) —
`{v, node_class, agent_version, host{os,kernel,arch}, capabilities[]}`. **No
signature, nonce, key, time or token fields exist in the body**; duplicate
representations are rejected (`invalid_request`).

`node_class` is `linux_vps` or `windows_terminal` (closed enum) and is
**immutable** for the node identity. The center binds event and class through the
admin-issued bootstrap token, not through agent self-assertion:

- The admin creates the one-time token with an explicit scope
  `{event_id, node_class, expires_at, max_uses=1}`; the token scope is the
  registration authorization. A token is never generic across classes or events.
- `node_class` in the signed body must match the token scope
  (`401 token_scope_mismatch` otherwise) and must agree with `host.os`
  (`linux_vps`↔`linux`, `windows_terminal`↔`windows`; `400 invalid_request`
  otherwise). `capabilities[]` is advisory; `terminal_v1` is meaningful only for
  `windows_terminal` and is rejected for `linux_vps` by runtime class validation.
- The enrollment transaction stores `node_id`, event binding and `node_class`
  together; there is no post-enrollment class change. Changing class requires
  admin revoke + re-enroll (new node_id), or a future audited admin rebinding
  action (not in v1).
- The center never infers event or class from agent-supplied host text beyond the
  deterministic OS consistency check above; unknown or mismatched scope is
  rejected before any node/key row is created.

Signed vector: [`test-vectors.v1.json`](../contracts/v1/test-vectors.v1.json)
`enroll_vector` (rev-5 body `examples/enroll-request.v1.json` with `node_class`,
signing string, Ed25519 public key and signature). The pre-rev-5 enrollment vector
is retained as `historical_rev4_enroll_vector` for traceability only and is not a
current positive vector. Cryptographic negatives: wrong key, tampered body,
cross-endpoint reuse. Behavioural negatives: unknown/expired/reused token,
class/scope mismatch, missing/duplicate headers, unsupported encoding, stale
timestamp, body containing a signature field (`negative-vectors.v1.json`
NEG-ENROLL-* / NEG-PLAT-*).

### Response and response-loss recovery (P1-07: no pending activation state)

Body: [`enroll-response.schema.json`](../contracts/v1/enroll-response.schema.json)
(`node_id`, `event_id`, `node_class`, `key_id`, `config_version`, `device_salt`,
`cadence_seconds`, `server_time`, optional `center_spki_sha256`). The agent MUST
verify that the returned `node_class` equals the class it requested and the OS
consistency rule; a mismatch is a fail-closed local error (no reports under a
wrong class).

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

Center processing (single durable transaction, `synchronous=FULL`):

1. headers/encoding/size/grammar/class binding; 2. node + event + node_class
binding; 3. key state; 4. `|server_time − sent_at| ≤ 300 s`; 5. signature over
decoded bytes; 6. nonce dedupe; 7. **boot generation / boot id** (A-1); 8. sequence
(A-2/A-3); 9. report_id dedupe/conflict; 10. schema + **platform isolation** +
privacy allowlist; 11. data apply or duplicate/stale-ignore decision; 12. persist
transport state + report dedupe + data; 13. commit; 14. ACK. Nothing is
acknowledged before the commit; a failed commit is `503 storage_unavailable`
(retryable) with no partial state.

Dedupe/durability tables (persistent, bounded):

| Table | Key | Purpose | Retention |
| --- | --- | --- | --- |
| `report_dedupe` | `(node_id, report_id)` → body SHA-256, first/last received | idempotency across retries/restarts; same report_id different hash → `409 report_conflict` | 8 days (spool 7 d + margin) |
| `nonce_dedupe` | **unique `(node_id, nonce)`** → `request_fingerprint` + received_at | network replay and cross-endpoint nonce reuse; a nonce maps to exactly one request fingerprint | 24 h |
| `seq_dedupe` | `(node_id, boot_gen, boot_id, seq)` → `request_fingerprint` | exact-retry classification when `seq <= last_seq` (ack loss/duplicate) | current generation, bounded last 256 seq entries |
| `node_boot` | `node_id` → `highest_gen`, `boot_id`, `last_seq`, `last_fingerprint`, `updated_at` | **authoritative boot-generation high-water**; acceptance consults this row only | current only (persistent) |
| `boot_registry` | `(node_id, boot_gen, boot_id)` → first/last seen, last seq, state | diagnostics/history only; **not an authorization source** | with node identity, bounded last 8 generations |

`request_fingerprint = SHA-256(endpoint | method | path | key_id | boot_gen |
boot_id | seq | sent_at | content-encoding | decoded-body-sha256)` with LF
separators, no trailing newline. For **report/config**, a nonce retry is "exactly
the same attempt" only when the fingerprint is identical; any change with a
reused nonce is `nonce_reuse` (even across endpoints). For **rotate** the nonce
identifies the persisted rotation intent: the agent may retry with the same nonce
and body but a refreshed `sent_at`/`seq`/`boot_gen` (freshness), and the center
matches `(node_id, nonce, old_key_id, body_sha256)`; changed body/key/endpoint →
`nonce_reuse` (see §7).

`seq` semantics (P1-09):

`seq` semantics (rev 5, A-2/A-3; normative recovery cases REC-01..REC-30):

- The agent starts each generation at `seq = 1`, increments per attempt and
  persist-before-send; it never reuses a sequence number.
- The center treats the **first accepted request of a generation** as the
  sequence baseline: it sets `last_seq` to the received `seq`, which may be `> 1`
  when earlier attempts were lost before reaching the center or when consecutive
  offline restarts changed the generation. There is **no** `seq == 1`
  requirement for the first accepted request.
- `seq > last_seq` → accepted. `seq == last_seq` **and** the fingerprint equals
  `node_boot.last_fingerprint` → `200 duplicate` (the previous attempt committed
  but its ACK was lost). `seq == last_seq` with a different fingerprint →
  `409 sequence_conflict`.
- `seq < last_seq`: if `seq_dedupe` holds the exact fingerprint for that
  `(boot_gen, boot_id, seq)` → `200 duplicate`; otherwise `409 sequence_conflict`
  (this is expected for a delayed, superseded attempt; see the agent rule below).
- ACK `next_seq = last_seq + 1`; the agent persists `max(local_next_seq,
  ack.next_seq)` before its next attempt. `next_seq: null` means the generation is
  numerically exhausted (§13): the agent MUST NOT reuse a seq and MUST start a
  new generation on a clean restart or enter operator recovery.
- Agent response binding: a response is matched to its `report_id` and
  generation/boot/seq (or an internal attempt id). A response for an attempt that
  has already been superseded is ignored; only the **latest** attempt receiving
  `409 sequence_conflict` is an operator-recovery condition.

Boot generation semantics (rev 5, A-1; normative recovery cases REC-01..REC-30):

- `node_boot.highest_gen` is the authoritative high-water. `X-UM-Boot-Gen` and
  `X-UM-Boot-Id` are signed transport fields, so neither can be altered without
  invalidating the signature.
- `gen == highest_gen`: accepted only if `boot_id == node_boot.boot_id`; a
  different boot_id with the same generation is `409 boot_identity_conflict`.
- `gen < highest_gen`: a retired generation is `409 stale_boot_generation`; it is
  never re-activated, even if an old `report_id` looks known. `boot_registry`
  retention cannot weaken this: acceptance consults `node_boot`, not the bounded
  registry.
- `gen > highest_gen`: define `gap = gen - highest_gen`. If `gap > MAX_BOOT_GAP`
  (`65535`, frozen) or the arithmetic/precondition fails, the request is
  `409 boot_identity_conflict` and a security event is written with no state
  change. Otherwise it is accepted as the first contact of a new generation; in
  the same transaction the center sets `highest_gen = gen`,
  `boot_id = X-UM-Boot-Id`, `last_seq = X-UM-Seq`, `last_fingerprint = fp`, writes
  a `boot_registry` entry and, when `gap > 1`, a `boot_generation_gap` audit entry.
  Gap 1 is the normal restart; gaps `2..65535` are the expected result of
  consecutive offline restarts and are not an error.
- If the **first report of a new generation is a duplicate** (its `report_id` was
  already stored by the previous generation, e.g. after a restart mid-spool), the
  generation/boot/seq transport state is still updated in the same transaction
  while no data is written and the ACK remains `duplicate`. This keeps the
  high-water correct even when spool replay makes the first new-generation request
  a duplicate.
- Agent persistence: the agent stores `{generation, boot_id}` durably (fsync)
  before incrementing/using it; a normal restart increments generation by exactly
  1 and generates a new random boot_id. The agent cannot know the center's
  `highest_gen`, so it MUST NOT try to "coalesce" skipped generations and MUST NOT
  reuse a boot_id. If the agent's boot-state file is missing or corrupt while the
  rest of its state exists, it must **not** reset the generation: it refuses to
  report (fail-closed, local `boot_state_corrupt` condition) and enters operator
  recovery. A full state loss leads to a new enrollment (new `node_id`); an
  in-place generation reset is never accepted (`stale_boot_generation`), so it
  cannot bypass the center high-water. Operator recovery = admin revokes the old
  identity and issues a new enrollment; there is no in-place reset endpoint.

Transaction order (single SQLite transaction, `synchronous=FULL`):

1. headers / encoding / size / grammar / class binding; 2. node + event +
node_class binding; 3. key state; 4. `|server_time − sent_at| ≤ 300 s`;
5. signature over decoded bytes; 6. nonce check/insert; 7. boot generation/id;
8. sequence; 9. report_id lookup; 10. schema + platform/isolation + privacy
allowlist; 11. data apply or duplicate/stale-ignore decision; 12. persist
transport high-water (`node_boot` + `seq_dedupe`), report dedupe and data in one
transaction; 13. commit; 14. ACK. A duplicate/new-generation first report follows
the same order and updates transport state before commit; if the transaction
aborts, no state changes persist and the agent retries. Rotate intent replay
(§7) uses the same boot/seq/nonce/identity order and does not bypass it.

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
be confused with another report. `next_seq` is the next usable sequence for this
generation; it is `null` only when `last_seq == MAX_NUMERIC` (generation exhausted,
§13), and the agent must then start a new generation on a clean restart or enter
operator recovery. The agent persists `max(local_next_seq, ack.next_seq)` and
ignores ACKs that do not match the current attempt.

## 6. Replay, sequence, boot and recovery state tables

### 6.1 Rules

- `nonce`: first use executes; exact replay (same endpoint + same body hash)
  inside 24 h is idempotent (`duplicate`/replay-safe); same nonce with different
  body/endpoint is `409 nonce_reuse` (permanent; security event).
- `seq`: per accepted generation monotonic; the first **accepted** request may
  have `seq > 1` (lost attempts / offline restarts) and sets the baseline;
  `seq < last` without an exact `seq_dedupe` fingerprint → `409
  sequence_conflict`; `seq > last` accepted (gap recorded). Sequence is bound to
  the generation in the signed headers and in `seq_dedupe`. Agent rule: a delayed
  response for an already-superseded attempt is ignored; only the latest attempt
  receiving `sequence_conflict` is an operator condition.
- Boot generation: `gen == highest_gen` requires the exact `boot_id` (else
  `boot_identity_conflict`); a normal restart sends `gen > highest_gen` with
  `gap <= MAX_BOOT_GAP` and is accepted as the new generation's first contact
  (its first accepted `seq` may be >1); `gen < highest_gen` → `stale_boot_generation`;
  `gap > MAX_BOOT_GAP` → `boot_identity_conflict`. The **first new-generation
  report may itself be a duplicate** (`report_id` already stored from the previous
  generation): transport state is still advanced/committed, no data is written,
  and the ACK is `duplicate`. Consecutive offline restarts are expected to produce
  gaps; a gap is never treated as an authorization bypass.
- Agent restart: the persisted generation is incremented by exactly 1 and a new
  random `boot_id` is generated. The spool contains payload records only
  (report_id + collected_at + type + body); the agent replays oldest-first under
  the new generation/seq with fresh nonce/sent_at. The center dedupes by
  `report_id`; the first new-generation record may be `duplicate` but the new
  generation high-water is still persisted. Agent boot-state loss/corruption is
  fail-closed local recovery (no generation reset, no old boot_id reuse); a fully
  re-enrolled agent gets a new node id, and an in-place reset is rejected.
- Center restart: boot-generation/dedupe/sequence state is in SQLite and survives;
  agents retry and receive `duplicate`/accepted without reordering.
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
| Agent restart mid-spool | persisted generation +1 and new boot_id; old spool replayed; already-stored report_ids → `duplicate` (first new-generation duplicate still advances transport state); no unsynced loss |
| Consecutive offline restarts | generation gaps `2..65535` accepted as new-generation first contact; first accepted `seq` may be >1; `boot_generation_gap` audit; no permanent block and no re-activation of the retired generation |
| Boot-generation re-activation | `gen < highest_gen` → `stale_boot_generation`; `gen == highest_gen` with different boot_id → `boot_identity_conflict`; `gap > 65535` → `boot_identity_conflict`; old generations never re-activated |
| First request of a generation lost | retry with the next `seq` is accepted; `last_seq` becomes the accepted seq (not forced to 1) |
| ACK `next_seq` exhaustion | accepted at `seq == MAX_NUMERIC`; ACK `next_seq` is `null`; agent starts a new generation on clean restart or operator recovery |
| Rotate retry across restart/gap | same nonce/body with refreshed `sent_at`/`seq`/`boot_gen` passes full signature/identity/boot/seq validation; same persisted response is replayed **after** high-water commit; stale generation or sequence conflict → no replay |
| Superseded delayed attempt | center may return `409 sequence_conflict`; agent ignores the response for an already-superseded attempt and continues the queue |
| Agent boot-state loss | local fail-closed; no generation reset; re-enrollment → new node_id; center rejects any in-place reset as stale generation |
| Center restart | dedupe/seq/boot survive; in-flight/spooled retries → `duplicate`/accepted; no reordering errors |
| Lost ACK (commit succeeded) | resend with new nonce/seq → `duplicate`; spool dropped |
| Lost ACK (commit failed/503) | resend → accepted; no duplicate |
| Power loss on agent | fsynced records survive; persisted generation increments on restart; a late old-generation request → `stale_boot_generation`; unsynced tail may be lost and is reported via spool_retention diagnostics |
| Power loss on center | committed reports survive (FULL); uncommitted → agent retries; dedupe prevents double apply |
| Revocation during backlog | backlog stays bounded/spooled; reports rejected `revoked_key`; operator re-enroll creates new node; old spool must be discarded (documented) |
| Rotation during backlog | backlog retransmits under new key after rotation; same node identity; accepted |
| Historical boot replay | old generation after a newer one accepted → `stale_boot_generation`; same report_id under the new generation is idempotent; bounded registry cannot re-accept it |
| Old snapshot after newer live snapshot | authenticated, `stale_ignored`, never applied to latest |

### 6.4 Rev-5 recovery conformance mapping (REC-01..REC-30)

The owner-accepted #128 recovery case set is kept as the executable conformance
input for UM-B1/B2/B3. The machine-readable cases remain in the #128 planning
package; this table is the normative rev-5 contract association. UM-B1/B2 MUST
implement every case with the rev-5 expectation below; UM-B3 implements the
agent-side rows. Cases that had a rev-4 expectation are marked in the #128 file
and in `negative-vectors.v1.json` `superseded_rev4_expectations`.

| ID | Scenario | Rev-5 expected outcome |
| --- | --- | --- |
| REC-01 | Normal online restart (gen+1, seq=1) | 200 accepted; high-water set |
| REC-02 | First request lost, retry seq=2 | 200 accepted; `last_seq=2` |
| REC-03 | Lost ACK, retry with next seq, same report_id | 200 duplicate; high-water advances; spool dropped |
| REC-04 | Lost ACK + restart; first new-gen report is a duplicate | 200 duplicate; new-generation high-water committed |
| REC-05 | Two consecutive offline restarts | 200 accepted; gap=2; audit entry |
| REC-06 | N offline restarts + oldest-first spool replay | accepted/duplicate mix; report_id dedupe; no loss |
| REC-07 | Gap > `MAX_BOOT_GAP` | 409 `boot_identity_conflict`; no state change |
| REC-08 | Same generation, different boot_id | 409 `boot_identity_conflict` |
| REC-09 | Retired generation replay | 409 `stale_boot_generation`; never reactivated |
| REC-10 | Delayed lower-seq superseded attempt | 409 `sequence_conflict`; agent ignores it and continues |
| REC-11 | `seq == last_seq`, same fingerprint | 200 duplicate |
| REC-12 | `seq == last_seq`, different fingerprint | 409 `sequence_conflict` |
| REC-13 | Multiple lost ACKs, adopt `next_seq` | 200 accepted; no conflict |
| REC-14 | Center restart, retry | 200 duplicate/accepted; persistent state survives |
| REC-15 | First request 503, retry | 200 accepted; aborted transaction left no high-water |
| REC-16 | First request non-retryable payload error | 400; record quarantined; next record becomes first contact |
| REC-17 | Agent boot-state missing/corrupt | no request; fail-closed local; operator recovery |
| REC-18 | Agent restored from old snapshot | 409 `stale_boot_generation`; no in-place reset |
| REC-19 | Rotate intent across two offline restarts | 200 identical response; full validation; high-water committed |
| REC-20 | Rotate intent expired after restarts | 409 `rotation_expired`; aborted path; old key active |
| REC-21 | Revocation during backlog | 401 `revoked_key`; spool retained; operator recovery |
| REC-22 | First contact is config pull (`{}`) with seq>1 | 200 agent-config; same high-water rules |
| REC-23 | First contact is rotate | 200 rotate-response; high-water committed |
| REC-24 | Enrollment response lost | 401 `token_used`; admin revokes orphan and reissues |
| REC-25 | `MAX_BOOT_GAP` boundary (65535) | 200 accepted; audit gap=65535 |
| REC-26 | Numeric maximum / exhaustion | 200 accepted at `MAX_NUMERIC`; ACK `next_seq=null`; no reuse |
| REC-27 | Agent power loss, seq persistence edge | resend committed seq → duplicate; unsynced seq never reused |
| REC-28 | Center power loss | committed → duplicate; uncommitted → accepted; no double apply |
| REC-29 | Old snapshot after newer live snapshot | 200 `stale_ignored`; latest not overwritten |
| REC-30 | Interleaved spool replay across two generations | oldest-first; duplicate/accepted; no reorder overwrite |

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

**Rev-5 full-validation rule for every rotate attempt (including intent replay).**
The rotate nonce is a persisted intent key, but it is **not** a bypass of transport
or high-water validation. Each rotate attempt, including a retry with the same
nonce/body, MUST execute, in this order:

1. header/encoding/size/grammar and class binding;
2. node identity/key state (old key active, new key provisional if a rotation
   exists, revocation wins);
3. signature over the decoded body with the old key;
4. boot generation/id under §5 A-1: `gen < highest_gen` →
   `stale_boot_generation`; same generation with a different boot_id or
   `gap > MAX_BOOT_GAP` → `boot_identity_conflict`; a bounded forward gap is
   accepted only as a new-generation first contact;
5. sequence under §5 A-2/A-3: either the exact previously committed attempt
   (same `seq` + identical fingerprint → idempotent replay) or a new attempt with
   `seq > last_seq`; `seq <= last_seq` without an exact fingerprint →
   `sequence_conflict`;
6. nonce intent match: the same nonce must map to the same
   `(node_id, nonce, old_key_id, body_sha256)`; a changed body/key/endpoint is
   `nonce_reuse` (cross-endpoint included).

Only after 1–6 pass may the center replay the persisted `rotate-response`; the
replay, the `node_boot` high-water update and the nonce/dedupe state commit in the
same transaction. A failed boot/sequence/identity check returns the corresponding
error and **no response is replayed**; it does not update high-water. The agent
treats a stale generation or conflicting sequence as fail-closed operator
recovery, never as a reason to reset state. This is the frozen rev-5 answer to
"rotation retry must not bypass high-water".

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

- Retry vs request fingerprint and 300 s freshness: a rotate retry keeps the
  **same nonce and same body** (the rotation intent key) but may refresh
  `sent_at`, `seq` and `boot_gen` so the 300 s transport-freshness window is
  satisfied; the center matches `(node_id, nonce, old_key_id, body_sha256)` and
  replays the persisted response. The nonce fingerprint for rotate therefore
  excludes those volatile transport fields; a changed body/key or a nonce used on
  another endpoint is `nonce_reuse`. **The refreshed transport fields are still
  fully validated by the rule above; intent matching only replaces identical
  attempt-fingerprint matching, never boot/seq/identity checks or the high-water
  commit.** (Report/config retries keep the exact attempt fingerprint and use a
  new nonce for a new attempt.)
- Agent recovery of a persisted rotation intent: state stores node_id, old/new
  key material, rotation nonce, attempt count and last known state. After a
  restart the agent rebuilds the rotate request with the persisted nonce/body and
  fresh transport headers; idempotent replay returns the same response, or
  `rotation_expired` moves it to the aborted path.
- New-key proof committed but ACK lost: the agent retries the report signed with
  the new key; the center (new key already active) answers `duplicate` (or
  accepted for a later record). Any 2xx response to a request signed by the new
  key proves confirmation, so the agent marks the rotation `confirmed`, deletes
  the old private key and keeps reporting with the new key.
- State distinction: **confirmed** = new active/old revoked (agent learns via a
  2xx new-key request; no auto re-activation of the old key); **aborted** =
  provisional new key revoked/old active (agent learns via `rotation_expired` or
  `401 revoked_key` on the new key, then falls back to the old key); **admin
  revoked** = all keys revoked (old-key fallback also gets `revoked_key`), agent
  stops reporting, keeps the bounded spool and awaits operator recovery. The agent
  must not guess between aborted and admin-revoked without probing both keys, and
  must never bypass a revocation.
- Unprovable safe recovery (e.g. both keys rejected, corrupt rotation state) =
  stop reporting and operator recovery (admin revoke + re-enroll); no automatic
  key adoption/reset.

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
| 400 | `invalid_request` | no | schema/body/duplicate representation/platform semantics |
| 400 | `platform_mismatch` | no | node_class payload/source/kinds isolation violation |
| 400 | `missing_header` / `invalid_header` | no | header grammar incl. canonical decimal and `MAX_NUMERIC` bound |
| 400 | `duplicate_header` | no | repeated/unknown `X-UM-*` header |
| 400 | `unsupported_encoding` | no | encoding token/gzip malformed/stacked |
| 401 | `unauthorized` | no | generic auth failure |
| 401 | `unknown_node` / `revoked_key` | no | identity/key state |
| 401 | `bad_signature` | no | signature/endpoint/body binding failed |
| 401 | `stale_timestamp` | yes (once) | recalibrate from `server_time` |
| 401 | `token_invalid` / `token_expired` / `token_used` | no | enrollment only |
| 401 | `token_scope_mismatch` | no | enrollment node_class/host does not match the admin token scope |
| 404 | `endpoint_not_found` | no | wrong listener plane/wrong path |
| 405 | `method_not_allowed` | no | non-POST on agent paths |
| 409 | `replay` | yes | duplicate transport attempt; treat as duplicate |
| 409 | `nonce_reuse` / `sequence_conflict` / `report_conflict` / `identity_mismatch` | no | replay/ordering conflicts |
| 409 | `stale_boot_generation` / `boot_identity_conflict` | no | retired generation, same-generation identity mismatch or `gap > MAX_BOOT_GAP`; bounded forward gaps and first-contact `seq>1` are accepted; operator recovery if local state is lost |
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

### 9.1 Node classes and platform isolation (rev 5)

`node_class` is bound at enrollment from the admin token scope (§4). It selects
the only allowed payload surface for that node; the center rejects a violation as
`400 platform_mismatch` (unless a more specific schema error applies):

| `node_class` | Allowed report bodies / objects | Required vs forbidden | Allowed source switches | Allowed event kinds |
| --- | --- | --- | --- | --- |
| `linux_vps` | `snapshot` (base system/services/protocols/traffic/clients), `metrics`, `events` | `terminal` object **forbidden**; `host.os=linux`; `expected_inbound_tags` non-empty | `system`, `services`, `singbox_api`, `events`; `terminal` MUST be false; `mihomo_api` not used | service/protocol/agent/config/clock/spool kinds only |
| `windows_terminal` | `snapshot` with `terminal` object, `events` | `terminal` object **required** when the source is configured (availability may be `unavailable`); base services/protocols/traffic/clients MUST be in honest `unavailable`/null/empty state; `host.os=windows`; `expected_inbound_tags` empty | `terminal`, `mihomo_api` (default false), `events`, `system` (optional); `services`/`singbox_api` MUST be false | `terminal_route_changed`, `terminal_source_unavailable` plus generic agent kinds |

- A `windows_terminal` node MUST NOT send `report-metrics` in v1 (per-minute
  terminal series can be derived by UM-D from snapshots/events; a future revision
  may add `terminal_samples`). A `linux_vps` node MUST NOT send `terminal`.
- The center stores `node_class` on the node identity; there is no per-report
  class field and no class change without revoke/re-enroll. Cross-class payloads
  are rejected before storage (`platform_mismatch`), never silently downgraded.
- The web/admin listener has no `/v1/agent/*` routes; the ingest listener has no
  `/api/*` routes and never accepts admin cookies (§1). Platform isolation is
  enforced on the ingest path before data apply.

### 9.2 Windows terminal telemetry (rev 5)

The Windows terminal reports only aggregate route/connection telemetry. Route
tokens are **exactly six, lowercase, aligned with the existing `windowsobs`
`Role` enum**; no duplicated enum and no free-form proxy names:

| Token | Meaning | Center aggregation |
| --- | --- | --- |
| `a_reality` | A path, Reality protocol | A |
| `a_hy2` | A path, Hysteria2 protocol | A |
| `b_reality` | B path, Reality protocol | B |
| `b_hy2` | B path, Hysteria2 protocol | B |
| `direct` | explicitly bound local direct path | DIRECT |
| `unknown` | observed but unresolvable/ambiguous path | UNKNOWN |

The center aggregates A = `{a_reality,a_hy2}` and B = `{b_reality,b_hy2}` and
keeps the protocol drill-down. `direct` is allowed only when the **operator-local**
Windows route binding explicitly maps a selected member/path to direct; an
unmapped/ambiguous path is `unknown`, **never auto-DIRECT**. Local binding names
are never sent to the center and never uploaded in reports; the center validates
only the closed six-token form and the aggregate coherence, not local names.

Snapshot `terminal` object (schema in
[`report-snapshot.schema.json`](../contracts/v1/report-snapshot.schema.json)):

- `selection`: `{availability, sampled_at, route, reason_code}`. `route` is the
  current selected leaf mapped to one of the six tokens or `null` when not
  resolvable; `reason_code` is a closed enum
  (`controller_unreachable|controller_auth|malformed_response|route_unbound|source_authorization_unproven`).
- `active_connections`: `{availability, sampled_at, total, by_route}` where
  `by_route` has exactly the six token keys. Each open connection is attributed to
  exactly one token; `total` equals the sum of all six counts when availability is
  `ok`.
- **Independent sampling**: `selection.sampled_at` and
  `active_connections.sampled_at` are separate and may differ. Both MUST lie in
  `[collected_at − 300 s, collected_at + 60 s]`; independent sampling does not
  permit unbounded skew. After a route switch, old connections may still be on the
  previous token, so `selection.route` and `active_connections.by_route` may
  legitimately disagree.
- Availability coherence: `ok` ⇒ non-null route/counts and sum equality;
  `partial` ⇒ at least one null/unknown value; `unavailable` ⇒ all null and the
  source-switch reason explains why. Empty API list/null distinction: a valid
  empty connection list is observed zero; a missing/malformed response is
  unknown/unavailable, never zero.
- The local `group`/`member` names used to classify routes stay local. They are
  part of an **operator-local Windows route-binding file** (not center config,
  not uploaded) that maps local names to the six tokens; the center sends only
  class switches and never needs the raw proxy names. The agent never uploads
  local proxy names, full YAML, controller secrets, destination/source IPs, URLs,
  process names or connection ids. A sentinel hit rejects the report
  (`invalid_request`, audited, value never logged/stdout). If the local binding
  is absent/ambiguous, the agent reports `unknown`/null; it never guesses
  `direct`.
- **Center-managed A/B → VPS-ID mapping**: mapping is center metadata, not agent
  payload. It is versioned and append-only:
  `route_mapping_versions{event_id, windows_node_id, version, effective_from,
  route_token→linux_vps_node_id, created_by, created_at}`. Reports store only the
  six tokens. Historical attribution is resolved with the mapping version whose
  `effective_from ≤ sample/event time < next.effective_from`; a new mapping never
  rewrites earlier samples, and deleting/overwriting a prior version is forbidden.
  Unmapped tokens are displayed as unmapped/UNKNOWN, never guessed. Only a
  `linux_vps` node of the same event may be a mapping target; mapping changes are
  audited (UM-B4).
- Windows collection is read-only: the agent MUST NOT modify Mihomo/Clash Verge
  Rev configuration, switch nodes, close connections or change HA-UI/P6/#67
  behavior. `mihomo_api` defaults to **false**. The R2 truly-read-only data source
  is the preferred enabler; R1 (a write-capable controller credential used by a
  read-only client) requires a later, separate owner risk acceptance and is never
  auto-enabled. Until an authorized source is proven, `terminal.availability` is
  `unavailable` with `reason_code=source_authorization_unproven`; no fabricated
  data.

### 9.3 Closed event details and privacy

- **Closed event details**: per-kind closed detail schemas are enforced
  (`report-events.schema.json` if/then + `additionalProperties:false`). No
  arbitrary keys, no free-text error messages, no paths/exception text. Windows
  terminal events are closed to `terminal_route_changed`
  (`previous_route,current_route,sampled_at`) and
  `terminal_source_unavailable` (`source=mihomo_api|local_readonly,reason_code`; R2 truly-read-only source uses `local_readonly`, R1 controller uses `mihomo_api`); no connection
  details or proxy names are allowed.
- **Privacy allowlist** (center MUST reject/strip before storage): no UUIDs,
  passwords, private keys, tokens, full YAML, client names, raw source/destination
  IPs or hostnames, URLs, command lines, journal text, free text, connection
  records, local proxy names or controller credentials. Allowed: aggregate
  counters, protocol/route state tokens, the six Windows terminal tokens, `device_ref`
  (HMAC-SHA256 with per-event salt of the local client identity, truncated to 32
  bytes), bounded counters, node-provided agent version/host class; local route
  binding names are operator-local on the Windows host and are never sent to the
  center or returned in reports.
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
  - **Platform isolation**: reject any report whose body/object/event-kind is
    not allowed for the authenticated `node_class` (§9.1) with
    `400 platform_mismatch`; the check runs before storage and before applying
    dedupe state for an otherwise newly authenticated request. A Windows
    `terminal` object is required for a windows_terminal snapshot; a linux_vps
    node must not send it.
  - **Windows terminal semantics**: `by_route` keys are exactly the six tokens;
    when availability is `ok`, `total` equals the sum of all six counts, route
    values are non-null, and both `sampled_at` values are within
    `[collected_at − 300 s, collected_at + 60 s]`; `direct` is a valid token but
    the agent itself must not emit it unless an operator-local binding explicitly
    maps the path to direct, otherwise the path is `unknown`/null. The center
    validates the closed token/count/sampling coherence but does not and cannot
    resolve local binding names. The center rejects negative, non-integer or
    out-of-range counts and any free-form or privacy-sentinel value in terminal
    fields.
  - **Mapping history**: reports carry no VPS IDs; route attribution is resolved
    at query time against the immutable, versioned center mapping effective at
    the sample/event timestamp (§9.2). A mapping update must not rewrite
    historical attribution; the center never joins a report to a mapping version
    by arrival time.
  - Privacy runtime: `device_ref` must be the only client identifier (43-char
    base64url), no UUID/IP/YAML/password/proxy-name-shaped values in any string
    field; a sentinel hit rejects the report and is audited (no value logged).
  - Unknown enum tokens are rejected; additional closed-set runtime checks are
    listed in UM-B tests. The center stores only validated values.
- **Sentinel negative contract**: UM-B must include tests that plant
  UUID/password/private-key/YAML/source-IP sentinel values in agent payloads and
  assert they are rejected at the boundary, absent from stored rows, logs, HTTP
  responses and backups (SEC-14 extension).

## 10. Versioning and compatibility

- Wire major is in the path namespace (`/v1/`), `X-UM-Protocol` and body `v`.
  Body `v` is the payload-schema version (currently 1); the header is the wire
  major. They are intentionally separate and both validated. This document is
  revision 5 of the v1 contract.
- Unknown fields are ignored only in objects documented as extensible (none in
  v1); closed enums reject unknown tokens (`invalid_request`).
- Revision-5 targeted changes (required `node_class`, optional `terminal` object,
  new closed event kinds, nullable ACK `next_seq`, bounded canonical decimals,
  `platform_mismatch`/`token_scope_mismatch`, six route tokens) are frozen **before
  any production agent/center deployment**. There is no deployed v1 estate to
  migrate; after the first production release, any change of this kind is a major
  revision. Rev-4 vectors and expectations are retained as history (see §12 and
  `negative-vectors.v1.json` `superseded_rev4_expectations`).
- Deprecation ≥90 days and one agent minor release before removal; unknown major
  → `426 unsupported_version`.
- Agent capabilities in enrollment are advisory for optional features;
  `terminal_v1` is meaningful only for `windows_terminal`. The v1 mandatory
  surface is class-specific: `linux_vps` requires snapshot+metrics+events;
  `windows_terminal` requires snapshot-with-terminal+events (metrics deferred).

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
  - **Mihomo source (windows_terminal only)** (`mihomo_api` switch): disabled by
    default and enabled only after an owner-approved data-source authorization.
    The external controller credential is generally read/write; the R2 truly
    read-only source (no controller secret, e.g. a verified local read-only
    surface) is the preferred R2 investigation and must be evaluated in UM-B3. R1
    (a write-capable controller credential used by a strictly GET-only client) is
    a documented residual risk that requires a separate, later owner acceptance;
    it is never auto-enabled and is never described as "read-only". Until an
    authorized source is proven, the terminal source reports `unavailable` with
    `reason_code=source_authorization_unproven`; no fabricated data. The Windows
    agent does not modify Mihomo/Clash Verge Rev configuration, does not switch
    nodes, does not close connections and does not change HA-UI/P6/#67 behavior.
    Only loopback controller access, fixed GET paths (`/proxies`, `/connections`),
    no redirects/proxy env/DNS, response caps and a closed local token mapping
    are allowed. Six route tokens are used exactly as in §9.2; local
    group/member names never leave the host. If R1 is ever accepted, the
    documented mitigations are: loopback-only binding, dedicated secret in
    DPAPI/private ACL, unprivileged agent with no exec, static+runtime
    method/path allowlist tests, per-version controller capability audit and an
    explicit audit record of the owner risk acceptance.
  - **Data-source matrix by class** (`linux_vps` vs `windows_terminal`): the
    `agent-config.collect` switches are validated against the node_class
    allowlist (§9.1); a config that enables a forbidden source is rejected by the
    agent as `platform_mismatch` and never applied. The center never sends raw
    proxy names, VPS IDs, hostnames, URLs or credentials to an agent.
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

## 12. Frozen vectors and validation (revision 5)

Committed under [`../contracts/v1/`](../contracts/v1/):

- `test-vectors.v1.json` (revision 5): positive report vector retained from rev-4
  (still valid), a **Windows terminal report vector**, a rev-5 enrollment vector
  with `node_class`, rotate and config positive vectors, and cryptographic
  negatives (tampered body/windows terminal body, boot-gen tamper, wrong key,
  cross-endpoint reuse). `historical_rev4_enroll_vector` is retained for
  traceability only and is not a current positive vector.
- `negative-vectors.v1.json` (revision 5, 67 cases): the 45 rev-4-origin
  behavioural cases updated where rev-5 changes the expectation, plus 22 rev-5
  recovery/platform/isolation cases (generation gaps, first-contact `seq>1`,
  numeric maximum/exhaustion, rotate retry with full validation, node_class
  isolation, six-token Windows telemetry, mapping history, privacy negatives).
  `superseded_rev4_expectations` records the old rev-4 expectations for
  traceability; do not delete it.
- `examples/`: positive snapshot/metrics/events/enroll/ack/enroll-response/
  rotate/config bodies plus `terminal-snapshot.v1.json` and negative examples
  (extra body signature field, arbitrary detail, free-text detail, impossible
  units, unknown error code, terminal sum mismatch, raw proxy name, unknown route
  token). Example data is synthetic only.

Config body fixed to `{}` (2 bytes); standard `Content-Encoding` must match the
signed `X-UM-Content-Encoding`; rotation and enrollment state machines are frozen
above. Any change to headers, signing strings, endpoint semantics, dedupe/
sequence/rotation rules, enums, numeric bounds or vectors is a frozen-contract
revision requiring independent review before implementation.

## 13. Numeric bounds, ACK exhaustion and SQLite storage semantics (rev 5)

Revision 5 removes all ambiguity between the wire's unsigned decimal fields and
the center's signed 64-bit storage:

1. **Bound**: `MAX_NUMERIC = 9223372036854775806` (2^63−2). `X-UM-Boot-Gen` and
   `X-UM-Seq` are canonical decimals in `[1, MAX_NUMERIC]`; `X-UM-Sent-At` is a
   canonical decimal in `[0, 2^63−1]`. The signing string always uses the exact
   header text. A non-canonical value (leading zero, `+`, whitespace) or a value
   above the bound is `400 invalid_header` and is rejected before any numeric
   conversion. The center parses with `uint64`, range-checks, then converts to
   `int64`; a conversion is impossible to overflow after the bound check and a
   wrapped value is never stored.
2. **`MAX_BOOT_GAP = 65535`** for generation forward jumps: `gen > highest_gen`
   is accepted only when `1 <= gen − highest_gen <= 65535`; the difference is
   computed after both values pass the numeric bound, so subtraction cannot
   underflow. Larger gaps are `409 boot_identity_conflict` (not `invalid_header`)
   and write a security event without high-water change.
3. **ACK `next_seq`**: `next_seq = last_seq + 1` while
   `last_seq < MAX_NUMERIC`; if `last_seq == MAX_NUMERIC` the ACK carries
   `next_seq: null` (generation numerically exhausted). The agent MUST NOT reuse
   or wrap a seq; on `null` it starts a new generation from a clean restart, and if
   it cannot (boot-state loss) it enters operator recovery. The center rejects any
   further same-generation request (no representable seq) as `invalid_header` and
   generation `MAX_NUMERIC` is a terminal operator condition (a new generation
   cannot be represented; admin revoke + re-enroll as a new node identity).
4. **SQLite mapping**: all protocol numeric state is stored as SQLite `INTEGER`
   (signed 64-bit) with `CHECK` constraints matching the bounds above — never as
   TEXT, BLOB or REAL, never as an unsigned value. Hash/hex/id fields stay TEXT;
   timestamps are `INTEGER` epoch seconds. `next_seq` is nullable `INTEGER`.
   Example constraints: `CHECK (highest_gen BETWEEN 1 AND 9223372036854775806)`,
   `CHECK (last_seq BETWEEN 1 AND 9223372036854775806)`,
   `CHECK (boot_gen BETWEEN 1 AND 9223372036854775806)`,
   `CHECK (seq BETWEEN 1 AND 9223372036854775806)`. Internal rows that only carry
   an "unset" state use `NULL`, not `0`.
5. **Transaction/durability**: the numeric high-water, dedupe rows and payload
   rows commit in one WAL transaction with `synchronous=FULL`; there is no
   in-memory-only high-water and no ACK before commit. A failed commit leaves no
   partial numeric state.
6. **Conformance**: UM-B1/B2 tests MUST cover `MAX_NUMERIC` acceptance,
   `MAX_NUMERIC+1` rejection, `MAX_BOOT_GAP` boundary (65535 accepted / 65536
   rejected), gap arithmetic, `next_seq:null` at exhaustion, restart after
   exhaustion, SQLite round-trip of the maximum values, and no TEXT/REAL
   representation (query the schema and assert column affinities/CHECKs).
