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
| POST | `/v1/agent/config` | current node key signature headers | empty body `{}` (0 bytes decoded) | `agent-config.schema.json` (200) |
| — | anything else | — | — | `error.schema.json` with `endpoint_not_found`/`method_not_allowed` |

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

Content-encoding rules: exactly one coding token, `identity` or `gzip`; no
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

### Response and response-loss recovery

Body: [`enroll-response.schema.json`](../contracts/v1/enroll-response.schema.json)
(`node_id`, `event_id`, `key_id`, `config_version`, `device_salt`,
`cadence_seconds`, `server_time`, optional `center_spki_sha256`).

Enrollment commits node + key + token-consumption atomically. If the response is
lost, the token is already consumed: the agent retries and receives
`401 token_used`; the node is left in `pending_activation` (visible to admins,
reports rejected with `401 pending_activation`). Recovery is explicit: admin
revokes the pending identity (or deletes it) and issues a new one-time token; the
agent generates a new key and node id. There is no automatic completion or
silent key adoption.

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
| `nonce_dedupe` | `(node_id, endpoint, nonce)` → body hash, received_at | network replay; same nonce different body/endpoint → `409 nonce_reuse` | 24 h |
| `boot_registry` | `(node_id, boot_id)` → first/last seen, last seq, state active/retired | reject reports from retired boots; bound boot history per node (last 8) | with node identity |
| `node_seq` | node_id → current boot_id, last_seq, updated_at | monotonic ordering per boot; gaps allowed and counted | current |

Apply rules:

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

## 7. Rotation, configuration and revocation

- Rotate: headers signed by the **old** key; body
  [`rotate-request.schema.json`](../contracts/v1/rotate-request.schema.json)
  `{v, new_pubkey}`; response
  [`rotate-response.schema.json`](../contracts/v1/rotate-response.schema.json)
  `{node_id, previous_key_id, new_key_id, config_version, server_time}`. Old key
  is accepted for ≤5 min grace and revoked on the first accepted report under the
  new key or at grace expiry.
- Rotate response loss/retry: the agent persists a pending rotation intent (new
  key + old key) and retries with the **same nonce/body**; the center returns the
  same recorded rotate-response (idempotent) while the old key is in grace. If the
  grace expires first, the rotation is failed; the agent discards the pending key
  and continues with the old key (no node-id change, no data loss). It may start a
  new rotate attempt with a new nonce later. A retry after the old key was revoked
  is `401 revoked_key`.
- Config: signed pull only, body `{}`; response
  [`agent-config.schema.json`](../contracts/v1/agent-config.schema.json) with
  `cadence_seconds` 30–300, boolean collect switches, `device_salt`,
  `config_version`. No center→agent push channel and no command/URL/host fields.
- Revocation/retirement: admin-only web action; reports rejected immediately;
  node identity row retained for audit/history until its retention boundary.

## 8. Errors (closed vocabulary)

HTTP status + [`error.schema.json`](../contracts/v1/error.schema.json).

| HTTP | error | Retryable | Notes |
| --- | --- | --- | --- |
| 400 | `invalid_request` | no | schema/body/duplicate representation |
| 400 | `missing_header` / `invalid_header` | no | header grammar |
| 400 | `duplicate_header` | no | repeated/unknown `X-UM-*` header |
| 400 | `unsupported_encoding` | no | encoding token/gzip malformed/stacked |
| 401 | `unauthorized` | no | generic auth failure |
| 401 | `unknown_node` / `revoked_key` / `pending_activation` | no | identity state |
| 401 | `bad_signature` | no | signature/endpoint/body binding failed |
| 401 | `stale_timestamp` | yes (once) | recalibrate from `server_time` |
| 401 | `token_invalid` / `token_expired` / `token_used` | no | enrollment only |
| 404 | `endpoint_not_found` | no | wrong listener plane/wrong path |
| 405 | `method_not_allowed` | no | non-POST on agent paths |
| 409 | `replay` | yes | duplicate transport attempt; treat as duplicate |
| 409 | `nonce_reuse` / `sequence_conflict` / `stale_boot` / `report_conflict` / `identity_mismatch` | no | replay/ordering conflicts |
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
- **Read-only data sources** (no exec, no root, no journald):
  - sing-box `service.api` over loopback using systemd `LoadCredential=` for the
    operator-provided API secret (copied into the service's private credential
    directory by systemd; existing file ownership/permissions are not changed).
    The agent's client implements only the audited read-only started-service
    subscription methods; there is no generic/dynamic RPC surface and no config
    mutation call in the client. UM-B must record the audited sing-box version,
    method allowlist and a negative test (no other RPC path strings).
  - `/proc`/syscalls for CPU, memory, disk, network counters (no subprocess).
  - systemd unit state via **read-only D-Bus property reads** on
    `org.freedesktop.systemd1` (`ActiveState` only); no start/stop/enable/exec
    calls. If D-Bus is unavailable the state is `unknown`/`unavailable`; the
    agent does **not** fall back to executing `systemctl`.
  - optional Mihomo controller GET via loopback with a credential the same way
    (`LoadCredential`), no mutation methods.
  - protocol state: derived only from available evidence (service state + API
    activity/optional loopback dial); absence of traffic is never reported as
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
- `negative-vectors.v1.json`: behavioural HTTP negative contracts
  (enrollment token/expired/used, header duplication/missing/encoding, tampered
  body, cross-endpoint replay, nonce/report/boot/sequence conflicts, size caps,
  rotation grace/revocation, listener-plane separation).
- `examples/`: positive snapshot/metrics/events/enroll bodies and negative
  examples used by schema negative tests (extra body signature field, arbitrary
  detail, free-text detail, impossible units, unknown error code).

Any change to headers, signing strings, endpoint semantics, dedupe/sequence
rules, enums or vectors is a frozen-contract revision requiring independent
review before implementation.
