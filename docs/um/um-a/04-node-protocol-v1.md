# UM-A 04 — Node protocol v1 (FROZEN contract)

Status: **FROZEN for UM-B implementation**, subject to the UM-A independent
review. An incompatible change requires an explicit design revision review; the
machine-readable schemas and test vector in
[../contracts/v1/](../contracts/v1/) are part of this contract, not illustrative
examples.

Related threat analysis: [06](06-threat-model-security-tests-performance.md).
Storage/retention consequences: [05](05-retention-capacity-backup.md).

## 1. Transport and endpoints

- Agent → center: HTTPS over TLS 1.3, HTTP/1.1 with keep-alive, JSON UTF-8.
- Base URL from provisioning config: `https://ingest.132431.xyz:8443` (owner may
  change host/port at deployment; the contract is origin-independent).
- TLS: public-CA-validated certificate for the ingest hostname (agent MUST NOT
  disable verification, MUST NOT allow a plaintext fallback or redirect). An
  optional `center_spki_sha256` pin may be configured for strict deployments;
  the pin is recorded at enrollment.
- The machine plane is **not** behind Cloudflare Access and has no cookies,
  sessions, CSRF, HTML or browser semantics.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/v1/agent/enroll` | one-time bootstrap token (Bearer) + new-key signature | bind a new node identity to an event |
| POST | `/v1/agent/report` | node signature headers | idempotent telemetry report |
| POST | `/v1/agent/rotate` | old-key signature headers | rotate the node key |
| POST | `/v1/agent/config` | node signature headers | fetch current agent config |
| — | `/v1/agent/revoke` | **does not exist** | revocation is admin-only on the web plane |

Anything else on the ingest listener → 404. The ingest listener exposes no
`/api/*` route; the web listener exposes no `/v1/agent/*` route (doc 03 §2).

## 2. Identities and enrollment

- `node_id`: lowercase UUIDv4, assigned by the center at enrollment.
- `event_id`: assigned by the center from the bootstrap token's event; the agent
  cannot choose or change it.
- Node key: Ed25519. The agent generates the keypair locally; the private key
  never leaves the node (0600). Public wire form is the raw 32-byte public key
  encoded base64url without padding.
- `key_id`: `key-` + 8 lowercase hex chars assigned by the center; a node has one
  active key plus a rotation grace entry.
- Bootstrap token: 256-bit random, base64url, event-scoped, **single use**,
  TTL ≤ 15 minutes, stored at the center only as SHA-256 hash; delivered to the
  VPS by the operator through a 0600 provisioning file and deleted by the agent
  after successful enrollment.

### Enrollment request

`POST /v1/agent/enroll`, `Authorization: Bearer <bootstrap-token>`, body schema
[`enroll-request.schema.json`](../contracts/v1/enroll-request.schema.json):

```json
{"v":1,"agent_version":"1.0.0","host":{"os":"linux","kernel":"6.8.0-45-generic","arch":"amd64"},
 "pubkey":"<base64url-32>","nonce":"<base64url-16>","signed_at":1795622400,
 "signature":"<base64url-ed25519>"}
```

Signature input (UTF-8): `um-enroll-v1\n<nonce>\n<signed_at>\n<sha256-hex(body-bytes)>`.
The signature is over that exact string; the body bytes are the exact received
body (no canonicalization, no re-serialization).

Center checks, in order: token hash exists/unused/unexpired → token event active
→ body size → grammar → timestamp ±300 s → signature with `pubkey` → event node
capacity → store node/key/token-used atomically → respond.

### Enrollment response

Schema [`enroll-response.schema.json`](../contracts/v1/enroll-response.schema.json):

```json
{"v":1,"node_id":"<uuid>","event_id":"<uuid>","key_id":"key-1a2b3c4d",
 "config_version":1,"device_salt":"<base64url-32>","server_time":1795622402,
 "cadence_seconds":60,"center_spki_sha256":"<base64url-32-or-null>"}
```

The agent persists `node_id`, `key_id`, `event_id`, `device_salt` (0600),
`center_spki_sha256` (if present), then deletes the bootstrap token. If the
response is lost after the center committed, the token is already consumed: the
agent retries enrollment → 401 `token_used`; the operator must issue a new token
and the agent starts a new identity (no half-enrolled agent is accepted).

## 3. Report envelope and signing (normative)

Headers on `/v1/agent/report`, `/v1/agent/rotate`, `/v1/agent/config`:

| Header | Grammar | Meaning |
| --- | --- | --- |
| `X-UM-Protocol` | `1` | protocol major |
| `X-UM-Node-Id` | lowercase UUIDv4 | node identity |
| `X-UM-Key-Id` | `key-[0-9a-f]{8}` | signing key id |
| `X-UM-Boot-Id` | 32 lowercase hex | random per agent process start |
| `X-UM-Seq` | decimal uint64 ≥ 1 | strictly increasing per boot |
| `X-UM-Sent-At` | decimal Unix seconds | signed timestamp |
| `X-UM-Nonce` | base64url, exactly 16 bytes | unique per request |
| `X-UM-Signature` | base64url Ed25519 (64 bytes) | signature over the string below |
| `Content-Type` | `application/json` | required |
| `Content-Encoding` | `gzip` (optional) | compressed body transport |

Signing string (exact bytes, UTF-8, LF `\n` separators, no trailing newline):

```text
um-report-v1
<node_id>
<key_id>
<boot_id>
<seq>
<sent_at>
<nonce>
<sha256-hex of the raw body bytes>
```

`X-UM-Signature = Ed25519_sign(node_private_key, signing_string_bytes)`.
The body is signed as received: the center MUST verify over the exact bytes and
only then parse JSON (it never re-serializes before verification). The bootstrap
token and all secrets never appear in the signing string, headers or body except
the one-time `Authorization` header at enrollment.

Why this shape: it binds protocol/version, node identity, key, boot generation,
sequence, time, anti-replay nonce and exact payload bytes. No JSON
canonicalization is needed, so implementations cannot disagree about number or
key formatting. This follows the audited #67 principle "sign the exact body
bytes" without reusing its code or contract.

## 4. Replay, sequence and idempotency rules

Accepted time window: `|server_time - sent_at| ≤ 300 s`. Outside → `stale_timestamp`
with `server_time` in the error body so the agent can recalibrate once.

Dedupe keys (center memory or `reports_dedupe`, both bounded):
`(node_id, nonce)` for ≥10 min and `(node_id, boot_id, seq)`.

| Condition | Result | Store? |
| --- | --- | --- |
| nonce already seen | `200 duplicate` | no |
| seq == last seq, same body sha256 | `200 duplicate` | no |
| seq == last seq, different body sha256 | `409 sequence_conflict` (permanent) | no |
| seq < last seq for current boot | `409 sequence_conflict` (permanent) | no |
| seq > last seq (gap allowed, counted) | `200 accepted` | yes |
| new boot_id, any seq | `200 accepted`; previous boot reports then rejected | yes |
| old boot_id after a new boot was accepted | `409 sequence_conflict` | no |

The center stores `last_boot_id`, `last_seq`, `last_body_sha256` per node. A gap
is recorded as `sequence_gap_count` (diagnostic only; loss is possible on a
network and must not block later data). A duplicate must be acknowledged (200)
because the agent may have lost the original ack.

## 5. Report bodies

All bodies are versioned `v:1` with a closed `type`. Exact field sets, types,
units and bounds are in the JSON schemas; the center validates the schema **and**
the allowlist before any write.

### 5.1 `snapshot` — latest state (upsert, idempotent)

[`report-snapshot.schema.json`](../contracts/v1/report-snapshot.schema.json),
example [`examples/report-snapshot.v1.json`](../contracts/v1/examples/report-snapshot.v1.json),
max 32 KiB (raw).

Contents: `generated_at`, `config_version`, `agent{version,boot_id,uptime_s}`,
`host{os,kernel,arch}`, `system{cpu_pct,load1,mem_total_bytes,mem_used_bytes,
disk_total_bytes,disk_used_bytes,net_rx_bytes,net_tx_bytes}`,
`services[{name,state}]`, `protocols[{kind,inbound_tag,state,reason,observed_at}]`,
`traffic[{scope,inbound_tag,uplink_total_bytes,downlink_total_bytes}]`,
`clients{active,tracked,summaries[{device_ref,active,uplink_bytes,downlink_bytes,last_seen}]}`.
`net_*_bytes`, `uplink_total_bytes`, `downlink_total_bytes` are cumulative
counters; the center derives deltas and detects counter resets from the
`counter_epoch` change (agent reports a new `counter_epoch` whenever the
underlying counter source restarts).

### 5.2 `metrics` — bounded minute samples

[`report-metrics.schema.json`](../contracts/v1/report-metrics.schema.json), max
32 KiB. `samples` is an array of 1..5 objects, each aligned to a UTC minute:
`at` (epoch seconds at minute start), `cpu_pct`, `load1`, `mem_used_bytes`,
`disk_used_bytes`, `net_rx_bytes_total`, `net_tx_bytes_total`,
`active_connections`. At most one sample per `at`; duplicates are rejected.

### 5.3 `events` — bounded fault/agent timeline

[`report-events.schema.json`](../contracts/v1/report-events.schema.json), max
32 KiB, 1..50 entries: `{event_id (uuidv4), at, kind, severity, detail{≤8 scalar
entries, each ≤64 chars}}`. `kind` ∈ `service_restart`, `service_failure`,
`protocol_outage`, `protocol_recovery`, `agent_started`, `agent_error`,
`config_update`, `clock_skew`, `spool_overflow`; `severity` ∈ `info`, `warning`,
`critical`. `event_id` is globally unique; duplicate event ids are ignored.

### 5.4 Response / ack

[`ack.schema.json`](../contracts/v1/ack.schema.json):

```json
{"v":1,"result":"accepted","server_time":1795622402,"next_seq":42,
 "config_version":1,"retry_after_s":null}
```

`result` ∈ `accepted`, `duplicate`; `server_time` is authoritative for clock
recalibration; `config_version` greater than the agent's value requires
`POST /v1/agent/config`; `next_seq` is diagnostic only (the agent keeps its own
monotonic counter; a resend uses the same seq+nonce to obtain `duplicate`).

## 6. Rotation, configuration and revocation

### 6.1 Rotation

`POST /v1/agent/rotate` is authenticated by the **old key** (same envelope and
signing string) with body
[`rotate-request.schema.json`](../contracts/v1/rotate-request.schema.json):
`{v, new_pubkey, nonce, signed_at}`. Center verifies the old-key signature and
timestamps, stores the new key with the same node/key generation, returns the new
`key_id`. Both keys are accepted for a grace window of ≤5 minutes; the old key is
automatically revoked on the first accepted report signed by the new key or when
the grace window expires. Rotation never changes `node_id`/`event_id`.

### 6.2 Configuration pull

`POST /v1/agent/config` (node signature) returns the current agent config:
`{v, node_id, event_id, config_version, cadence_seconds (30..300),
collect{...allowlisted booleans...}, device_salt, server_time}`. The center has
**no push channel**: agents pull only. Configuration changes are limited to
cadence, collection enable flags and device-salt rotation; they can never add a
command, URL, host or write capability.

### 6.3 Revocation and retirement

Admin-only web action. After revocation: reports signed by any node key are
rejected with `401 revoked_key`; the agent stops sending, records a local
`agent_error` state and requires operator action. The node row becomes
`revoked`; history remains queryable. `retired` is a later admin state (after
revocation) with 30-day retention for the identity row. Re-enrollment requires a
new bootstrap token and creates a new `node_id`.

## 7. Errors

HTTP status plus body [`error.schema.json`](../contracts/v1/error.schema.json):
`{"v":1,"error":"closed_code","retryable":false,"server_time":...}`.
No stack traces, paths, exception text, request bodies or secrets.

| HTTP | code | Retryable | Agent behavior |
| --- | --- | --- | --- |
| 400 | `invalid_request` | no | quarantine report (bounded), continue |
| 401 | `unauthorized` | no | stop; re-enrollment required |
| 401 | `unknown_node` / `revoked_key` | no | stop; mark revoked; operator action |
| 401 | `bad_signature` | no | stop; record security event |
| 401 | `stale_timestamp` | yes (once) | recalibrate from `server_time`, retry once |
| 409 | `replay` | yes | treat as duplicate (ack may have been lost) |
| 409 | `sequence_conflict` | no | stop; requires config/enrollment action |
| 409 | `identity_mismatch` | no | stop; operator action |
| 413 | `payload_too_large` | no | drop/quarantine; reduce batching |
| 426 | `upgrade_required` | no | stop; agent upgrade required |
| 429 | `rate_limited` | yes | honor `Retry-After` |
| 503 | `storage_unavailable` | yes | exponential backoff, keep spool |

## 8. Versioning and compatibility

- Major version is in the URL namespace (`/v1/`) and `X-UM-Protocol`/`v`; the
  center accepts only supported majors (initially `1`). A leaf with an unknown
  major gets `426 upgrade_required` (never a silent downgrade).
- Within v1, changes must be additive/optional: unknown fields are ignored only
  in objects documented as extensible (`detail` maps, future ack fields); closed
  enums reject unknown values with `invalid_request`.
- Removing/renaming a field, changing a unit/meaning/enum token or tightening a
  bound in a way old agents violate is a major change.
- Deprecation policy: a deprecated major/field is announced for ≥90 days and at
  least one agent minor release before removal.
- Agent `agent_version` is recorded for fleet visibility; the center may require
  a minimum version via `426 upgrade_required` only with owner-approved policy.
- Capability announcement (`metrics_v1`, `events_v1`, `rotate_v1`, `config_v1`)
  is optional in enrollment and required only when a future feature needs it;
  the v1 baseline center accepts agents implementing the mandatory set.

## 9. Agent runtime behavior (contract, not implementation)

- Spool-before-ack: persist durably (fsync) before first send; remove only on
  `accepted`/`duplicate`; ordered replay; one in-flight request; backoff with
  full jitter 1 s → 60 s cap; honor `Retry-After`.
- Bounded spool: ≤32 MiB and ≤7 days (both enforced; evict oldest with a counted
  `spool_overflow` event, never unbounded growth); startup retention failure is
  fail-closed (no half-open agent); single-writer lock.
- Cadence default 60 s (snapshot + metrics), events immediately (batched ≤50);
  minimum 30 s, maximum 300 s, center-controlled.
- No listening socket; no outbound connection other than the configured center
  origin; no exec; no root; no `sbox-cm`/journald access; no shell.
- Clock: agent uses local monotonic time for scheduling and the ack
  `server_time` to maintain a bounded offset; it MUST NOT trust local wall clock
  for ordering (the nonce/seq are authoritative).
- Local quota: one process, bounded queue, bounded CPU (doc 06 performance
  budget), no writes outside its private directories.

## 10. Center validation order (normative)

1. TLS and route; 2. body size/encoding limits; 3. identity header grammar;
4. node lookup and event binding; 5. key existence/status; 6. clock window;
7. signature over exact bytes; 8. nonce replay; 9. sequence rules;
10. JSON schema + privacy allowlist; 11. store in one transaction;
12. ack. Any failure before step 11 writes nothing; failures are logged as closed
codes only (no payload content).

## 11. Frozen test vector

Committed under [`../contracts/v1/test-vectors.v1.json`](../contracts/v1/test-vectors.v1.json):

- the exact body bytes are
  [`../contracts/v1/examples/report-snapshot.v1.json`](../contracts/v1/examples/report-snapshot.v1.json);
- the signed string and Ed25519 signature were produced and independently
  verified with OpenSSL (commands in
  [`../contracts/v1/README.md`](../contracts/v1/README.md));
- the vector fixes body sha256, signing string, public key, signature and
  expected verification result, so any implementation can prove wire
  compatibility before UM-B integration.

Any change to the signing string, header names/grammar, body type names, closed
enums or the test vector requires a frozen-contract revision review.
