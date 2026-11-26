# UM contracts v1 (revision 5)

Frozen machine-readable contracts for Unified Monitor node protocol v1 revision 5.
Normative prose: [`../../um-a/04-node-protocol-v1.md`](../../um-a/04-node-protocol-v1.md).
Review response: [`../../um-a/08-review-response-matrix.md`](../../um-a/08-review-response-matrix.md).

Revision 2 changes: signatures are **transport headers only** (no signed body
contains a signature field, removing the enrollment circular dependency); signing
strings bind endpoint/method/path/content-encoding/identity/time/sequence/nonce/
body hash; every report body carries `report_id` + `collected_at`; snapshot/metric
fields can be `null`/unknown with explicit availability; event `detail` is closed
per kind; ACK/error/rotation schemas and the negative contract were added.

Revision 3 changes (targeted): enrollment is **active on commit** (no
`pending_activation`); rotation is a persistent state machine where the old key is
owned only until new-key proof (expiry aborts the provisional key, never the old
one) with `rotation_in_progress`/`rotation_expired`; replay is closed by unique
`(node_id, nonce)` + full request fingerprint and current-boot acceptance with
`seq` exact-retry rules and defined transaction ordering; the config request body
is exactly **two bytes `{}`** and the HTTP `Content-Encoding` must match the signed
`X-UM-Content-Encoding`; agent source switches default `false` and unproven source
authorization disables the source; `agent-config` carries
`expected_inbound_tags`. Final corrections of that cycle added the signed
monotonic `X-UM-Boot-Gen` and expanded the behavioural contract to 45 cases.

**Revision 5 changes (targeted final amendment):** integrates the owner-accepted
A-1..A-5 recovery semantics (bounded generation forward jumps with
`MAX_BOOT_GAP=65535`; the first accepted request of a new generation may have
`seq>1`; ACK `next_seq` reconciliation; superseded-attempt handling for the
agent; rotate intent replay runs full boot/seq/nonce/identity validation and never
bypasses high-water). Adds canonical numeric bounds (`MAX_NUMERIC = 2^63−2`) and
SQLite INTEGER storage semantics, ACK `next_seq: null` on generation exhaustion,
`node_class` (linux_vps/windows_terminal) enrollment/registration binding and
platform isolation (`platform_mismatch`), the Windows terminal telemetry object
with exactly six route tokens (`a_reality`, `a_hy2`, `b_reality`, `b_hy2`,
`direct`, `unknown`), independent selection/connection sampling, closed Windows
event kinds, versioned center-managed route mapping (historical attribution is
not rewritten), privacy negatives, and rotate/config/Windows signed vectors. The
rev-4 report vector remains valid and is retained; the rev-4 enrollment vector is
retained as `historical_rev4_enroll_vector` only (the body lacks the now-required
`node_class`). Superseded behavioural expectations are retained in
`negative-vectors.v1.json` under `superseded_rev4_expectations`.

## Files

| File | Direction | Content |
| --- | --- | --- |
| `enroll-request.schema.json` | agent → center | signed-header enrollment body with `node_class` |
| `enroll-response.schema.json` | center → agent | identity/event/class/config assignment |
| `report-snapshot.schema.json` | agent → center | latest state (upsert, newer `collected_at` only); optional Windows `terminal` telemetry |
| `report-metrics.schema.json` | agent → center | bounded minute samples (nullable unknowns) |
| `report-events.schema.json` | agent → center | bounded events with closed per-kind details, incl. Windows terminal kinds |
| `rotate-request.schema.json` / `rotate-response.schema.json` | agent ↔ center | key rotation |
| `agent-config.schema.json` | center → agent | pulled agent configuration (class-specific switches, expected tags, bounded route bindings) |
| `ack.schema.json` / `error.schema.json` | center → agent | acknowledgement (nullable `next_seq`) / closed error |
| `negative-vectors.v1.json` | — | behavioural HTTP/recovery/isolation negative contract (67 cases; rev-4 superseded expectations retained) |
| `test-vectors.v1.json` | — | signed positive/negative vectors (rev-5) |
| `examples/` | — | positive bodies (incl. `terminal-snapshot.v1.json`) and negative examples |

HTTP headers (identity, sequence, nonce, signature, content encoding, token) are
part of the protocol, not JSON Schema fields; doc 04 §2–§3 is normative.

## Conventions

- JSON Schema draft 2020-12; `additionalProperties: false` everywhere.
- Base64url without padding; lowercase hex; epoch seconds UTC.
- `boot_gen`/`seq` are canonical decimals in `[1, 9223372036854775806]`, validated
  before signed-64-bit conversion and stored as SQLite INTEGER; `next_seq` is
  nullable only on generation exhaustion. No leading zeros, `+`, whitespace or
  uint64 wrap.
- Missing metrics are `null`, not `0`; availability status is explicit; service/
  protocol state may be `unknown`; no fabricated healthy state.
- **Node classes**: `linux_vps` reports base snapshot/metrics/events and must not
  send `terminal`; `windows_terminal` sends a snapshot with `terminal` and
  Windows event kinds only (metrics deferred in v1). Class/event are bound by the
  admin-issued enrollment token scope, not self-asserted.
- **Windows route tokens** are exactly `a_reality`, `a_hy2`, `b_reality`,
  `b_hy2`, `direct`, `unknown` (aligned with the existing `windowsobs` role
  enum). No proxy names/targets/IPs/YAML/credentials. Unmapped/ambiguous paths
  are `unknown`, never `direct`; `direct` requires an explicit operator-local
  binding on the Windows host (agent-enforced; local names are never sent to the
  center).
- Size caps: compressed ≤256 KiB, decoded ≤128 KiB, enroll ≤8 KiB; center rejects
  before parsing.
- Historical vectors and expectations are retained for traceability; they are not
  current positives (see `historical_rev4_enroll_vector`,
  `superseded_rev4_expectations`).

## Signed vectors

- `report_vector` (rev-4 retained, still valid): body
  `examples/report-snapshot.v1.json`; signing string
  `um-v1\nreport\nPOST\n/v1/agent/report\n1\n<node>\n<key>\n<boot-gen>\n<boot-id>\n<seq>\n<sent>\n<nonce>\n<encoding>\n<sha256(body)>`.
- `windows_terminal_report_vector` (rev-5): body
  `examples/terminal-snapshot.v1.json`, six-token terminal object, independent
  selection/connection sampling, Ed25519 signature over the same 15-line node
  string.
- `enroll_vector` (rev-5): body `examples/enroll-request.v1.json` with
  `node_class`, signing string `um-enroll-v1\nPOST\n/v1/agent/enroll\n1\n<encoding>\n<pubkey>\n<sent>\n<nonce>\n<sha256(body)>`.
- `rotate_vector` / `config_vector` (rev-5): positive node-auth vectors for the
  rotate body and the fixed two-byte `{}` config request.
- `negative_crypto_vectors`: tampered body (Linux and Windows terminal), wrong key,
  cross-endpoint reuse, boot-generation tamper, rotate body tamper.
- `negative-vectors.v1.json`: enrollment token/scope/class, header duplication/
  missing/encoding/config-body, nonce/report/boot/sequence conflicts, bounded
  generation gaps and first-contact `seq>1`, numeric maximum/exhaustion, rotate
  retry full-validation/stale/sequence conflict, platform isolation, six-token
  sum/sampling/route-binding/privacy negatives, size caps, rotation grace, and
  listener-plane separation.

Verification (from the repository root; OpenSSL ≥3, synthetic keys only):

```bash
cd docs/um/contracts/v1
# Rebuild each signing string from the vector fields (LF, no trailing newline),
# verify Ed25519 with the committed public key, and confirm negative vectors fail.
# Private keys are not committed; the vectors contain public key + signature only.
```

UM-B1 owns the automated conformance harness; it must execute these vectors and
the behavioural cases, not merely parse JSON. Any change to headers, signing
strings, endpoint semantics, numeric bounds, dedupe/sequence/rotation rules,
enums, node classes or vectors is a frozen-contract revision requiring independent
review **before** implementation.

## Privacy rule

Examples contain synthetic values only. Real UUIDs, passwords, private keys,
tokens, full private YAML, client identifiers, proxy names, route mappings or
source IPs must never be committed here or in CI.
