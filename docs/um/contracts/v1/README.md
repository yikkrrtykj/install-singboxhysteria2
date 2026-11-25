# UM contracts v1 (revision 3 final)

Frozen machine-readable contracts for Unified Monitor node protocol v1.
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
authorization disables the source (Mihomo disabled in v1); `agent-config` carries
`expected_inbound_tags` for runtime tag/kind validation. Final corrections add the
signed monotonic `X-UM-Boot-Gen` boot generation with `stale_boot_generation` /
`boot_identity_conflict`, closed rotation-retry/boot recovery cases, and expand
the behavioural contract to 45 cases; the report test vector was re-signed with
the boot-generation field and a boot-generation-tamper negative was added.

## Files

| File | Direction | Content |
| --- | --- | --- |
| `enroll-request.schema.json` | agent → center | signed-header enrollment body |
| `enroll-response.schema.json` | center → agent | identity/config assignment |
| `report-snapshot.schema.json` | agent → center | latest state (upsert, newer `collected_at` only) |
| `report-metrics.schema.json` | agent → center | bounded minute samples (nullable unknowns) |
| `report-events.schema.json` | agent → center | bounded events with closed per-kind details |
| `rotate-request.schema.json` / `rotate-response.schema.json` | agent ↔ center | key rotation |
| `agent-config.schema.json` | center → agent | pulled agent configuration |
| `ack.schema.json` / `error.schema.json` | center → agent | acknowledgement / closed error |
| `negative-vectors.v1.json` | — | behavioural HTTP negative contract |
| `test-vectors.v1.json` | — | signed positive/negative vectors (report + enrollment) |
| `examples/` | — | positive bodies + schema-negative examples |

HTTP headers (identity, sequence, nonce, signature, content encoding, token) are
part of the protocol, not JSON Schema fields; doc 04 §2–§3 is normative.

## Conventions

- JSON Schema draft 2020-12; `additionalProperties: false` everywhere except none
  in v1 (details are per-kind closed schemas).
- Base64url without padding; lowercase hex; epoch seconds UTC.
- Missing metrics are `null`, not `0`; availability status is explicit; service/
  protocol state may be `unknown`; no fabricated healthy state.
- Closed enums reject unknown values; `agent_error.detail.code` is a closed enum,
  never free text.
- Size caps: compressed ≤256 KiB, decoded ≤128 KiB, enroll ≤8 KiB; center rejects
  before parsing.

## Signed vectors

- `report_vector`: body `examples/report-snapshot.v1.json`; signing string
  `um-v1\nreport\nPOST\n/v1/agent/report\n1\n<node>\n<key>\n<boot>\n<seq>\n<sent>\n<nonce>\n<encoding>\n<sha256(body)>`;
  Ed25519 signature over its exact UTF-8 bytes.
- `enroll_vector`: body `examples/enroll-request.v1.json`; signing string
  `um-enroll-v1\nPOST\n/v1/agent/enroll\n1\n<encoding>\n<pubkey>\n<sent>\n<nonce>\n<sha256(body)>`.
- `negative_crypto_vectors`: tampered body, wrong key, cross-endpoint reuse — each
  must fail verification/return the frozen error.
- `negative-vectors.v1.json`: token expiry/reuse, duplicate/missing headers,
  encoding ambiguity, nonce/report/boot/sequence conflicts, size caps, rotation
  grace, listener-plane separation.

Verification (from the repository root; OpenSSL ≥3, synthetic keys only):

```bash
cd docs/um/contracts/v1
sha256sum examples/report-snapshot.v1.json examples/enroll-request.v1.json
# rebuild each signing string from the vector fields (LF, no trailing newline),
# verify Ed25519 with the committed public key, and confirm negative vectors fail.
# Private keys are not committed; the vectors contain public key + signature only.
```

Any change to headers, signing strings, endpoint semantics, dedupe/sequence rules,
enums or vectors is a frozen-contract revision requiring independent review
**before** implementation.

## Privacy rule

Examples contain synthetic values only. Real UUIDs, passwords, private keys,
tokens, full private YAML, client identifiers or source IPs must never be
committed here or in CI.
