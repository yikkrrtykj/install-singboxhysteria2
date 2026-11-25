# UM contracts v1

Frozen machine-readable contracts for Unified Monitor node protocol v1.
Normative prose: [`../../um-a/04-node-protocol-v1.md`](../../um-a/04-node-protocol-v1.md).

## Files

| File | Direction | Content |
| --- | --- | --- |
| `enroll-request.schema.json` | agent → center | signed enrollment body |
| `enroll-response.schema.json` | center → agent | identity/config assignment |
| `report-snapshot.schema.json` | agent → center | latest state (upsert) |
| `report-metrics.schema.json` | agent → center | bounded minute samples |
| `report-events.schema.json` | agent → center | bounded fault/agent events |
| `rotate-request.schema.json` | agent → center | key rotation body |
| `agent-config.schema.json` | center → agent | pulled agent configuration |
| `ack.schema.json` | center → agent | report acknowledgement |
| `error.schema.json` | center → agent | closed error body |
| `examples/report-snapshot.v1.json` | — | exact bytes used by the signed test vector |
| `test-vectors.v1.json` | — | signing string, public key, signature, hashes |

HTTP headers (identity, sequence, nonce, signature) are part of the protocol but
are not represented in JSON Schema; doc 04 §3 is normative.

## Conventions

- JSON Schema draft 2020-12; objects are `additionalProperties: false` except
  `detail` maps explicitly marked as extensible.
- All byte fields are base64url without padding; hex fields are lowercase hex.
- Timestamps are integer Unix seconds (UTC).
- Byte counters are cumulative non-negative integers; center derives deltas and
  handles counter-epoch changes.
- Closed enums reject unknown values; agents must not send them.
- Limits are enforced by the center before parsing (HTTP body caps) and again by
  schema/bounds validation.

## Signed test vector verification

The committed example body is signed with an ephemeral test key; the private key
is **not** committed. Verification (from the repository root, OpenSSL ≥3):

```bash
cd docs/um/contracts/v1
# 1. body hash must match test-vectors.v1.json
sha256sum examples/report-snapshot.v1.json
# 2. reconstruct the signing string from the vector fields, byte-exact with LF
#    separators and no trailing newline, then verify with the committed pubkey.
#    (Any Ed25519 library/CLI may be used; the vector also fixes the signing
#     string itself, so implementations can compare strings directly.)
```

The vector records: body file + byte length + SHA-256, signing string, Ed25519
public key (base64url raw 32 bytes) and signature. A conforming implementation
must reproduce the same signature input and verify successfully; a tampered body
must fail.

## Change control

Any change to a schema, the signing string, header grammar, body `type` names or
closed enum tokens is a frozen-contract change: it requires a UM-A revision,
threat-model impact, compatibility statement, updated vector and independent
review **before** implementation. Additive optional fields are allowed only for
objects documented as extensible and require the same review before UM-B ships
them.

## Privacy rule for all committed material

Examples and vectors contain synthetic values only. Real UUIDs, passwords,
private keys, tokens, full private YAML, client identifiers or source IPs must
never be committed here or in CI.
