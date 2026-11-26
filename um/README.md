# Unified Monitor Go development

This directory is the Unified Monitor Go module (`github.com/yikkrrtykj/install-singboxhysteria2/um`).
It currently contains the **UM-B1 Draft PR** foundation: the shared rev-5 wire
signing primitives, the pure recovery state machine, the SQLite data layer,
contract conformance tests and the experimental Windows observer prototype.

**Status: Draft PR / design-and-code review only.** Not production code, not a
service, not connected to any center or production system. UM-B2..UM-E are not
started; UM-F is deferred; production is HOLD. The Windows observer/CLI remain
experimental and are not wired into a service or deployment.

## Layout

| Path | Purpose |
| --- | --- |
| `internal/wire` | Rev-5 canonical signing strings, Ed25519 sign/verify, canonical numeric bounds, request fingerprint, typed field errors. Reads the frozen vectors from `docs/um/contracts/v1`. |
| `internal/protocol` | Pure A-1..A-5 recovery/ordering state machine (generation gaps, first-contact `seq>1`, ACK exhaustion, rotation retry ordering). No I/O. |
| `internal/store` | SQLite (WAL, `synchronous=FULL`, per-connection DSN PRAGMAs) schema/migrations; STRICT bounded protocol numerics; transactional boot/seq high-water; B2-safe `Tx` nonce/report/seq API; immutable effective-dated route mappings; basic security-ledger chain and retention basics. |
| `internal/schema` | Real JSON Schema 2020-12 validation of the frozen `docs/um/contracts/v1` files (not JSON parsing only), plus strict duplicate-key/trailing-data rejection. |
| `internal/contract` | Platform isolation, Linux/Windows availability semantics (Windows `system` optional), terminal-config presence, temporal metric/event checks, and path-aware privacy scanning. |
| `internal/windowsobs` | Experimental read-only Windows Mihomo route observer (prototype; not a service, not in the B1 acceptance path). |
| `cmd/um-windows-observe` | One-shot experimental observer CLI. |
| `docs/adr` | UM-B1 dependency/toolchain ADR. |

## Testing

From this directory:

```bash
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...   # Linux only; race detector needs cgo
go build -trimpath ./...
```

Tests read the frozen contract files at `../docs/um/contracts/v1/**` and the
normative REC fixture `../docs/um/um-127/conformance/transport-recovery.cases.json`
(repository path; not copied). Contract/REC changes must trigger Go CI. The
dependency/toolchain policy is
`docs/adr/ADR-UM-B1-001-go-toolchain-and-dependencies.md`: Go `1.27.4` is pinned
exactly, dependencies are pinned and checksum-locked, and CI runs
`govulncheck@v1.10.0` distinguishing called from module-only advisories.

The B1 execution count is **11 REC cases executed**; REC-29 is deferred in whole
to UM-B2 and is not claimed as a partial PASS. See
`docs/um-b1-conformance-map.md` for the full REC mapping, the mapping/clarification
notes and deferred retention/ledger ownership.

## Windows snapshot (experimental)

Build from this directory with `go build ./cmd/um-windows-observe`. Run the EXE
as the current user with `-profile <json>` and, if the loopback controller
requires authentication, `-secret-file <local-file>`. Store both files in a
private directory. Put only the controller secret on the first line of the
secret file.

Example local profile with synthetic node names:

```json
{
  "controller": "http://127.0.0.1:9090",
  "group": "EVENT",
  "routes": {
    "a_reality": "vps-a-reality",
    "a_hy2": "vps-a-hy2",
    "b_reality": "vps-b-reality",
    "b_hy2": "vps-b-hy2"
  }
}
```

- `selection` records the mapped leaf selected by the named group, including
  nested groups.
- `active_connections` counts currently open connections whose chain includes
  the named group. Active connections can remain on the prior route after a
  selection changes. Chains with absent or ambiguous configured roles count as
  unknown. The command treats Mihomo's empty list and null as observed zero and
  reports a missing or malformed response as unknown. The two views are
  sampled in separate requests.
- The command reads only `GET /proxies` and `GET /connections` at a literal
  loopback IP. Output contains timestamps, states and configured role codes.
  Local proxy names, destinations, connection IDs and the controller secret
  are excluded from the JSON output.

The rev-5 contract adds `direct`/`unknown` to the existing four role tokens and
defines the terminal snapshot/event bodies. The observer remains an
experimental component; UM-B3 owns any service integration, R2/R1 source
decision and real Mihomo/Clash Verge Rev validation. The controller credential
is write-capable in general; a GET-only client is not an authorization proof.

## Shared wire signing (rev-5)

The signing package is exercised against the frozen rev-5 vectors in
[`docs/um/contracts/v1`](../docs/um/contracts/v1). It covers:

- enrollment signing string (unchanged) and node-auth 15-line signing string
  with `X-UM-Boot-Gen`;
- canonical decimal bounds (`1..2^63-2`), refusal of leading zeros/overflows;
- request fingerprint (endpoint/method/path/key/boot/seq/sent-at/encoding/body hash);
- typed field errors and a sign/verify round-trip.

HTTP ingestion, identity registration, revocation and replay state belong to
UM-B2; this module does not expose a listener. The store exposes a `WithTx` /
`ApplyTransport(*Tx)` transaction boundary for B2; callbacks must use the safe
`Tx` methods and never call public Store methods that open a second transaction.
The hash-chain ledger is basic tamper evidence only: it is not a signed
checkpoint, has no offsite recovery/tail-truncation protection, and `VerifyChain`
must not be used as recovery authorization.

## Migration order

Build the unified center and Linux and Windows agents in Go. Continue to use
Shell for installation and systemd orchestration. Version Windows telemetry
before connecting it to the center and validate its privacy, freshness and
delivery behavior with two synthetic events. Validate Windows collection on
the target Clash Verge Rev and Mihomo builds before packaging it as a service.

For future installer changes, start with read-only configuration validation,
generation and preview that can be compared against historical exports.
Replace configuration writes only after the replacement demonstrates the same
lock, recovery, reload and rollback behavior through all existing entry points.

Web management is a planned phase. Begin with a typed client-create operation
with explicit event and node scope, node-side authorization, an operation
receipt and retry and failure semantics. Reuse the existing configuration
transaction boundary for committing writes. Device disable and configuration
apply each need their own permissions and post-apply checks.
