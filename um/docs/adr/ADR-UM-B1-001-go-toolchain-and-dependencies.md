# ADR-UM-B1-001 — Go toolchain and dependency policy for UM-B1

- Status: **Accepted for the UM-B1 Draft PR** (implementation-stage ADR); does
  not authorize deployment or production use.
- Scope: `um/` Go module only. Existing workflows/product code are untouched.
- Related contract: PR #126 rev-5 (`docs/um/contracts/v1/**`).

## Decision

### Toolchain

- Minimum/locked language version: `go 1.27.4` in `um/go.mod`.
- CI pins the exact toolchain patch `1.27.4` with `actions/setup-go@v5` and uses
  `GOTOOLCHAIN=local` so the CI cannot silently download another toolchain.
- Local development may use the same `go 1.27.4` toolchain. Any patch/minor bump is
  a separate reviewed change; go.mod, CI and this ADR must move together.
- `-trimpath` is required for builds; CI records the Go version in the job log.

### Dependencies (pinned, checksum-locked)

| Module | Version | Why | Rejected alternative |
| --- | --- | --- | --- |
| `modernc.org/sqlite` | `v1.38.2` | Pure-Go SQLite, no cgo, works on Linux + Windows runners; supports WAL and `synchronous=FULL`; the contract requires SQLite. | `mattn/go-sqlite3` needs cgo/C toolchain on Windows; other bindings add a larger binary/ABI surface; no pure-Go stdlib SQLite exists. |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | Real JSON Schema 2020-12 validation of the frozen schemas; small dependency tree. | A hand-written partial validator would masquerade as conformance (forbidden by the UM-B1 acceptance criteria); JSON-parse-only validation is not schema validation. |
| `golang.org/x/vuln` (`govulncheck`) | tool `v1.10.0` (CI only, not a runtime dependency) | Dependency vulnerability audit. | Trusting `go.sum` without a vulnerability scan. |

Transitive modules are pinned by `um/go.sum`; `go mod verify` and
`go list -m all` are part of CI. No unpinned/latest installs are allowed except
the explicitly pinned `govulncheck@v1.10.0` tool. Any new direct dependency needs
a new ADR, license review, `go.sum` update and independent review.

### Vulnerability audit policy

CI runs pinned `govulncheck@v1.10.0` (older v1.1.4 panicked under the Go 1.27 SSA
builder). The report MUST distinguish **called** vulnerabilities (blocking) from
module/package-only advisories not reachable from this code (recorded, not
silently treated as clean). At review time the result is 0 called
vulnerabilities and 3 module/package advisories not reachable from UM-B1 code.
The initial red logs (Go 1.23.12/1.24.13/1.25.14 stdlib advisories, then the tool
panic) are retained as evidence; the fix was a toolchain/tool pin, never a
skipped check.

### GOPROXY policy

The previous prototype workflow used `GOPROXY=off` because it had zero
dependencies. UM-B1 needs the two pinned modules above, so the workflow
explicitly sets:

```yaml
env:
  GOPROXY: 'https://proxy.golang.org,direct'
  GOSUMDB: 'sum.golang.org'
  GOTOOLCHAIN: 'local'
```

This is a **visible, reviewed change** in `um-go.yml`, not a silent relaxation:
the module graph is fully pinned by `go.mod`/`go.sum`, `go mod verify` fails
closed on checksum mismatch, and CI runs `govulncheck`. If the environment
requires an internal proxy/mirror, it must be configured explicitly by the
owner in a separate change.

### Contract files and test coupling

- Tests read the frozen contract files from the repository path
  `docs/um/contracts/v1/**`; schemas and vectors are **not copied** into `um/`
  (a copy would drift and is forbidden by the UM-G/UM-B reuse rules).
- CI must trigger when `docs/um/contracts/v1/**` or the normative REC fixture
  `docs/um/um-127/conformance/**` changes; otherwise a contract/REC update could
  break protocol tests without any Go CI signal.
- The rev-5 vectors are the single source of truth; rev-4 history is read only
  through the explicit `historical_rev4_*`/`superseded_rev4_expectations`
  entries.

### Build/test matrix

- Ubuntu 24.04 and Windows 2022: `go build -trimpath ./...`, `go vet ./...`,
  `go test -count=1 ./...`.
- Linux only: `go test -race -count=1 ./...` (requires cgo/C toolchain for the
  race detector; the SQLite driver itself is pure Go).
- Coverage: `go test -coverprofile` on Linux with an uploaded artifact.
- Independent jobs for `govulncheck`; no existing workflow is modified.

## Consequences

- UM-B1 is the first Go code on `main`; the module stays self-contained under
  `um/` and does not touch `monitor-v2`, `sbox-cm`, HA-UI or the frozen #67
  contract.
- The Windows observer/CLI remain experimental and are not wired into a service
  or production path in UM-B1.
- Any dependency or toolchain change after merge needs this ADR to be revised
  and reviewed.


## SQLite / schema decisions (P1-01)

- Migrations are append-only. Version 1 is the original B1 schema; version 2
  rebuilds `node_boot`, `seq_dedupe` and `boot_registry` as STRICT tables with
  explicit `typeof(...)='integer'` and range CHECKs, preserves legacy v1 rows,
  and fails closed if a legacy row violates the frozen bounds. A database whose
  `schema_migrations` version is newer than this build is rejected before any
  migration runs.
- SQLite's legal lossless TEXT→INTEGER conversion is accepted, but the stored
  `typeof` value is asserted to be `integer`. Fractional REAL, non-numeric TEXT,
  negative, BLOB and out-of-range values are rejected by raw-SQL negative tests.
  `MAX_NUMERIC` remains 2^63−2.

## Contract-clarification proposals

`um/docs/um-b1-conformance-map.md` records the conservative mapping semantics
(no backdating/duplicate effective time, future versions allowed, empty/subset
version = unmapped, direct/unknown never mapped) and the ledger/retention
ownership statements. These are implementation clarifications for review; the
frozen rev-5 contract files are not edited.
