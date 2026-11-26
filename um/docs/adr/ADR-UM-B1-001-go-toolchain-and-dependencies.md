# ADR-UM-B1-001 — Go toolchain and dependency policy for UM-B1

- Status: **Accepted for the UM-B1 Draft PR** (implementation-stage ADR); does
  not authorize deployment or production use.
- Scope: `um/` Go module only. Existing workflows/product code are untouched.
- Related contract: PR #126 rev-5 (`docs/um/contracts/v1/**`).

## Decision

### Toolchain

- Minimum/locked language version: `go 1.27.0` in `um/go.mod`.
- CI pins Go `1.27.x` with `actions/setup-go@v5` and uses
  `GOTOOLCHAIN=local` so the CI cannot silently download another toolchain.
- Local development may use a newer Go (the repository workspace currently has
  Go 1.27.x) but must keep the module go directive and CI-pinned version
  compatible. Any bump is a separate reviewed change.
- `-trimpath` is required for builds; CI records the Go version in the job log.

### Dependencies (pinned, checksum-locked)

| Module | Version | Why | Rejected alternative |
| --- | --- | --- | --- |
| `modernc.org/sqlite` | `v1.38.2` | Pure-Go SQLite, no cgo, works on Linux + Windows runners; supports WAL and `synchronous=FULL`; the contract requires SQLite. | `mattn/go-sqlite3` needs cgo/C toolchain on Windows; other bindings add a larger binary/ABI surface; no pure-Go stdlib SQLite exists. |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | Real JSON Schema 2020-12 validation of the frozen schemas; small dependency tree. | A hand-written partial validator would masquerade as conformance (forbidden by the UM-B1 acceptance criteria); JSON-parse-only validation is not schema validation. |
| `golang.org/x/vuln` (`govulncheck`) | tool `v1.10.0` (CI only, not a runtime dependency) | Dependency vulnerability audit. | Trusting `go.sum` without a vulnerability scan. |

Transitive modules are pinned by `um/go.sum`; `go mod verify` and
`go list -m all` are part of CI. No unpinned/latest installs are allowed except
the explicitly pinned `govulncheck@v1.1.4` tool. Any new direct dependency needs
a new ADR, license review, `go.sum` update and independent review.

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
- CI must trigger when `docs/um/contracts/v1/**` changes; otherwise a contract
  update could break protocol tests without any Go CI signal.
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
