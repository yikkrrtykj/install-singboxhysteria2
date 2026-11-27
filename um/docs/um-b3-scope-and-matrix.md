# UM-B3 agent delivery — scope, write boundaries and acceptance matrix (Draft)

- Status: **UM-B3 Draft PR only.** Not merged, not reviewed as accepted, not
  deployed, not production. No production credentials, hosts, services or
  Cloudflare/VPS resources were created, installed or enabled for this work.
- Base: `main` **54efc81c** (B2 merged, PR #130). Branch: `codex/um-b3-agents`.
- Frozen contract: UM-A revision 5, `docs/um/um-a/04-node-protocol-v1.md` and
  `docs/um/contracts/v1/**` (PR #126 HEAD `048fc170`). This Draft **does not
  change** any frozen contract file, schema, vector or REC fixture.
- Planning inputs: `docs/um/um-127/04-implementation-plan.md`,
  `docs/um/um-127/05-owner-decisions.md` (OD-P3 R2-first / R1 not authorized;
  OD-P7 pending), `docs/um/um-127/02-dual-platform-contract.md`,
  `docs/um/um-127/03-recovery-semantics.md`.
- Dependency note: the B3 code slice promotes the already-present indirect
  `golang.org/x/sys v0.34.0` to a direct dependency for the Windows SCM wrapper
  (`windows/svc`); the version and `go.sum` entries are unchanged. No other new
  dependency was added. DPAPI uses stdlib `syscall`/`crypt32`.
- This file is the status map for the B3 Draft. It reports only evidence that
  exists in this Draft or on the B2 baseline; real-environment and
  production-level claims are explicitly **not** made (see §7).

## 1. Scope of UM-B3

UM-B3 delivers the node side of the platform: one shared Go agent runtime for
both node classes, the Linux read-only collectors, the Windows terminal
collector after the R2 evaluation, durable spool/recovery behavior, and
isolated installation/service assets plus operator runbook/ADRs.

| Slice | Deliverable | Contract / plan reference |
| --- | --- | --- |
| **B3.1** | Shared agent runtime: Ed25519 identity + enrollment (`--token-stdin`), atomic fsync boot state (generation/boot id/seq), single-instance lock, report spool (32 MiB / 7 d, fsync-before-send, quarantine, oldest-first replay), 1→60 s bounded retry, ACK `next_seq` adoption / `null` exhaustion, rotation intent recovery, fail-closed config, one signing/transport state machine | `04` §5–§7, §11, §13; REC-01..30 agent-side rows; `06` SEC-21/31/32/33 |
| **B3.2** | Linux `linux_vps` agent: `/proc` system counters, read-only systemd D-Bus `ActiveState`, authorization-gated sing-box `service.api` (default off), honest UNKNOWN/UNAVAILABLE data, no exec/root/listener; systemd unit + one-shot installer templates | `04` §9.1, §11; `03` §11; `06` SEC-31..33, SEC-39 |
| **B3.3** | Windows `windows_terminal` agent: contractized six-token `windowsobs` projection (`a_reality`, `a_hy2`, `b_reality`, `b_hy2`, `direct`, `unknown`), independent selection/connection sampling, route binding stays operator-local, honesty rules, R2-first source research, R1 never auto-enabled; Windows service install template | `04` §9.1–§9.2, §11; `02` §2–§4; `06` SEC-42..47 |
| **B3.4** | Delivery docs and isolated deploy/run assets: this scope/matrix, architecture, OD-P7 credentials ADR proposal, OD-P3 Windows sources ADR/research plan, runbook, Linux unit/installer, Windows service installer template | `04-implementation-plan` §6 UM-B3; `07` §5; this file |

Out of scope for UM-B3 (and for this Draft):

- UM-B4 admin API/CLI; UM-C public web entry/authentication; UM-D dashboard;
  UM-E security/deployment/load/backup acceptance; UM-F remote write (DEFERRED).
- Any frozen-contract change (headers, signing strings, endpoints, enums,
  numeric bounds, dedupe/rotation rules, schemas, vectors, REC expectations).
- Production deployment, packaging release, credentials, VPS/Cloudflare
  resources, enabling real services, or touching existing production systems.
- Any center→node command channel or remote write path.

## 2. File and write boundaries

**This documentation/deployment slice creates only new files** and modifies
nothing that exists:

```text
um/docs/um-b3-scope-and-matrix.md
um/docs/um-b3-architecture.md
um/docs/um-b3-adr-credentials.md
um/docs/um-b3-adr-windows-sources.md
um/docs/um-b3-runbook.md
um/deploy/linux/um-agent.service
um/deploy/linux/um-agent-noexec.conf
um/deploy/linux/install-agent.sh
um/deploy/windows/install-agent-service.ps1
```

**Must not be modified by this slice:** any existing file, in particular
`docs/um/**` (frozen contract/schemas/vectors/REC), `um/internal/**`,
`um/cmd/um-center`, `.github/workflows/**`, `install.sh`,
`monitor-v2/**`, `sbox-cm/**`, `ha-ui/**`, `windows/**`, `tools/**` and all other
modules. B3 agent implementation code that lands in the same Draft PR is
tracked by its own diff and must also not change frozen contract files.

Reused assets (no second implementation is created):

| Asset | Reused as | Constraint |
| --- | --- | --- |
| `um/internal/wire` | **only** signing/verification, canonical header grammar, `MAX_NUMERIC`/`MAX_BOOT_GAP`, request fingerprint | no second signer, no copied signing string, rev-5 only |
| `um/internal/protocol` | A-1..A-5 reference semantics (center side) | agent mirrors the rules but does not create a competing contract |
| `docs/um/contracts/v1/**` + REC fixture | normative schemas/vectors/REC-01..30 | read only, unchanged |
| `um/internal/windowsobs` | existing four-role enum, loopback-only `GET /proxies`/`GET /connections`, privacy-minimized output | extended to the frozen six tokens; no duplicate role enum; still not the Linux source |
| `um/internal/contract` | platform isolation / availability/privacy validators (center side) | agent must produce bodies that pass them; no weakened validation |
| B2 center (`um/internal/center`, `um/internal/store`) | enrollment/report/config/rotate semantics and HTTP/SQLite evidence | unchanged; agent must satisfy them |
| Existing per-VPS Monitor (`monitor-v2`) | **none at runtime** | read-only coexistence only; no config/permission/service change |
| `sing-box service.api`, systemd D-Bus, `/proc` | reviewed read-only local surfaces | authorization-gated, never root, never exec |

## 3. Conformance and recovery ownership

The 30-recovery-case fixture is owned jointly; B3 must not re-claim B2 results.

| REC | B3 responsibility | B3 evidence level expected |
| --- | --- | --- |
| REC-17 | agent boot-state missing/corrupt → **no request**, fail-closed local `boot_state_corrupt`, operator recovery | unit (durable-state harness) |
| REC-18 | agent restored from old snapshot → center `409 stale_boot_generation`; no in-place reset; operator revoke/re-enroll | unit + mocked center |
| REC-27 | agent power-loss edge: committed seq resend → duplicate; unsynced seq never reused | unit/durable-state harness |
| REC-01/02/03/04/06 | agent side of restart/generation increment, first-contact `seq>1`, lost-ACK resend, oldest-first spool replay | unit/mock center |
| REC-10/13 | delayed superseded attempt ignored; ACK `next_seq` adoption | unit/mock center |
| REC-19/20/21 | rotation intent across restarts/expiry; revocation during backlog stops the queue and keeps spool | unit/mock center |
| REC-26 | `MAX_NUMERIC` exhaustion / ACK `next_seq:null` → new generation or operator recovery; never reuse seq | unit |
| REC-30 | interleaved spool replay across generations oldest-first | unit |

B2-owned REC rows (03/04/05/06/10/13/15/16/19/20/21/22/23/24/29/30 real HTTP
halves) remain the B2 results in `docs/um-b2-conformance-map.md`; B3 does not
count them again.

## 4. Acceptance matrix

Status vocabulary — use exactly these words:

- **IMPLEMENTED** — the artifact exists in this Draft and compiles/loads or is a
  reviewed template; it is not by itself a passing test or a real-environment
  proof.
- **MOCK-UNIT PASS** — an automated test in this Draft passes using synthetic
  data, a mock collector or an in-process fake center.
- **INTEGRATION PASS** — a test/check in this Draft passes against a real local
  boundary (real listeners/SQLite/process/filesystem), not a mock.
- **DEFERRED** — belongs to a later slice or needs a lab/real environment that
  is not available in this Draft; not claimed.
- **BLOCKED** — cannot proceed until an Owner decision/authorization or a
  missing external prerequisite exists; do not work around it.

`IMPLEMENTED` never implies production readiness and is never used for a row
whose real-environment verification is the substance of the claim.

| # | Capability | Slice | Contract / plan | Evidence in this Draft | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Ed25519 identity generated on node; private key local only; enrollment signed, `node_class` from build; response class verified | B3.1 | `04` §3–§4, §11 | `um/internal/agent/{state,client,runtime}.go` | IMPLEMENTED |
| 2 | Enrollment token over stdin/pipe as `umagent`; root token file not agent-readable; token deleted by installer after success; no resident root process | B3.1/B3.4 | `04` §4, §11; P1-03 | installer template `um/deploy/linux/install-agent.sh`; runbook | IMPLEMENTED (template; not executed) |
| 3 | Atomic fsync boot state: generation +1 per normal restart, new random boot id, seq persist-before-send; corrupt/missing boot state = fail-closed `boot_state_corrupt` (never reset) | B3.1 | `04` §5, §6.1; REC-17/18/27 | `state.go` (`writeAtomic`, boot validation), `runtime.go` recovery | IMPLEMENTED |
| 4 | Single-agent/single-writer rule (state-directory lock, no two instances per node) | B3.1 | `04` §6.1 | `state.go` lock | IMPLEMENTED |
| 5 | Durable report spool: 32 MiB / 7 d, file+dir fsync before first send, oldest-first, ack-only removal, corrupt/terminal quarantine, age retention at startup, **over-capacity fail-closed (no silent eviction of fsynced records)** | B3.1 | `04` §11, §6.2 | `spool.go` | IMPLEMENTED |
| 6 | ACK adoption: `max(local_next_seq, ack.next_seq)`, `next_seq:null` exhaustion → new generation or operator recovery; no seq reuse/wrap | B3.1 | `04` §5, §13; REC-26 | `runtime.go` `applyAck`/`nextAttempt` | IMPLEMENTED |
| 7 | Retry policy: 1→60 s bounded backoff; 5xx/429/transport retryable; stale_timestamp clock recalibration; non-retryable payload quarantine; auth/sequence/boot/revocation stop the queue | B3.1 | `04` §6.2, §8; REC-10/15/16/21 | `runtime.go` `Drive`, `errors.go` | IMPLEMENTED |
| 8 | Rotation intent recovery: persist nonce/new key before send, restart replay, `rotation_expired` abort path, new-key proof confirmation, revocation wins, no bypass of high-water | B3.1 | `04` §7; REC-19/20/21 | `runtime.go` `Rotate`, state rotation file | IMPLEMENTED |
| 9 | Config pull exactly `{}` on the wire, response validated, class/source allowlist, fail-closed defaults (`collect` switches false), no center push | B3.1 | `04` §7, §9.1 | `client.go`, `runtime.go`; center enforces | IMPLEMENTED |
| 10 | Agent-side privacy: no local names/IPs/URLs/process names/connection ids/credentials/YAML in bodies, logs or state diagnostics; closed error logging | B3.1 | `04` §9.3; `06` SEC-14 extension | collector contract + runtime status (no payload logging); negative tests | IMPLEMENTED + MOCK-UNIT PASS (see §5) |
| 11 | Linux `/proc` read-only system counters (CPU/mem/disk/net), no subprocess, no root; honest UNKNOWN/UNAVAILABLE | B3.2 | `04` §11 | `um/internal/linuxobs/{collector,procfs,system,disk}.go` + synthetic-fixture tests | MOCK-UNIT PASS (synthetic procfs; not a real-host proof) |
| 12 | Linux systemd unit state via read-only D-Bus `ActiveState`; unavailable → UNKNOWN; no `systemctl` exec fallback | B3.2 | `04` §11; P1-03 | `linuxobs.ServiceProbe`/`DBusProbe` interfaces only; honest `ErrProbeUnavailable` default; no raw D-Bus client shipped | DEFERRED (real D-Bus lab absent; source is honestly unavailable) |
| 13 | Linux `singbox_api` disabled by default; server-side authorization audit required before enable; unproven source → honest `unavailable`, no fallback credential | B3.2 | `04` §11 (P1-10); SEC-39 | `linuxobs.SingBoxProbe` fixed read-only GET surface + honest unavailable default; source stays off | DEFERRED (audit absent; source off; the explicit `agent_error code=source_authorization_unproven` event is a recorded gap, see §8 G7) |
| 14 | Linux no-exec/least-privilege runtime: non-root `umagent`, no listener, no exec/root/sudo/shell/systemctl, only own state dir writable; `LoadCredential` for API secrets; source permissions unchanged | B3.2/B3.4 | `04` §11; `03` §11; SEC-31/32/33 | `um-agent.service` + noexec drop-in + runbook | IMPLEMENTED (template); INTEGRATION DEFERRED (systemd lab) |
| 15 | Windows six-token projection of `windowsobs` data; exactly one role enum; independent `selection`/`active_connections` sampling; `direct` only with explicit operator-local binding, otherwise `unknown`/null | B3.3 | `04` §9.2; `02` §2 | `windowsobs` six-token `Role`/`Tokens()` + `windowsagent` collector unit tests | MOCK-UNIT PASS |
| 16 | Windows honesty: availability coherence, sum equality when `ok`, empty list = observed zero, missing/malformed = unknown/unavailable, no fabricated data | B3.3 | `04` §9.2; SEC-33/45 | `windowsagent/collector_test.go` synthetic observer cases | MOCK-UNIT PASS |
| 17 | Windows read-only/HA: no config write, no node switch, no connection close, no HA-UI/P6/#67 change; local proxy names never leave host | B3.3 | `04` §9.2; `02` §4 | loopback-GET-only observer + no-write/HA design tests (synthetic) | MOCK-UNIT PASS; real-build read-only/HA proof DEFERRED (UM-E) |
| 18 | R2 truly read-only Windows source (no controller secret) researched/evaluated; result recorded with build/version evidence | B3.3 | OD-P3; `02` §4; ADR | `um-b3-adr-windows-sources.md` research plan/template | DEFERRED — no real R2 result in this Draft |
| 19 | R1 (write-capable controller credential used by GET-only client) **not enabled**, not called read-only, separate Owner risk acceptance required | B3.3 | OD-P3; `02` §4 | ADR records it; installer/agent default off | BLOCKED (Owner risk acceptance absent) |
| 20 | Windows service install: Owner-approved account, ACL/DPAPI plan, session isolation, no secrets in repo/script/logs, no R1 provisioning | B3.3/B3.4 | OD-P7; ADR | `cmd/um-agent/service_windows.go` SCM lifecycle wrapper; `windowsagent/service_windows.go` DPAPI `SecretProtector` + deferred account/ACL hooks; `install-agent-service.ps1` template; ADR proposal | IMPLEMENTED (SCM wrapper + template/DPAPI helper); real SCM/account/ACL service integration DEFERRED (OD-P7 PENDING; no SCM lab) |
| 21 | Windows service/agent real run on target Clash Verge Rev/Mihomo builds with read-only/HA assertions | B3.3 | `06` SEC-42..47; UM-E | — | DEFERRED (UM-E/real lab) |
| 22 | Linux one-shot installer: root-only install orchestration, non-root runtime user, `/var/lib/um-agent` 0700, unit install, enrollment over pipe, token cleanup, dry-run default, no service start by default, no changes to existing Monitor/sing-box/sbox-cm | B3.4 | `04` §11; P1-03 | `install-agent.sh` | IMPLEMENTED (template; not executed) |
| 23 | Coexistence with existing per-VPS Monitor: no shared unit/port/socket; only read-only duplicate load on loopback sing-box API; existing config/secret/permissions unchanged | B3.4 | Q-COEXIST; `01` §9 | runbook §5 | IMPLEMENTED (documented); real coexistence test DEFERRED |
| 24 | Linux systemd lab proof: `systemd-analyze verify`, unit hardening, no-exec `NoExecPaths=/` on supporting systemd, D-Bus read proof, non-root file access proof | B3.4 | SEC-31/32; `06` §6 | unit + drop-in template only | DEFERRED — real systemd/D-Bus lab not run |
| 25 | Runbook: install/run/upgrade/uninstall/recovery/rollback for both platforms, REC-17/18/27 operator steps, backup/no-secret logging | B3.4 | `07` §5 | `um-b3-runbook.md` | IMPLEMENTED (documentation) |
| 26 | ADR proposals: OD-P7 credentials and OD-P3 Windows sources, status PROPOSED/PENDING OWNER, never APPROVED | B3.4 | 05 §C/F | two ADR files | IMPLEMENTED (proposals only) |
| 27 | Dual-platform CI: existing `um-go.yml` covers `um/**`; agent tests run under the existing lane without weakening; local build/vet/test executed | B3.4 | plan §7 | local `go build ./...`, `go vet ./...`, `go test ./...` (from `um/`); existing CI file unchanged | INTEGRATION PASS for the local full suite (includes B2 real-listener/SQLite tests); GitHub exact-HEAD CI result is recorded on the Draft PR after push |
| 28 | Frozen contract untouched, no second signing/transport state machine, no center/B2 changes | B3.1–B3.4 | plan §2/§6 | diff/write boundaries in §2 | IMPLEMENTED (boundary rule) |
| 29 | CLI entrypoint and platform wiring: `um-agent enroll/run/rotate/status/service/version`, platform collector selection, enrollment token path `--token-stdin` (root-opened pipe) or `--token-file`; Windows SCM lifecycle wrapper (`x/sys/windows/svc`, runs the shared runtime under SCM stop/shutdown) | B3.1/B3.4 | `04` §11; P1-03 | `um/cmd/um-agent/{main,platform_linux,service_windows}.go`; builds and vet clean | IMPLEMENTED (SCM wrapper only; no SCM lab executed → Windows Service integration unverified; account/ACL/DPAPI installation remains OD-P7-gated) |
| 30 | Linux installer syntax/template review; dry-run default; no service start/enable by default; contract-conformant stdin token pipe | B3.4 | P1-03; `04` §11 | `install-agent.sh` (`bash -n` clean); no execution | IMPLEMENTED (template only; not executed) |
| 31 | Windows installer template syntax and safety guards: explicit Owner confirmation, LocalSystem refused, R1/secret provisioning refused, no start by default | B3.4 | OD-P7/P3; `04` §11 | `install-agent-service.ps1` (PowerShell parser clean); no execution | IMPLEMENTED (template only; not executed) |
| 32 | Agent ↔ real center end-to-end: real `um-center` HTTP listeners + real SQLite + the real Linux/Windows collectors, enrollment → config → snapshot report accepted | B3.1/B3.3 | `04` §1–§6; B2 center | `internal/agentintegration/integration_test.go` (`TestLinuxCollectorToRealCenter`, `TestWindowsCollectorToRealCenter`) | INTEGRATION PASS (in-process real center/SQLite; not a public-TLS/real-host deployment) |

## 5. Test/evidence inventory in this Draft

This section is filled from the actual files in the Draft; a missing test name
means the row above stays IMPLEMENTED, never MOCK-UNIT PASS. The local commands
were run from `um/` on the review host at documentation finalization:
`go build ./...` **PASS**, `go vet ./...` **PASS**, `go test -count=1 ./...`
**PASS** (all packages `ok`, including the existing B1/B2 suites and the new B3
packages). This is a local evidence run, not the GitHub CI lane; the PR must
report its own CI result.

- `um/internal/agent` (shared runtime, mock/durable-state tests):
  `TestAgentEnrollConfigReportAndRestart`, `TestAgentBootStateCorruptREC17`,
  `TestAgentStaleGenerationREC18`, `TestAgentACKLossDuplicateREC27`,
  `TestAgentRotationIntentSurvivesRestart`, `TestAgentRevokedFailsClosed`,
  `TestAgentGenerationExhaustion`, `TestAgentCleanRestartReplaysSpoolUnderNewGeneration`, `TestStateAtomicLockAndBootCorruption`,
  `TestSpoolCorruptionQuarantineAndLimits`, `TestUUIDAndNonceShapes`,
  `TestClientURLRules`, `TestControlStateJSONRoundTrip`.
- `um/internal/linuxobs` (synthetic fixtures only; no real host):
  collector/procfs/system/disk/service/singbox projection and safety tests
  including availability honesty, source-switch gating and the honest
  `ErrProbeUnavailable` default. The sing-box client is exercised only against
  `httptest`; it is not validated against live sing-box.
- `um/internal/windowsagent` (synthetic observer, never a real controller):
  `TestNewDefaultsAndInvalidOptions`, `TestSnapshotH1DefaultAbsence`,
  `TestSnapshotSelectionOnlyAuthorization`, `TestSnapshotActiveOnlyAuthorization`,
  `TestSnapshotBothSourcesIndependentSampling`,
  `TestSnapshotUnmappedRouteIsUnknownNotDirect`,
  `TestSnapshotObserverFailureMapping`, `TestSnapshotActiveSanitization`,
  `TestSnapshotNoObserverAuthorized`, `TestSnapshotSampledAtFallback`,
  `TestSnapshotInvalidReportContext`, `TestMetricsUnsupported`,
  `TestEventsContract`, `TestCounterEpoch`, `TestUptimeBounds`,
  `TestSnapshotSixTokenShapeForEveryAvailability`,
  `TestSnapshotDirectBindingEndToEnd`, `TestSnapshotFreeFormObserverValuesNeverLeak`;
  Windows-only `service_windows_test.go` exercises the DPAPI `SecretProtector`
  with synthetic plaintext (no real secret/service/account).
- `um/internal/windowsobs` (mock loopback controller): six frozen tokens,
  direct-only-with-explicit-binding, unknown-not-bindable, ambiguous chain
  unknown, independent sampling, failure reasons, literal-loopback/no-redirect,
  oversize handling.
- `um/internal/agentintegration` (in-process **real** boundary): real
  `internal/center` service + real SQLite + real HTTP listeners, with the real
  Linux/Windows collector implementations; enrollment → config pull → snapshot
  report accepted:
  `TestLinuxCollectorToRealCenter`, `TestWindowsCollectorToRealCenter`. This is
  INTEGRATION PASS for the agent/center boundary, not a public-TLS deployment
  or a real VPS/terminal source proof.
- `um/cmd/um-agent`: builds and vets; no test file (the CLI is thin and the
  Windows SCM wrapper is compiled/smoke-built only — no SCM lab was executed,
  so Windows Service integration is not PASS).
- Local syntax checks for deploy templates: `bash -n` on
  `um/deploy/linux/install-agent.sh` PASS; PowerShell parser on
  `um/deploy/windows/install-agent-service.ps1` PASS. Neither script was
  executed; no service was installed/started and no credential was created.
- B2 regression: the same local `go test ./...` run keeps
  `internal/center`, `internal/store`, `internal/conformance`,
  `internal/protocol`, `internal/schema`, `internal/contract` and
  `internal/wire` green; this is not re-claimed as new B3 evidence.
- Not executed: Linux `-race` lane, GitHub CI jobs, systemd/D-Bus lab,
  Windows Service lab, real center over public TLS, real Clash Verge
  Rev/Mihomo, R2/R1 source, production. These stay DEFERRED/BLOCKED in §4.

## 6. Review/merge gates (unchanged; this Draft does not grant them)

| Gate | State |
| --- | --- |
| Independent review of the B3 Draft PR | not requested/not passed |
| Owner approval per slice (OD-G5) | HOLD |
| Owner decisions OD-P3 (R2/R1) and OD-P7 (account/secrets) | **PENDING** |
| Merge authorization / normal merge commit | not granted |
| Production deployment/release/credentials | HOLD (UM-E + separate authorization) |
| R1 enablement | **not authorized**; never auto-enabled |
| Existing systems (#33/#67/Monitor/HA-UI) | unchanged |

## 7. Explicitly not verified (do not read as PASS)

1. **Real R2 source** — no real Clash Verge Rev/Mihomo build was inspected;
   the R2 research plan/results template is empty and remains DEFERRED.
2. **R1** — not authorized, not enabled, no credential exists; the agent never
   describes a write-capable controller credential as read-only.
3. **Windows final service account / DPAPI / ACL** — OD-P7 is PENDING; the
   Windows installer is a template that refuses to proceed without explicit
   Owner confirmation, and it creates no secret.
4. **Real systemd/D-Bus lab** — no host service was installed or started; the
   unit, no-exec drop-in, non-root file-access and D-Bus read behavior were not
   executed in a lab.
5. **Real sing-box `service.api` authorization audit** — absent; the Linux
   source remains disabled/`unavailable` by design.
6. **Real Windows read-only/HA proof**, real agent-to-center over public TLS,
   real enrollment with a center token, real service account, real clock skew,
   power-loss/power-fail durability on target hardware — all DEFERRED.
7. **Production, UM-E acceptance, load/capacity, backup/restore, offsite
   ledger, independent security review** — not started (UM-E/HOLD).
8. **CI on the Draft PR** — local build/tests only; the GitHub lane has not
   been reported for this Draft at the time of writing.

## 8. Known gaps and follow-ups

- G1: Windows collector must prove the six-token projection against the real
  `windowsobs` contract (single enum, no A/B collapse); only mock evidence
  exists now.
- G2: `NoExecPaths=/` requires systemd ≥ 254 and a start test; Debian 12
  (systemd 252) cannot enforce it with that directive. The installer installs
  the drop-in only on supporting versions; the gap must be recorded in UM-E
  acceptance. Blocking `execve`/`execveat` directly in `SystemCallFilter=`
  would prevent the unit's own startup (systemd applies the filter before the
  service-binary exec) and is **not** used as a fake proof.
- G3: Windows event log/state ACL and DPAPI scope need the OD-P7 decision;
  template defaults must not be read as the decision.
- G4: Linux real D-Bus/systemd state read and `/proc` sampling were not run on
  a target VPS; only synthetic fixtures.
- G5: operator recovery (boot-state loss, revoked key, rotation mismatch) is
  documented but not drilled on a real node (UM-E drill).
- G6: R2 research and the OD-P3/OD-P7 Owner answers are prerequisites for any
  Windows source enablement; no agent code path may be enabled before them.
- G7: Linux `singbox_api` gating currently produces honest `unavailable`
  availability when the source is disabled, but the contract's explicit
  `agent_error code=source_authorization_unproven` event is not demonstrated
  for Linux in this Draft; P1-10 also requires the versioned server-side
  authorization audit before any enablement (absent).
- G8: Windows SCM lifecycle wrapper exists (`um-agent service --state-dir ...
  --center ... --node-class windows_terminal`), but service-account/ACL/DPAPI
  installation and whether a secret is ever needed remain OD-P7 PENDING; the
  installer template registers a Manual-start service and must not be started
  before the Owner decision + code-slice installation path are reviewed. DPAPI
  protection exists only as tested scaffolding (`ServiceHost` seam has no
  implementation).
- G9: the CLI flag names are Draft names (not frozen); deploy assets and the
  runbook must be re-checked against the final code slice at review (the frozen
  contract command `enroll --token-stdin` is implemented and used by the
  installer).
- G10: `go test ./...` is run locally by the documentation slice at
  finalization; the GitHub CI result for the Draft PR is not part of this
  evidence and must be reported separately on the PR.

## 9. Required statement

**This is a B3 Draft PR.** It is not a merge request approval, not a release,
not a production installation, and it does not enable R1, install services,
create credentials or touch production. UM-B4/C/D/E/F/G are not started, the
frozen contract is unchanged, and all Owner decisions in
`docs/um/um-127/05-owner-decisions.md` remain PENDING unless the Owner records
otherwise.
