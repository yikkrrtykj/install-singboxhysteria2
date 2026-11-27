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
- Dependency note: B3 promotes `golang.org/x/sys v0.34.0` to direct for the
  Windows SCM/DPAPI primitives and adds the pinned direct dependency
  `github.com/godbus/dbus/v5 v5.2.4` (BSD-2-Clause; pure Go on Linux; no new
  transitive module; OSV clean) for the read-only systemd D-Bus probe. DPAPI
  uses stdlib `syscall`/`crypt32`; no R1/Mihomo SDK or cloud dependency was
  added.
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
| **B3.4** | Delivery docs and isolated deploy/run assets: this scope/matrix, architecture, OD-P7 credentials ADR proposal, OD-P3 Windows sources ADR with R2 investigation result/R1 proposal, runbook, Linux unit/installer, Windows service installer template | `04-implementation-plan` §6 UM-B3; `07` §5; this file |

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

**Must not be modified by the documentation slice:** any existing file, in
particular `docs/um/**` (frozen contract/schemas/vectors/REC), `um/internal/**`,
`um/cmd/um-center`, `.github/workflows/**`, `install.sh`,
`monitor-v2/**`, `sbox-cm/**`, `ha-ui/**`, `windows/**`, `tools/**` and all other
modules. B3 implementation code in the same Draft PR is tracked by its own diff and
must also not change frozen contract files. It legitimately extends
`um/internal/**`, `um/cmd/um-agent`, deploy assets and B3 docs.

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
| REC-17 | agent boot-state missing/corrupt → **no request**, fail-closed local `boot_state_corrupt`, operator recovery | real child-process crash/`os.Exit` + real spool/center; operator revoke/re-enroll remains procedural |
| REC-18 | agent restored from old snapshot → center `409 stale_boot_generation`; no in-place reset; operator revoke/re-enroll | real child-process generation-12 commit, parent restores gen9, real HTTP 409; operator revoke remains procedural |
| REC-27 | agent power-loss edge: committed seq resend → duplicate; unsynced seq never reused | real child process + real center/spool with fixture state gen3/seq4/boot b3 and a real fingerprint: fourth ACK is lost after commit, child exits, parent resends → duplicate; exact persisted attempt asserted |
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
| 12 | Linux systemd unit state via read-only D-Bus `ActiveState`; unavailable → UNKNOWN; no `systemctl` exec fallback | B3.2 | `04` §11; P1-03 | `linuxobs.SystemdDBusProbe` (godbus v5.2.4, fixed GetUnit+Properties.Get, FlagNoAutoStart, no write/exec/root) + exact-call/security tests; CLI injection; honest unavailable fallback | IMPLEMENTED + MOCK-UNIT PASS; REAL LAB-REAL systemd HOLD (no Linux host) |
| 13 | Linux `singbox_api` disabled by default; server-side authorization audit required before enable; unproven source → honest `unavailable`, no fallback credential | B3.2 | `04` §11 (P1-10); SEC-39 | Official service.api gRPC-Web client/accumulator (`serviceapi*.go`), synthetic fixtures + isolated sing-box 1.14.5 lab; legacy Clash client compatibility only; G7 `agent_error code=source_authorization_unproven` implemented/tested; source stays off | IMPLEMENTED + MOCK-UNIT/LAB-REAL (isolated synthetic sing-box); P1-10 audit + source enablement HOLD |
| 14 | Linux no-exec/least-privilege runtime: non-root `umagent`, no listener, no exec/root/sudo/shell/systemctl, only own state dir writable; `LoadCredential` for API secrets; source permissions unchanged | B3.2/B3.4 | `04` §11; `03` §11; SEC-31/32/33 | `um-agent.service` + noexec drop-in + runbook | IMPLEMENTED (template); INTEGRATION DEFERRED (systemd lab) |
| 15 | Windows six-token projection of `windowsobs` data; exactly one role enum; independent `selection`/`active_connections` sampling; `direct` only with explicit operator-local binding, otherwise `unknown`/null | B3.3 | `04` §9.2; `02` §2 | `windowsobs` six-token `Role`/`Tokens()` + `windowsagent` collector unit tests | MOCK-UNIT PASS |
| 16 | Windows honesty: availability coherence, sum equality when `ok`, empty list = observed zero, missing/malformed = unknown/unavailable, no fabricated data | B3.3 | `04` §9.2; SEC-33/45 | `windowsagent/collector_test.go` synthetic observer cases | MOCK-UNIT PASS |
| 17 | Windows read-only/HA: no config write, no node switch, no connection close, no HA-UI/P6/#67 change; local proxy names never leave host | B3.3 | `04` §9.2; `02` §4 | loopback-GET-only observer + no-write/HA design tests (synthetic) | MOCK-UNIT PASS; real-build read-only/HA proof DEFERRED (UM-E) |
| 18 | R2 truly read-only Windows source (no controller secret) researched/evaluated; result recorded with build/version evidence | B3.3 | OD-P3; `02` §4; ADR | `um-b3-adr-windows-sources.md` with isolated Clash Verge Rev 2.5.10/Mihomo 1.19.33 TCP and named-pipe evidence (unauthenticated pipe exposes write methods) | **R2 INFEASIBLE on tested surfaces; full target matrix UNVERIFIED; OWNER DECISION PENDING** |
| 19 | R1 (write-capable controller credential used by GET-only client) **not enabled**, not called read-only, separate Owner risk acceptance required | B3.3 | OD-P3; `02` §4 | ADR records risk; gated CLI path requires explicit env + owner-approved profile/secret and is disabled by default; installer refuses R1 provisioning | BLOCKED (Owner risk acceptance absent) |
| 20 | Windows service install: Owner-approved account, ACL/DPAPI plan, session isolation, no secrets in repo/script/logs, no R1 provisioning | B3.3/B3.4 | OD-P7; ADR | SCM wrapper + event-log source; shared `internal/secretstore` DPAPI CurrentUser protects identity/rotation private keys; Windows source R1 path gated/off by default; installer template | IMPLEMENTED (SCM wrapper + DPAPI at-rest + template); real SCM/account/ACL/enrollment lab DEFERRED (OD-P7 PENDING) |
| 21 | Windows service/agent real run on target Clash Verge Rev/Mihomo builds with read-only/HA assertions | B3.3 | `06` SEC-42..47; UM-E | — | DEFERRED (UM-E/real lab) |
| 22 | Linux one-shot installer: root-only install orchestration, non-root runtime user, `/var/lib/um-agent` 0700, unit install, enrollment over pipe, token cleanup, dry-run default, no service start by default, no changes to existing Monitor/sing-box/sbox-cm | B3.4 | `04` §11; P1-03 | `install-agent.sh` | IMPLEMENTED (template; not executed) |
| 23 | Coexistence with existing per-VPS Monitor: no shared unit/port/socket; only read-only duplicate load on loopback sing-box API; existing config/secret/permissions unchanged | B3.4 | Q-COEXIST; `01` §9 | runbook §5 | IMPLEMENTED (documented); real coexistence test DEFERRED |
| 24 | Linux systemd lab proof: `systemd-analyze verify`, unit hardening, no-exec `NoExecPaths=/` on supporting systemd, D-Bus read proof, non-root file access proof | B3.4 | SEC-31/32; `06` §6 | unit + drop-in template; Documentation/Wants fixed; noexec gate corrected to systemd >=248; verify now fails closed in installer | DEFERRED — real systemd/D-Bus lab not run; noexec not claimed PASS |
| 25 | Runbook: install/run/upgrade/uninstall/recovery/rollback for both platforms, REC-17/18/27 operator steps, backup/no-secret logging | B3.4 | `07` §5 | `um-b3-runbook.md` | IMPLEMENTED (documentation) |
| 26 | ADR proposals: OD-P7 credentials and OD-P3 Windows sources, status PROPOSED/PENDING OWNER, never APPROVED | B3.4 | 05 §C/F | two ADR files | IMPLEMENTED (proposals only) |
| 27 | Dual-platform CI: existing `um-go.yml` covers `um/**`; agent tests run under the existing lane without weakening; local build/vet/test executed | B3.4 | plan §7 | local build/vet/test and exact-HEAD GitHub CI evidence recorded on Draft PR; existing CI file unchanged | LOCAL INTEGRATION PASS; exact final HEAD CI to be re-recorded after this fix commit |
| 28 | Frozen contract untouched, no second signing/transport state machine, no center/B2 changes | B3.1–B3.4 | plan §2/§6 | diff/write boundaries in §2 | IMPLEMENTED (boundary rule) |
| 29 | CLI entrypoint and platform wiring: `um-agent enroll/run/rotate/status/service/version`, platform collector selection, D-Bus/service.api wiring, gated Windows R1 observer, Windows SCM lifecycle wrapper | B3.1/B3.4 | `04` §11; P1-03 | `um/cmd/um-agent/{main,platform_linux,service_windows}.go`; Windows gate tests; builds/vet clean | IMPLEMENTED; Windows SCM/account/service integration unverified (OD-P7); R1 off by default |
| 30 | Linux installer syntax/template review; dry-run default; no service start/enable by default; contract-conformant stdin token pipe | B3.4 | P1-03; `04` §11 | `install-agent.sh` (`bash -n` clean); no execution | IMPLEMENTED (template only; not executed) |
| 31 | Windows installer template syntax and safety guards: explicit Owner confirmation, LocalSystem refused, R1/secret provisioning refused, no start by default | B3.4 | OD-P7/P3; `04` §11 | `install-agent-service.ps1` (PowerShell parser clean); no execution | IMPLEMENTED (template only; not executed) |
| 32 | Agent ↔ real center end-to-end: real `um-center` HTTP listeners + real SQLite + real collectors, enrollment → config → snapshot/metrics/events/report accepted | B3.1/B3.3/B3.2 | `04` §1–§6; B2 center | `TestLinuxCollectorToRealCenter`, `TestWindowsCollectorToRealCenter`, `TestAgentRunSchedulesSnapshotMetricsAndEvents`; plus isolated real sing-box 1.14.5 service.api → Linux collector → real center lab | INTEGRATION PASS (in-process real center/SQLite); isolated real-source LAB-REAL evidence; not public-TLS/production |

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
  `TestClientURLRules`, `TestControlStateJSONRoundTrip`,
  `TestReportRejectsMissingRequiredACKFields`, `TestConfigClassAllowlist`,
  `TestSpoolSameSecondUsesSequenceOrder`, plus OS-lock/DPAPI tests.
- `um/internal/linuxobs`: collector/procfs/system/disk/service/singbox
  projection and safety tests including availability honesty, source-switch
  gating, G7 event schema, service.api projection, D-Bus exact-call/security
  tests and the honest `ErrProbeUnavailable` default. The service.api client has
  synthetic gRPC-Web fixtures and an **isolated real sing-box 1.14.5 lab** with
  an active connection (LAB-REAL for the tested instance only).
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
  Linux/Windows collector implementations; enrollment → config pull →
  snapshot/metrics/events/report accepted:
  `TestLinuxCollectorToRealCenter`, `TestWindowsCollectorToRealCenter`,
  `TestAgentRunSchedulesSnapshotMetricsAndEvents`, and the parent/child
  process-crash harness `TestB3RecoveryProcessCrashREC17/REC18/REC27`
  (real child process `os.Exit(99)`, real HTTP center/SQLite/spool; no clean
  marker). An additional isolated lab
  connected real sing-box 1.14.5 service.api → Linux collector → real center +
  SQLite and persisted `test-in` traffic. This is INTEGRATION/LAB-REAL for the
  tested boundary, not public-TLS or a real VPS/terminal proof.
- `um/cmd/um-agent`: Windows source authorization-file gate tests and builds;
  Windows SCM/service/account integration still not lab-executed.
- Local syntax checks for deploy templates: `bash -n` on
  `um/deploy/linux/install-agent.sh` PASS; PowerShell parser on
  `um/deploy/windows/install-agent-service.ps1` PASS. Neither script was
  executed; no service was installed/started and no credential was created.
- B2 regression: the same local `go test ./...` run keeps
  `internal/center`, `internal/store`, `internal/conformance`,
  `internal/protocol`, `internal/schema`, `internal/contract` and
  `internal/wire` green; this is not re-claimed as new B3 evidence.
- Executed locally: isolated real sing-box 1.14.5 service.api with an active
  connection and a real center/SQLite round trip; named-pipe/TCP R2 lab on the
  installed Clash Verge Rev/Mihomo versions; Windows current-user DPAPI tests;
  process-level REC-17/18/27 crash harness.
- Not executed: Linux `-race` local, systemd/D-Bus real lab, Windows SCM/
  service-account/ACL lab, real center over public TLS, real tournament
  Clash Verge/Mihomo read-only/HA proof, R2/R1 enablement, production. These
  stay DEFERRED/BLOCKED.

## 6. Review/merge gates (unchanged; this Draft does not grant them)

| Gate | State |
| --- | --- |
| Independent review of the B3 Draft PR | Round-15 independent review COMPLETE / BLOCKED; review findings remediation in progress; final independent review pending |
| Owner approval per slice (OD-G5) | HOLD |
| Owner decisions OD-P3 (R2/R1) and OD-P7 (account/secrets) | **PENDING** |
| Merge authorization / normal merge commit | not granted |
| Production deployment/release/credentials | HOLD (UM-E + separate authorization) |
| R1 enablement | **not authorized**; never auto-enabled |
| Existing systems (#33/#67/Monitor/HA-UI) | unchanged |

## 7. Explicitly not verified (do not read as PASS)

1. **Real R2 source** — investigated on Clash Verge Rev 2.5.10/Mihomo 1.19.33;
   no conforming R2 surface was found (TCP needs write-capable secret; named
   pipe is unauthenticated yet write-capable). R2 is INFEASIBLE on tested
   surfaces; full target build matrix remains UNVERIFIED.
2. **R1** — not authorized and disabled by default; no R1 credential is
   created by the build/installer. The optional observer path requires an
   explicit operator environment gate and owner-approved profile/secret; it is
   never described as read-only.
3. **Windows final service account / DPAPI / ACL** — OD-P7 is PENDING. Node
   identity and rotation private keys are DPAPI CurrentUser-protected at rest
   and tested on the current Windows user; service-account/session-0/ACL/SCM and
   enrollment-under-service-account validation remain unverified. The installer
   is a template that creates no controller secret.
4. **Real systemd/D-Bus lab** — no host service was installed or started; the
   unit, no-exec drop-in, non-root file-access and D-Bus read behavior were not
   executed in a lab.
5. **Real sing-box `service.api` authorization audit** — absent; the Linux
   source remains disabled by design. The client itself now has synthetic
   fixtures and an isolated sing-box 1.14.5 lab; this is not the P1-10 audit.
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
- G2: `NoExecPaths=/`/`ExecPaths=` were introduced in systemd v248 (official
  NEWS). The installer now gates on >=248, so Ubuntu 22.04/Debian 12 are
  eligible; a real start/no-exec lab and `systemd-analyze verify` on those
  target versions are still pending (UM-E/lab), not a PASS. Blocking
  `execve`/`execveat` directly in `SystemCallFilter=`
  would prevent the unit's own startup (systemd applies the filter before the
  service-binary exec) and is **not** used as a fake proof.
- G3: Windows service account, state ACL, EventLog/SCM and DPAPI CurrentUser
  service-account behavior need the OD-P7 decision/lab. DPAPI CurrentUser is
  implemented and tested at the current-user scope; template defaults must not
  be read as the final account decision.
- G4: Linux real D-Bus/systemd state read and `/proc` sampling were not run on
  a target VPS. The D-Bus client and exact-call/security tests are implemented;
  only the isolated systemd lab/`systemd-analyze verify` remains.
- G5: operator recovery (boot-state loss, revoked key, rotation mismatch) is
  documented but not drilled on a real node (UM-E drill).
- G6: R2 research and the OD-P3/OD-P7 Owner answers are prerequisites for any
  Windows source enablement; no agent code path may be enabled before them.
- G7: the Linux `singbox_api` unproven-source path now emits the contract
  `agent_error code=source_authorization_unproven` event (with stable event id
  and schema-validation test) while keeping availability unavailable. The
  versioned P1-10 server-side authorization audit and Owner enablement are
  still absent; this is an implementation-complete diagnostic, not enablement.
- G8: Windows SCM lifecycle wrapper exists (`um-agent service --state-dir ...
  --center ... --node-class windows_terminal`), but service-account/ACL/DPAPI
  installation and whether a secret is ever needed remain OD-P7 PENDING; the
  installer template registers a Manual-start service and must not be started
  before the Owner decision + code-slice installation path are reviewed. The
  shared DPAPI CurrentUser implementation now protects agent identity/rotation
  private keys at rest and has current-user tests; virtual service account,
  ACL/enrollment, EventLog/service SCM and machine-scope validation remain
  pending, so it is not an OD-P7 PASS.
- G9: the CLI flag names are Draft names (not frozen); deploy assets and the
  runbook must be re-checked against the final code slice at review (the frozen
  contract command `enroll --token-stdin` is implemented and used by the
  installer).
- G10: local `go test ./...` and the exact-HEAD GitHub CI result are recorded
  on the Draft PR; the final HEAD after fixes must be re-run and re-recorded.
  The existing CI lane does not execute systemd/SCM/DPAPI/service-account labs.

## 9. Required statement

**This is a B3 Draft PR.** It is not a merge request approval, not a release,
not a production installation, and it does not enable R1, install services,
create credentials or touch production. UM-B4/C/D/E/F/G are not started, the
frozen contract is unchanged, and all Owner decisions in
`docs/um/um-127/05-owner-decisions.md` remain PENDING unless the Owner records
otherwise.
