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
| 3 | Atomic fsync boot state: generation +1 on every enrolled runtime start (clean or unclean), new random boot id, seq persist-before-send; corrupt/missing boot state = fail-closed `boot_state_corrupt` (never reset) | B3.1 | `04` §5, §6.1; REC-17/18/27; proposed power-loss amendment | `state.go` (`writeAtomic`, boot validation), `runtime.go` recovery; live center tests for same-runtime vs restart duplicate | IMPLEMENTED; acceptance DEPENDS ON DRAFT AMENDMENT PR #132 (not frozen) |
| 4 | Single-agent/single-writer rule (OS advisory lock, no PID stale-lock removal, no two instances per node); symlink/reparse state-path rejection | B3.1 | `04` §6.1 | `state.go` lock + `lock_{unix,windows}.go`, path checks | IMPLEMENTED |
| 5 | Durable report spool: 32 MiB / 7 d, fsync-before-send, same-second seq ordering, oldest-first, ack-only removal, hash-bound quarantine, age retention during outage, **over-capacity fail-closed** | B3.1 | `04` §11, §6.2 | `spool.go` + same-second/quarantine tests | IMPLEMENTED |
| 6 | ACK adoption: `max(local_next_seq, ack.next_seq)`, `next_seq:null` exhaustion → new generation or operator recovery; no seq reuse/wrap | B3.1 | `04` §5, §13; REC-26 | `runtime.go` `applyAck`/`nextAttempt` | IMPLEMENTED |
| 7 | Retry policy: 1→60 s bounded backoff; 5xx/429/transport retryable; stale_timestamp clock recalibration; non-retryable payload quarantine; auth/sequence/boot/revocation stop the queue | B3.1 | `04` §6.2, §8; REC-10/15/16/21 | `runtime.go` `Drive`, `errors.go` | IMPLEMENTED |
| 8 | Rotation intent recovery: persist nonce/new key before send, restart replay, `rotation_expired` abort path, new-key proof confirmation, revocation wins, no bypass of high-water | B3.1 | `04` §7; REC-19/20/21 | `runtime.go` `Rotate`, state rotation file | IMPLEMENTED |
| 9 | Config pull exactly `{}` on the wire, response validated, class/source allowlist, fail-closed defaults (`collect` switches false), no center push | B3.1 | `04` §7, §9.1 | `client.go`, `runtime.go`; center enforces | IMPLEMENTED |
| 10 | Agent-side privacy: no local names/IPs/URLs/process names/connection ids/credentials/YAML in bodies, logs or state diagnostics; closed error logging | B3.1 | `04` §9.3; `06` SEC-14 extension | collector contract + runtime status (no payload logging); negative tests | IMPLEMENTED + MOCK-UNIT PASS (see §5) |
| 11 | Linux `/proc` read-only system counters (CPU/mem/disk/net), no subprocess, no root; honest UNKNOWN/UNAVAILABLE | B3.2 | `04` §11 | `um/internal/linuxobs/{collector,procfs,system,disk}.go` + synthetic-fixture tests | MOCK-UNIT PASS (synthetic procfs; not a real-host proof) |
| 12 | Linux systemd unit state via read-only D-Bus `ActiveState`; unavailable → UNKNOWN; no `systemctl` exec fallback | B3.2 | `04` §11; P1-03 | `linuxobs.SystemdDBusProbe` (godbus v5.2.4, fixed GetUnit+Properties.Get, FlagNoAutoStart, no write/exec/root) + exact-call/security tests; isolated Ubuntu 24.04 workflow read a real synthetic `sing-box.service` and persisted `services:[{state:"active"}]` | **REAL LAB-REAL PASS on systemd 255 / Ubuntu 24.04 (isolated workflow)**; target VPS matrix broader |
| 13 | Linux `singbox_api` disabled by default; server-side authorization audit required before enable; unproven source → honest `unavailable`, no fallback credential; no lower bounds as lifetime totals | B3.2 | `04` §11 (P1-10); SEC-39 | Official service.api gRPC-Web client/accumulator (`serviceapi*.go`), synthetic fixtures + reproducible real sing-box 1.14.5 lab (run 46039366384 PASS); v1.14.5 proto audit shows the single service secret authorizes write/control RPCs, so P1-10 fails; legacy Clash compatibility only; G7 event implemented; traffic unavailable/empty | IMPLEMENTED + LAB-REAL isolated; **P1-10 AUTHORIZATION AUDIT FAIL; source disabled/unavailable; no production enablement** |
| 14 | Linux no-exec/least-privilege runtime: non-root `umagent`, no listener, no exec/root/sudo/shell/systemctl, only own state dir writable; `LoadCredential` for API secrets; source permissions unchanged | B3.2/B3.4 | `04` §11; `03` §11; SEC-31/32/33 | installer + unit + noexec whitelist; isolated systemd workflow verified non-root, no listener, state 0700, NoExecPaths present and restart-safe | **REAL LAB PASS on systemd 255 (isolated)**; target-version matrix broader |
| 15 | Windows six-token projection of `windowsobs` data; exactly one role enum; independent `selection`/`active_connections` sampling; `direct` only with explicit operator-local binding, otherwise `unknown`/null | B3.3 | `04` §9.2; `02` §2 | `windowsobs` six-token `Role`/`Tokens()` + `windowsagent` collector unit tests | MOCK-UNIT PASS |
| 16 | Windows honesty: availability coherence, sum equality when `ok`, empty list = observed zero, missing/malformed = unknown/unavailable, no fabricated data | B3.3 | `04` §9.2; SEC-33/45 | `windowsagent/collector_test.go` synthetic observer cases | MOCK-UNIT PASS |
| 17 | Windows read-only/HA: no config write, no node switch, no connection close, no HA-UI/P6/#67 change; local proxy names never leave host | B3.3 | `04` §9.2; `02` §4 | loopback-GET-only observer + no-write/HA design tests (synthetic) | MOCK-UNIT PASS; real-build read-only/HA proof DEFERRED (UM-E) |
| 18 | R2 truly read-only Windows source (no controller secret) researched/evaluated; result recorded with build/version evidence | B3.3 | OD-P3; `02` §4; ADR | `um-b3-adr-windows-sources.md` with isolated Clash Verge Rev 2.5.10/Mihomo 1.19.33 TCP and named-pipe evidence (unauthenticated pipe exposes write methods) | **R2 INFEASIBLE on tested surfaces; full target matrix UNVERIFIED; OWNER DECISION PENDING** |
| 19 | R1 (write-capable controller credential used by GET-only client) isolated-lab authorized; not called read-only; no env/center bypass; production disabled | B3.3 | Owner R1 isolated-lab acceptance; OD-P3; `02` §4 | `um-b3-r1-isolated-lab-acceptance.md` + versioned JSON; fixed protected `<state>/r1` bundle, DPAPI CurrentUser, private DACL, `r1-provision`; no env secret/authorization path; real Windows lab harness under `um/deploy/lab` | **R1 LAB AUTHORIZED / IMPLEMENTED / REAL LAB PASS (isolated Windows 2022, run 46038057860); R1 PRODUCTION ENABLEMENT HOLD** |
| 20 | Windows service install: virtual non-admin account priority, service SID/ACL, DPAPI CurrentUser, session 0, enrollment-under-service-account, no LocalSystem, no machine-scope fallback | B3.3/B3.4 | OD-P7; ADR; Owner direction | SCM wrapper + event-log source; DPAPI CurrentUser identity/rotation; protected R1 bundle; `sc create obj=`/`qc` installer; UM-specific Windows SCM/DPAPI/R1 lab workflow | **IMPLEMENTED; REAL SCM/DPAPI/R1/SESSION-0 LAB PASS (isolated Windows 2022, run 46038057860); final production account still Owner PENDING** |
| 21 | Windows service/agent real run on target Clash Verge Rev/Mihomo builds with read-only/HA assertions | B3.3 | `06` SEC-42..47; UM-E | — | DEFERRED (UM-E/real lab) |
| 22 | Linux one-shot installer: root-only install orchestration, non-root runtime user, `/var/lib/um-agent` 0700, unit install, enrollment over pipe, token cleanup, dry-run default, no service start by default, no changes to existing Monitor/sing-box/sbox-cm | B3.4 | `04` §11; P1-03 | `install-agent.sh` | IMPLEMENTED (template; not executed) |
| 23 | Coexistence with existing per-VPS Monitor: no shared unit/port/socket; only read-only duplicate load on loopback sing-box API; existing config/secret/permissions unchanged | B3.4 | Q-COEXIST; `01` §9 | runbook §5 | IMPLEMENTED (documented); real coexistence test DEFERRED |
| 24 | Linux systemd lab proof: `systemd-analyze verify`, unit hardening, no-exec whitelist, D-Bus read proof, non-root file access, restart | B3.4 | SEC-31/32; `06` §6 | `um/deploy/lab/linux-systemd-lab.sh` + UM workflow on Ubuntu 24.04; verifies real D-Bus active state, non-root, no listener, state 0700, restart-safe NoExecPaths whitelist, restart generation advance | **REAL LAB PASS on systemd 255 / Ubuntu 24.04 (isolated)**; target matrix broader |
| 25 | Runbook: install/run/upgrade/uninstall/recovery/rollback for both platforms, REC-17/18/27 operator steps, backup/no-secret logging | B3.4 | `07` §5 | `um-b3-runbook.md` | IMPLEMENTED (documentation) |
| 26 | ADR proposals: OD-P7 credentials and OD-P3 Windows sources, status PROPOSED/PENDING OWNER, never APPROVED | B3.4 | 05 §C/F | two ADR files | IMPLEMENTED (proposals only) |
| 27 | Dual-platform CI plus isolated service labs: existing CI unchanged; UM-specific lab workflow builds/executes real systemd and SCM/DPAPI/R1 environments | B3.4 | plan §7 | `um-b3-lab.yml`; local full suite; exact-HEAD CI evidence on Draft PR | LOCAL INTEGRATION PASS; final exact-HEAD CI + lab results to be recorded |
| 28 | Frozen contract untouched, no second signing/transport state machine, no center/B2 changes | B3.1–B3.4 | plan §2/§6 | diff/write boundaries in §2 | IMPLEMENTED (boundary rule) |
| 29 | CLI entrypoint/platform wiring: `enroll/run/rotate/status/service/r1-provision/version`, D-Bus/service.api wiring, protected R1 bundle, Windows SCM wrapper | B3.1/B3.4 | `04` §11; P1-03 | `um/cmd/um-agent/*`; Windows provisioning tests; builds/vet clean | IMPLEMENTED; SCM service account lab PASS (run 46039366384); R1 production HOLD |
| 30 | Linux installer syntax/template review; dry-run default; no service start/enable by default; contract-conformant stdin token pipe | B3.4 | P1-03; `04` §11 | `install-agent.sh` (`bash -n` clean); no execution | IMPLEMENTED (template only; not executed) |
| 31 | Windows installer template: explicit Owner confirmation, LocalSystem refused, built-in/virtual account created with correct no-password SCM syntax, account verified with `sc qc`, no R1 provisioning, no start by default | B3.4 | OD-P7/P3; `04` §11 | `install-agent-service.ps1`; PowerShell parser clean; isolated SCM lab probe verified virtual-account creation | IMPLEMENTED; full installer execution pending in lab |
| 32 | Agent ↔ real center end-to-end: real HTTP/SQLite + real systemd Linux agent with real D-Bus, plus isolated Windows SCM/R1 service path | B3.1/B3.2/B3.3 | `04` §1–§6; B2 center | integration tests; Linux systemd lab on real Ubuntu runner (installer, service, D-Bus, restart, cleanup); Windows SCM/R1 lab harness | **Linux and Windows isolated service labs PASS (run 46038057860); not public-TLS/production** |

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
  `TestSpoolSameSecondUsesSequenceOrder`, `TestAgentRestartAfterLostACKNewGeneration`,
  `TestAgentRunRecoversCommittedProofBeforeConfig`, `TestAgentRunResumesAfterRecoveredConfigRetry`,
  `TestAgentRotationWithPendingSpoolUsesNewIdentity`, `TestAgentProofRotationExpiredClearsIntent`,
  plus OS-lock/DPAPI tests.
- `um/internal/linuxobs`: collector/procfs/system/disk/service/singbox
  projection and safety tests including availability honesty, source-switch
  gating, G7 event schema, service.api projection, D-Bus exact-call/security
  tests and the honest `ErrProbeUnavailable` default. The service.api client has
  synthetic gRPC-Web fixtures, source-authorization gating tests and an
  **isolated real sing-box 1.14.5 lab** with an active connection (LAB-REAL for
  the tested instance only; transcript/version in `um-b3-lab-evidence.md`).
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
2. **R1** — Owner-authorized for isolated lab only, not production; the
   protected local bundle is implemented and no environment/center switch can
   enable it. R1 remains described as a write-capable credential used by a
   GET-only client, never as read-only. Real Windows lab result is pending.
3. **Windows final service account / DPAPI / ACL** — OD-P7 final account is
   PENDING. Virtual account creation was probed in a real runner; a full
   SCM/DPAPI/enrollment/session-0 lab harness is present and its result is
   pending. Node/R1 keys are DPAPI CurrentUser-protected; LocalSystem and
   machine-scope fallback are forbidden.
4. **Linux systemd/D-Bus lab** — real isolated Ubuntu 24.04 workflow PASS:
   installer, non-root service, real D-Bus ActiveState, no listener, state mode,
   restart-safe noexec whitelist and restart generation advance. Broader target
   version matrix remains lab/UM-E scope.
5. **Real sing-box `service.api` authorization audit** — executed for v1.14.5:
   the single service secret authorizes write/control RPCs (ClearLogs,
   SetClashMode, SelectOutbound, CloseConnection, etc.), so the credential is not
   read-only and P1-10 authorization cannot be proven. The source remains
   disabled; a reproducible opt-in lab exercises only the connection stream.
   Per-inbound daemon-lifetime totals do not exist; traffic is reported
   unavailable/empty, never as an active-byte lower bound.
6. **Real Windows R1/HA proof**, real agent-to-center over public TLS,
   production account, target Clash builds, real clock skew and hardware
   power-loss durability — lab/production HOLD.
7. **Production, UM-E acceptance, load/capacity, backup/restore, offsite
   ledger, independent security review** — not started (UM-E/HOLD).
8. **CI on the Draft PR** — the exact final HEAD CI evidence is recorded after
   the last push; intermediate commits had green GitHub lanes, but no claim is
   made for a later HEAD until its run completes.

## 8. Known gaps and follow-ups

- G1: Windows six-token/selection/active projection has mock tests and a real
  isolated Mihomo R1 lab PASS (all five selections plus active direct); no A/B
  collapse or second enum exists.
- G2: `NoExecPaths=` was introduced in systemd v248. The real systemd 255 lab
  found that `NoExecPaths=/` + a single `ExecPaths=` re-allow denied the service
  binary on restart (203/EXEC); the drop-in now hides standard tool directories
  instead, and the lab verifies the service restarts successfully with the
  whitelist. Broader Ubuntu/Debian target versions remain UM-E/lab scope.
  Blocking `execve`/`execveat` directly in `SystemCallFilter=`
  would prevent the unit's own startup (systemd applies the filter before the
  service-binary exec) and is **not** used as a fake proof.
- G3: the isolated Windows 2022 lab created the virtual account, enrolled under
  it, verified DPAPI identity/rotation, provisioned R1 under the same account
  and ran the real service in session 0 (run 46038057860 PASS). Final production
  account remains Owner PENDING.
- G4: Linux real D-Bus/systemd state read was executed on the isolated Ubuntu
  24.04 runner and persisted `active`; `/proc` system data was observed in the
  same snapshot. Target VPS/version matrix remains UM-E.
- G5: operator recovery (boot-state loss, revoked key, rotation mismatch) is
  documented but not drilled on a real node (UM-E drill).
- G6: R2 investigation is complete (INFEASIBLE on tested builds); Owner has
  authorized R1 for isolated lab only. R1 enables only through the protected
  local bundle (no env/center bypass), and production enablement remains HOLD.
- G7: the Linux `singbox_api` unproven-source path now emits the contract
  `agent_error code=source_authorization_unproven` event (with stable event id
  and schema-validation test) while keeping availability unavailable. The
  versioned P1-10 server-side authorization audit and Owner enablement are
  still absent; this is an implementation-complete diagnostic, not enablement.
- G8: Windows SCM lifecycle wrapper and virtual-account creation are in place;
  the isolated lab performed enrollment under the virtual account, DPAPI
  identity/rotation checks, R1 provisioning and session-0 service run.
  **Lab PASS on run 46038057860.** Final account/ACL decision remains Owner
  PENDING; LocalSystem and machine-scope fallback remain forbidden.
- G9: the CLI flag names are Draft names (not frozen); deploy assets and the
  runbook must be re-checked against the final code slice at review (the frozen
  contract command `enroll --token-stdin` is implemented and used by the
  installer).
- G10: local `go test ./...`, exact-HEAD CI, and UM-specific isolated lab
  workflow run `46039366384` (Linux systemd/D-Bus, Windows SCM/DPAPI/R1, real
  sing-box service.api) are recorded. The lab workflow is evidence, not a
  production gate.

## 9. Required statement

**This is a B3 Draft PR.** It is not a merge request approval, not a release,
not a production installation. R1 is authorized only for isolated lab and
remains production-disabled; the frozen contract is unchanged in this PR and
the power-loss amendment is a separate docs-only Draft PR. UM-B4/C/D/E/F/G are
not started; Owner decisions in `docs/um/um-127/05-owner-decisions.md` remain
the governing record.
