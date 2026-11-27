# UM-B3 isolated lab evidence (2026-11-27)

This file records the non-production lab runs referenced by the B3 matrix. All
tests used isolated temporary directories, synthetic configuration and synthetic
credentials. No production host, VPS, Cloudflare account, real Mihomo config or
real credential was used. The lab environment included the Windows review host
and disposable GitHub-hosted Ubuntu 24.04 / Windows 2022 runners; the isolated
systemd/D-Bus and SCM/DPAPI/R1 labs were executed and are recorded below.

## 1. Real sing-box 1.14.5 service.api

- Official release asset:
  `https://github.com/SagerNet/sing-box/releases/download/v1.14.5/sing-box-1.14.5-windows-amd64.zip`
  (download returned 32,638,892 bytes; the extracted executable reported
  `sing-box version 1.14.5`, `go1.27.4 windows/amd64`,
  `Revision: a6844a780ba173e189a018d0ac62df67cd50b8e9`).
- Isolated config (no production settings): mixed inbound tag `test-in` on
  `127.0.0.1:19092`; top-level `services` entry of type `api`, tag
  `monitor-api`, listen `127.0.0.1:19091`, synthetic secret.
- The lab opened an HTTP CONNECT through the mixed inbound and kept it active.
  The new client was called directly:
  - first `ObserveServiceAPI`: `connected=true`, one inbound;
  - second: `test-in` `ActiveConnections=1`, active
    `UplinkBytes=0`/`DownlinkBytes=2`, `UplinkTotalBytes=0`,
    `DownlinkTotalBytes=2`, `TotalsAvailable=true`, `TotalsExact=false`.
  - temporary `TestZZRealServiceAPI` PASS; harness removed.
- End-to-end temporary lab with the same live service.api, `linuxobs.Collector`,
  `agent.Runtime` and the real `um-center` HTTP + SQLite boundary: center config
  `singbox_api=true`, expected tag `test-in/other`; snapshot accepted with
  `"test-in"` and `"traffic":"ok"` in the persisted payload. Temporary
  `TestZZRealSingletonToCenter` PASS; harness removed.
- Limitations: one isolated synthetic instance; not the P1-10 production
  authorization audit and not a production claim. The in-repo serviceapi tests
  are synthetic gRPC-Web fixtures (`internal/linuxobs/serviceapi_test.go`).

## 2. R2 Windows source investigation

See `um-b3-adr-windows-sources.md` §6. Isolated Mihomo/Clash Verge Rev lab:

- Clash Verge Rev **2.5.10**, Mihomo Meta **v1.19.33 windows/amd64**
  (`with_gvisor`), temporary config and synthetic secret.
- TCP controller: no/wrong secret → 401; correct secret → 200; controller API
  is write-capable.
- Windows named pipe: official docs say the pipe does not validate the secret;
  isolated `/version`, `/connections`, `/proxies` returned 200 without/with a
  wrong secret; `PUT /proxies/UM-TEST-GROUP` → 204 and `PATCH /configs` → 204.
  Observed pipe DACL:
  `D:P(A;OICI;0x12019f;;;BU)(A;OICI;0x12019f;;;SY)` (BUILTIN\Users + SYSTEM).
- Local config/state files contained profile/selection metadata but no
  authoritative live active-connection/route distribution.
- Verdict: **R2 INFEASIBLE on the tested surfaces; full target build matrix
  UNVERIFIED.** A GET-only local bridge would introduce a separate
  write-capable-capability process and is not classified as R2.

## 3. Current-user DPAPI lab

- Windows host current-user DPAPI round-trip tests pass for
  `internal/secretstore` and `internal/agent/state_windows_test.go`.
- The test asserts `identity.json` and `rotation.json` do not contain the
  Ed25519/rotation private-key plaintext and can be reopened by the same
  Windows user.
- This was originally current-user only on the non-admin review host. The
  isolated Windows 2022 SCM lab later executed the same DPAPI identity/rotation
  checks under `NT SERVICE\um-agent` with session-0/service-SID ACL (run
  46039366384 PASS). The final production account remains OD-P7 PENDING.

## 4. Process-level crash/recovery harness

`internal/agentintegration/crash_recovery_test.go` starts the Go test binary as
a child process, uses the real center/HTTP/SQLite and real filesystem spool, and
exits with `os.Exit(99)` (no clean-shutdown marker).

- REC-17: child queues a fsynced record, removes boot state, exits; parent
  returns `boot_state_corrupt`, center snapshot count 0, spool retained.
- REC-18: child commits generation 12, exits; parent restores generation 9;
  real center returns 409 `stale_boot_generation`; no reset, spool retained.
- REC-27: center generation 3/boot b3; child commits three seed reports, then a
  fourth whose ACK is dropped after commit; persisted attempt is asserted as
  gen3/seq4/boot b3 with a non-empty fingerprint; parent resends → duplicate,
  spool drains, center snapshot count remains 4, no reinsertion.
- Hardware power-loss durability on target hardware remains UM-E/hardware lab
  scope; software process crashes are covered.

## 4a. Linux systemd/D-Bus real lab (isolated GitHub runner; PASS)

`um/deploy/lab/linux-systemd-lab.sh` and the UM lab workflow execute on a
disposable Ubuntu 24.04 runner with systemd 255:

- built the real agent/center/lab binaries and issued a synthetic enrollment
  token from the real local center/SQLite;
- executed the repository installer as root, which created the non-login
  `umagent` user, installed the binary/unit/noexec drop-in, ran
  `systemd-analyze verify`, enrolled over the frozen stdin token path, and
  started the service;
- verified the service main process ran as `umagent`, `StateDirectory`/state
  mode was 0700, no listening socket existed, and the unit's root-owned
  hardened binary executed successfully;
- enabled a synthetic `sing-box.service` and enabled the `services`/`system`
  center sources; the real D-Bus probe returned `ActiveState=active` and the
  persisted snapshot contained `services:[{name:"sing-box",state:"active"}]`
  plus real `/proc` system values;
- restarted the service and verified the new generation advanced and identity
  state survived;
- stopped/started the service, then disabled/removed the unit/user/state in
  cleanup.
- **Result: PASS on Ubuntu 24.04 / systemd 255 (workflow run 46038057860).**
  This is a disposable isolated runner, not a production VPS or the broader
  target-version matrix.

## 4b. Windows SCM/virtual-account/DPAPI/R1 lab harness

`um/deploy/lab/windows-service-r1-lab.ps1` and the UM lab workflow ran on a
disposable administrator Windows 2022 runner (workflow run
`46038057860`, **PASS**). The run:

- created the real `um-agent` SCM service under `NT SERVICE\um-agent` with the
  no-password virtual-account syntax and obtained its per-service SID;
- ran enrollment through the lab SCM helper under that service account, proving
  DPAPI CurrentUser private-key protection (`private_key_dpapi`, no plaintext
  field) and rotation provisional-key protection
  (`new_private_key_dpapi`);
- provisioned the R1 bundle through `um-agent r1-provision` under the same
  service account (DPAPI-sealed controller secret, versioned isolated-lab
  acceptance, hash binding, private ACL);
- started the real `um-agent service` wrapper in **session 0** under
  `NT SERVICE\um-agent` while the lab runner stayed in its interactive session;
- observed all five selection bindings (`a_reality`, `a_hy2`, `b_reality`,
  `b_hy2`, `direct`) through the real isolated Mihomo controller and a real
  loopback CONNECT/active-connection projection; the persisted terminal
  snapshot reported the active direct connection;
- stopped the controller and verified the persisted terminal selection degraded
  to unavailable/partial, with no fabricated healthy data;
- verified the Mihomo config file hash was unchanged, the snapshot contained no
  local profile/controller sentinel, the state ACL did not include broad users,
  and identity/DPAPI state survived a service stop/start.

The R1 credential is still treated as **write-capable**; only the agent's
GET-only request surface is tested. No real controller secret was used and R1
production enablement remains HOLD.

## 4c. Power-loss generation amendment

The proposed amendment is a separate docs/fixture-only Draft PR #132
(`docs/um/um-127/09-power-loss-generation-amendment-draft.md` plus
`power-loss-generation.amendment.v1.json`). It is **not frozen**; B3 tests label
the new restart behavior as dependent on that approval. Same-runtime ACK-loss
exact duplicate remains the old REC-27 consistency case; process crash/restart
replay uses a new generation/boot/fresh attempt and is duplicate-by-report_id
while advancing the new generation high-water. Reconciliation tests are in
`internal/agent` and the real-center process crash harness.

## 4d. R1 isolated-lab acceptance

The Owner's limited R1 authorization is recorded in
`um-b3-r1-isolated-lab-acceptance.md` and `r1-acceptance-record.v1.json`:
isolated lab only, no production enablement, credential is write-capable, no
named pipe/bridge, protected local provisioning with DPAPI CurrentUser, and no
real controller secret.

## 4e. sing-box service.api v1.14.5 reproducible lab and authorization audit

`um/deploy/lab/singbox-serviceapi-lab.sh` downloads the official sing-box
1.14.5 Linux amd64 binary, starts a synthetic loopback mixed inbound and
`service.api`, opens a real HTTP CONNECT connection, and runs the opt-in
`TestServiceAPIOptInLab`. The isolated lab workflow run `46039366384` passed all
five jobs including this real service.api job. The lab verifies the real
connection stream and records that the accumulator exposes only a non-exact
lower bound. The frozen
schema has no lower-bound representation, so B3's traffic projection is
`unavailable` with an empty traffic array for both service.api and legacy Clash
paths.

`docs/um-b3-singbox-serviceapi-audit.md` records the v1.14.5 proto audit: the
single service secret authorizes write/control RPCs (`ClearLogs`,
`SetClashMode`, `SelectOutbound`, `CloseConnection`, etc.), so it is not a
read-only credential and P1-10 cannot be proven. The source stays disabled.
The lab uses a synthetic mixed inbound, not real Reality/Hysteria2 inbounds;
those protocol-specific experiments remain unverified and are not claimed
(the source itself is disabled because the P1-10 authorization audit fails).

## 5. Remaining not executed / external HOLD

- Real Linux systemd/D-Bus evidence is now available from the isolated Ubuntu
  runner (above); the broader target-version matrix and noexec on other systemd
  versions remain HOLD/UM-E.
- Windows full SCM/virtual-account/DPAPI/R1 service lab is now PASS on the
  disposable Windows 2022 runner (run 46038057860); target tournament builds and
  production account/credentials remain HOLD.
- Public-TLS center deployment, real VPS/terminal production, real tournament
  Clash Verge/Mihomo builds, R1/R2 enablement: HOLD.

## 6. Verification commands

Local (Windows) commands and results used for the final evidence are recorded in
the PR/Issue archive; representative commands:

```text
go test -count=1 ./...
go build ./...
go vet ./...
go mod verify
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
bash -n um/deploy/linux/install-agent.sh
PowerShell parser: install-agent-service.ps1 (0 parse errors)
```

The exact-HEAD GitHub CI result is linked from PR #131; this file does not
replace CI.
