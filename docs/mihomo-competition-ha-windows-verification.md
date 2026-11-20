# Windows runtime verification runbook (HA-03 #91)

Purpose: collect the **real** Windows/Clash Verge Rev/Mihomo evidence that the
offline transform and CI cannot produce. Every row below is NOT RUN / BLOCKED
until an operator executes it on the authorized Windows test PC with the two
authorized test VPSes. No LAB or CI result may be substituted.

One-time setup: use only the authorized test PC and disposable test resources.
Never point this at a production VPS, daily Clash profile or an event PC in
service. Record a synthetic run ID. Do not paste secrets, full certificates,
private YAML or endpoint tuples into a ticket/PR. Keep any remote-management
path (SSH/RDP/WinRM, out-of-band console) outside the proxied test traffic and
verify it stays reachable while the competition profile is active.

## 1. Pin the exact combination (candidate, not yet supported)

```powershell
# Windows build
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' |
  Select-Object ProductName, DisplayVersion, CurrentBuild, UBR

# Verge release actually installed (record the real path, not a guessed one)
$verge = Get-ChildItem "$env:LOCALAPPDATA\Programs" -Recurse -Filter 'Clash Verge.exe' |
  Select-Object -First 1
$verge.FullName
(Get-Item $verge.FullName).VersionInfo.FileVersion

# Installer provenance (record URL + SHA-256 of the file you installed)
Get-FileHash 'C:\path\to\Clash.Verge_2.5.10_x64-setup.exe' -Algorithm SHA256

# On-disk core actually running (never the release ZIP hash)
$corePid = (Get-Process verge-mihomo -ErrorAction Stop).Id
$core = (Get-Process -Id $corePid).Path
$corePid
$core
(Get-FileHash $core -Algorithm SHA256).Hash.ToLower()
& $core -v
```

Record: Windows build, Verge version + installer SHA-256, actual core path, core
banner, **core binary SHA-256**, release tag/asset URL, download time, and the
`gh api` asset digest. The candidate is Clash Verge Rev v2.5.10 with its bundled
Mihomo v1.19.33; if the on-disk banner/hash differ, record the actual
combination and drop the candidate claim. Disable auto-update and never press
"升级内核"; re-hash the core before/after each run (a changed hash reopens the
gates).

## 2. Stop in order, then back up a coherent private snapshot (required)

Do this **before** importing anything. Stop the running app/core first so the
snapshot cannot mix profiles, cache and selection files from different states.

```powershell
# 1. Quit Verge from the tray (or its UI "退出"), wait for processes to exit.
#    If the core lingers, stop it explicitly and record that you did.
Get-Process 'Clash Verge', verge-mihomo -ErrorAction SilentlyContinue |
  Select-Object ProcessName, Id, Path
Stop-Process -Name 'Clash Verge', verge-mihomo -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Get-Process 'Clash Verge', verge-mihomo -ErrorAction SilentlyContinue |
  Select-Object ProcessName, Id

# 2. Private backup directory (operator + SYSTEM + Administrators only)
$cfg = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
$backup = "$env:USERPROFILE\ha03-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Force $backup | Out-Null
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $backup /inheritance:r /grant:r "$me:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"

# 3. Copy profiles, settings, cache and selection state; record hashes
Copy-Item "$cfg\*" $backup -Recurse -Force
Get-ChildItem $cfg -Recurse -File | ForEach-Object {
  $_.FullName
  (Get-FileHash $_.FullName -Algorithm SHA256).Hash
} | Out-File "$backup\before-hashes.txt"
Get-ChildItem $backup -Recurse -File | Measure-Object | Select-Object Count
```

Keep the backup private and off the proxied path. Record the backup path,
file count/hashes, and the current selection state (section 6) **before**
importing.

## 3. Import and effective configuration

1. Import exactly one generated `<name>-hac.yaml` via the Verge UI and activate
   it manually. Default OFF: nothing auto-imports.
2. Confirm the **file the core actually loads** contains the competition
   invariants (Verge may override TUN/DNS/ports in its own settings; record the
   runtime value, not just the imported YAML):

```powershell
$cfg = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
Get-ChildItem $cfg -Recurse -File -Filter '*.yaml' |
  Select-String -Pattern 'allow-lan:|bind-address:|fingerprint:|skip-cert-verify|listen:' |
  Select-Object Path, LineNumber, Line
```

Expected in the effective profile: `allow-lan: false`,
`bind-address: "127.0.0.1"`, DNS `listen: "127.0.0.1:53"`, two `fingerprint:`
lines, no `skip-cert-verify: true`. If Verge overrides any of these, record the
effective value and treat the deviation as a finding, not a pass.

3. Load check with the exact core before trusting the profile:

```powershell
& $core -t -d "$env:TEMP\ha03-core-test" -f "<active profile path>"
```

## 4. Listener binds and access control (actual runtime, TCP and UDP)

```powershell
$corePid = (Get-Process verge-mihomo).Id
Get-NetTCPConnection -State Listen | Where-Object OwningProcess -eq $corePid |
  Select-Object LocalAddress, LocalPort, OwningProcess
Get-NetUDPEndpoint | Where-Object OwningProcess -eq $corePid |
  Select-Object LocalAddress, LocalPort
```

Record every TCP and UDP bind. Required: controller, mixed-port and DNS
(TCP and UDP 53) on loopback (`127.0.0.1`/`::1`) only; no `0.0.0.0`/`::` for
controller, DNS or proxy listener unless an explicitly approved site exception
exists. `Test-NetConnection` tests TCP only — for UDP 53 use `nslookup`/
`Resolve-DnsName` from the second device.

```powershell
# controller auth: unauthenticated request must fail; authenticated must work
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:9090/version
# repeat with the configured bearer secret via an env/header method that does
# not print the secret, then confirm 200.
```

From a **second authorized LAN device**, verify all of these fail: controller
TCP 9090, mixed-port TCP, DNS TCP 53, DNS UDP 53 (e.g.
`Resolve-DnsName example.com -Server <pc-ip>`), and any other listening port
found above. Record the second device and each result.

## 5. TUN, DNS/Fake-IP, IPv4/IPv6, UDP and effective paths

```powershell
Get-NetAdapter | Where-Object InterfaceDescription -match 'Mihomo|TUN'
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
  Where-Object InterfaceAlias -match 'Mihomo'
Resolve-DnsName example.com -Server 127.0.0.1
curl.exe -4 https://api.ipify.org          # IPv4 egress
curl.exe -6 https://api64.ipify.org        # IPv6 egress (only if in scope)
```

- Rule/Global/Direct: switch mode via the Verge UI or authenticated controller;
  for each mode record the effective egress IP (proxy vs local), the observed
  route/interface, and the attributed process/connection. A green node or HTTP
  204 is not attributed traffic.
- **Application UDP**: verify real application UDP through the TUN path with an
  authorized app/protocol (e.g. QUIC/WebRTC/DNS-over-UDP test), attributing the
  connection to the process and endpoint. A Hysteria2 outer UDP connection or a
  plain ICMP/TCP test is **not** evidence that application UDP works.
- LAN/production/management: while the competition profile is active, verify
  the production equipment network, local device management and management
  subnet are still reachable; record failures. Verify the remote-management
  channel (SSH/RDP/WinRM/oob) remains reachable and is not captured by the
  proxy/TUN. Direct mode and intentional bypasses are bypasses, not VPS
  protection.
- Cross-check for overrides: compare the effective YAML/Verge settings with the
  imported artifact (TUN stack/route/DNS/ports). Record every difference.

## 6. TLS identity, expiry, rotation and application attribution

This section needs the two authorized test VPSes and must not be run against
production. The offline pin/date control is **not** TLS PASS.

For each VPS (A and B), and for both the primary and backup HY2 role:

1. Re-run the trusted SSH certificate acquisition (profile doc) and confirm the
   pin/dates match the pins file and both competition deliveries.
2. With the pinned profile active, force a **fresh** HY2 connection to the
   candidate; confirm success and attribute the connection (section 5).
3. Serve a wrong certificate on the test VPS (or pin a wrong value): the affected
   node must be rejected; the client must fail over **without** weakening
   verification. Never enable `skip-cert-verify: true` as a fallback.
4. Serve an expired or retired certificate: record the observed rejection and
   failover. Confirm a retired fingerprint is no longer accepted.
5. Rotation: renew the test cert, update pins/delivery, `--check`, re-import,
   verify fresh accept with the new pin and reject with the old pin.
6. Failed rotation: break the renewal (wrong path/missing cert) and confirm the
   client rejects rather than silently continues; then restore the previous
   valid pair and `--check` before re-import.
7. Rollback: restore the original profile and verify the original behaviour;
   a retired cert/pin must remain rejected unless the rollback target is
   still-valid and explicitly approved.
8. HA-03 owns **actual application path attribution** (which app/connection
   used which node/VPS). HA-04 owns full failover/recovery timing; do not merge
   the two claims. A pinned LAB loopback result is not VPS identity acceptance.

If the owner finds the date/pin control insufficient for the frozen contract,
evaluate a trusted chain + name verification on a disposable test VPS with its
own approval. Never modify production certificates; an approved exception is
not TLS PASS.

## 7. Selection cache and exit/restore

Use the authenticated controller; never print the secret.

```powershell
# GET /proxies via the authenticated controller, then record:
#   节点选择.now / 节点选择.fixed ; 自动选择.now / 自动选择.fixed
```

Record outer/inner state for: before import, after import, each mode change,
normal exit, abnormal close (`Stop-Process -Force` on the core/UI),
core restart, control-process restart, config switch, and full restore.

Required checks:

- a historical manual pin on `自动选择` must not silently invalidate A/B
  automatic mode; intentional manual choices are preserved — do **not** clear
  all caches to make a test pass;
- if migration to automatic mode is needed, perform it explicitly and record
  the operator action and resulting `/proxies` state;
- after removing the competition profile and re-importing the original, verify
  profile/settings/selection/TUN/DNS/LAN/application behaviour and hashes
  against the section 2 backup;
- record the full original snapshot restoration path and the private ACL on the
  backup/recovery material.

## 8. Receipt (sanitized)

For each row record: run ID, HA-03, Windows build, Verge version + installer
SHA-256, actual core path/banner/SHA-256 + provenance, profile version/output
SHA-256, A/B role, mode, outer/inner cache state, actual TCP+UDP bind list,
second-device results, effective-config deviations, command result, UTC time and
verdict (`PASS` only for executed reproducible rows; `NOT RUN` / `BLOCKED` /
`UNKNOWN` otherwise). No private YAML, certificate body, account, secret,
session ID or endpoint tuples.

This runbook itself is not evidence. HA-03 remains BLOCKED for every row that
was not executed on the real PC/VPS. HA-03 code landing does not change issue
#91 acceptance state.
