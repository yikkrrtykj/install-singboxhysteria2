# Windows runtime verification runbook (HA-03 #91)

Purpose: collect the **real** Windows/Clash Verge Rev/Mihomo evidence that the
offline transform and CI cannot produce. Every row below is NOT RUN / BLOCKED
until an operator executes it on the authorized Windows test PC with the two
authorized test VPSes. No LAB or CI result may be substituted.

One-time setup: use only the authorized test PC and disposable test resources.
Never point this at a production VPS, daily Clash profile or an event PC in
service. Record a synthetic run ID. Do not paste secrets, full certificates,
private YAML or endpoint tuples into a ticket/PR.

## 1. Pin the exact combination (candidate, not yet supported)

```powershell
# Windows build
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' |
  Select-Object ProductName, DisplayVersion, CurrentBuild, UBR

# Verge release actually installed
$verge = Get-ChildItem "$env:LOCALAPPDATA\Programs" -Recurse -Filter 'Clash Verge.exe' |
  Select-Object -First 1
$verge.FullName
(Get-Item $verge.FullName).VersionInfo.FileVersion

# Installer provenance (record URL + SHA-256 of the file you installed)
Get-FileHash 'C:\path\to\Clash.Verge_2.5.10_x64-setup.exe' -Algorithm SHA256

# On-disk core actually running (never the release ZIP hash)
Get-Process verge-mihomo -ErrorAction SilentlyContinue | Select-Object Path
$core = (Get-Process verge-mihomo).Path
(Get-FileHash $core -Algorithm SHA256).Hash.ToLower()
& $core -v
```

Record in the receipt: Windows build, Verge version + installer SHA-256, core
path, core banner, **core binary SHA-256**, release tag/asset URL, download
time, and the `gh api` asset digest. The candidate is Clash Verge Rev v2.5.10
with its bundled Mihomo v1.19.33; if the on-disk banner/hash differ, record the
actual combination and drop the candidate claim. Disable auto-update and never
press “升级内核”; re-hash the core before/after each run (a changed hash reopens
the gates).

## 2. Backup before import (required rollback evidence)

```powershell
$cfg = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
$backup = "$env:USERPROFILE\ha03-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Force $backup | Out-Null
Copy-Item "$cfg\*" $backup -Recurse -Force
Get-ChildItem $cfg -Recurse -File | ForEach-Object {
  $_.FullName; (Get-FileHash $_.FullName -Algorithm SHA256).Hash
} | Out-File "$backup\before-hashes.txt"
```

Record the backup path, file count/hashes and the current selected nodes
(section 6) before importing anything. Keep this backup private.

## 3. Import and effective configuration

1. Import exactly one `<name>-hac.yaml` (the generated competition profile) via
   the Verge UI, then activate it manually. Default OFF: nothing auto-imports.
2. Confirm the active runtime file actually contains the pins:

```powershell
$cfg = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
Get-ChildItem $cfg -Recurse -File -Filter '*.yaml' |
  Select-String -Pattern 'fingerprint:|skip-cert-verify|listen:' |
  Select-Object Path, LineNumber, Line
```

Expected: two `fingerprint:` lines, no `skip-cert-verify: true`, and DNS
`listen: "127.0.0.1:53"` **in the file the core actually loads**. If Verge
overrides DNS/TUN/controller values in its own app settings, record the runtime
value (section 4), not the YAML text.

3. Load check with the exact core before trusting the profile:

```powershell
& $core -t -d "$env:TEMP\ha03-core-test" -f "<active profile path>"
```

## 4. Listener binds and access control (must be actual runtime)

```powershell
$pid = (Get-Process verge-mihomo).Id
Get-NetTCPConnection -State Listen | Where-Object OwningProcess -eq $pid |
  Select-Object LocalAddress, LocalPort, OwningProcess
Get-NetUDPEndpoint | Where-Object OwningProcess -eq $pid |
  Select-Object LocalAddress, LocalPort
```

Record every bind. Required: controller and DNS on loopback (`127.0.0.1` /
`::1`) only; no `0.0.0.0`/`::` DNS or controller unless explicitly reviewed and
approved for the site. Mixed-port exposure follows the reviewed competition
policy (loopback preferred; LAN only with recorded approval).

```powershell
# controller auth: unauthenticated request must fail; authenticated must work
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:9090/version
# repeat with the configured bearer secret via an environment/header method that
# does not print the secret, then confirm 200.
```

From a second authorized LAN device, confirm `Test-NetConnection <pc-ip>
-Port 9090` and `<pc-ip>:53` fail. Record the second device and the result.

## 5. TUN, DNS/Fake-IP, IPv4/IPv6, UDP and paths

```powershell
Get-NetAdapter | Where-Object InterfaceDescription -match 'Mihomo|TUN'
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
  Where-Object InterfaceAlias -match 'Mihomo'
Resolve-DnsName example.com -Server 127.0.0.1
curl.exe -4 https://api.ipify.org          # IPv4 egress
curl.exe -6 https://api64.ipify.org        # IPv6 egress (only if IPv6 is in scope)
```

- Rule/Global/Direct: switch mode via the Verge UI or the controller; for each
  mode record the effective egress IP (proxy vs local) and the attributed
  process/route. A green node/HTTP 204 is not attributed traffic.
- UDP: confirm the TUN path carries UDP (e.g. an authorized QUIC/HY2 test
  through the proxy) and that a TCP-only check is not used as UDP evidence.
- LAN/production/management: while the competition profile is active, verify the
  production equipment network, local device management and management subnet
  are still reachable; record failures. Direct mode and intentional bypasses are
  bypasses, not VPS protection.
- HY2 TLS identity: with the pinned profile active, force new connections to
  `Hysteria2` and `Backup-Hysteria2` in turn and record success. Then (only on
  the authorized test VPS) serve a wrong/expired certificate and record that the
  affected candidate is rejected and the profile fails over **without weakening
  verification** (never enable `skip-cert-verify: true` as a fallback). Repeat
  after renewal/rotation and after rollback.

## 6. Selection cache and exit/restore

Use the controller with authentication; never print the secret:

```powershell
# Read now/fixed for the two groups (node names only)
# GET /proxies via the authenticated controller, then select:
#   节点选择.now / 节点选择.fixed ; 自动选择.now / 自动选择.fixed
```

Record before/after for: first start, normal exit, abnormal close
(`Stop-Process -Force`), core restart, control-process stop/restart, config
switch, and full restore of the original profile.

Required checks:

- outer `节点选择` and inner `自动选择` effective state (automatic vs manual);
- a historical manual pin on `自动选择` must not silently invalidate A/B
  automatic mode; intentional manual choices are preserved (do not clear all
  caches);
- if a migration to automatic mode is needed, perform it explicitly and record
  the operator action and resulting `/proxies` state;
- after removing the competition profile and re-importing the original, verify
  selection/settings/TUN/DNS/LAN and application behaviour are restored.

## 7. Receipt (sanitized)

For each row record: run ID, HA-03, Windows build, Verge version + installer
SHA-256, core banner + core binary SHA-256 + provenance, profile version/output
SHA-256, A/B role, mode, cache/manual state, actual bind list, command result,
UTC time and verdict (`PASS` only for executed reproducible rows; `NOT RUN` /
`BLOCKED` / `UNKNOWN` otherwise). No private YAML, certificate body, account,
secret, session ID or endpoint tuples.

This runbook itself is not evidence. HA-03 remains BLOCKED for every row that
was not executed on the real PC/VPS.
