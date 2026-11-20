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

## 2. Stop in order, keep remote control, then back up a coherent private snapshot (required)

Do this **before** importing anything. First open and confirm a second,
out-of-band management path (SSH/RDP/WinRM or an out-of-band console) and keep it
outside the proxied traffic; never route your own management channel through the
profile you are about to test. Stop the running app/core before the snapshot so
the backup cannot mix profiles, cache and selection files from different states,
and **verify the processes are actually gone** before copying.

```powershell
$ErrorActionPreference = 'Stop'   # cmdlet failures must stop the backup

# 1. Record the running processes, stop them, then prove they are gone.
Get-Process 'Clash Verge', verge-mihomo -ErrorAction SilentlyContinue |
  Select-Object ProcessName, Id, Path
Stop-Process -Name 'Clash Verge', verge-mihomo -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$left = Get-Process 'Clash Verge', verge-mihomo -ErrorAction SilentlyContinue
if ($left) {
  $left | Select-Object ProcessName, Id, Path
  throw 'Verge/core still running; coherent backup refused'
}

# 2. Private backup directory. Use the current SID (locale-safe): the supported
#    name form is "${me}:(OI)(CI)F"; "$me:(OI)(CI)F" is invalid PowerShell
#    interpolation, so it must not be used.
$cfg = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
if (-not (Test-Path $cfg)) { throw 'Verge config directory not found; refusing backup' }
$backup = "$env:USERPROFILE\ha03-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Force $backup | Out-Null
$sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
icacls $backup /inheritance:r /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
if ($LASTEXITCODE -ne 0) { throw 'icacls failed on the backup directory' }

# 3. Re-read the real ACL and refuse any allow principal outside the allowlist.
$allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544')
$badAcl = (Get-Acl $backup).Access |
  Where-Object AccessControlType -eq 'Allow' |
  ForEach-Object {
    $_.IdentityReference.Translate(
      [System.Security.Principal.SecurityIdentifier]).Value
  } |
  Where-Object { $allowed -notcontains $_ }
if ($badAcl) { throw "backup ACL outside allowlist: $($badAcl -join ',')" }

# 4. Snapshot source hashes first, copy, then prove the backup is coherent
#    (same relative path, same size, same SHA-256; nothing missing).
$before = @{}
Get-ChildItem $cfg -Recurse -File | ForEach-Object {
  $before[$_.FullName.Substring($cfg.Length)] = [pscustomobject]@{
    Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    Length = $_.Length
  }
}
if ($before.Count -eq 0) { throw 'no config files found; refusing empty snapshot' }
$before | ConvertTo-Json -Depth 3 | Set-Content "$backup\before-hashes.json"
Copy-Item "$cfg\*" $backup -Recurse -Force
$bad = @(); $missing = @()
foreach ($rel in $before.Keys) {
  $dest = Join-Path $backup $rel
  if (-not (Test-Path $dest)) { $missing += $rel; continue }
  if ((Get-Item $dest).Length -ne $before[$rel].Length -or
      (Get-FileHash $dest -Algorithm SHA256).Hash -ne $before[$rel].Hash) {
    $bad += $rel
  }
}
if ($bad -or $missing) {
  throw "backup not coherent: bad=$($bad -join ',') missing=$($missing -join ',')"
}
Get-ChildItem $backup -Recurse -File | Measure-Object | Select-Object Count
```

Keep the backup private and outside the proxied path; do not put it in the
profile directory or on a network share. Record the backup path, the source file
count/byte total, the `before-hashes.json` SHA-256, and the selection state
(section 7) **before** importing. Only the Verge app and its core are stopped:
do not stop SSH/RDP/WinRM, the network adapter or the TUN service you still need
for remote management.

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

## 6. TLS identity, expiry, rotation and rollback (TLS1–TLS5)

This section needs the two authorized test VPSes and must not be run against
production. The offline pin/date control is **not** TLS PASS.

Stage boundary (do not merge the claims): **HA-03** owns the TLS identity rows
below and the per-node/connection **path attribution** (which application or
connection used which node/VPS); **HA-04** owns the hard-failure switch timing
and recovery ordering; **HA-05** owns the complete business-application
recovery (vMix/TikTok LIVE Studio/Google Drive T3). A TLS row passing says the
identity/validity policy behaved as recorded; it does not prove failover timing
or application recovery.

For each VPS (A and B), and for both the primary and backup HY2 role, run and
record the row IDs:

### TLS1 — Expected peer accepted and attributed

Re-run the trusted SSH certificate acquisition (profile doc) and confirm the
pin/dates match the pins file and the competition delivery. With the pinned
profile active, force a **fresh** HY2 connection to the candidate; confirm
success and attribute the connection/process (section 5). Record the sanitized
endpoint alias, role, config version/SHA-256 and the UTC time.

### TLS2 — Wrong certificate / identity rejected

Serve a wrong certificate on the test VPS (or pin a wrong value): the affected
node must be rejected; the client must fail over **without** weakening
verification. Never enable `skip-cert-verify: true` as a fallback. Record the
affected node, whether another candidate recovered and the sanitized evidence.

### TLS3 — Expired / retired certificate: actual peer behaviour vs validity control

Mihomo leaf pinning compares the leaf DER SHA-256 and does **not** enforce the
certificate validity window. Do **not** expect the pinned core to reject an
expired certificate merely because a matching pin exists:

1. Serve (or keep) an expired certificate whose DER pin still matches the pin in
   the active competition profile. Record the **actual** observed behaviour
   (accepted or rejected) with timestamps and attribution. Acceptance is the
   documented residual exposure, not a pass; rejection is recorded as observed.
2. Demonstrate the mandatory validity control: run the preflight
   (`--check --source-delivery ...`) on the event PC before the run and show that
   an expired/insufficient pin fails it, then deactivate or remove the affected
   competition profile in Verge. Record the commands, sanitized output and the
   deactivation action.
3. Confirm a retired fingerprint is no longer accepted on a fresh connection.

If part 2 (mandatory preflight + deactivation) cannot be executed, TLS3 stays
**BLOCKED** and the competition profile must not be used.

### TLS4 — Planned renewal / pin rotation and failed renewal

Renew the test certificate, update pins/delivery, run `--check`, re-import, and
verify a fresh accept with the new pin and rejection with the old pin. Then break
the renewal (wrong path/missing certificate): confirm the client rejects rather
than silently continuing; restore the previous valid pair, `--check`, and
re-import.

### TLS5 — Rollback within competition mode; legacy restore exits competition mode

1. **TLS5 competition rollback**: restore a previous competition delivery that is
   still pin-valid and `--check`-GREEN. Verify a fresh connection succeeds with
   the restored pin and that a retired pin stays rejected. This is a rollback
   within competition-safe mode.
2. **Exiting competition mode is not a TLS5 rollback**: restoring the legacy
   HA-02 profile (`skip-cert-verify: true`) deliberately leaves the
   competition-safe mode. It requires an explicit operator decision, restores
   the original profile/settings/selection, and must be recorded separately as
   "exit competition mode", never counted as TLS recovery.

Record for each row: expected vs observed outcome, node/role, fresh-connection
proof, failover/attribution result, UTC time and verdict. A pinned LAB loopback
result is not VPS identity acceptance.

If the owner finds the date/pin control insufficient for the frozen contract,
evaluate a trusted chain + name verification on a disposable test VPS with its
own approval. Never modify production certificates; an approved exception is
not TLS PASS.

## 7. Selection cache and exit/restore

Stage boundary: HA-03 records the cache/exit/restart/restore **behaviour and
receipts** here, including the complete original profile/settings/selection
restore required by #91; the complete business-application recovery verdict
belongs to HA-05 and hard-failure timing to HA-04. A clean
settings/selection restore does not substitute for an application recovery
result.

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
  profile/settings/selection/TUN/DNS/LAN behaviour and hashes against the
  section 2 backup; these are HA-03 restore rows, not an HA-05 application
  recovery result;
- record the full original snapshot restoration path and the private ACL on the
  backup/recovery material.

## 8. Receipt (sanitized)

For each row record: run ID, HA-03, Windows build, Verge version + installer
SHA-256, actual core path/banner/SHA-256 + provenance, profile version/output
SHA-256, A/B role, mode, outer/inner cache state, actual TCP+UDP bind list,
second-device results, effective-config deviations, command result, UTC time and
verdict (`PASS` only for executed reproducible rows; `NOT RUN` / `BLOCKED` /
`UNKNOWN` otherwise). TLS rows carry their `TLS1`–`TLS5` ID; a rollback row also
states whether it stayed inside competition mode or exited it. Add a stage label
(`HA-03` path/identity/restore, `HA-04` failover timing, `HA-05` business
recovery) and never record an HA-04/HA-05 row as HA-03 PASS. No private YAML,
certificate body, account, secret, session ID or endpoint tuples.

This runbook itself is not evidence. HA-03 remains BLOCKED for every row that
was not executed on the real PC/VPS. HA-03 code landing does not change issue
#91 acceptance state.
