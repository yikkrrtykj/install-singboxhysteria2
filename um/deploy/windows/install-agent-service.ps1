#Requires -Version 5.1
<#
.SYNOPSIS
  UM-B3 Draft Windows Service installer template for the `windows_terminal` agent.

.DESCRIPTION
  Installs the reviewed `um-agent.exe` as a deliberately unprivileged Windows
  service (default: LocalService, session 0, Manual start). Dry-run/plan is the
  default; without -ConfirmOwnerApproval no change is made.

  HISTORY/BOUNDARIES:
    * This file is a TEMPLATE; it was not executed by UM-B3 delivery work and
      does not install, enable or start anything by itself.
    * It creates NO credential and stores NO secret. R1 (a write-capable
      Mihomo/Clash Verge Rev controller credential) is NOT supported here and
      must not be enabled until the separate Owner risk acceptance (OD-P3) and
      the OD-P7 account/secret decision are recorded.
    * It never modifies Clash Verge Rev / Mihomo / HA-UI configuration; it adds
      no write path and no listening socket.
    * The Windows runtime account and DPAPI/ACL scope are OD-P7 PENDING
      (see um/docs/um-b3-adr-credentials.md). Choosing LocalService here is a
      placeholder minimum, not an approved final decision.
    * Service command line uses the Draft CLI (subject to the code slice):
      `um-agent.exe service --state-dir <dir> --center <url> `
      `--node-class windows_terminal` (the SCM wrapper parses flags; there is
      no literal `run` word). Service account/ACL/DPAPI installation remains
      OD-P7-gated.

.PARAMETER ServiceAccount
  Session-0 service account. Built-in `NT AUTHORITY\LocalService` needs no
  credential. A virtual account `NT SERVICE\<ServiceName>` needs a supported
  SCM/Windows build. Any other user account requires -ServiceCredential
  (interactive Get-Credential; the password is never written to disk/logs by
  this script). `LocalSystem` and `NetworkService` are refused.

.PARAMETER ConfirmOwnerApproval
  Required for any real change. Confirms the Owner-approved account decision
  and that this is a lab/authorized host, not production.

.EXAMPLE
  # Plan only (no changes):
  .\install-agent-service.ps1 -BinaryPath 'C:\build\um-agent.exe' `
      -CenterUrl 'https://ingest.example.xyz'

.EXAMPLE
  # Real install after Owner approval (account/secret decision recorded):
  .\install-agent-service.ps1 -BinaryPath 'C:\build\um-agent.exe' `
      -CenterUrl 'https://ingest.example.xyz' -ConfirmOwnerApproval `
      -ServiceAccount 'NT SERVICE\um-agent' -StartService
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [string]$BinaryPath,

  [Parameter(Mandatory = $true)]
  [string]$CenterUrl,

  [string]$ServiceName = 'um-agent',
  [string]$DisplayName = 'UM Agent (unified monitor node agent)',
  [string]$StateDir = 'C:\ProgramData\UM Agent',
  [string]$ServiceAccount = 'NT AUTHORITY\LocalService',
  [string]$BinarySha256 = '',
  [System.Management.Automation.PSCredential]$ServiceCredential,
  [switch]$ConfirmOwnerApproval,
  [switch]$StartService,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$PlanOnly = [bool]$WhatIfPreference
if ($ServiceName -ne 'um-agent') {
  Fail 'the um-agent SCM wrapper uses the fixed service name ''um-agent''; a different -ServiceName is not supported by this build'
}

function Fail([string]$msg) {
  Write-Error "install-agent-service: $msg"
  exit 1
}
function Step([string]$msg) {
  if ($PlanOnly) { Write-Host "PLAN  $msg" } else { Write-Host "APPLY $msg" }
}
function Invoke-Step([string]$description, [scriptblock]$action) {
  if ($PlanOnly) { Write-Host "PLAN  $description"; return }
  if ($PSCmdlet.ShouldProcess($description, 'Execute')) {
    Write-Host "APPLY $description"
    & $action
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
      throw "command failed with exit code $LASTEXITCODE : $description"
    }
  }
}

# ---------------------------------------------------------------------------
# Guard rails (checked even in a plan so the plan is meaningful)
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $PlanOnly -and -not $isAdmin) {
  Fail 'real installation requires an elevated (Administrator) PowerShell session'
}
if (-not $PlanOnly -and -not $ConfirmOwnerApproval) {
  Fail 'refusing to change the host without -ConfirmOwnerApproval (Owner-approved account/secret decision is OD-P7 PENDING)'
}
if ($ServiceAccount -match '(?i)^(\.?\\?)?(localsystem|system)$|^nt authority\\system$') {
  Fail 'LocalSystem is forbidden for the UM agent (least privilege); choose an unprivileged account'
}
if ($ServiceAccount -match '(?i)^nt authority\\networkservice$') {
  Fail 'NetworkService is not an approved UM agent account'
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) { Fail "binary not found: $BinaryPath" }
if (-not $PlanOnly) {
  $bound = $PSBoundParameters.Keys | Where-Object { $_ -match '(?i)(controller.?secret|r1|mihomo|password)' }
  if ($bound) { Fail "R1/controller-secret provisioning is not supported (found: $($bound -join ', ')); R1 requires a separate Owner risk acceptance" }
}
$center = $null
if (-not [uri]::TryCreate($CenterUrl, [System.UriKind]::Absolute, [ref]$center)) { Fail "invalid -CenterUrl: $CenterUrl" }
$loopback = $center.Host -in @('127.0.0.1', '::1', 'localhost')
if ($center.Scheme -ne 'https' -and -not $loopback) {
  Fail '-CenterUrl must be https:// (plain http is allowed only for loopback tests)'
}
$actualHash = (Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash
if ($BinarySha256) {
  if ($BinarySha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail '-BinarySha256 must be 64 hex characters' }
  if ($BinarySha256.ToLowerInvariant() -ne $actualHash.ToLowerInvariant()) {
    Fail "binary SHA-256 mismatch: expected $BinarySha256 got $actualHash"
  }
  Write-Host "binary SHA-256 verified: $actualHash"
} else {
  Write-Warning "no -BinarySha256 given; verify the build receipt manually before applying (computed $actualHash)"
}

$builtInAccount = $false
$virtualAccount = $false
if ($ServiceAccount -match '(?i)^nt authority\\localservice$') { $builtInAccount = $true }
elseif ($ServiceAccount -match ('(?i)^NT SERVICE\\' + [regex]::Escape($ServiceName) + '$')) { $virtualAccount = $true }
elseif (-not $ServiceCredential) {
  Fail "account '$ServiceAccount' requires -ServiceCredential (use Get-Credential at install time; the script never stores the password)"
}
if ($virtualAccount -and $ServiceCredential) { Fail 'virtual service accounts do not take a password; omit -ServiceCredential' }

Write-Host "target service : $ServiceName"
Write-Host "binary        : $BinaryPath (sha256 $actualHash)"
Write-Host "center        : $CenterUrl"
Write-Host "state dir     : $StateDir"
Write-Host "service account: $ServiceAccount (built-in=$builtInAccount virtual=$virtualAccount)"
Write-Host 'secret policy : no credential/DPAPI secret is created by this template; R1 is disabled; OD-P7 PENDING'

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  if (-not $Force) { Fail "service '$ServiceName' already exists; use -Force only after reviewing the target state" }
  if ($existing.Status -ne 'Stopped') {
    Invoke-Step "stop existing service $ServiceName" { Stop-Service -Name $ServiceName -Force; Start-Sleep -Seconds 1 }
  }
}
if ([Environment]::OSVersion.Version.Major -lt 10) {
  Fail 'Windows 10/11 is the planned target matrix (Q-AGENT-OS PENDING); older OS is unsupported by this template'
}

# ---------------------------------------------------------------------------
# State directory + ACL (no secrets; inherits nothing permissive)
# ---------------------------------------------------------------------------
Invoke-Step "create state directory $StateDir" {
  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
  }
}
$serviceSid = $null
function Resolve-AccountSid([string]$account) {
  try {
    return (New-Object System.Security.Principal.NTAccount($account)).Translate(
      [System.Security.Principal.SecurityIdentifier]).Value
  } catch { return $null }
}
if ($builtInAccount) {
  $serviceSid = 'S-1-5-19' # NT AUTHORITY\LocalService
} elseif ($virtualAccount) {
  # per-service SID is known only after service creation; resolves below
} else {
  $serviceSid = Resolve-AccountSid $ServiceAccount
  if (-not $serviceSid) { Fail "cannot resolve account SID for '$ServiceAccount'" }
}

$aclArgs = @(
  $StateDir, '/inheritance:r',
  '/grant:r', '*S-1-5-18:(OI)(CI)F',   # SYSTEM
  '/grant:r', '*S-1-5-32-544:(OI)(CI)F' # Administrators
)
if ($serviceSid) { $aclArgs += @('/grant:r', "*$($serviceSid):(OI)(CI)M") }
Invoke-Step "apply restrictive ACL to $StateDir" { & icacls @aclArgs | Out-Null }

# The SCM wrapper writes closed-code failures to the Application log. Create the
# event source only for a real apply; this requires elevation and creates no
# secret/credential.
Invoke-Step "create Application log source 'um-agent'" {
  if (-not [System.Diagnostics.EventLog]::SourceExists('um-agent')) {
    New-EventLog -LogName Application -Source 'um-agent'
  }
}

# ---------------------------------------------------------------------------
# Service creation (Manual start; no automatic start/enable)
# ---------------------------------------------------------------------------
$quotedBinary = '"' + $BinaryPath + '"'
# The SCM lifecycle wrapper is `um-agent service` with the run flags; do not
# insert a literal "run" word (the service host parses the flags, not a run
# subcommand). Account/ACL/DPAPI provisioning remains OD-P7-gated.
$binPath = $quotedBinary + ' service --state-dir "' + $StateDir + '" --center "' + $CenterUrl + '" --node-class windows_terminal'
Invoke-Step "create service $ServiceName (Manual start, session 0)" {
  $newServiceArgs = @{
    Name           = $ServiceName
    BinaryPathName = $binPath
    DisplayName    = $DisplayName
    Description    = 'Unified Monitor terminal telemetry agent (read-only; six route tokens; no remote write).'
    StartupType    = 'Manual'
  }
  if ($ServiceCredential) { $newServiceArgs.Credential = $ServiceCredential }
  New-Service @newServiceArgs | Out-Null
  if ($virtualAccount) {
    # Request a per-service SID for ACLs (no password/credential involved).
    & sc.exe sidtype $ServiceName unrestricted | Out-Null
  }
  & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/""/0 | Out-Null
}

if ($virtualAccount -and -not $PlanOnly) {
  $out = (& sc.exe showsid $ServiceName) 2>$null
  if ($out -match 'S-1-5-80-\d+(-\d+)+') { $serviceSid = $Matches[0] }
  if ($serviceSid) {
    & icacls $StateDir /grant:r "*$($serviceSid):(OI)(CI)M" | Out-Null
  } else {
    Write-Warning 'could not resolve the per-service SID; verify ACLs manually before starting the service'
  }
}

# ---------------------------------------------------------------------------
# Optional start (explicit only)
# ---------------------------------------------------------------------------
if ($StartService) {
  if (-not $PlanOnly -and -not $ConfirmOwnerApproval) {
    Fail '-StartService also requires -ConfirmOwnerApproval'
  }
  Invoke-Step "start service $ServiceName" { Start-Service -Name $ServiceName }
  if (-not $PlanOnly) {
    Get-Service -Name $ServiceName | Format-List Name, Status, StartType
  }
} else {
  Write-Host "service installed but NOT started/enabled; next steps:"
  Write-Host "  1) confirm the Owner-approved account/ACL (OD-P7) and that no secret is needed (R2);"
  Write-Host "  2) Start-Service $ServiceName"; Write-Host "  3) review the Windows event log for closed error codes only (no secrets)"
}

if ($PlanOnly) {
  Write-Host 'PLAN ONLY: no changes were made (re-run with -ConfirmOwnerApproval and without -WhatIf to apply)'
} else {
  Write-Host 'done: service is Manual-start; R1 remains disabled; no credential was created.'
}
