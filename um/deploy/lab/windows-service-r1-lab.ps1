# Isolated Windows SCM / virtual-service-account / DPAPI / R1 lab.
# Runs only on a disposable administrator Windows runner or VM. It builds the
# real agent/center from this checkout, creates the synthetic loopback center,
# installs the actual `um-agent` SCM service under NT SERVICE\um-agent, enrolls
# under that service account (DPAPI CurrentUser), provisions the R1 bundle
# through the service account, runs the real service in session 0, and drives a
# real isolated Mihomo controller through the R1 projection. No production
# endpoint, credential or Mihomo configuration is touched.
#
# This script intentionally performs elevated setup only; the agent process is
# never started as administrator/SYSTEM.

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$lab = Join-Path $env:RUNNER_TEMP "um-b3-windows-lab"
$svc = 'um-agent'
$state = Join-Path $lab 'state'
$db = Join-Path $lab 'center.db'
$contracts = Join-Path $repo 'docs\um\contracts\v1'
$agent = Join-Path $lab 'um-agent.exe'
$center = Join-Path $lab 'um-center.exe'
$labtool = Join-Path $lab 'um-lab.exe'
$labSvc = Join-Path $lab 'um-lab-service.exe'
$serviceLog = Join-Path $lab 'service.log'
$tokenFile = Join-Path $lab 'bootstrap.token'
$profilePath = Join-Path $lab 'mihomo-profile.json'
$secretPath = Join-Path $lab 'mihomo.secret'
$mihomoDir = Join-Path $lab 'mihomo'
$mihomoConfig = Join-Path $mihomoDir 'config.yaml'
$mihomoLog = Join-Path $lab 'mihomo.log'
$centerLog = Join-Path $lab 'center.log'
$centerProc = $null
$mihomoProc = $null
$echoListener = $null
$activeProxy = $null

function Fail([string]$msg) { throw "windows-service-r1-lab: $msg" }
function Invoke-Native([string]$exe, [string[]]$arguments) {
  & $exe @arguments
  if ($LASTEXITCODE -ne 0) { Fail "$exe failed with exit $LASTEXITCODE" }
}
function Wait-ServiceStatus([string]$name, [string]$wanted, [int]$seconds = 90) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $s -and $s.Status.ToString() -eq $wanted) { return }
    Start-Sleep -Milliseconds 500
  }
  $s = Get-Service -Name $name -ErrorAction SilentlyContinue
  Fail "service $name did not reach $wanted (current=$($s.Status))"
}
function Get-ServiceSid([string]$name) {
  $out = (& sc.exe showsid $name | Out-String)
  if ($out -match '(S-1-5-80-\d+(-\d+)+)') { return $Matches[1] }
  Fail "cannot resolve service SID for $name"
}
function Set-AgentService([string]$binPath) {
  Invoke-Native 'sc.exe' @('config', $svc, 'binPath=', $binPath)
}
function Start-OneShotService {
  # A one-shot console action legitimately exits quickly; Start-Service may
  # report "failed to start" even though the child completed. Treat the durable
  # state checks below as the authority for one-shot actions.
  Start-Service -Name $svc -ErrorAction SilentlyContinue
  Wait-ServiceStatus $svc 'Stopped'
}
function Stop-DeleteService {
  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
  if ($null -ne $s) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    & sc.exe delete $svc | Out-Null
  }
}

function Cleanup {
  $ErrorActionPreference = 'SilentlyContinue'
  if ($null -ne $activeProxy) { $activeProxy.Close() }
  if ($null -ne $echoListener) { $echoListener.Stop() }
  Stop-DeleteService
  if ($null -ne $mihomoProc -and -not $mihomoProc.HasExited) { Stop-Process -Id $mihomoProc.Id -Force }
  if ($null -ne $centerProc -and -not $centerProc.HasExited) { Stop-Process -Id $centerProc.Id -Force }
  Remove-Item -LiteralPath $lab -Recurse -Force
}
trap { Write-Host "LAB ERROR: $_"; Cleanup; throw }

Remove-Item -LiteralPath $lab -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $lab -Force | Out-Null
New-Item -ItemType Directory -Path $state -Force | Out-Null
New-Item -ItemType Directory -Path $mihomoDir -Force | Out-Null
Stop-DeleteService

Push-Location (Join-Path $repo 'um')
try {
  Invoke-Native 'go' @('build', '-trimpath', '-o', $agent, './cmd/um-agent')
  Invoke-Native 'go' @('build', '-trimpath', '-o', $center, './cmd/um-center')
  Invoke-Native 'go' @('build', '-trimpath', '-o', $labtool, './cmd/um-lab')
  Invoke-Native 'go' @('build', '-trimpath', '-o', $labSvc, './cmd/um-lab-service')
} finally { Pop-Location }

# ---------------------------------------------------------------------------
# Real local center + real SQLite, one synthetic token.
# ---------------------------------------------------------------------------
$event = [guid]::NewGuid().ToString()
$token = (& $center -contracts $contracts -db $db -issue-enroll-token -token-event $event -token-class windows_terminal | Select-Object -Last 1)
if ([string]::IsNullOrWhiteSpace($token)) { Fail 'center token issue failed' }
Set-Content -LiteralPath $tokenFile -Value $token -NoNewline -Encoding ascii
$centerProc = Start-Process -FilePath $center -ArgumentList @('-contracts', $contracts, '-db', $db, '-ingest', '127.0.0.1:18080', '-admin', '127.0.0.1:18081') -RedirectStandardOutput $centerLog -RedirectStandardError ($centerLog + '.err') -PassThru
$deadline = (Get-Date).AddSeconds(30)
$healthy = $false
while ((Get-Date) -lt $deadline) {
  try { Invoke-RestMethod -Uri 'http://127.0.0.1:18081/api/health' -TimeoutSec 1 | Out-Null; $healthy = $true; break } catch { Start-Sleep -Milliseconds 300 }
}
if (-not $healthy) { Fail 'center did not become healthy' }

# ---------------------------------------------------------------------------
# Service account + enrollment under that account (DPAPI CurrentUser).
# ---------------------------------------------------------------------------
$enrollPath = '"' + $labSvc + '" --log "' + $serviceLog + '" "' + $agent + '" enroll --state-dir "' + $state + '" --center "http://127.0.0.1:18080" --node-class windows_terminal --token-file "' + $tokenFile + '"'
Invoke-Native 'sc.exe' @('create', $svc, 'binPath=', $enrollPath, 'start=', 'demand', 'obj=', "NT SERVICE\$svc")
Invoke-Native 'sc.exe' @('sidtype', $svc, 'unrestricted')
$sid = Get-ServiceSid $svc
Invoke-Native 'icacls' @($lab, '/grant', "*${sid}:(OI)(CI)M", '/T')
Invoke-Native 'icacls' @($state, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "*${sid}:(OI)(CI)F", '/T')
Invoke-Native 'icacls' @($tokenFile, '/grant', "*${sid}:R")
Start-OneShotService
$identity = Get-Content -LiteralPath (Join-Path $state 'identity.json') -Raw | ConvertFrom-Json
$nodeID = $identity.node_id
if ([string]::IsNullOrWhiteSpace($nodeID)) { Fail 'enrollment did not persist identity' }
if (-not ($identity.PSObject.Properties.Name -contains 'private_key_dpapi') -or
    ($identity.PSObject.Properties.Name -contains 'private_key')) {
  Fail 'identity private key is not DPAPI-protected in the service-account state'
}
$qc = (& sc.exe qc $svc | Out-String)
if ($qc -notmatch [regex]::Escape("NT SERVICE\$svc")) { Fail 'SCM start account is not the virtual service account' }

# ---------------------------------------------------------------------------
# Rotation provisional key must also be DPAPI protected. Run rotate through the
# same temporary service; the actual service later recovers the proof.
# ---------------------------------------------------------------------------
$rotatePath = '"' + $labSvc + '" --log "' + $serviceLog + '" "' + $agent + '" rotate --state-dir "' + $state + '" --center "http://127.0.0.1:18080" --node-class windows_terminal'
Set-AgentService $rotatePath
Start-OneShotService
$rotationFile = Join-Path $state 'rotation.json'
if (Test-Path -LiteralPath $rotationFile) {
  $rotation = Get-Content -LiteralPath $rotationFile -Raw | ConvertFrom-Json
  if (-not ($rotation.PSObject.Properties.Name -contains 'new_private_key_dpapi') -or
      ($rotation.PSObject.Properties.Name -contains 'new_private_key')) {
    Fail 'rotation provisional key is not DPAPI-protected'
  }
}

# ---------------------------------------------------------------------------
# Isolated real Mihomo controller (R1 write-capable controller, GET-only client).
# ---------------------------------------------------------------------------
$release = Invoke-RestMethod -Headers @{'User-Agent'='um-b3-lab'} -Uri 'https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33'
$asset = $release.assets | Where-Object { $_.name -match '(?i)windows-amd64.*\.zip$' } | Select-Object -First 1
if ($null -eq $asset) { Fail 'Mihomo v1.19.33 windows-amd64 zip not found' }
$mihomoZip = Join-Path $lab $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $mihomoZip -UseBasicParsing
Expand-Archive -LiteralPath $mihomoZip -DestinationPath (Join-Path $mihomoDir 'bin') -Force
$mihomoExe = Get-ChildItem -Path (Join-Path $mihomoDir 'bin') -Recurse -Filter 'mihomo*.exe' | Select-Object -First 1
if ($null -eq $mihomoExe) { Fail 'Mihomo executable not found' }
@'
mixed-port: 19091
external-controller: 127.0.0.1:19090
secret: synthetic-r1-controller-secret
log-level: info
proxies:
  - {name: A_REALITY, type: socks5, server: 127.0.0.1, port: 9}
  - {name: A_HY2, type: socks5, server: 127.0.0.1, port: 9}
  - {name: B_REALITY, type: socks5, server: 127.0.0.1, port: 9}
  - {name: B_HY2, type: socks5, server: 127.0.0.1, port: 9}
proxy-groups:
  - {name: UM, type: select, proxies: [DIRECT, A_REALITY, A_HY2, B_REALITY, B_HY2]}
rules:
  - MATCH,UM
'@ | Set-Content -LiteralPath $mihomoConfig -Encoding utf8
$mihomoHashBefore = (Get-FileHash -LiteralPath $mihomoConfig -Algorithm SHA256).Hash
$mihomoProc = Start-Process -FilePath $mihomoExe.FullName -ArgumentList @('-d', $mihomoDir, '-f', $mihomoConfig) -RedirectStandardOutput $mihomoLog -RedirectStandardError ($mihomoLog + '.err') -PassThru
$deadline = (Get-Date).AddSeconds(30)
$controllerReady = $false
while ((Get-Date) -lt $deadline) {
  try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:19090/version' -Headers @{Authorization='Bearer synthetic-r1-controller-secret'} -TimeoutSec 1 | Out-Null
    $controllerReady = $true; break
  } catch { Start-Sleep -Milliseconds 300 }
}
if (-not $controllerReady) { Fail 'isolated Mihomo controller did not start' }
Set-Content -LiteralPath $profilePath -Value (@{
  controller = 'http://127.0.0.1:19090'
  group = 'UM'
  routes = @{ a_reality='A_REALITY'; a_hy2='A_HY2'; b_reality='B_REALITY'; b_hy2='B_HY2'; direct='DIRECT' }
} | ConvertTo-Json -Compress) -Encoding ascii
Set-Content -LiteralPath $secretPath -Value 'synthetic-r1-controller-secret' -NoNewline -Encoding ascii
Invoke-Native 'icacls' @($profilePath, '/grant', "*${sid}:R")
Invoke-Native 'icacls' @($secretPath, '/grant', "*${sid}:R")

# Provision the protected R1 bundle through the same service account.
$provisionPath = '"' + $labSvc + '" --log "' + $serviceLog + '" "' + $agent + '" r1-provision --state-dir "' + $state + '" --profile "' + $profilePath + '" --secret-file "' + $secretPath + '" --owner-reference "OD-P3-R1/isolated-lab/windows-github-actions"'
Set-AgentService $provisionPath
Start-OneShotService
if (-not (Test-Path -LiteralPath (Join-Path $state 'r1\acceptance.json'))) { Fail 'R1 authorization record was not provisioned' }
if (-not (Test-Path -LiteralPath (Join-Path $state 'r1\controller.secret.dpapi'))) { Fail 'R1 sealed credential was not provisioned' }
$aclState = (& icacls $state | Out-String)
if ($aclState -match '(?i)BUILTIN\\Users|Everyone|Authenticated Users') { Fail 'state ACL grants a broad principal' }

# ---------------------------------------------------------------------------
# Real service in session 0 with R1 enabled, plus center config for terminal.
# ---------------------------------------------------------------------------
$runPath = '"' + $agent + '" service --state-dir "' + $state + '" --center "http://127.0.0.1:18080" --node-class windows_terminal'
Set-AgentService $runPath
Start-Service -Name $svc
Wait-ServiceStatus $svc 'Running'
$svcInfo = Get-CimInstance Win32_Service -Filter "Name='$svc'"
if ($svcInfo.StartName -notmatch '(?i)NT SERVICE\\um-agent') { Fail "service StartName=$($svcInfo.StartName)" }
$proc = Get-Process -Id $svcInfo.ProcessId
if ($proc.SessionId -ne 0) { Fail "service process session=$($proc.SessionId), want 0" }
if ($proc.Id -eq $PID) { Fail 'synthetic lab must not run agent in the admin runner session' }
Invoke-Native $labtool @('configure', '--db', $db, '--node-id', $nodeID, '--sources', 'terminal=true,mihomo_api=true,events=true', '--cadence', '30')
Restart-Service -Name $svc
Wait-ServiceStatus $svc 'Running'

function Get-LatestPayload {
  $summary = (& $labtool summary --db $db --node-id $nodeID --print-payload | Out-String) | ConvertFrom-Json
  if ($null -eq $summary.latest_snapshot -or [string]::IsNullOrWhiteSpace($summary.latest_snapshot.payload)) { return $null }
  return ($summary.latest_snapshot.payload | ConvertFrom-Json)
}

$deadline = (Get-Date).AddSeconds(60)
$payload = $null
while ((Get-Date) -lt $deadline) {
  $payload = Get-LatestPayload
  if ($null -ne $payload -and $null -ne $payload.terminal) { break }
  Start-Sleep -Milliseconds 500
}
if ($null -eq $payload -or $null -eq $payload.terminal) { Fail 'real center did not receive a terminal snapshot' }
if ($payload.terminal.selection.availability -ne 'ok') { Fail "R1 selection availability=$($payload.terminal.selection.availability)" }
if ($null -eq $payload.terminal.selection.route) { Fail 'R1 selection route is null' }
if (($payload | ConvertTo-Json -Depth 20) -match 'A_REALITY|A_HY2|B_REALITY|B_HY2|synthetic-r1-controller-secret|127\.0\.0\.1:19090') {
  Fail 'R1 snapshot leaked local profile/controller metadata'
}

# Selection path coverage through the isolated controller; the lab harness is
# the only actor allowed to PUT selection. The agent keeps GET-only.
foreach ($pair in @(@('A_REALITY','a_reality'), @('A_HY2','a_hy2'), @('B_REALITY','b_reality'), @('B_HY2','b_hy2'), @('DIRECT','direct'))) {
  Invoke-RestMethod -Method Put -Uri 'http://127.0.0.1:19090/proxies/UM' -Headers @{Authorization='Bearer synthetic-r1-controller-secret'} -ContentType 'application/json' -Body (@{name=$pair[0]} | ConvertTo-Json -Compress) | Out-Null
  $projection = (& $labtool r1-project --profile $profilePath --secret $secretPath | Out-String) | ConvertFrom-Json
  if ($projection.selection.state -ne 'observed' -or $projection.selection.role -ne $pair[1]) {
    Fail "selection $($pair[0]) projected as $($projection.selection.role)/$($projection.selection.state)"
  }
}

# Active-connection coverage with a real loopback CONNECT through the isolated
# mixed inbound while the group selects DIRECT.
Invoke-RestMethod -Method Put -Uri 'http://127.0.0.1:19090/proxies/UM' -Headers @{Authorization='Bearer synthetic-r1-controller-secret'} -ContentType 'application/json' -Body '{"name":"DIRECT"}' | Out-Null
$echoListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 19092)
$echoListener.Start()
$echoAccept = $echoListener.BeginAcceptTcpClient($null, $null)
$activeProxy = [System.Net.Sockets.TcpClient]::new('127.0.0.1', 19091)
$stream = $activeProxy.GetStream()
$writer = [System.IO.StreamWriter]::new($stream)
$writer.NewLine = "`r`n"
$writer.WriteLine('CONNECT 127.0.0.1:19092 HTTP/1.1')
$writer.WriteLine('Host: 127.0.0.1:19092')
$writer.WriteLine('')
$writer.Flush()
$reader = [System.IO.StreamReader]::new($stream)
$statusLine = $reader.ReadLine()
if ($statusLine -notmatch '200') { Fail "mixed inbound CONNECT failed: $statusLine" }
Start-Sleep -Milliseconds 500
$projection = (& $labtool r1-project --profile $profilePath --secret $secretPath | Out-String) | ConvertFrom-Json
if ($projection.active_connections.state -ne 'observed' -or
    ($projection.active_connections.counts.direct + 0) -lt 1) {
  Fail "active direct connection not projected: $($projection.active_connections | ConvertTo-Json -Compress)"
}
$payloadAfterActive = Get-LatestPayload
if ($null -eq $payloadAfterActive -or $null -eq $payloadAfterActive.terminal -or
    $payloadAfterActive.terminal.active_connections.availability -ne 'ok' -or
    ($payloadAfterActive.terminal.active_connections.by_route.direct + 0) -lt 1) {
  Fail "persisted terminal active connection not observed: $($payloadAfterActive.terminal | ConvertTo-Json -Compress -Depth 10)"
}
$activeProxy.Close(); $activeProxy = $null
$echoListener.Stop(); $echoListener = $null

# Controller loss must degrade honestly, never fake healthy data.
Stop-Process -Id $mihomoProc.Id -Force
Wait-Process -Id $mihomoProc.Id -Timeout 10 -ErrorAction SilentlyContinue
$mihomoProc = $null
Restart-Service -Name $svc
Wait-ServiceStatus $svc 'Running'
Start-Sleep -Seconds 35
$payload = Get-LatestPayload
if ($null -eq $payload -or $null -eq $payload.terminal) { Fail 'snapshot missing after controller loss' }
if ($payload.terminal.selection.availability -notin @('unavailable','partial')) {
  Fail "terminal selection after controller loss = $($payload.terminal.selection.availability)"
}
$mihomoHashAfter = (Get-FileHash -LiteralPath $mihomoConfig -Algorithm SHA256).Hash
if ($mihomoHashBefore -ne $mihomoHashAfter) { Fail 'Mihomo config changed during R1 lab' }

# Stop/start and identity/state recovery.
Stop-Service -Name $svc -Force
Wait-ServiceStatus $svc 'Stopped'
Start-Service -Name $svc
Wait-ServiceStatus $svc 'Running'
$identity2 = Get-Content -LiteralPath (Join-Path $state 'identity.json') -Raw | ConvertFrom-Json
if ($identity2.node_id -ne $nodeID) { Fail 'identity changed across service restart' }
if (-not ($identity2.PSObject.Properties.Name -contains 'private_key_dpapi')) { Fail 'DPAPI identity lost after restart' }

Stop-Service -Name $svc -Force
Wait-ServiceStatus $svc 'Stopped'
Invoke-Native 'icacls' @($state, '/remove', "*$sid")
Stop-DeleteService
Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $lab 'r1') -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'windows-service-r1-lab: PASS'
