# Signed generic setup; Client Bundle remains a separate sensitive input.
# Do not add an unsigned fallback or change machine-wide execution/TLS policy.
[CmdletBinding()]
param(
    [ValidateSet('install','rollback','import','status','pause','resume','remove','purge','uninstall')]
    [string]$Operation = 'install',
    [string]$Bundle,
    [string]$Profile,
    [string]$ControllerKeyFile
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$publisher = '@P6_PUBLISHER@'
$failed = $false
$staging = $null

function Diagnostic([bool]$Condition, [string]$Label) {
    if ($Condition) { Write-Host "[PASS] $Label" }
    else { Write-Host "[FAIL] $Label"; $script:failed = $true }
}
function RealPath([string]$Path) {
    $node = [IO.Path]::GetFullPath($Path)
    while ($node) {
        if (Test-Path -LiteralPath $node) {
            $attributes = [IO.File]::GetAttributes($node)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'unsafe path' }
        }
        $parent = [IO.Path]::GetDirectoryName($node)
        if ($parent -eq $node) { break }
        $node = $parent
    }
}
function ProtectedDirectory([string]$Path) {
    RealPath $Path
    if (Test-Path -LiteralPath $Path) { throw 'staging collision' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    $directory = New-Object IO.DirectoryInfo($Path)
    $directory.Create($acl)
}
function VerifyPackage([string]$Path) {
    foreach ($file in @('Setup.ps1','payload.cat')) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Path $file) -ErrorAction Stop
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $publisher) {
            throw 'publisher verification failed'
        }
    }
    $catalog = Test-FileCatalog -Path (Join-Path $Path 'payload') -CatalogFilePath (Join-Path $Path 'payload.cat') -ErrorAction Stop
    if ($catalog -ne 'Valid') { throw 'catalog mismatch' }
}

try {
    $administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator)
    Diagnostic $administrator 'administrator authority'
    Diagnostic ([Environment]::Is64BitProcess -and [Environment]::OSVersion.Version.Major -ge 10) 'Windows x64 target'
    Diagnostic ($publisher -match '^[A-F0-9]{40}$') 'configured release publisher'
    Diagnostic ($null -ne (Get-Command Test-FileCatalog -ErrorAction SilentlyContinue)) 'native catalog verifier'
    if ($failed) { exit 2 }
    # Bootstrap signature before any runtime byte is executed.
    VerifyPackage $PSScriptRoot
    Write-Host '[PASS] signed setup and payload catalog'
    $common = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    RealPath $common
    $staging = Join-Path $common ('P6Setup-' + [Guid]::NewGuid().ToString('N'))
    ProtectedDirectory $staging
    # Never use recursive Copy-Item on untrusted input. Explicitly enumerate
    # the finite package tree; copied bytes are revalidated under protected ACL.
    foreach ($name in @('Setup.ps1','payload.cat')) {
        $source = Join-Path $PSScriptRoot $name
        RealPath $source
        [IO.File]::Copy($source, (Join-Path $staging $name), $false)
    }
    $payload = Join-Path $staging 'payload'
    ProtectedDirectory $payload
    ProtectedDirectory (Join-Path $payload 'runtime')
    $sourcePayload = Join-Path $PSScriptRoot 'payload'
    RealPath $sourcePayload
    RealPath (Join-Path $sourcePayload 'runtime')
    $objects = @(Get-ChildItem -LiteralPath $sourcePayload -Force -ErrorAction Stop)
    $objects += @(Get-ChildItem -LiteralPath (Join-Path $sourcePayload 'runtime') -Force -ErrorAction Stop)
    if ($objects.Count -gt 68) { throw 'payload capacity' }
    $total = 0L
    foreach ($object in $objects) {
        RealPath $object.FullName
        if ($object.PSIsContainer) {
            if ($object.Name -ne 'runtime' -or $object.Parent.FullName -ne (Join-Path $PSScriptRoot 'payload')) { throw 'payload directory' }
            continue
        }
        $relative = $object.FullName.Substring((Join-Path $PSScriptRoot 'payload').Length + 1)
        if ($relative -notmatch '^(runtime\\[A-Za-z0-9_.-]+|p6-agent\.pyz|p6-installer\.pyz|release\.json)$') { throw 'payload name' }
        $total += $object.Length
        if ($total -gt 67108864) { throw 'payload capacity' }
        [IO.File]::Copy($object.FullName, (Join-Path $payload $relative), $false)
    }
    VerifyPackage $staging
    Write-Host '[PASS] protected payload copy verified'
    $python = Join-Path $payload 'runtime\python.exe'
    $entry = Join-Path $payload 'p6-installer.pyz'
    $arguments = @('-I','-B',$entry,$Operation,'--package',$staging)
    if ($Bundle) { $arguments += @('--bundle',[IO.Path]::GetFullPath($Bundle)) }
    if ($Profile) { $arguments += @('--profile',$Profile) }
    if ($ControllerKeyFile) { $arguments += @('--controller-key-file',[IO.Path]::GetFullPath($ControllerKeyFile)) }
    & $python @arguments
    $result = $LASTEXITCODE
    if ($result -ne 0) { Write-Host '[FAIL] installer operation; protected state retained for retry' }
    exit $result
} catch {
    # Never echo exception/input bodies: they can contain profile credentials.
    Write-Host '[FAIL] windows_setup_unavailable'
    exit 2
} finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        try {
            # Only this exact random directory created above. Validate every
            # object again before recursive removal, never computed glob paths.
            RealPath $staging
            foreach ($object in @(Get-ChildItem -LiteralPath $staging -Recurse -Force -ErrorAction Stop)) { RealPath $object.FullName }
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop
        } catch { Write-Host '[SKIP] protected setup staging retained for manual cleanup' }
    }
}
