# Signed generic setup; Client Bundle remains a separate sensitive input.
# Do not add an unsigned fallback or change machine-wide execution/TLS policy.
[CmdletBinding()]
param(
    [ValidateSet('install','rollback','import','status','gui','pause','resume','remove','purge','uninstall')]
    [string]$Operation = 'install',
    [string]$Bundle,
    [string]$Profile,
    [string]$ControllerKeyFile,
    [switch]$PromptControllerSecret
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$PSModuleAutoloadingPreference = 'None'
foreach ($module in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
    try { Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$module,($module + '.psd1'))) -ErrorAction Stop }
    catch { Write-Host '[FAIL] native setup modules unavailable'; exit 2 }
}
$PSModuleAutoloadingPreference = 'None'
$publisher = '@P6_PUBLISHER@'
$failed = $false
$staging = $null
$credentialDirectory = $null

function Diagnostic([bool]$Condition, [string]$Label) {
    if ($Condition) { Write-Host "[PASS] $Label" }
    else { Write-Host "[FAIL] $Label"; $script:failed = $true }
}
function RealPath([string]$Path) {
    $node = [IO.Path]::GetFullPath($Path)
    if ($node.StartsWith('\\') -or $node.Substring(2).Contains(':')) { throw 'network or alternate stream path' }
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
    $openedAcl = $directory.GetAccessControl()
    $owner = $openedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($openedAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($owner -notin @('S-1-5-18','S-1-5-32-544') -or -not $openedAcl.AreAccessRulesProtected -or $rules.Count -ne 2) { throw 'unsafe staging authority' }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'unsafe staging DACL' }
    }
}
# P6_GUI_CODE

function VerifyPackage([string]$Path) {
    foreach ($file in @('P6Setup.exe','Setup.ps1','payload.cat')) {
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
    $total = 0L
    foreach ($name in @('P6Setup.exe','Setup.ps1','payload.cat')) {
        $source = Join-Path $PSScriptRoot $name
        RealPath $source
        $length = (Get-Item -LiteralPath $source -ErrorAction Stop).Length
        if ($length -gt 4194304) { throw 'entry capacity' }
        $total += $length
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
    if ($Operation -eq 'gui') {
        if ($Bundle -or $Profile -or $ControllerKeyFile -or $PromptControllerSecret) { throw 'graphical input must be selected in window' }
        Show-P6Manager $python $entry $staging $common
        exit 0
    }
    $arguments = @('-I','-B',$entry,$Operation,'--package',$staging)
    if ($PromptControllerSecret) {
        if ($ControllerKeyFile -or $Operation -notin @('install','import')) { throw 'invalid credential interaction' }
        $credentialDirectory = Join-Path $common ('P6Credential-' + [Guid]::NewGuid().ToString('N'))
        ProtectedDirectory $credentialDirectory
        $ControllerKeyFile = Join-Path $credentialDirectory 'mihomo.key'
        $credential = Read-Host 'Local Mihomo controller secret (empty if no authentication)' -AsSecureString
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential)
        $bytes = $null
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
            if ($bytes.Length -gt 4096) { throw 'credential capacity' }
            [IO.File]::WriteAllBytes($ControllerKeyFile,$bytes)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            if ($bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
            $plain = $null
            $credential.Dispose()
        }
    }
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
    if ($credentialDirectory -and (Test-Path -LiteralPath $credentialDirectory)) {
        try {
            RealPath $credentialDirectory
            $keyPath = Join-Path $credentialDirectory 'mihomo.key'
            if (Test-Path -LiteralPath $keyPath) { RealPath $keyPath; Remove-Item -LiteralPath $keyPath -Force -ErrorAction Stop }
            Remove-Item -LiteralPath $credentialDirectory -Force -ErrorAction Stop
        } catch { Write-Host '[SKIP] protected credential staging retained for manual cleanup' }
    }
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
