# Administrator's BUILD HOST only. Never include this tool or private key in a client bundle.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Output,
      [Parameter(Mandatory=$true)][ValidatePattern('^CN=[A-Za-z0-9 ._-]{1,80}$')][string]$Subject,
      [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExistingThumbprint)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSModuleAutoloadingPreference='None'
try {
    foreach($m in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','PKI')) {
        Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop
    }
    $path=[IO.Path]::GetFullPath($Output)
    if([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) {throw 'output exists; reuse the recorded identity instead'}
    $parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($path))
    if(-not $parent.Exists) {throw 'existing output parent required'}
    while($null -ne $parent) {
        if(($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'unsafe output parent'}
        $parent=$parent.Parent
    }
    # Reserve before key creation. A crash leaves an explicit incomplete directory,
    # rather than silently generating another publisher on the next run.
    [void][IO.Directory]::CreateDirectory($path)
    if($ExistingThumbprint) {
        $certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$ExistingThumbprint) -ErrorAction Stop
        if($certificate.Subject -ne $Subject) {throw 'subject mismatch'}
    } else {
        $certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
            -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable `
            -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 3072 `
            -HashAlgorithm SHA256 -NotAfter ([DateTime]::Now.AddYears(2))
    }
    if(-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now -or $certificate.NotBefore -gt [DateTime]::Now) {throw 'valid private signing identity required'}
    $extensions=@($certificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'})
    if($extensions.Count -ne 1) {throw 'code-only EKU required'}
    $eku=@($extensions[0].EnhancedKeyUsages | ForEach-Object {$_.Value})
    if($eku.Count -ne 1 -or $eku[0] -ne '1.3.6.1.5.5.7.3.3' -or $certificate.PublicKey.Key.KeySize -lt 3072) {throw 'code-only RSA identity required'}
    $public=[byte[]]$certificate.RawData
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=[BitConverter]::ToString($sha.ComputeHash($public)).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
    [IO.File]::WriteAllBytes((Join-Path $path 'publisher.cer'),$public)
    $record=[ordered]@{v=1;kind='company-internal-code-publisher/1';subject=$certificate.Subject;
        publisher=$certificate.Thumbprint;certificate_sha256=$digest;
        not_after=$certificate.NotAfter.ToUniversalTime().ToString('o');
        private_key_exported=$false;trust_installed=$false}
    [IO.File]::WriteAllText((Join-Path $path 'publisher.json'),($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    Write-Output ('[PASS] fixed internal publisher public identity '+($record|ConvertTo-Json -Compress))
    Write-Output '[SKIP] private key export, trust import, client installation and VPS publication'
    exit 0
} catch {
    Write-Output '[FAIL] internal_publisher_unavailable; no automatic identity replacement; retain any incomplete output for administrator recovery'
    exit 2
}
