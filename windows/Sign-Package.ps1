# Build-host only. Uses a certificate already held in the Windows cert store;
# no private-key/password arguments, no certificate creation/trust changes.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Package,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
      [Parameter(Mandatory=$true)][ValidatePattern('^https?://')][string]$TimestampServer)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$PSModuleAutoloadingPreference = 'None'
try {
    foreach ($module in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
        Import-Module -Name ([IO.Path]::Combine($PSHOME,'Modules',$module,($module + '.psd1'))) -ErrorAction Stop
    }
    $PSModuleAutoloadingPreference = 'None'
    $uri = [Uri]$TimestampServer
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http','https') -or -not $uri.Host -or $uri.UserInfo -or $uri.Fragment) { throw 'invalid timestamp endpoint' }
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $CertificateThumbprint) -ErrorAction Stop
    if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now) { throw 'signing unavailable' }
    $catalogPath = Join-Path $Package 'payload.cat'
    if (Test-Path -LiteralPath $catalogPath) { throw 'catalog already exists' }
    New-FileCatalog -Path (Join-Path $Package 'payload') -CatalogFilePath $catalogPath -CatalogVersion 2.0 -ErrorAction Stop | Out-Null
    foreach ($file in @((Join-Path $Package 'P6Setup.exe'), (Join-Path $Package 'Setup.ps1'), $catalogPath)) {
        $signature = Set-AuthenticodeSignature -LiteralPath $file -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) { throw 'signature unavailable' }
        if (-not $signature.TimeStamperCertificate) { throw 'timestamp unavailable' }
    }
    if ((Test-FileCatalog -Path (Join-Path $Package 'payload') -CatalogFilePath $catalogPath -ErrorAction Stop) -ne 'Valid') { throw 'catalog mismatch' }
    Write-Host '[PASS] publisher signatures, timestamps and payload catalog verified'
    exit 0
} catch {
    Write-Host '[FAIL] production_release_signing_unavailable'
    exit 2
}
