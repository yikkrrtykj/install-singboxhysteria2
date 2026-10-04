# Run through an independently trusted administrator channel, never auto-run by Setup.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Check','Install','Remove')][string]$Operation,
      [Parameter(Mandatory=$true)][string]$Certificate,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
      [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedPublisher)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$added=[Collections.Generic.List[object]]::new()
$public=$null
try {
    $PSModuleAutoloadingPreference='None'
    foreach($m in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility')) {
        Import-Module ([IO.Path]::Combine($PSHOME,'Modules',$m,($m+'.psd1'))) -ErrorAction Stop
    }
    $path=[IO.Path]::GetFullPath($Certificate)
    $info=[IO.FileInfo]::new($path)
    if(-not $info.Exists -or $info.Length -lt 256 -or $info.Length -gt 16384) {throw 'certificate bounds'}
    $node=$info
    while($null -ne $node) {
        if(($node.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {throw 'unsafe certificate path'}
        if($node -is [IO.FileInfo]) {$node=$node.Directory} else {$node=$node.Parent}
    }
    # One handle, no writer/delete sharing. The verified bytes alone become trust.
    $file=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $raw=[byte[]]::new([int]$file.Length);$offset=0
        while($offset -lt $raw.Length) {$n=$file.Read($raw,$offset,$raw.Length-$offset);if($n -le 0){throw 'short read'};$offset+=$n}
        if($file.ReadByte() -ne -1) {throw 'file grew'}
    } finally {$file.Dispose()}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=[BitConverter]::ToString($sha.ComputeHash($raw)).Replace('-','')} finally {$sha.Dispose()}
    if($digest -ne $ExpectedSha256) {throw 'independent digest mismatch'}
    $public=[Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
    # Require bare DER: PFX/PKCS7/PEM/trailing bytes never accepted as a trust package.
    if([Convert]::ToBase64String($public.RawData) -ne [Convert]::ToBase64String($raw) -or $public.HasPrivateKey `
       -or $public.Thumbprint -ne $ExpectedPublisher -or $public.Subject -ne $public.Issuer) {throw 'publisher binding'}
    $eku=@($public.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'})
    if($eku.Count -ne 1) {throw 'code-only EKU required'}
    $oids=@($eku[0].EnhancedKeyUsages | ForEach-Object {$_.Value})
    if($oids.Count -ne 1 -or $oids[0] -ne '1.3.6.1.5.5.7.3.3' -or $public.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1' `
       -or $public.PublicKey.Key.KeySize -lt 3072) {throw 'code-only RSA identity required'}
    $constraints=@($public.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.19'})
    if($constraints.Count -gt 1 -or ($constraints.Count -eq 1 -and $constraints[0].CertificateAuthority)) {throw 'leaf publisher required'}
    if($Operation -ne 'Remove' -and ($public.NotBefore -gt [DateTime]::Now -or $public.NotAfter -le [DateTime]::Now)) {throw 'certificate expired/not yet valid'}
    # Removal intentionally accepts an expired exact identity for incident response.
    if($Operation -ne 'Check') {
        $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if(-not $admin) {throw 'administrator authority required'}
    }
    $present=[ordered]@{}
    foreach($name in @('Root','TrustedPublisher')) {
        $store=[Security.Cryptography.X509Certificates.X509Store]::new($name,'LocalMachine')
        try {
            $flags=if($Operation -eq 'Check') {[Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly} else {[Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite}
            $store.Open($flags)
            $matches=@($store.Certificates | Where-Object {$_.Thumbprint -eq $ExpectedPublisher})
            foreach($entry in $matches) {
                if([Convert]::ToBase64String($entry.RawData) -ne [Convert]::ToBase64String($raw)) {throw 'store identity collision'}
            }
            if($Operation -eq 'Install' -and $matches.Count -eq 0) {
                $store.Add($public);$added.Add(@{name=$name;certificate=$public})
            } elseif($Operation -eq 'Remove') {
                foreach($entry in $matches) {$store.Remove($entry)}
            }
            $after=@($store.Certificates | Where-Object {$_.Thumbprint -eq $ExpectedPublisher})
            $present[$name]=($after.Count -gt 0)
            if(($Operation -eq 'Install' -and $after.Count -ne 1) -or ($Operation -eq 'Remove' -and $after.Count -ne 0)) {throw 'trust readback mismatch'}
        } finally {$store.Close()}
    }
    Write-Output ('[PASS] internal publisher '+$Operation+' '+([ordered]@{publisher=$public.Thumbprint;stores=$present;private_key_imported=$false}|ConvertTo-Json -Compress))
    Write-Output '[SKIP] execution-policy changes, TLS certificate import, service/Clash/VPS operations'
    exit 0
} catch {
    # Roll back only this operation's newly added public entries, never previous trust.
    foreach($entry in $added) {
        $rollback=[Security.Cryptography.X509Certificates.X509Store]::new($entry.name,'LocalMachine')
        try {$rollback.Open('ReadWrite');$rollback.Remove($entry.certificate)} catch {} finally {$rollback.Close()}
    }
    Write-Output '[FAIL] internal_publisher_trust_unavailable; exact identity required; no unsigned fallback'
    exit 2
} finally {if($null -ne $public){$public.Dispose()}}
