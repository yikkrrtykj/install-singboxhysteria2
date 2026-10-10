param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$qualityExe = Get-Item -LiteralPath $Executable
if ($qualityExe.Name -ne '质量切换.exe' -or $qualityExe.Length -lt 1024 -or $qualityExe.Length -gt 64MB -or ($qualityExe.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw '不是预期的质量切换程序。'
}
$qualityPublisher = '92E0176599764946F7E5AB332A5CEF150355BE9B'
$qualityCertificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $qualityPublisher)
if (!$qualityCertificate.HasPrivateKey -or $qualityCertificate.NotAfter -le (Get-Date)) { throw '公司签名证书不可用。' }
$qualitySigned = Set-AuthenticodeSignature -LiteralPath $qualityExe.FullName -Certificate $qualityCertificate -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
$qualityVerified = Get-AuthenticodeSignature -LiteralPath $qualityExe.FullName
if ($qualitySigned.Status -ne 'Valid' -or $qualityVerified.Status -ne 'Valid' -or $qualityVerified.SignerCertificate.Thumbprint -ne $qualityPublisher -or !$qualityVerified.TimeStamperCertificate) {
    throw '签名或时间戳校验未通过，不能发布。'
}
Write-Output '[PASS] 公司签名及时间戳校验通过；未安装证书或修改系统信任。'
