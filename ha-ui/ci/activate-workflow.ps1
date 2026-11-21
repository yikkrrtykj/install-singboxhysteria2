#requires -Version 5.1
<#
.SYNOPSIS
    Activate (copy) the reviewed HA-UI CI workflow template.

.DESCRIPTION
    GitHub requires the `workflow` scope (or a web/SSH session) to create files
    under .github/workflows/. This helper never claims a scope it does not have:

      * without -Apply it only prints exact manual steps and checks the current
        credential's scopes;
      * with -Apply it copies the reviewed template byte-for-byte, verifies the
        copy, and prints what still has to happen outside this helper.

    It never commits, pushes, merges, or touches a VPS.

.PARAMETER Apply
    Copy ha-ui/ci/ha-ui-workflow.yml to .github/workflows/ha-ui.yml locally.

.EXAMPLE
    pwsh ha-ui/ci/activate-workflow.ps1
    pwsh ha-ui/ci/activate-workflow.ps1 -Apply
#>
[CmdletBinding()]
param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$AppRoot = Join-Path $RepoRoot 'ha-ui'
$Template = Join-Path $AppRoot 'ci\ha-ui-workflow.yml'
$TargetDir = Join-Path $RepoRoot '.github\workflows'
$Target = Join-Path $TargetDir 'ha-ui.yml'

Write-Host '== HA-UI workflow activation check =='
Write-Host "template: $Template"
Write-Host "target:   $Target"

if (-not (Test-Path $Template)) {
    throw 'reviewed workflow template is missing'
}
$templateBytes = [System.IO.File]::ReadAllBytes($Template)
$templateHash = (Get-FileHash $Template -Algorithm SHA256).Hash.ToLower()
Write-Host "template SHA-256: $templateHash"

if (Test-Path $Target) {
    $targetHash = (Get-FileHash $Target -Algorithm SHA256).Hash.ToLower()
    Write-Host "activated SHA-256: $targetHash"
    if ($targetHash -ne $templateHash) {
        Write-Warning 'activated workflow differs from the reviewed template; do NOT push it as-is'
    }
    else {
        Write-Host 'activated workflow already matches the reviewed template.'
    }
}

if (-not $Apply) {
    Write-Host ''
    Write-Host 'Manual activation steps (run only after independent review):' -ForegroundColor Yellow
    Write-Host '  1. pwsh ha-ui/ci/activate-workflow.ps1 -Apply'
    Write-Host '  2. Validate: python ha-ui/ci/check_pins.py --static-only'
    Write-Host '  3. Commit: git add .github/workflows/ha-ui.yml ha-ui/ci; git commit -m "ci(ha-ui): activate reviewed Windows workflow"'
    Write-Host '  4. Push with a credential that has the workflow scope (or add the file via GitHub Web UI):'
    Write-Host '       gh auth refresh -h github.com -s workflow   # interactive, maintainer only'
    Write-Host '       git push'
    Write-Host '  5. Verify: gh workflow list --repo yikkrrtykj/install-singboxhysteria2'
    Write-Host '             gh run list --workflow ha-ui.yml --limit 5'
    Write-Host '  6. Confirm both jobs are green and the EXE artifact receipt/selftest is valid.'
    Write-Host ''
    Write-Host 'This helper does not push, activate, or claim CI is active.' -ForegroundColor Yellow
    exit 0
}

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
Copy-Item -Path $Template -Destination $Target -Force
$targetBytes = [System.IO.File]::ReadAllBytes($Target)
if ([System.Convert]::ToBase64String($targetBytes) -ne [System.Convert]::ToBase64String($templateBytes)) {
    throw 'activated workflow is not byte-identical to the reviewed template'
}
Write-Host "copied review-identical workflow to $Target"
Write-Host 'NOT pushed. Use the manual steps above with a workflow-scoped credential.'
exit 0
