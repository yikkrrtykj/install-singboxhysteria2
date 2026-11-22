#requires -Version 5.1
<#
.SYNOPSIS
    Local mirror of the HA-UI Windows CI job.

.DESCRIPTION
    Runs the same gates as windows-tests + windows-exe in
    ha-ui/ci/ha-ui-workflow.yml, without any VPS/network/credential access:

      * Python 3.13 + exact pinned dependency gate
      * offscreen pytest (Windows ACL tests included)
      * GUI cold-start self-test
      * PyInstaller EXE build with EXE self-test
      * receipt/EXE SHA-256 verification

    Outputs stay under .scratch/ci and dist/ (both git-ignored). This script is a
    convenience/acceptance harness; it does not activate the GitHub workflow and
    does not replace a real Windows + two-VPS acceptance run.

.PARAMETER SkipInstall
    Do not run pip install (use when the venv was prepared earlier).

.PARAMETER SkipBuild
    Run tests/self-test only (fast pre-merge check).

.EXAMPLE
    pwsh ha-ui/ci/run-windows-ci.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$SkipBuild,
    [string]$Python = ""
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$AppRoot = Join-Path $RepoRoot 'ha-ui'
$Scratch = Join-Path $RepoRoot '.scratch\ci'
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$env:QT_QPA_PLATFORM = 'offscreen'
$env:HA_UI_HOME = Join-Path $Scratch 'home'
$env:HA_UI_TOOLS_DIR = Join-Path $RepoRoot 'tools'
$Summary = [ordered]@{
    schema = 'ha-ui/local-ci/1'
    started_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    host = 'windows'
    python = $null
    pytest_rc = $null
    selftest_rc = $null
    exe = $null
    exe_sha256 = $null
    receipt_sha256 = $null
    ok = $false
}

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "== $Name ==" -ForegroundColor Cyan
    & $Body
}

function Assert-LastExit([string]$Label) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed (exit $LASTEXITCODE)"
    }
}

$PythonPath = $Python
if (-not $PythonPath) { $PythonPath = $env:HA_UI_PYTHON }
if (-not $PythonPath) {
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command) { $PythonPath = $command.Source }
}
if (-not $PythonPath) {
    throw "python 3.13 not found; pass -Python <path> or activate the pinned venv"
}
$Summary.python = (& $PythonPath -c "import sys; print('%d.%d.%d' % sys.version_info[:3])")
if (-not $Summary.python -or -not $Summary.python.StartsWith('3.13.')) {
    throw "CI requires Python 3.13.x, found $($Summary.python)"
}
$env:HA_UI_PYTHON = $PythonPath

try {
    if (-not $SkipInstall) {
        Step 'install pinned dependencies' {
            & $Python -m pip install --disable-pip-version-check -r (Join-Path $AppRoot 'requirements-dev.txt')
            Assert-LastExit 'pip install'
        }
    }

    Step 'pip check' {
        & $Python -m pip check
        Assert-LastExit 'pip check'
    }
    Step 'exact pin gate' {
        & $Python (Join-Path $AppRoot 'ci\check_pins.py')
        Assert-LastExit 'pin gate'
    }

    Push-Location $AppRoot
    try {
        Step 'pytest (offscreen Qt)' {
            $junit = Join-Path $Scratch 'pytest-ha-ui.xml'
            & $Python -m pytest tests -q "--junitxml=$junit"
            $Summary.pytest_rc = $LASTEXITCODE
            Assert-LastExit 'pytest'
        }
        Step 'GUI cold-start self-test' {
            & $Python -m ha_ui.app --self-test
            $Summary.selftest_rc = $LASTEXITCODE
            Assert-LastExit 'self-test'
        }
    }
    finally {
        Pop-Location
    }

    if (-not $SkipBuild) {
        Step 'build EXE (includes EXE self-test)' {
            & $Python (Join-Path $AppRoot 'scripts\build_windows.py')
            Assert-LastExit 'EXE build'
        }
        Step 'verify receipt, source/tool hashes and EXE SHA-256' {
            & $Python (Join-Path $AppRoot 'ci\verify_receipt.py') --dist (Join-Path $RepoRoot 'dist')
            Assert-LastExit 'receipt verification'
            $dist = Join-Path $RepoRoot 'dist'
            $receiptPath = Join-Path $dist 'receipt.json'
            $receipt = Get-Content $receiptPath -Raw | ConvertFrom-Json
            $Summary.exe = Join-Path $dist 'ha-ui.exe'
            $Summary.exe_sha256 = $receipt.exe_sha256
            $Summary.receipt_sha256 = (Get-FileHash $receiptPath -Algorithm SHA256).Hash.ToLower()
            Write-Host "EXE SHA-256: $($receipt.exe_sha256)"
        }
        Step 'verify SHA256SUMS hashes every built artifact' {
            & $Python (Join-Path $AppRoot 'ci\verify_artifact_sums.py') --dist (Join-Path $RepoRoot 'dist')
            Assert-LastExit 'artifact sums verification'
        }
    }

    $Summary.ok = $true
    Write-Host '== local CI: OK ==' -ForegroundColor Green
}
catch {
    $Summary.ok = $false
    $Summary.error = $_.Exception.Message
    throw
}
finally {
    $Summary.finished_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Summary | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $Scratch 'summary.json')
    Write-Host "summary: $(Join-Path $Scratch 'summary.json')"
}
