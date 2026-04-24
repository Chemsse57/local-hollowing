# harden.ps1 - Rebuild loop until ThreatCheck reports the loader clean.
#
# Each pipeline run randomises: OLLVM passes, XOR keys (resolve.h), AES key.
# So every attempt produces a materially different binary.
#
# Requires: ThreatCheck.exe (https://github.com/matterpreter/ThreatCheck)
#           Windows Defender must be ENABLED for ThreatCheck to work (it queries
#           AMSI / MsMpEng).
#
# Usage:
#   .\scripts\harden.ps1
#   .\scripts\harden.ps1 -MaxAttempts 30
#   .\scripts\harden.ps1 -InputPath input\mimikatz.exe
#   .\scripts\harden.ps1 -ThreatCheck "C:\Tools\ThreatCheck\ThreatCheck.exe"

param(
    [string]$InputPath,
    [int]$MaxAttempts = 20,
    [string]$ThreatCheck = "ThreatCheck.exe"
)

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent
$OUTPUT_EXE   = Join-Path $PROJECT_ROOT "output\LocalHollowing.exe"
$SCRIPTS_DIR  = $PSScriptRoot
$LOG_FILE     = Join-Path $PROJECT_ROOT "output\harden.log"

# -- Resolve ThreatCheck path --------------------------------------------------

$tcCmd = Get-Command $ThreatCheck -ErrorAction SilentlyContinue
if (-not $tcCmd) {
    Write-Error "ThreatCheck not found: $ThreatCheck"
    Write-Host "Pass -ThreatCheck <absolute_path> or add it to PATH." -ForegroundColor Yellow
    Write-Host "Download: https://github.com/matterpreter/ThreatCheck" -ForegroundColor Yellow
    exit 1
}
$TC_PATH = $tcCmd.Source

# -- Verify Defender is enabled (ThreatCheck needs it) -------------------------

$defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defStatus -and -not $defStatus.AntivirusEnabled) {
    Write-Warning "Windows Defender AV is DISABLED. ThreatCheck may return false 'clean' results."
    Write-Host "Re-enable Defender before running harden.ps1 for meaningful results." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Yellow
Write-Host "   Harden Loop : build until AV-clean" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Yellow
Write-Host "ThreatCheck  : $TC_PATH"        -ForegroundColor DarkGray
Write-Host "Max attempts : $MaxAttempts"    -ForegroundColor DarkGray
Write-Host "Log          : $LOG_FILE"       -ForegroundColor DarkGray
Write-Host ""

"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Harden loop start" | Out-File $LOG_FILE

$success = $false
$attempt = 0
for ($i = 1; $i -le $MaxAttempts; $i++) {
    $attempt = $i
    Write-Host ""
    Write-Host "===== Attempt $i / $MaxAttempts =====" -ForegroundColor Magenta

    # Build with new random params
    $buildArgs = @()
    if ($InputPath) { $buildArgs = @('-InputPath', $InputPath) }
    & "$SCRIPTS_DIR\run_pipeline.ps1" @buildArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Pipeline build failed on attempt $i"
        "[$i] BUILD FAILED" | Out-File $LOG_FILE -Append
        exit 1
    }

    if (-not (Test-Path $OUTPUT_EXE)) {
        Write-Error "Output binary not produced: $OUTPUT_EXE"
        exit 1
    }

    $size = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1KB, 1)
    Write-Host "[*] Built $OUTPUT_EXE ($size KB)" -ForegroundColor Cyan

    # Run ThreatCheck
    Write-Host "[*] Running ThreatCheck..." -ForegroundColor Cyan
    $tcOutput = & $TC_PATH -f $OUTPUT_EXE 2>&1 | Out-String

    # Clean detection: only if ThreatCheck explicitly reports no threat
    $isClean = ($tcOutput -match 'No threat (found|detected)' -or
                $tcOutput -match 'file is clean' -or
                $tcOutput -match 'not detected')

    if ($isClean) {
        Write-Host "[+] Attempt $i : CLEAN" -ForegroundColor Green
        "[$i] CLEAN  size=${size}KB" | Out-File $LOG_FILE -Append
        $success = $true
        break
    } else {
        # Log first interesting line for quick glance
        $firstLine = ($tcOutput -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 3) -join ' | '
        Write-Host "[-] Attempt $i : DETECTED - $firstLine" -ForegroundColor Red
        "[$i] DETECTED size=${size}KB  $firstLine" | Out-File $LOG_FILE -Append
    }
}

# -- Final report --------------------------------------------------------------

Write-Host ""
Write-Host "=========================================" -ForegroundColor Yellow
if ($success) {
    Write-Host "   SUCCESS after $attempt attempt(s)" -ForegroundColor Green
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $cleanCopy = Join-Path $PROJECT_ROOT "output\LocalHollowing_clean_$ts.exe"
    Copy-Item $OUTPUT_EXE $cleanCopy
    Write-Host "   Current : $OUTPUT_EXE" -ForegroundColor White
    Write-Host "   Saved   : $cleanCopy"  -ForegroundColor White
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SUCCESS attempt=$attempt saved=$cleanCopy" | Out-File $LOG_FILE -Append
    exit 0
} else {
    Write-Host "   FAILED : still detected after $MaxAttempts attempts" -ForegroundColor Red
    Write-Host "   Options : raise -MaxAttempts, tweak main.cpp patterns," -ForegroundColor Yellow
    Write-Host "             or widen OLLVM pass ranges in build.ps1." -ForegroundColor Yellow
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] FAILED after $MaxAttempts attempts" | Out-File $LOG_FILE -Append
    exit 1
}
Write-Host "=========================================" -ForegroundColor Yellow
Write-Host ""
