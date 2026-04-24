# build.ps1 - Compile LocalHollowing with OLLVM and randomized obfuscation flags.
#
# Each run randomises the OLLVM pass parameters so every build is unique.
# Constraint: never bcf_loop>=3 AND bcf_prob>=60 simultaneously (binary size explodes).
#
# Usage:
#   .\build.ps1             # randomized OLLVM flags
#   .\build.ps1 -NoObf      # no obfuscation (debug / diagnose crashes)
#
# -- CONFIGURE THESE PATHS ----------------------------------------------------

param(
    [switch]$NoObf
)

# vcvarsall.bat for the MSVC environment (adjust Community/Enterprise/BuildTools)
$VCVARSALL = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"

# Directory containing clang-cl.exe and lld-link.exe (VS-bundled LLVM with OLLVM passes)
$OLLVM_BIN = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin"

# -----------------------------------------------------------------------------

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent
$SOURCE_DIR   = Join-Path $PROJECT_ROOT "LocalHollowing"
$OUTPUT_DIR   = Join-Path $PROJECT_ROOT "output"
$OBJ_FILE     = Join-Path $OUTPUT_DIR   "main.obj"
$OUTPUT_EXE   = Join-Path $OUTPUT_DIR   "LocalHollowing.exe"
$CLANG_CL     = Join-Path $OLLVM_BIN    "clang-cl.exe"
$LLD_LINK     = Join-Path $OLLVM_BIN    "lld-link.exe"

# -- VALIDATE TOOLCHAIN -------------------------------------------------------

if (-not (Test-Path $VCVARSALL)) {
    Write-Error "vcvarsall.bat not found: $VCVARSALL"
    exit 1
}
if (-not (Test-Path $CLANG_CL)) {
    Write-Error "clang-cl.exe not found: $CLANG_CL"
    exit 1
}
if (-not (Test-Path $LLD_LINK)) {
    Write-Error "lld-link.exe not found: $LLD_LINK"
    exit 1
}

# -- RANDOMISE OLLVM FLAGS ----------------------------------------------------

$ollvmFlags = @()
$ollvmLog   = @()

if ($NoObf) {
    Write-Host ""
    Write-Host "[!] -NoObf set: building without OLLVM passes (diagnostic)" -ForegroundColor Yellow
}

# Instruction substitution  (80% chance)
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 80) {
    $subLoop = Get-Random -Minimum 1 -Maximum 3   # 1 or 2
    $ollvmFlags += '-mllvm', '-sub', '-mllvm', "-sub_loop=$subLoop"
    $ollvmLog   += "sub(loop=$subLoop)"
}

# Control flow flattening  (70% chance)
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 70) {
    $ollvmFlags += '-mllvm', '-fla'
    $ollvmLog   += 'fla'
}

# Bogus control flow  (80% chance)
# Hard constraint: bcf_loop in [1,2], bcf_prob in [30,60] -> size stays sane
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 80) {
    $bcfLoop = Get-Random -Minimum 1 -Maximum 3   # 1 or 2
    $bcfProb = Get-Random -Minimum 30 -Maximum 61 # 30-60
    $ollvmFlags += '-mllvm', '-bcf', '-mllvm', "-bcf_loop=$bcfLoop", '-mllvm', "-bcf_prob=$bcfProb"
    $ollvmLog   += "bcf(loop=$bcfLoop,prob=$bcfProb)"
}

# Basic block splitting  (60% chance)
if (-not $NoObf -and (Get-Random -Maximum 100) -lt 60) {
    $splitNum = Get-Random -Minimum 2 -Maximum 4  # 2 or 3
    $ollvmFlags += '-mllvm', '-split', '-mllvm', "-split_num=$splitNum"
    $ollvmLog   += "split(n=$splitNum)"
}

Write-Host ""
Write-Host "[*] OLLVM flags : $($ollvmLog -join ' | ')" -ForegroundColor Cyan

# -- SETUP MSVC ENVIRONMENT ---------------------------------------------------

Write-Host "[*] Loading MSVC environment (amd64)..." -ForegroundColor Cyan

$tmpBat    = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
$tmpEnvFile = [System.IO.Path]::GetTempFileName()

# Redirect 'set' output to a file to bypass CMD's 8191-char stdout line limit
"@echo off`r`npushd %TEMP%`r`ncall `"$VCVARSALL`" amd64 2>NUL`r`nset > `"$tmpEnvFile`"" | Out-File -FilePath $tmpBat -Encoding ASCII
$null = cmd /c $tmpBat
Remove-Item $tmpBat -ErrorAction SilentlyContinue

$envLines = Get-Content $tmpEnvFile -ErrorAction SilentlyContinue
Remove-Item $tmpEnvFile -ErrorAction SilentlyContinue

foreach ($line in $envLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}

# -- COMPILE ------------------------------------------------------------------

New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null

Write-Host "[*] Compiling $SOURCE_DIR\main.cpp ..." -ForegroundColor Cyan

$compileArgs = @(
    '/c',
    '/O2',
    '/DNDEBUG', '/D_CONSOLE',
    '/MT',
    '/Gy',
    '/Oi',
    '/W0',
    '/EHsc',
    "/I$SOURCE_DIR",
    "/Fo$OBJ_FILE"
) + $ollvmFlags + @("$SOURCE_DIR\main.cpp")

& $CLANG_CL @compileArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed (exit code $LASTEXITCODE)"
    exit 1
}

# -- LINK ---------------------------------------------------------------------

Write-Host "[*] Linking..." -ForegroundColor Cyan

$linkArgs = @(
    $OBJ_FILE,
    '/SUBSYSTEM:CONSOLE',
    '/MACHINE:X64',
    '/OPT:REF',
    '/OPT:ICF',
    "/OUT:$OUTPUT_EXE"
)

& $LLD_LINK @linkArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Linking failed (exit code $LASTEXITCODE)"
    exit 1
}

# -- RESULT -------------------------------------------------------------------

$sizeKB = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1KB, 1)
$sizeMB = [math]::Round((Get-Item $OUTPUT_EXE).Length / 1MB, 2)

Write-Host "[+] Output      : $OUTPUT_EXE" -ForegroundColor Green
Write-Host "[+] Size        : $sizeKB KB ($sizeMB MB)" -ForegroundColor Green

if ((Get-Item $OUTPUT_EXE).Length -gt 2MB) {
    Write-Warning "Binary exceeds 2 MB ($sizeMB MB) - OLLVM params may be too aggressive"
}
