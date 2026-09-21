# =====================================================================
# SentinelPR — build-release.ps1
# Release engineering script (no business logic).
#
#  1. Clean the project
#  2. Run the full test suite (mvn test)
#  3. Package the JAR (mvn package, tests already executed)
#  4. Generate SHA256SUMS.txt for all release artifacts
#  5. Copy release assets into ./release
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1 -SkipTests
# =====================================================================
[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

# Resolve repository root (parent of scripts/)
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$releaseDir = Join-Path $root 'release'
$targetDir  = Join-Path $root 'target'
$jarName    = "sentinel-pr-$Version.jar"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " SentinelPR release build (v$Version)" -ForegroundColor Cyan
Write-Host " Root: $root" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ── Step 1 + 2: clean + test ────────────────────────────────────────
if ($SkipTests) {
    Write-Host "[1/5] mvn clean (tests skipped via -SkipTests)" -ForegroundColor Yellow
    & mvn -B clean
} else {
    Write-Host "[1/5] mvn clean test" -ForegroundColor Yellow
    & mvn -B clean test
    if ($LASTEXITCODE -ne 0) { throw "mvn test failed with exit code $LASTEXITCODE. Aborting release build." }
}

# ── Step 3: package ─────────────────────────────────────────────────
Write-Host "[2/5] mvn package" -ForegroundColor Yellow
if ($SkipTests) {
    & mvn -B package
} else {
    & mvn -B package -DskipTests   # tests already executed above
}
if ($LASTEXITCODE -ne 0) { throw "mvn package failed with exit code $LASTEXITCODE." }

$jarPath = Join-Path $targetDir $jarName
if (-not (Test-Path $jarPath)) { throw "Expected artifact not found: $jarPath" }

# ── Step 4 + 5: assemble release/ ───────────────────────────────────
Write-Host "[3/5] Assembling release/ directory" -ForegroundColor Yellow
if (Test-Path $releaseDir) { Remove-Item $releaseDir -Recurse -Force }
New-Item -ItemType Directory -Path $releaseDir | Out-Null

# Core artifact
Copy-Item $jarPath $releaseDir

# Example / governance assets (existing repository files only)
$assets = @(
    'strict-policy.json',
    'local-baseline.json',
    'LICENSE',
    'RELEASE-NOTES.md',
    'README.md',
    'CHANGELOG.md'
)
foreach ($asset in $assets) {
    $src = Join-Path $root $asset
    if (Test-Path $src) { Copy-Item $src $releaseDir }
    else { Write-Host "      note: asset not found, skipped: $asset" -ForegroundColor DarkYellow }
}

# ── SHA256SUMS ──────────────────────────────────────────────────────
Write-Host "[4/5] Generating SHA256SUMS.txt" -ForegroundColor Yellow
$hashLines = Get-ChildItem $releaseDir -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
$hashLines | Set-Content -Path (Join-Path $releaseDir 'SHA256SUMS.txt') -Encoding ascii
Copy-Item (Join-Path $releaseDir 'SHA256SUMS.txt') (Join-Path $root 'SHA256SUMS.txt')

Write-Host "[5/5] Done." -ForegroundColor Green
Write-Host ""
Write-Host "Release contents ($releaseDir):" -ForegroundColor Green
Get-ChildItem $releaseDir -File | ForEach-Object { Write-Host ("  {0,-40} {1,12:N0} bytes" -f $_.Name, $_.Length) }
Write-Host ""
Write-Host "Next: follow RELEASE-NOTES.md to tag, create the GitHub Release, and upload the JAR + SHA256SUMS.txt." -ForegroundColor Green
