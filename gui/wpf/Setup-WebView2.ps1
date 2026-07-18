#Requires -Version 7.0
<#
.SYNOPSIS
    Downloads the WebView2 SDK DLLs from NuGet — one-time setup, no Node.js needed.
.DESCRIPTION
    Fetches Microsoft.Web.WebView2 NuGet package (a zip file), extracts the
    three DLLs EntraScopeGUI.ps1 needs, and places them in .\lib\.
    Run once. After this, the GUI requires zero additional installs.
#>

param(
    [string]$Version = "1.0.2651.64",   # Pinned stable release
    [string]$LibPath = "$PSScriptRoot\lib",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "`n[EntraScope GUI — WebView2 Setup]" -ForegroundColor Cyan
Write-Host "==================================`n" -ForegroundColor Cyan

# ── Already done? ─────────────────────────────────────────────────────────────
$required = @(
    "Microsoft.Web.WebView2.Core.dll"
    "Microsoft.Web.WebView2.Wpf.dll"
    "WebView2Loader.dll"
)
$allPresent = $required | ForEach-Object { Test-Path (Join-Path $LibPath $_) }
if (($allPresent -notcontains $false) -and -not $Force) {
    Write-Host "[OK] All WebView2 DLLs already in $LibPath" -ForegroundColor Green
    Write-Host "     Run with -Force to re-download.`n"
    exit 0
}

# ── Create lib dir ─────────────────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Path $LibPath -Force
Write-Host "  Target folder: $LibPath" -ForegroundColor Gray

# ── Determine architecture ─────────────────────────────────────────────────────
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") {
    "win-arm64"
} elseif ([System.Environment]::Is64BitProcess) {
    "win-x64"
} else {
    "win-x86"
}
Write-Host "  Architecture : $arch" -ForegroundColor Gray

# ── Check connectivity ─────────────────────────────────────────────────────────
Write-Host "  Checking NuGet connectivity..." -ForegroundColor Gray
try {
    $null = Invoke-RestMethod "https://api.nuget.org/v3/index.json" -TimeoutSec 10
    Write-Host "  [OK] NuGet API reachable`n" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Cannot reach NuGet: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  If offline, manually copy the three DLLs into: $LibPath`n" -ForegroundColor Yellow
    Write-Host "  DLLs needed from NuGet package Microsoft.Web.WebView2 $Version :"
    Write-Host "    lib\netcoreapp3.0\Microsoft.Web.WebView2.Core.dll"
    Write-Host "    lib\netcoreapp3.0\Microsoft.Web.WebView2.Wpf.dll"
    Write-Host "    runtimes\$arch\native\WebView2Loader.dll"
    exit 1
}

# ── Try to get the latest stable if version not pinned ────────────────────────
Write-Host "[1/3] Resolving WebView2 version..." -ForegroundColor Cyan
try {
    $pkgMeta = Invoke-RestMethod "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/index.json" -TimeoutSec 15
    $stable  = $pkgMeta.versions | Where-Object { $_ -notmatch "-" } | Select-Object -Last 1
    if ($stable -and $Version -eq "1.0.2651.64") {
        $Version = $stable
        Write-Host "  Using latest stable: $Version" -ForegroundColor Green
    } else {
        Write-Host "  Using pinned version: $Version" -ForegroundColor Green
    }
} catch {
    Write-Host "  Could not query versions — using pinned $Version" -ForegroundColor Yellow
}

# ── Download the .nupkg (it's just a zip) ─────────────────────────────────────
Write-Host "[2/3] Downloading Microsoft.Web.WebView2 $Version..." -ForegroundColor Cyan
$nupkgUrl  = "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/$Version"
$nupkgPath = Join-Path $LibPath "webview2.nupkg.zip"
$extractDir = Join-Path $LibPath "webview2_extract"

try {
    $progress = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"   # suppress slow Invoke-WebRequest bar
    Invoke-WebRequest -Uri $nupkgUrl -OutFile $nupkgPath -TimeoutSec 60
    $ProgressPreference = $progress
    $sizeMB = [Math]::Round((Get-Item $nupkgPath).Length / 1MB, 1)
    Write-Host "  Downloaded: $sizeMB MB" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Extract DLLs ──────────────────────────────────────────────────────────────
Write-Host "[3/3] Extracting DLLs..." -ForegroundColor Cyan

if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path $nupkgPath -DestinationPath $extractDir -Force

# Try netcoreapp3.0 first (best for PS7), fall back to net45
$managedPaths = @(
    "lib\netcoreapp3.0"
    "lib\net6.0-windows"
    "lib\net45"
)

$managedDir = $null
foreach ($p in $managedPaths) {
    $candidate = Join-Path $extractDir $p
    if (Test-Path $candidate) { $managedDir = $candidate; break }
}

if (-not $managedDir) {
    Write-Host "  [FAIL] Could not find managed DLL directory in NuGet package" -ForegroundColor Red
    Write-Host "  Contents: $(Get-ChildItem $extractDir -Directory | Select-Object -ExpandProperty Name)"
    exit 1
}
Write-Host "  Using managed DLLs from: $($managedDir -replace [regex]::Escape($extractDir),'')" -ForegroundColor Gray

$dllsToCopy = @{
    "Microsoft.Web.WebView2.Core.dll" = Join-Path $managedDir "Microsoft.Web.WebView2.Core.dll"
    "Microsoft.Web.WebView2.Wpf.dll"  = Join-Path $managedDir "Microsoft.Web.WebView2.Wpf.dll"
    "WebView2Loader.dll"              = Join-Path $extractDir "runtimes\$arch\native\WebView2Loader.dll"
}

$allOk = $true
foreach ($dest in $dllsToCopy.Keys) {
    $src = $dllsToCopy[$dest]
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $LibPath $dest) -Force
        $size = [Math]::Round((Get-Item (Join-Path $LibPath $dest)).Length / 1KB, 0)
        Write-Host "  [OK] $dest ($size KB)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Not found in package: $src" -ForegroundColor Red
        $allOk = $false
    }
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Remove-Item $nupkgPath  -Force -ErrorAction SilentlyContinue
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($allOk) {
    Write-Host "[SETUP COMPLETE]" -ForegroundColor Green
    Write-Host "  WebView2 DLLs installed to: $LibPath"
    Write-Host ""
    Write-Host "  Next step — launch the GUI:"
    Write-Host "  pwsh -STA -File `"$PSScriptRoot\EntraScopeGUI.ps1`"" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "[SETUP INCOMPLETE] — Some DLLs could not be extracted." -ForegroundColor Red
    Write-Host "  Try running with -Force or a different -Version"
    exit 1
}
