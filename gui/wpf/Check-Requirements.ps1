#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope GUI — PowerShell + WPF Requirements Setup Script
.DESCRIPTION
    Verifies all prerequisites for the PowerShell + WPF GUI option and
    installs any missing optional dependencies. Run once before gui\wpf\EntraScopeGUI.ps1
#>

Write-Host "`n[EntraScope WPF GUI — Requirements Check]" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

$allGood = $true

# ── 1. PowerShell Version ────────────────────────────────────────────────────
$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -ge 7) {
    Write-Host "[OK] PowerShell $($psVer.ToString())" -ForegroundColor Green
} else {
    Write-Host "[FAIL] PowerShell 7.0+ required. Current: $($psVer.ToString())" -ForegroundColor Red
    Write-Host "       Download: https://aka.ms/powershell" -ForegroundColor Yellow
    $allGood = $false
}

# ── 2. WPF / PresentationFramework ──────────────────────────────────────────
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore      -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase           -ErrorAction Stop
    Add-Type -AssemblyName System.Xaml           -ErrorAction Stop
    Write-Host "[OK] WPF assemblies (PresentationFramework, PresentationCore, WindowsBase, System.Xaml)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] WPF assemblies not available: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       WPF requires .NET on Windows. Run on Windows 10/11 with .NET 7+ installed." -ForegroundColor Yellow
    $allGood = $false
}

# ── 3. .NET Runtime ─────────────────────────────────────────────────────────
try {
    $dotnetVer = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
    Write-Host "[OK] $dotnetVer" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Could not determine .NET version" -ForegroundColor Yellow
}

# ── 4. System.Web (HTML encoding in report) ──────────────────────────────────
try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
    Write-Host "[OK] System.Web (HTML encoding)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] System.Web not available — HTML report encoding may fall back to manual escaping" -ForegroundColor Yellow
}

# ── 5. System.Windows.Forms (for file/folder dialogs) ───────────────────────
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Write-Host "[OK] System.Windows.Forms (file picker dialogs)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] System.Windows.Forms not available — file picker dialogs will use manual path entry" -ForegroundColor Yellow
}

# ── 6. Check EntraScope root modules ────────────────────────────────────────
$rootPath    = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
$mainScript  = Join-Path $rootPath "EntraScope.ps1"
$configFile  = Join-Path $rootPath "config\scope.json"
$modulesPath = Join-Path $rootPath "modules"

if (Test-Path $mainScript) {
    Write-Host "[OK] EntraScope.ps1 found at: $mainScript" -ForegroundColor Green
} else {
    Write-Host "[FAIL] EntraScope.ps1 not found at: $mainScript" -ForegroundColor Red
    Write-Host "       Run this script from EntraScope\gui\wpf\" -ForegroundColor Yellow
    $allGood = $false
}

if (Test-Path $configFile) {
    Write-Host "[OK] config\scope.json found" -ForegroundColor Green
} else {
    Write-Host "[WARN] config\scope.json not found — will need to be created before scanning" -ForegroundColor Yellow
}

$moduleCount = (Get-ChildItem $modulesPath -Filter "Phase*.ps1" -ErrorAction SilentlyContinue).Count
if ($moduleCount -eq 8) {
    Write-Host "[OK] All 8 phase modules found in modules\" -ForegroundColor Green
} else {
    Write-Host "[WARN] Found $moduleCount/8 phase modules in modules\" -ForegroundColor Yellow
}

# ── 7. Execution Policy ──────────────────────────────────────────────────────
$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -in @("RemoteSigned","Unrestricted","Bypass")) {
    Write-Host "[OK] PowerShell Execution Policy: $policy" -ForegroundColor Green
} else {
    Write-Host "[WARN] Execution Policy is '$policy' — GUI and modules may be blocked" -ForegroundColor Yellow
    Write-Host "       Fix: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned" -ForegroundColor Gray
}

# ── 8. MSAL.PS (optional — enables interactive browser auth from GUI) ─────────
$msal = Get-Module MSAL.PS -ListAvailable -ErrorAction SilentlyContinue
if ($msal) {
    Write-Host "[OK] MSAL.PS $($msal[0].Version) installed (interactive browser auth available)" -ForegroundColor Green
} else {
    Write-Host "[INFO] MSAL.PS not installed — GUI will use Device Code auth by default" -ForegroundColor Cyan
    Write-Host "       Install: Install-Module MSAL.PS -Scope CurrentUser" -ForegroundColor Gray
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
if ($allGood) {
    Write-Host "[READY] All required components present. Run the GUI with:" -ForegroundColor Green
    Write-Host "        pwsh -File .\EntraScopeGUI.ps1" -ForegroundColor White
} else {
    Write-Host "[ACTION REQUIRED] Fix the items marked [FAIL] above before running the GUI." -ForegroundColor Red
}
Write-Host ""
