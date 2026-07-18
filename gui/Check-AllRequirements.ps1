#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope GUI — Universal Requirements Checker & Installer
.DESCRIPTION
    Checks prerequisites for ALL four GUI options and reports which ones
    are ready to use without any further installation.
    Run this to decide which GUI option fits your environment best.
#>

param(
    [ValidateSet("All","Electron","Python","WPF","Tauri")]
    [string]$Check = "All",
    [switch]$Install    # Attempt to install missing prerequisites
)

$results = [ordered]@{}

function Test-Command { param([string]$Cmd) (Get-Command $Cmd -ErrorAction SilentlyContinue) -ne $null }
function Write-Status {
    param([string]$Label, [bool]$OK, [string]$Detail = "", [string]$Fix = "")
    $icon   = if ($OK) { "[OK]  " } else { "[MISS]" }
    $color  = if ($OK) { "Green" } else { "Yellow" }
    Write-Host "  $icon $Label" -ForegroundColor $color -NoNewline
    if ($Detail) { Write-Host " — $Detail" -ForegroundColor DarkGray } else { Write-Host "" }
    if (-not $OK -and $Fix) { Write-Host "         Fix: $Fix" -ForegroundColor Gray }
    return $OK
}

Clear-Host
Write-Host @"

  EntraScope GUI — Requirements Checker
  ──────────────────────────────────────
"@ -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────
#  SHARED PREREQUISITES
# ─────────────────────────────────────────────────────────────
Write-Host "`n[Shared Prerequisites]" -ForegroundColor Cyan

$ps7      = $PSVersionTable.PSVersion.Major -ge 7
$isWin    = $IsWindows
$policy   = (Get-ExecutionPolicy -Scope CurrentUser)
$policyOK = $policy -in @("RemoteSigned","Unrestricted","Bypass")

Write-Status "PowerShell 7.0+"         $ps7      "v$($PSVersionTable.PSVersion)" "winget install Microsoft.PowerShell"
Write-Status "Windows OS"              $isWin    $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)
Write-Status "Execution Policy OK"     $policyOK "CurrentUser: $policy"          "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned"

$entraScopeRoot = Join-Path $PSScriptRoot ".." ".." | Resolve-Path -ErrorAction SilentlyContinue
$mainScriptOK   = $entraScopeRoot -and (Test-Path (Join-Path $entraScopeRoot "EntraScope.ps1"))
Write-Status "EntraScope.ps1 found"    $mainScriptOK $entraScopeRoot

# ─────────────────────────────────────────────────────────────
#  OPTION 1: ELECTRON
# ─────────────────────────────────────────────────────────────
if ($Check -in @("All","Electron")) {
    Write-Host "`n[Option 1: Electron (Node.js)]" -ForegroundColor Magenta

    $nodeOK    = Test-Command "node"
    $npmOK     = Test-Command "npm"
    $nodeVer   = if ($nodeOK) { (node --version 2>$null) } else { "not found" }
    $npmVer    = if ($npmOK)  { (npm --version 2>$null)  } else { "not found" }
    $nodeMinOK = $nodeOK -and ([version]($nodeVer -replace 'v','') -ge [version]"20.0.0")

    $n1 = Write-Status "Node.js >= 20"  $nodeMinOK $nodeVer  "winget install OpenJS.NodeJS.LTS"
    $n2 = Write-Status "npm >= 10"      $npmOK     $npmVer   "Bundled with Node.js"

    # Check for windows build tools (for node-pty)
    $msbuild = Test-Command "msbuild" 
    $n3 = Write-Status "MSBuild (C++ tools)" $msbuild "Required for node-pty native compilation" "winget install Microsoft.VisualStudio.2022.BuildTools"

    $electronScore = @($n1,$n2,$n3) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    $results["Electron"] = [PSCustomObject]@{ Score = $electronScore; Max = 3; Ready = ($electronScore -eq 3) }

    if ($electronScore -eq 3) {
        Write-Host "  ✅ READY — run: cd gui\electron && npm install && npm run dev" -ForegroundColor Green
    } elseif ($electronScore -ge 2) {
        Write-Host "  ⚠️  ALMOST READY — fix missing items above, then: cd gui\electron && npm install" -ForegroundColor Yellow
    } else {
        Write-Host "  ❌ NOT READY — install Node.js 20 LTS first" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────
#  OPTION 2: PYTHON + CUSTOMTKINTER
# ─────────────────────────────────────────────────────────────
if ($Check -in @("All","Python")) {
    Write-Host "`n[Option 2: Python + CustomTkinter]" -ForegroundColor Magenta

    $pyOK    = Test-Command "python"
    $pyVer   = if ($pyOK) { (python --version 2>&1) -replace "Python ",""} else { "not found" }
    $pyMinOK = $pyOK -and ([version]$pyVer -ge [version]"3.11")
    $pipOK   = Test-Command "pip"

    $p1 = Write-Status "Python >= 3.11"  $pyMinOK  $pyVer   "winget install Python.Python.3.11"
    $p2 = Write-Status "pip"             $pipOK    ""       "Bundled with Python"

    # Check if customtkinter is installed
    $ctkOK = $false
    if ($pyOK) {
        $ctkCheck = python -c "import customtkinter; print(customtkinter.__version__)" 2>$null
        $ctkOK = $null -ne $ctkCheck
    }
    $p3 = Write-Status "customtkinter"  $ctkOK  ($ctkCheck ?? "not installed")  "pip install customtkinter==5.2.2"

    # tkinter (built-in but sometimes missing on non-standard Python installs)
    $tkOK = $false
    if ($pyOK) { $tkOK = $null -ne (python -c "import tkinter" 2>$null) -or $LASTEXITCODE -eq 0 }
    $p4 = Write-Status "tkinter (built-in)" ($pyOK) "" "Use python.org installer — NOT Windows Store Python"

    $pythonScore = @($p1,$p2,$p3,$p4) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    $results["Python"] = [PSCustomObject]@{ Score = $pythonScore; Max = 4; Ready = ($pythonScore -eq 4) }

    if ($pythonScore -eq 4) {
        Write-Host "  ✅ READY — run: cd gui\python && python app.py" -ForegroundColor Green
    } elseif ($p1 -and $p2) {
        Write-Host "  ⚠️  ALMOST READY — run: pip install -r gui\python\requirements.txt" -ForegroundColor Yellow
    } else {
        Write-Host "  ❌ NOT READY — install Python 3.11+ from python.org (not Windows Store)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────
#  OPTION 3: POWERSHELL + WPF
# ─────────────────────────────────────────────────────────────
if ($Check -in @("All","WPF")) {
    Write-Host "`n[Option 3: PowerShell + WPF]" -ForegroundColor Magenta

    $wpfOK = $false
    try { Add-Type -AssemblyName PresentationFramework -ErrorAction Stop; $wpfOK = $true } catch {}
    $msalOK = $null -ne (Get-Module MSAL.PS -ListAvailable -ErrorAction SilentlyContinue)

    $w1 = Write-Status "PowerShell 7.0+"     $ps7    "v$($PSVersionTable.PSVersion)" "winget install Microsoft.PowerShell"
    $w2 = Write-Status "WPF assemblies"      $wpfOK  "PresentationFramework"         "Included with .NET on Windows — ensure running on Windows"
    $w3 = Write-Status "Execution Policy"    $policyOK $policy                       "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned"
    $w4 = Write-Status "MSAL.PS (optional)"  $msalOK ""                              "Install-Module MSAL.PS -Scope CurrentUser"

    $wpfScore = @($w1,$w2,$w3) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    $results["WPF"] = [PSCustomObject]@{ Score = $wpfScore; Max = 3; Ready = ($wpfScore -eq 3) }

    if ($wpfScore -eq 3) {
        Write-Host "  ✅ READY — run: pwsh -STA -File gui\wpf\EntraScopeGUI.ps1" -ForegroundColor Green
    } else {
        Write-Host "  ❌ NOT READY — fix items above" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────────────────────
#  OPTION 4: TAURI (informational only)
# ─────────────────────────────────────────────────────────────
if ($Check -in @("All","Tauri")) {
    Write-Host "`n[Option 4: Tauri (Rust + Web)]" -ForegroundColor Magenta

    $rustOK   = Test-Command "rustc"
    $cargoOK  = Test-Command "cargo"
    $rustVer  = if ($rustOK) { (rustc --version) } else { "not found" }
    $nodeOK2  = Test-Command "node"

    $t1 = Write-Status "Rust toolchain"  $rustOK   $rustVer  "winget install Rustlang.Rustup  then: rustup install stable"
    $t2 = Write-Status "Cargo"           $cargoOK  ""        "Bundled with rustup"
    $t3 = Write-Status "Node.js"         $nodeOK2  ""        "winget install OpenJS.NodeJS.LTS  (for Vite frontend)"
    $t4 = Write-Status "WebView2 Runtime" $isWin   "Edge WebView2 — pre-installed on Win10/11" ""

    $tauriScore = @($t1,$t2,$t3,$t4) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    $results["Tauri"] = [PSCustomObject]@{ Score = $tauriScore; Max = 4; Ready = ($tauriScore -eq 4) }

    if ($tauriScore -eq 4) {
        Write-Host "  ✅ READY — run: cd gui\tauri && npm install && npm run tauri dev" -ForegroundColor Green
    } else {
        Write-Host "  ❌ NOT READY — Rust toolchain not found" -ForegroundColor Red
        Write-Host "     Install: winget install Rustlang.Rustup" -ForegroundColor Gray
        Write-Host "     Then:    rustup install stable" -ForegroundColor Gray
    }
}

# ─────────────────────────────────────────────────────────────
#  SUMMARY TABLE
# ─────────────────────────────────────────────────────────────
Write-Host "`n════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════" -ForegroundColor Cyan

foreach ($opt in $results.Keys) {
    $r     = $results[$opt]
    $pct   = [Math]::Round($r.Score / $r.Max * 100)
    $color = if ($r.Ready) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }
    $icon  = if ($r.Ready) { "✅" } elseif ($pct -ge 50) { "⚠️ " } else { "❌" }
    $bar   = ("█" * $r.Score) + ("░" * ($r.Max - $r.Score))
    Write-Host "  $icon  $($opt.PadRight(12)) [$bar]  $($r.Score)/$($r.Max) ready" -ForegroundColor $color
}

Write-Host ""
$bestOption = $results.GetEnumerator() | Sort-Object { $_.Value.Score } -Descending | Select-Object -First 1
Write-Host "  Best match for your environment: $($bestOption.Key)" -ForegroundColor Cyan
Write-Host "  Tell EntraScope which GUI to build and it will be built immediately." -ForegroundColor Gray
Write-Host ""
