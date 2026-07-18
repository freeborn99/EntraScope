#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Setup Script
.DESCRIPTION
    Installs prerequisites, validates environment, and configures your
    EntraScope installation. Run this once before using EntraScope.
#>

param(
    [switch]$Force,
    [switch]$SkipModules
)

Write-Host "`n[EntraScope Setup]" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 7) {
    Write-Host "ERROR: PowerShell 7.0+ required. Current: $($psVersion.ToString())" -ForegroundColor Red
    Write-Host "Install from: https://aka.ms/powershell" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] PowerShell $($psVersion.ToString())" -ForegroundColor Green

# Ensure reports and config directories exist
$dirs = @("reports", "config")
foreach ($dir in $dirs) {
    $path = Join-Path $PSScriptRoot $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "[OK] Created: $dir\" -ForegroundColor Green
    } else {
        Write-Host "[OK] Exists: $dir\" -ForegroundColor Green
    }
}

# Install optional but recommended modules
if (-not $SkipModules) {
    $modules = @(
        @{ Name = "MSAL.PS"; Description = "Interactive browser authentication (recommended)" }
        @{ Name = "Microsoft.Graph"; Description = "Alternative Graph API module" }
    )

    foreach ($mod in $modules) {
        $installed = Get-Module $mod.Name -ListAvailable -ErrorAction SilentlyContinue
        if (-not $installed) {
            Write-Host "  Installing $($mod.Name) ($($mod.Description))..." -ForegroundColor Yellow
            try {
                Install-Module -Name $mod.Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host "  [OK] $($mod.Name) installed" -ForegroundColor Green
            } catch {
                Write-Host "  [WARN] Could not install $($mod.Name): $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "         Install manually: Install-Module $($mod.Name) -Scope CurrentUser" -ForegroundColor Gray
            }
        } else {
            Write-Host "[OK] $($mod.Name) already installed (v$($installed[0].Version))" -ForegroundColor Green
        }
    }
}

# Check/create scope.json
$configPath = Join-Path $PSScriptRoot "config\scope.json"
if (-not (Test-Path $configPath) -or $Force) {
    $config = @{
        TenantDomain     = "yourtenant.onmicrosoft.com"
        TenantId         = ""
        SubscriptionIds  = @()
        HoneypotAccounts = @(
            @{
                UPN         = "honeypot1@yourtenant.onmicrosoft.com"
                Description = "Dedicated test account for credential attack simulation. Do NOT use real user accounts."
            }
        )
        TestAccount      = @{
            UPN         = "pentest-lowpriv@yourtenant.onmicrosoft.com"
            Description = "Low-privilege test account for privilege escalation tests"
        }
        Options = @{
            RateLimitMs       = 2000
            CleanupAfterTest  = $true
            MaxUsersToScan    = 50
            IncludeHybrid     = $true
            FailOnWarning     = $false
        }
    }
    $config | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding UTF8
    Write-Host "[OK] Created config template: config\scope.json" -ForegroundColor Green
    Write-Host ""
    Write-Host "ACTION REQUIRED: Edit config\scope.json with your tenant details:" -ForegroundColor Yellow
    Write-Host "  1. Set TenantDomain to your tenant (e.g., contoso.onmicrosoft.com)" -ForegroundColor Yellow
    Write-Host "  2. Set HoneypotAccounts with dedicated test accounts" -ForegroundColor Yellow
    Write-Host "  3. Optionally add SubscriptionIds for Azure resource testing" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Config exists: config\scope.json" -ForegroundColor Green
}

# Validate network connectivity to key endpoints
Write-Host "`n[Network Validation]" -ForegroundColor Cyan
$endpoints = @(
    @{ Uri = "https://login.microsoftonline.com"; Name = "Microsoft Login" }
    @{ Uri = "https://graph.microsoft.com";        Name = "Microsoft Graph" }
    @{ Uri = "https://management.azure.com";       Name = "Azure Management" }
)

foreach ($ep in $endpoints) {
    try {
        $resp = Invoke-WebRequest -Uri $ep.Uri -Method HEAD -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[OK] $($ep.Name) ($($ep.Uri))" -ForegroundColor Green
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($code -in @(400,401,403)) {
            Write-Host "[OK] $($ep.Name) - reachable (HTTP $code = requires auth)" -ForegroundColor Green
        } else {
            Write-Host "[WARN] $($ep.Name) may not be reachable: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[Setup Complete]" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Edit .\config\scope.json with your tenant and test account details" -ForegroundColor White
Write-Host "  2. Run a dry run: .\EntraScope.ps1 -DryRun" -ForegroundColor White
Write-Host "  3. Full scan: .\EntraScope.ps1 -AuthMethod Interactive" -ForegroundColor White
Write-Host "  4. Skip some phases: .\EntraScope.ps1 -ExcludePhases '2,5'" -ForegroundColor White
Write-Host ""
