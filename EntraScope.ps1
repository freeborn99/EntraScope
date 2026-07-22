#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope - Azure & M365 Entra Penetration Testing Toolkit
.DESCRIPTION
    EntraScope is a comprehensive red-team simulation and penetration testing
    framework for Azure Active Directory / Entra ID environments. It actively
    probes for misconfigurations, attack paths, and detection gaps across
    8 distinct attack phases, producing pentest-grade HTML and JSON reports.

    AUTHORIZED USE ONLY. Use only on environments you own or have explicit
    written permission to test.

.PARAMETER ConfigFile
    Path to scope.json configuration file. Default: .\config\scope.json

.PARAMETER Phases
    Which phases to run. Comma-separated list or "All". Default: All
    Values: Recon, Cred, OAuth, PrivEsc, Persist, Lateral, Azure, Detect

.PARAMETER TenantDomain
    Override tenant domain from scope.json (e.g., "contoso.com")

.PARAMETER AuthMethod
    Authentication method. Default: Interactive
    Values: Interactive, DeviceCode, ServicePrincipal, CurrentToken

.PARAMETER ClientId
    Service Principal Application (client) ID for SP authentication

.PARAMETER ClientSecret
    Service Principal client secret (use SecureString in production)

.PARAMETER OutputDir
    Directory for output reports. Default: .\reports

.PARAMETER DryRun
    Run all tests in simulation mode without making any API calls that
    modify or probe production systems.

.PARAMETER IncludePhases
    Additional control: comma-separated phase numbers to include (1-8)

.PARAMETER ExcludePhases
    Comma-separated phase numbers to skip (e.g., "2,5" to skip Cred and Persist)

.EXAMPLE
    # Full scan with interactive browser login
    .\EntraScope.ps1 -ConfigFile .\config\scope.json

.EXAMPLE
    # Recon only, dry run
    .\EntraScope.ps1 -Phases Recon -DryRun

.EXAMPLE
    # Full scan with service principal
    .\EntraScope.ps1 -AuthMethod ServicePrincipal -ClientId "xxx" -ClientSecret "yyy"

.EXAMPLE
    # Skip credential and persistence phases
    .\EntraScope.ps1 -ExcludePhases "2,5"
#>
[CmdletBinding()]
param(
    [string]$ConfigFile    = "$PSScriptRoot\config\scope.json",
    [string]$Phases        = "All",
    [string]$TenantDomain  = "",
    [ValidateSet("Interactive","DeviceCode","ServicePrincipal","CurrentToken")]
    [string]$AuthMethod    = "Interactive",
    [string]$ClientId      = "",
    [string]$ClientSecret  = "",
    [string]$OutputDir     = "$PSScriptRoot\reports",
    [switch]$DryRun,
    [string]$IncludePhases = "",
    [string]$ExcludePhases = "",
    [switch]$NoHybrid,
    [switch]$Quiet,
    [switch]$Menu,
    [switch]$SkipAutoProvision
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
#   GLOBAL STATE
# ─────────────────────────────────────────────────────────────
$script:Config                = $null
$script:AccessToken           = $null   # Graph API token
$script:AzToken               = $null   # ARM token
$script:DryRun                = $DryRun.IsPresent
$script:StartTime             = Get-Date
$script:TestResults           = [System.Collections.Generic.List[object]]::new()
$script:DiscoveredSubscriptions = @()
$script:LogLines              = [System.Collections.Generic.List[string]]::new()

# ─────────────────────────────────────────────────────────────
#   LOGGING
# ─────────────────────────────────────────────────────────────
function Write-EntraLog {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ValidateSet("Info","Warn","Success","Error","Attack","Debug")]
        [string]$Level = "Info"
    )

    $ts = Get-Date -Format "HH:mm:ss"
    $colors = @{
        Info    = "Cyan"
        Warn    = "Yellow"
        Success = "Green"
        Error   = "Red"
        Attack  = "Magenta"
        Debug   = "DarkGray"
    }
    $prefixes = @{
        Info    = "  "
        Warn    = " !"
        Success = " +"
        Error   = " X"
        Attack  = ">>>"
        Debug   = "..."
    }
    $prefix = $prefixes[$Level]
    $color  = $colors[$Level]
    $line   = "$ts $prefix $Message"
    $script:LogLines.Add($line)
    if (-not $Quiet -or $Level -in @("Error","Warn","Attack")) {
        Write-Host $line -ForegroundColor $color
    }
}

# ─────────────────────────────────────────────────────────────
#   RESULT HELPER - STANDARDIZED OBJECT
# ─────────────────────────────────────────────────────────────
function New-TestResult {
    [CmdletBinding()]
    param(
        [string]$TestId,
        [string]$Phase,
        [string]$Name,
        [ValidateSet("Critical","High","Medium","Low","Info")]
        [string]$Severity,
        [ValidateSet("PASS","FAIL","WARNING","WARN","INFO","SKIPPED","ERROR")]
        [string]$Status,
        [string]$Description,
        [string]$AttackTechnique,
        [string]$Result,
        [string]$Evidence,
        [string]$Remediation,
        [string]$MSDocsLink,
        [string]$Duration
    )

    return [PSCustomObject]@{
        TestId          = $TestId
        Phase           = $Phase
        Name            = $Name
        Severity        = $Severity
        Status          = $Status
        Description     = $Description
        AttackTechnique = $AttackTechnique
        Result          = $Result
        Evidence        = $Evidence
        Remediation     = $Remediation
        MSDocsLink      = $MSDocsLink
        Duration        = $Duration
        Timestamp       = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    }
}

# ─────────────────────────────────────────────────────────────
#   CONFIGURATION LOADER
# ─────────────────────────────────────────────────────────────
function Initialize-Config {
    if (-not (Test-Path $ConfigFile)) {
        Write-EntraLog "Config file not found: $ConfigFile" -Level Error
        Write-EntraLog "Creating default config template..." -Level Warn
        $defaultConfig = @{
            TenantDomain     = "yourtenant.onmicrosoft.com"
            TenantId         = ""
            SubscriptionIds  = @()
            HoneypotAccounts = @(
                @{ UPN = "honeypot1@yourtenant.onmicrosoft.com"; Description = "Test account 1" }
            )
            TestAccount      = @{ UPN = ""; Password = "" }
            Options          = @{
                RateLimitMs     = 2000
                CleanupAfterTest = $true
                MaxUsersToScan  = 50
                IncludeHybrid   = $true
            }
        }
        $null = New-Item -ItemType Directory -Path (Split-Path $ConfigFile) -Force
        $defaultConfig | ConvertTo-Json -Depth 5 | Set-Content $ConfigFile -Encoding UTF8
        throw "Please edit $ConfigFile with your tenant details and re-run."
    }

    $script:Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json

    # Override from parameters
    if ($TenantDomain) { $script:Config.TenantDomain = $TenantDomain }
    if (-not $script:Config.Options) { $script:Config | Add-Member -NotePropertyName Options -NotePropertyValue ([PSCustomObject]@{RateLimitMs=2000;CleanupAfterTest=$true;MaxUsersToScan=50}) }
    if (-not $script:Config.Options.RateLimitMs) { $script:Config.Options | Add-Member -NotePropertyName RateLimitMs -NotePropertyValue 2000 }

    Write-EntraLog "Config loaded: $($script:Config.TenantDomain)" -Level Info
}

# ─────────────────────────────────────────────────────────────
#   AUTHENTICATION
# ─────────────────────────────────────────────────────────────
function Invoke-Authentication {
    Write-EntraLog "" -Level Info
    Write-EntraLog "=====================================" -Level Info
    Write-EntraLog " AUTHENTICATION" -Level Attack
    Write-EntraLog "=====================================" -Level Info

    if ($script:DryRun) {
        Write-EntraLog "DRY RUN mode - skipping authentication" -Level Warn
        return
    }

    $tenantId = $script:Config.TenantId
    if (-not $tenantId) {
        # Discover tenant ID from domain
        try {
            $oidcConfig = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($script:Config.TenantDomain)/.well-known/openid-configuration" -TimeoutSec 15 -ErrorAction Stop
            $tenantId = $oidcConfig.token_endpoint -replace ".*/([0-9a-f-]+)/oauth2/.*", '$1'
            $script:Config.TenantId = $tenantId
            Write-EntraLog "Discovered Tenant ID: $tenantId" -Level Success
        }
        catch { Write-EntraLog "Could not discover TenantId: $($_.Exception.Message)" -Level Error }
    }

    switch ($AuthMethod) {
        "Interactive" {
            Write-EntraLog "Starting interactive browser auth..." -Level Info
            Write-EntraLog "A browser window will open - sign in with your test account." -Level Warn

            # Use MSAL.PS if available, otherwise device code fallback
            $msalAvailable = Get-Module MSAL.PS -ListAvailable -ErrorAction SilentlyContinue
            if ($msalAvailable) {
                try {
                    Import-Module MSAL.PS -ErrorAction Stop
                    $graphToken = Get-MsalToken -TenantId $tenantId -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e" `
                        -Scopes "https://graph.microsoft.com/.default" -Interactive -ErrorAction Stop
                    $script:AccessToken = $graphToken.AccessToken
                    Write-EntraLog "Graph token acquired via MSAL" -Level Success

                    try {
                        $armToken = Get-MsalToken -TenantId $tenantId -ClientId "14d82eec-204b-4c2f-b7e8-296a70dab67e" `
                            -Scopes "https://management.azure.com/.default" -Silent -ErrorAction Stop
                        $script:AzToken = $armToken.AccessToken
                        Write-EntraLog "ARM token acquired" -Level Success
                    } catch { Write-EntraLog "ARM token not acquired (requires Azure subscription access)" -Level Warn }
                }
                catch { Write-EntraLog "MSAL.PS auth failed: $($_.Exception.Message). Falling back to Device Code." -Level Warn; $AuthMethod = "DeviceCode" }
            } else {
                Write-EntraLog "MSAL.PS module not installed. Falling back to Device Code auth." -Level Warn
                Write-EntraLog "To install: Install-Module MSAL.PS -Scope CurrentUser" -Level Info
                $AuthMethod = "DeviceCode"
            }
        }
        "DeviceCode" {
            Write-EntraLog "Starting Device Code authentication..." -Level Info
            $dcBody = @{
                client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
                scope     = "https://graph.microsoft.com/.default offline_access"
            }
            $dcResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" `
                -Method POST -Body $dcBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop

            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Yellow
            Write-Host "  GO TO: $($dcResp.verification_uri)" -ForegroundColor Yellow
            Write-Host "  ENTER CODE: $($dcResp.user_code)" -ForegroundColor Green
            Write-Host "===================================================================" -ForegroundColor Yellow
            Write-Host ""

            $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 5
                try {
                    $tokenBody = @{
                        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                        device_code = $dcResp.device_code
                        client_id   = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                    }
                    $tokens = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                        -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10 -ErrorAction Stop
                    $script:AccessToken = $tokens.access_token
                    Write-EntraLog "Device code auth SUCCESS" -Level Success
                    break
                }
                catch {
                    $err = $null
                    try { $err = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                    if ($err.error -ne "authorization_pending") { throw }
                }
            }
            if (-not $script:AccessToken) { Write-EntraLog "Device code auth timed out" -Level Error }
        }
        "ServicePrincipal" {
            if (-not $ClientId -or -not $ClientSecret) { throw "ClientId and ClientSecret required for ServicePrincipal auth" }
            $body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            $tokens = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop
            $script:AccessToken = $tokens.access_token
            Write-EntraLog "Service Principal auth SUCCESS" -Level Success

            # ARM token
            $armBody = $body.Clone()
            $armBody["scope"] = "https://management.azure.com/.default"
            try {
                $armTokens = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
                    -Method POST -Body $armBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop
                $script:AzToken = $armTokens.access_token
                Write-EntraLog "ARM token acquired for SP" -Level Success
            } catch { Write-EntraLog "ARM token failed for SP: $($_.Exception.Message)" -Level Warn }
        }
    }

    if ($script:AccessToken) {
        # Discover subscriptions
        if ($script:AzToken) {
            try {
                $subs = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2022-12-01" `
                    -Headers @{Authorization = "Bearer $script:AzToken"} -TimeoutSec 15 -ErrorAction Stop
                $script:DiscoveredSubscriptions = $subs.value.subscriptionId
                Write-EntraLog "Discovered $($script:DiscoveredSubscriptions.Count) subscription(s)" -Level Success
            } catch { Write-EntraLog "Could not enumerate subscriptions: $($_.Exception.Message)" -Level Warn }
        }

        # Supplement with config-specified subscriptions safely to avoid StrictMode errors
        if ($script:Config.psobject.Properties.Match('SubscriptionIds').Count -gt 0) {
            if ($script:Config.SubscriptionIds -and $script:Config.SubscriptionIds.Count -gt 0) {
                $script:DiscoveredSubscriptions = @($script:DiscoveredSubscriptions + $script:Config.SubscriptionIds | Select-Object -Unique)
            }
        }

        # Verify token by calling /me
        try {
            $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=displayName,userPrincipalName" `
                -Headers @{Authorization = "Bearer $script:AccessToken"} -TimeoutSec 10 -ErrorAction Stop
            Write-EntraLog "Authenticated as: $($me.displayName) ($($me.userPrincipalName))" -Level Success
        } catch { Write-EntraLog "Token valid but /me failed: $($_.Exception.Message)" -Level Warn }
    }
}

# ─────────────────────────────────────────────────────────────
#   PHASE SELECTOR
# ─────────────────────────────────────────────────────────────
function Get-PhasesToRun {
    $allPhases = @(1,2,3,4,5,6,7,8)

    $phaseMap = @{
        "Recon"   = 1; "Cred" = 2; "OAuth" = 3; "PrivEsc" = 4
        "Persist" = 5; "Lateral" = 6; "Azure" = 7; "Detect" = 8
        "All"     = 0
    }

    $requested = if ($Phases -eq "All") { $allPhases } else {
        $Phases -split "," | ForEach-Object { $phaseMap[$_.Trim()] ?? [int]$_.Trim() }
    }

    if ($IncludePhases) {
        $include = $IncludePhases -split "," | ForEach-Object { [int]$_.Trim() }
        $requested = @($requested + $include | Select-Object -Unique | Sort-Object)
    }

    if ($ExcludePhases) {
        $exclude = $ExcludePhases -split "," | ForEach-Object { [int]$_.Trim() }
        $requested = $requested | Where-Object { $_ -notin $exclude }
    }

    return $requested | Sort-Object
}

# ─────────────────────────────────────────────────────────────
#   HTML REPORT ENGINE
# ─────────────────────────────────────────────────────────────
function New-HTMLReport {
    [CmdletBinding()]
    param(
        [object[]]$Results,
        [string]$OutputPath
    )

    $runDate = $script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")
    $duration = [Math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)

    $total  = $Results.Count
    $pass   = ($Results | Where-Object Status -eq "PASS").Count
    $fail   = ($Results | Where-Object Status -eq "FAIL").Count
    $warn   = ($Results | Where-Object { $_.Status -in @("WARNING","WARN") }).Count
    $skip   = ($Results | Where-Object Status -in @("SKIPPED","INFO")).Count
    $err    = ($Results | Where-Object Status -eq "ERROR").Count

    $secScore = if ($total -gt 0) { [Math]::Round($pass / [Math]::Max(($total - $skip),1) * 100, 0) } else { 0 }

    $scoreColor = if ($secScore -ge 85) { "#00c851" } elseif ($secScore -ge 60) { "#ff8800" } else { "#ff4444" }

    # Generate test rows HTML
    $rowsHtml = ""
    foreach ($r in $Results | Sort-Object Phase, TestId) {
        $statusClass = switch ($r.Status) {
            "PASS"    { "pass" }
            "FAIL"    { "fail" }
            "WARNING" { "warn" }
            "WARN"    { "warn" }
            "INFO"    { "info" }
            default   { "skip" }
        }
        $sevClass = switch ($r.Severity) {
            "Critical" { "sev-critical" }
            "High"     { "sev-high" }
            "Medium"   { "sev-medium" }
            default    { "sev-low" }
        }
        $evidenceHtml = if ($r.Evidence) { "<details><summary>View Evidence</summary><pre class='evidence'>$([System.Web.HttpUtility]::HtmlEncode($r.Evidence))</pre></details>" } else { "" }
        $docsLink = if ($r.MSDocsLink) { "<a href='$($r.MSDocsLink)' target='_blank'>📖 MS Docs</a>" } else { "" }

        $rowsHtml += @"
        <div class="test-card $statusClass">
            <div class="test-header">
                <div class="test-id">$($r.TestId)</div>
                <div class="test-name">$([System.Web.HttpUtility]::HtmlEncode($r.Name))</div>
                <div class="badge $statusClass">$($r.Status)</div>
                <div class="badge $sevClass">$($r.Severity)</div>
                <div class="test-duration">⏱ $($r.Duration)</div>
            </div>
            <div class="test-body">
                <div class="test-phase">$([System.Web.HttpUtility]::HtmlEncode($r.Phase))</div>
                <div class="test-desc">$([System.Web.HttpUtility]::HtmlEncode($r.Description))</div>
                <div class="attack-technique"><strong>⚔️ Attack Technique:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.AttackTechnique))</div>
                <div class="result-box"><strong>📋 Result:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.Result))</div>
                $(if ($r.Remediation) { "<div class='remediation'><strong>🔧 Remediation:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.Remediation))</div>" })
                $evidenceHtml
                $docsLink
            </div>
        </div>
"@
    }

    # Phase summary cards
    $phaseSummaryHtml = ""
    $phases = $Results | Select-Object -ExpandProperty Phase -Unique | Sort-Object
    foreach ($phase in $phases) {
        $phaseTests = $Results | Where-Object Phase -eq $phase
        $pPass = ($phaseTests | Where-Object Status -eq "PASS").Count
        $pFail = ($phaseTests | Where-Object Status -eq "FAIL").Count
        $pWarn = ($phaseTests | Where-Object { $_.Status -in @("WARNING","WARN") }).Count
        $phaseSummaryHtml += @"
        <div class="phase-summary-card">
            <div class="phase-name">$([System.Web.HttpUtility]::HtmlEncode($phase))</div>
            <div class="phase-stats">
                <span class="stat-pass">✅ $pPass</span>
                <span class="stat-fail">❌ $pFail</span>
                <span class="stat-warn">⚠️ $pWarn</span>
            </div>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EntraScope Pentest Report - $($script:Config.TenantDomain)</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0a0e1a; color: #c8d6ef; line-height: 1.6; }
        
        .header { background: linear-gradient(135deg, #0d1b3e 0%, #1a237e 50%, #0a0e1a 100%); padding: 40px; border-bottom: 2px solid #1e3a6e; }
        .header h1 { font-size: 2.5rem; color: #fff; font-weight: 700; letter-spacing: -0.5px; }
        .header h1 span { color: #4fc3f7; }
        .header-meta { display: flex; gap: 30px; margin-top: 15px; flex-wrap: wrap; }
        .header-meta .meta-item { color: #90a4ae; font-size: 0.9rem; }
        .header-meta .meta-item strong { color: #b0bec5; }
        
        .score-banner { display: flex; align-items: center; justify-content: space-between; background: #0f1929; padding: 25px 40px; border-bottom: 1px solid #1e3a6e; flex-wrap: wrap; gap: 20px; }
        .score-circle { width: 100px; height: 100px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 800; border: 4px solid; color: #fff; }
        .score-label { margin-left: 20px; }
        .score-label h2 { color: #90a4ae; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
        .score-label p { font-size: 1.5rem; font-weight: 700; color: #fff; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; }
        .stat-card { background: #0f1929; border-radius: 8px; padding: 15px; text-align: center; border: 1px solid #1e3a6e; }
        .stat-card .stat-value { font-size: 2rem; font-weight: 800; }
        .stat-card .stat-label { font-size: 0.75rem; text-transform: uppercase; color: #78909c; letter-spacing: 0.5px; margin-top: 4px; }
        .stat-card.pass .stat-value { color: #00c851; }
        .stat-card.fail .stat-value { color: #ff4444; }
        .stat-card.warn .stat-value { color: #ff8800; }
        .stat-card.info .stat-value { color: #4fc3f7; }
        .stat-card.skip .stat-value { color: #78909c; }
        
        .section { padding: 30px 40px; }
        .section h2 { font-size: 1.4rem; color: #4fc3f7; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #1e3a6e; text-transform: uppercase; letter-spacing: 1px; }
        
        .phase-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .phase-summary-card { background: #0f1929; border: 1px solid #1e3a6e; border-radius: 8px; padding: 15px; }
        .phase-name { font-weight: 600; color: #b0bec5; font-size: 0.85rem; margin-bottom: 8px; }
        .phase-stats { display: flex; gap: 12px; }
        .stat-pass { color: #00c851; font-weight: 700; }
        .stat-fail { color: #ff4444; font-weight: 700; }
        .stat-warn { color: #ff8800; font-weight: 700; }
        
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 6px 16px; border-radius: 20px; border: 1px solid; cursor: pointer; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; background: transparent; }
        .filter-btn.active, .filter-btn:hover { filter: brightness(1.3); }
        .filter-btn.all { border-color: #4fc3f7; color: #4fc3f7; }
        .filter-btn.pass { border-color: #00c851; color: #00c851; }
        .filter-btn.fail { border-color: #ff4444; color: #ff4444; }
        .filter-btn.warn { border-color: #ff8800; color: #ff8800; }
        
        .test-card { background: #0f1929; border: 1px solid #1e3a6e; border-radius: 8px; margin-bottom: 12px; overflow: hidden; transition: border-color 0.2s; }
        .test-card:hover { border-color: #4fc3f7; }
        .test-card.fail { border-left: 3px solid #ff4444; }
        .test-card.pass { border-left: 3px solid #00c851; }
        .test-card.warn { border-left: 3px solid #ff8800; }
        .test-card.info { border-left: 3px solid #4fc3f7; }
        .test-card.skip { border-left: 3px solid #78909c; }
        
        .test-header { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; flex-wrap: wrap; }
        .test-header:hover { background: #131f35; }
        .test-id { font-family: monospace; font-size: 0.8rem; color: #546e7a; background: #0a0e1a; padding: 2px 8px; border-radius: 4px; }
        .test-name { flex: 1; font-weight: 600; color: #eceff1; }
        .test-duration { font-size: 0.75rem; color: #546e7a; margin-left: auto; }
        
        .badge { padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .badge.pass { background: #00c85120; color: #00c851; border: 1px solid #00c85140; }
        .badge.fail { background: #ff444420; color: #ff4444; border: 1px solid #ff444440; }
        .badge.warn { background: #ff880020; color: #ff8800; border: 1px solid #ff880040; }
        .badge.info { background: #4fc3f720; color: #4fc3f7; border: 1px solid #4fc3f740; }
        .badge.skip { background: #78909c20; color: #78909c; border: 1px solid #78909c40; }
        .badge.error { background: #e91e6320; color: #e91e63; border: 1px solid #e91e6340; }
        .sev-critical { background: #b71c1c20; color: #ef5350; border: 1px solid #b71c1c40; }
        .sev-high { background: #e65100_20; color: #ff7043; border: 1px solid #e6510040; }
        .sev-medium { background: #f9a82520; color: #ffca28; border: 1px solid #f9a82540; }
        .sev-low { background: #1b5e2020; color: #66bb6a; border: 1px solid #1b5e2040; }
        
        .test-body { padding: 16px; border-top: 1px solid #1e3a6e; display: none; }
        .test-card.expanded .test-body { display: block; }
        .test-phase { font-size: 0.75rem; color: #546e7a; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; }
        .test-desc { color: #90a4ae; margin-bottom: 12px; font-size: 0.9rem; }
        .attack-technique { background: #1a0a1a; border: 1px solid #4a1040; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; font-size: 0.85rem; color: #ce93d8; }
        .result-box { background: #0a1a0a; border: 1px solid #1b5e20; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; font-size: 0.9rem; color: #a5d6a7; }
        .test-card.fail .result-box { background: #1a0a0a; border-color: #7f1010; color: #ef9a9a; }
        .test-card.warn .result-box { background: #1a1000; border-color: #7f5000; color: #ffe082; }
        .remediation { background: #0a1529; border: 1px solid #0d47a1; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; font-size: 0.85rem; color: #90caf9; }
        .evidence { background: #050a14; border: 1px solid #1e3a6e; border-radius: 4px; padding: 12px; font-size: 0.75rem; color: #78909c; white-space: pre-wrap; word-break: break-all; margin-top: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; }
        details summary { cursor: pointer; color: #4fc3f7; font-size: 0.8rem; margin-bottom: 5px; }
        details summary:hover { color: #81d4fa; }
        a { color: #4fc3f7; text-decoration: none; font-size: 0.85rem; }
        a:hover { color: #81d4fa; text-decoration: underline; }
        
        .footer { text-align: center; padding: 30px; color: #37474f; font-size: 0.8rem; border-top: 1px solid #1e3a6e; }
        .disclaimer { background: #1a0a00; border: 1px solid #7f4500; border-radius: 8px; padding: 15px 20px; margin: 20px 40px; color: #ff8800; font-size: 0.85rem; }
        
        @media print { .filters { display: none; } .test-body { display: block !important; } }
    </style>
</head>
<body>

<div class="header">
    <h1>⚡ Entra<span>Scope</span> Pentest Report</h1>
    <div class="header-meta">
        <div class="meta-item"><strong>Tenant:</strong> $($script:Config.TenantDomain)</div>
        <div class="meta-item"><strong>Run Date:</strong> $runDate</div>
        <div class="meta-item"><strong>Duration:</strong> ${duration}m</div>
        <div class="meta-item"><strong>Mode:</strong> $(if ($script:DryRun) { "DRY RUN" } else { "ACTIVE PROBE" })</div>
        <div class="meta-item"><strong>Auth:</strong> $AuthMethod</div>
    </div>
</div>

<div class="disclaimer">
    ⚠️ <strong>AUTHORIZED SECURITY ASSESSMENT</strong> — This report was generated by EntraScope for authorized penetration testing.
    All findings represent actual security gaps found in the tested environment. Handle with appropriate security controls.
</div>

<div class="score-banner">
    <div style="display:flex; align-items:center;">
        <div class="score-circle" style="border-color:$scoreColor; color:$scoreColor;">$secScore%</div>
        <div class="score-label">
            <h2>Security Score</h2>
            <p>$(if ($secScore -ge 85) { "✅ Strong" } elseif ($secScore -ge 60) { "⚠️ Moderate" } else { "❌ Needs Immediate Attention" })</p>
        </div>
    </div>
    <div class="stats-grid">
        <div class="stat-card pass"><div class="stat-value">$pass</div><div class="stat-label">Pass</div></div>
        <div class="stat-card fail"><div class="stat-value">$fail</div><div class="stat-label">Fail</div></div>
        <div class="stat-card warn"><div class="stat-value">$warn</div><div class="stat-label">Warning</div></div>
        <div class="stat-card skip"><div class="stat-value">$skip</div><div class="stat-label">Skipped</div></div>
        <div class="stat-card info"><div class="stat-value">$total</div><div class="stat-label">Total Tests</div></div>
    </div>
</div>

<div class="section">
    <h2>Phase Summary</h2>
    <div class="phase-grid">
        $phaseSummaryHtml
    </div>
</div>

<div class="section">
    <h2>Test Results</h2>
    <div class="filters">
        <button class="filter-btn all active" onclick="filterTests('all')">All ($total)</button>
        <button class="filter-btn fail" onclick="filterTests('fail')">❌ Fail ($fail)</button>
        <button class="filter-btn warn" onclick="filterTests('warn')">⚠️ Warning ($warn)</button>
        <button class="filter-btn pass" onclick="filterTests('pass')">✅ Pass ($pass)</button>
        <button class="filter-btn skip" onclick="filterTests('skip')">⏭ Skipped ($skip)</button>
    </div>
    <div id="test-results">
        $rowsHtml
    </div>
</div>

<div class="footer">
    Generated by <strong>EntraScope</strong> v1.0 | Azure & M365 Entra Penetration Testing Toolkit<br>
    Report Date: $runDate | Tests Run: $total | <em>CONFIDENTIAL - For Authorized Personnel Only</em>
</div>

<script>
function filterTests(status) {
    const cards = document.querySelectorAll('.test-card');
    cards.forEach(card => {
        if (status === 'all') {
            card.style.display = '';
        } else {
            card.style.display = card.classList.contains(status) ? '' : 'none';
        }
    });
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

document.querySelectorAll('.test-header').forEach(header => {
    header.addEventListener('click', () => {
        header.closest('.test-card').classList.toggle('expanded');
    });
});

// Auto-expand failed tests
document.querySelectorAll('.test-card.fail').forEach(card => {
    card.classList.add('expanded');
});
</script>

</body>
</html>
"@

    $html | Set-Content $OutputPath -Encoding UTF8
    Write-EntraLog "HTML Report: $OutputPath" -Level Success
}

# ─────────────────────────────────────────────────────────────
#   JSON REPORT
# ─────────────────────────────────────────────────────────────
function New-JSONReport {
    [CmdletBinding()]
    param(
        [object[]]$Results,
        [string]$OutputPath
    )

    $total  = $Results.Count
    $pass   = ($Results | Where-Object Status -eq "PASS").Count
    $fail   = ($Results | Where-Object Status -eq "FAIL").Count
    $warn   = ($Results | Where-Object { $_.Status -in @("WARNING","WARN") }).Count
    $skip   = ($Results | Where-Object Status -in @("SKIPPED","INFO")).Count
    $secScore = if ($total -gt 0) { [Math]::Round($pass / [Math]::Max(($total - $skip),1) * 100, 0) } else { 0 }

    $report = [PSCustomObject]@{
        ReportMetadata = [PSCustomObject]@{
            Tool        = "EntraScope v1.0"
            Tenant      = $script:Config.TenantDomain
            TenantId    = $script:Config.TenantId
            RunDate     = $script:StartTime.ToString("o")
            Duration    = "$([Math]::Round(((Get-Date)-$script:StartTime).TotalMinutes,1))m"
            AuthMethod  = $AuthMethod
            DryRun      = $script:DryRun
        }
        ExecutiveSummary = [PSCustomObject]@{
            SecurityScore        = $secScore
            TotalTests           = $total
            PassCount            = $pass
            FailCount            = $fail
            WarningCount         = $warn
            SkippedCount         = $skip
            CriticalFindings     = ($Results | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "Critical" }).Count
            HighFindings         = ($Results | Where-Object { $_.Status -eq "FAIL" -and $_.Severity -eq "High" }).Count
        }
        Findings = $Results
        LogLines = $script:LogLines
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content $OutputPath -Encoding UTF8
    Write-EntraLog "JSON Report: $OutputPath" -Level Success
}

# ─────────────────────────────────────────────────────────────
#   CLI MENU
# ─────────────────────────────────────────────────────────────
function Show-EntraScopeMenu {
    try { Initialize-Config } catch {}
    
    $run = $true
    while ($run) {
        Clear-Host
        Write-Host @"

  ███████╗███╗   ██╗████████╗██████╗  █████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║███████╗██║     ██║   ██║██████╔╝█████╗  
  ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
  ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝

  --- EntraScope CLI Menu ---

  [1] Run Full Security Scan (All Phases)
  [2] Run Custom Security Scan (Select Phases)
  [3] Edit Configuration (scope.json)
  [4] Auto-Provision Test Environment (Honeypot Accounts)
  [5] Remove Test Environment
  [0] Exit

"@ -ForegroundColor Cyan

        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" {
                $script:Phases = "All"
                Invoke-EntraScope
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "2" {
                $customPhases = Read-Host "Enter comma-separated phases (e.g. 1,2,3 or Recon,Cred)"
                $script:Phases = $customPhases
                Invoke-EntraScope
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "3" {
                if (-not $script:Config) { try { Initialize-Config } catch {} }
                $currentTenant = if ($script:Config.TenantDomain) { $script:Config.TenantDomain } else { "none" }
                $newTenant = Read-Host "Enter Tenant Domain [Current: $currentTenant]"
                if ($newTenant) {
                    $script:Config.TenantDomain = $newTenant
                    $script:Config.TenantId = "" # reset to force discovery
                    $script:Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigFile -Encoding UTF8
                    Write-Host "Config saved to $ConfigFile" -ForegroundColor Green
                }
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "4" {
                Write-Host "`n--- Provisioning Test Environment ---" -ForegroundColor Cyan
                try {
                    Invoke-Authentication
                    $setupModule = Join-Path $PSScriptRoot "modules\SetupTestEnvironment.ps1"
                    if (Test-Path $setupModule) { . $setupModule } else { throw "Setup module not found" }
                    $result = New-EntraScopeTestEnvironment
                    if ($result.Success) { Write-Host "`nTest Environment Provisioned Successfully" -ForegroundColor Green }
                } catch {
                    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "5" {
                Write-Host "`n--- Removing Test Environment ---" -ForegroundColor Cyan
                try {
                    Invoke-Authentication
                    $setupModule = Join-Path $PSScriptRoot "modules\SetupTestEnvironment.ps1"
                    if (Test-Path $setupModule) { . $setupModule } else { throw "Setup module not found" }
                    $result = Remove-EntraScopeTestEnvironment
                    if ($result.Success) { Write-Host "`nTest Environment Removed Successfully" -ForegroundColor Green }
                } catch {
                    Write-Host "`nError: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host "`nPress any key to return to menu..." -ForegroundColor Yellow
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "0" {
                $run = $false
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────
#   MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────
function Invoke-EntraScope {
    Clear-Host
    Write-Host @"

  ███████╗███╗   ██╗████████╗██████╗  █████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║███████╗██║     ██║   ██║██████╔╝█████╗  
  ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
  ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝

  Azure & M365 Entra Penetration Testing Toolkit v1.0-beta
  ─────────────────────────────────────────────────────────────────────────────────────
  AUTHORIZED USE ONLY. Test only environments you own or have written permission to test.
  ─────────────────────────────────────────────────────────────────────────────────────

"@ -ForegroundColor Cyan

    # Initialize
    Initialize-Config
    Invoke-Authentication

    # Load all phase modules
    $modulesPath = "$PSScriptRoot\modules"
    $moduleFiles  = @(
        "Phase1-Recon.ps1"
        "Phase2-CredAttacks.ps1"
        "Phase3-OAuthTokenAbuse.ps1"
        "Phase4-PrivEsc.ps1"
        "Phase5-Persistence.ps1"
        "Phase6-LateralMovement.ps1"
        "Phase7-AzureResources.ps1"
        "Phase8-DetectionGaps.ps1"
    )

    foreach ($mf in $moduleFiles) {
        $mp = Join-Path $modulesPath $mf
        if (Test-Path $mp) {
            . $mp
            Write-EntraLog "Loaded module: $mf" -Level Debug
        } else {
            Write-EntraLog "Module not found: $mp" -Level Warn
        }
    }
    
    # Load custom modules
    $customModulesPath = "$PSScriptRoot\custom_modules"
    if (Test-Path $customModulesPath) {
        $customFiles = Get-ChildItem -Path $customModulesPath -Filter "*.ps1"
        foreach ($cf in $customFiles) {
            . $cf.FullName
            Write-EntraLog "Loaded custom module: $($cf.Name)" -Level Debug
        }
    }

    # Determine which phases to run
    $phasesToRun = Get-PhasesToRun
    Write-EntraLog "Phases to run: $($phasesToRun -join ', ')" -Level Info

    # Auto-Provision Test Environment
    if (-not $SkipAutoProvision) {
        $setupModule = Join-Path $PSScriptRoot "modules\SetupTestEnvironment.ps1"
        if (Test-Path $setupModule) {
            . $setupModule
            Write-EntraLog "Auto-Provisioning Test Environment..." -Level Info
            try {
                $null = New-EntraScopeTestEnvironment
            } catch {
                Write-EntraLog "Auto-provisioning failed: $($_.Exception.Message)" -Level Error
            }
        }
    }

    $allResults = [System.Collections.Generic.List[object]]::new()

    $phaseMap = @{
        1 = { Invoke-Phase1 }
        2 = { Invoke-Phase2 }
        3 = { Invoke-Phase3 }
        4 = { Invoke-Phase4 }
        5 = { Invoke-Phase5 }
        6 = { Invoke-Phase6 }
        7 = { Invoke-Phase7 }
        8 = { Invoke-Phase8 }
        9 = { if (Get-Command Invoke-Phase9 -ErrorAction SilentlyContinue) { Invoke-Phase9 } }
    }

    foreach ($phaseNum in $phasesToRun) {
        if ($phaseMap[$phaseNum]) {
            try {
                $phaseResults = & $phaseMap[$phaseNum]
                if ($phaseResults) { $phaseResults | ForEach-Object { $allResults.Add($_) } }
            }
            catch {
                Write-EntraLog "Phase $phaseNum failed with error: $($_.Exception.Message)" -Level Error
                $allResults.Add((New-TestResult -TestId "PHASE-$phaseNum" -Phase "Phase $phaseNum" `
                    -Name "Phase Execution Error" -Severity "High" -Status "ERROR" `
                    -Description "The phase encountered an unexpected error." `
                    -AttackTechnique "N/A" -Result $_.Exception.Message -Evidence "" -Remediation "" `
                    -MSDocsLink "" -Duration "0s"))
            }
        }
    }

    # Auto-Cleanup Test Environment
    if ($script:Config.Options.CleanupAfterTest) {
        $setupModule = Join-Path $PSScriptRoot "modules\SetupTestEnvironment.ps1"
        if (Test-Path $setupModule) {
            . $setupModule
            Write-EntraLog "Auto-Cleaning Test Environment..." -Level Info
            try {
                $null = Remove-EntraScopeTestEnvironment
            } catch {
                Write-EntraLog "Auto-cleanup failed: $($_.Exception.Message)" -Level Warn
            }
        }
    }

    # Generate reports
    Write-EntraLog "" -Level Info
    Write-EntraLog "=====================================" -Level Info
    Write-EntraLog " GENERATING REPORTS" -Level Attack
    Write-EntraLog "=====================================" -Level Info

    $null = New-Item -ItemType Directory -Path $OutputDir -Force
    $timestamp = $script:StartTime.ToString("yyyyMMdd-HHmm")
    $htmlPath  = Join-Path $OutputDir "EntraScope-Report-${timestamp}.html"
    $jsonPath  = Join-Path $OutputDir "EntraScope-Report-${timestamp}.json"

    # Load HttpUtility for HTML encoding
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    New-HTMLReport -Results $allResults -OutputPath $htmlPath
    New-JSONReport -Results $allResults -OutputPath $jsonPath

    # Print executive summary
    $total  = $allResults.Count
    $pass   = ($allResults | Where-Object Status -eq "PASS").Count
    $fail   = ($allResults | Where-Object Status -eq "FAIL").Count
    $warn   = ($allResults | Where-Object { $_.Status -in @("WARNING","WARN") }).Count
    $secScore = if ($total -gt 0) { [Math]::Round($pass / [Math]::Max(($total),1) * 100, 0) } else { 0 }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ENTRASCOPE SUMMARY - $($script:Config.TenantDomain)" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Security Score:  $secScore%" -ForegroundColor $(if ($secScore -ge 85) {"Green"} elseif ($secScore -ge 60) {"Yellow"} else {"Red"})
    Write-Host "  Total Tests:     $total" -ForegroundColor White
    Write-Host "  ✅ PASS:         $pass" -ForegroundColor Green
    Write-Host "  ❌ FAIL:         $fail" -ForegroundColor Red
    Write-Host "  ⚠️  WARNING:      $warn" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  CRITICAL Fails: $(($allResults | Where-Object {$_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical'}).Count)" -ForegroundColor Red
    Write-Host "  HIGH Fails:     $(($allResults | Where-Object {$_.Status -eq 'FAIL' -and $_.Severity -eq 'High'}).Count)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  📊 HTML Report: $htmlPath" -ForegroundColor Cyan
    Write-Host "  📋 JSON Report: $jsonPath" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan

    return $allResults
}

# Run
if ($Menu -or ($PSBoundParameters.Count -eq 0)) {
    Show-EntraScopeMenu
} else {
    Invoke-EntraScope
}
