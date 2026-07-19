#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope GUI — PowerShell + WPF + WebView2 (zero external dependencies)
.DESCRIPTION
    Launch with:  pwsh -STA -File .\EntraScopeGUI.ps1
    Run Setup-WebView2.ps1 once first to populate .\lib\ with the three DLLs.
#>
[CmdletBinding()]
param(
    [string]$Root    = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [string]$LibPath = "$PSScriptRoot\lib"
)
$ErrorActionPreference = "Stop"

# ─── 0. STA CHECK ─────────────────────────────────────────────────────────────
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne "STA") {
    Write-Host "[ERROR] Must run in STA mode: pwsh -STA -File EntraScopeGUI.ps1" -ForegroundColor Red
    exit 1
}

# ─── 1. LOAD ASSEMBLIES ───────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
Add-Type -AssemblyName System.Windows.Forms

$coreDll = Join-Path $LibPath "Microsoft.Web.WebView2.Core.dll"
$wpfDll  = Join-Path $LibPath "Microsoft.Web.WebView2.Wpf.dll"

if (-not (Test-Path $coreDll) -or -not (Test-Path $wpfDll)) {
    [System.Windows.MessageBox]::Show(
        "WebView2 DLLs not found in:`n$LibPath`n`nRun Setup-WebView2.ps1 first.",
        "EntraScope", "OK", "Error") | Out-Null
    exit 1
}
Add-Type -Path $coreDll, $wpfDll

# ─── 2. SHARED STATE ──────────────────────────────────────────────────────────
$script:sync = [hashtable]::Synchronized(@{
    LogQueue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    Results  = [System.Collections.Generic.List[object]]::new()
    Status   = "Idle"
    Cancel   = $false
})
$script:drainTimer = $null
$script:webReady   = $false
$script:webView    = $null   # set after EnsureCoreWebView2Async completes

# ─── 3. HELPER FUNCTIONS ──────────────────────────────────────────────────────
function Get-ConfigPath { Join-Path $Root "config\scope.json" }

function Read-ScopeConfig {
    $p = Get-ConfigPath
    if (Test-Path $p) { return (Get-Content $p -Raw | ConvertFrom-Json) }
    return $null
}

function Save-ScopeConfig([object]$data) {
    $p = Get-ConfigPath
    $null = New-Item -ItemType Directory -Path (Split-Path $p) -Force
    $data | ConvertTo-Json -Depth 10 | Set-Content $p -Encoding UTF8
}

function Get-ReportList {
    $d = Join-Path $Root "reports"
    if (-not (Test-Path $d)) { return @() }
    Get-ChildItem $d -Filter "*.html" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                name = $_.Name
                path = $_.FullName
                date = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            }
        }
}

function Send-Page([string]$json) {
    if (-not $script:webReady -or -not $script:webView) { return }
    $j = $json  # capture for closure
    $script:webView.Dispatcher.BeginInvoke([Action]{
        try { $script:webView.CoreWebView2.PostWebMessageAsJson($j) } catch {}
    })
}

function Start-Scan([object]$params) {
    if ($script:sync.Status -eq "Running") { return }
    $script:sync.Status  = "Running"
    $script:sync.Cancel  = $false
    $script:sync.Results = [System.Collections.Generic.List[object]]::new()
    $tmp = ""
    while ($script:sync.LogQueue.TryDequeue([ref]$tmp)) {}

    $phases     = if ($params.phases)      { $params.phases }      else { @(1,2,3,4,5,6,7,8) }
    $authMethod = if ($params.authMethod)  { $params.authMethod }  else { "Interactive" }
    $dryRun     = [bool]($params.dryRun)
    $clientId   = if ($params.clientId)   { $params.clientId }    else { "" }
    $clientSec  = if ($params.clientSecret){ $params.clientSecret } else { "" }
    $autoProv   = [bool]($params.autoProvision)

    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = "MTA"
    $rs.Open()
    $rs.SessionStateProxy.SetVariable("sync",       $script:sync)
    $rs.SessionStateProxy.SetVariable("Root",       $Root)
    $rs.SessionStateProxy.SetVariable("phases",     $phases)
    $rs.SessionStateProxy.SetVariable("authMethod", $authMethod)
    $rs.SessionStateProxy.SetVariable("dryRun",     $dryRun)
    $rs.SessionStateProxy.SetVariable("clientId",   $clientId)
    $rs.SessionStateProxy.SetVariable("clientSec",  $clientSec)
    $rs.SessionStateProxy.SetVariable("autoProvision", $autoProv)

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
        try {
            function Write-EntraLog {
                param([string]$Message,[string]$Level="Info")
                if ($Level -eq "Debug") { return }
                $sync.LogQueue.Enqueue("$Level`t$Message")
            }
            function New-TestResult {
                param($TestId,$Phase,$Name,$Severity,$Status,$Description,
                      $AttackTechnique,$Result,$Evidence,$Remediation,$MSDocsLink,$Duration)
                [PSCustomObject]@{
                    TestId=$TestId; Phase=$Phase; Name=$Name; Severity=$Severity
                    Status=$Status; Description=$Description
                    AttackTechnique=$AttackTechnique; Result=$Result
                    Evidence=$Evidence; Remediation=$Remediation
                    MSDocsLink=$MSDocsLink; Duration=$Duration
                    Timestamp=(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                }
            }

            $cfgPath = Join-Path $Root "config\scope.json"
            if (Test-Path $cfgPath) {
                $script:Config = Get-Content $cfgPath -Raw | ConvertFrom-Json
            } else {
                $script:Config = [PSCustomObject]@{
                    TenantDomain=""; TenantId=""
                    HoneypotAccounts=@()
                    Options=[PSCustomObject]@{ RateLimitMs=2000; CleanupAfterTest=$true }
                }
            }
            $script:DryRun      = $dryRun
            $script:AccessToken = $null
            $script:AzToken     = $null

            $moduleMap = @{
                "1"="Phase1-Recon.ps1";      "2"="Phase2-CredAttacks.ps1"
                "3"="Phase3-OAuthTokenAbuse.ps1"; "4"="Phase4-PrivEsc.ps1"
                "5"="Phase5-Persistence.ps1"; "6"="Phase6-LateralMovement.ps1"
                "7"="Phase7-AzureResources.ps1"; "8"="Phase8-DetectionGaps.ps1"
            }
            $phaseFnMap = @{
                "1"="Invoke-Phase1"; "2"="Invoke-Phase2"; "3"="Invoke-Phase3"
                "4"="Invoke-Phase4"; "5"="Invoke-Phase5"; "6"="Invoke-Phase6"
                "7"="Invoke-Phase7"; "8"="Invoke-Phase8"
            }
            foreach ($n in $phases) {
                $nStr = [string]$n
                if ($moduleMap.ContainsKey($nStr)) {
                    $mf = Join-Path $Root "modules\$($moduleMap[$nStr])"
                    if (Test-Path $mf -PathType Leaf) { . $mf }
                }
            }

            if (-not $dryRun) {
                Write-EntraLog "Starting authentication ($authMethod)..." Info
                $tid = $script:Config.TenantId
                if (-not $tid -and $script:Config.TenantDomain) {
                    try {
                        $oidc = Invoke-RestMethod "https://login.microsoftonline.com/$($script:Config.TenantDomain)/.well-known/openid-configuration" -TimeoutSec 10
                        $tid  = $oidc.issuer -replace ".*/([0-9a-f-]{36})/.*",'$1'
                        $script:Config.TenantId = $tid
                        Write-EntraLog "TenantId: $tid" Success
                    } catch { Write-EntraLog "TenantId discovery failed: $($_.Exception.Message)" Warn }
                }
                switch ($authMethod) {
                    "None" {
                        Write-EntraLog "Recon-only mode — skipping authentication" Warn
                    }
                    "DeviceCode" {
                        $dcBody = @{ client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                                     scope="https://graph.microsoft.com/.default offline_access" }
                        $dcResp = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/devicecode" `
                            -Method POST -Body $dcBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
                        $sync.LogQueue.Enqueue("AUTH_CODE`t$($dcResp.user_code)`t$($dcResp.verification_uri)")
                        $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
                        while ((Get-Date) -lt $deadline -and -not $sync.Cancel) {
                            Start-Sleep 5
                            try {
                                $tb = @{ grant_type="urn:ietf:params:oauth:grant-type:device_code"
                                         device_code=$dcResp.device_code
                                         client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46" }
                                $tok = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                                    -Method POST -Body $tb -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10
                                $script:AccessToken = $tok.access_token
                                Write-EntraLog "Authentication successful" Success
                                break
                            } catch {
                                $e = $null; try { $e = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                                if ($e.error -ne "authorization_pending") { throw }
                            }
                        }
                    }
                    "ServicePrincipal" {
                        if ($clientId -and $clientSec) {
                            $body = @{ grant_type="client_credentials"; client_id=$clientId
                                       client_secret=$clientSec; scope="https://graph.microsoft.com/.default" }
                            $tok  = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                                -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
                            $script:AccessToken = $tok.access_token
                            Write-EntraLog "Service Principal auth successful" Success
                        }
                    }
                    default {
                        # Interactive browser auth can't work from a background runspace.
                        # Use Device Code flow instead — the GUI will display the code + URL.
                        Write-EntraLog "Interactive mode: using Device Code flow for GUI auth..." Info
                        try {
                            $dcBody = @{ client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                                         scope="https://graph.microsoft.com/.default offline_access" }
                            $dcResp = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/devicecode" `
                                -Method POST -Body $dcBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
                            Write-EntraLog "Device code: $($dcResp.user_code) — open $($dcResp.verification_uri)" Attack
                            $sync.LogQueue.Enqueue("AUTH_CODE`t$($dcResp.user_code)`t$($dcResp.verification_uri)")
                            $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
                            while ((Get-Date) -lt $deadline -and -not $sync.Cancel) {
                                Start-Sleep 5
                                try {
                                    $tb = @{ grant_type="urn:ietf:params:oauth:grant-type:device_code"
                                             device_code=$dcResp.device_code
                                             client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46" }
                                    $tok = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                                        -Method POST -Body $tb -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10
                                    $script:AccessToken = $tok.access_token
                                    Write-EntraLog "Authentication successful" Success
                                    break
                                } catch {
                                    $e = $null; try { $e = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                                    if ($e.error -ne "authorization_pending") { throw }
                                }
                            }
                        } catch {
                            Write-EntraLog ("Auth failed: " + $_.Exception.Message) Error
                        }
                    }
                }

                # Acquire ARM token for Azure Resource phases (7/8) if Graph auth succeeded
                if ($script:AccessToken -and -not $script:AzToken) {
                    Write-EntraLog "Acquiring Azure Management token..." Info
                    try {
                        $armBody = @{ client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                                      scope="https://management.azure.com/.default offline_access" }
                        $armDc = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/devicecode" `
                            -Method POST -Body $armBody -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15
                        Write-EntraLog ("ARM device code: " + $armDc.user_code + " — open " + $armDc.verification_uri) Attack
                        $sync.LogQueue.Enqueue("AUTH_CODE`t$($armDc.user_code)`t$($armDc.verification_uri)")
                        $armDeadline = (Get-Date).AddSeconds($armDc.expires_in)
                        while ((Get-Date) -lt $armDeadline -and -not $sync.Cancel) {
                            Start-Sleep 5
                            try {
                                $armTb = @{ grant_type="urn:ietf:params:oauth:grant-type:device_code"
                                            device_code=$armDc.device_code
                                            client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46" }
                                $armTok = Invoke-RestMethod "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                                    -Method POST -Body $armTb -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10
                                $script:AzToken = $armTok.access_token
                                Write-EntraLog "ARM token acquired" Success
                                break
                            } catch {
                                $armErr = $null; try { $armErr = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
                                if ($armErr.error -ne "authorization_pending") {
                                    Write-EntraLog ("ARM auth skipped: " + $_.Exception.Message) Warn
                                    break
                                }
                            }
                        }
                    } catch {
                        Write-EntraLog ("ARM token skipped: " + $_.Exception.Message) Warn
                    }
                }
            } else {
                Write-EntraLog "DRY RUN — no live API calls" Warn
            }

            if ($autoProvision -and -not $dryRun -and $authMethod -ne "None") {
                Write-EntraLog "▶ Auto-provisioning Test Environment..." Attack
                $setupModule = Join-Path $Root "modules\SetupTestEnvironment.ps1"
                if (Test-Path $setupModule) { 
                    . $setupModule 
                    try {
                        $setupRes = New-EntraScopeTestEnvironment
                        if ($setupRes.Success) {
                            Write-EntraLog "Test environment provisioned successfully" Success
                            $sync.LogQueue.Enqueue("SETUP_DONE`t" + ($setupRes | ConvertTo-Json -Depth 10 -Compress))
                        } else {
                            Write-EntraLog "Test environment setup failed: $($setupRes.Message)" Error
                        }
                    } catch {
                        Write-EntraLog "Test environment setup error: $($_.Exception.Message)" Error
                    }
                } else {
                    Write-EntraLog "modules\SetupTestEnvironment.ps1 not found — skipping auto-provision" Warn
                }
            }

            $total = @($phases).Count; $i = 0
            foreach ($n in ($phases | Sort-Object)) {
                if ($sync.Cancel) { Write-EntraLog "Cancelled" Warn; break }
                $i++
                $nStr = [string]$n
                if (-not $phaseFnMap.ContainsKey($nStr)) { continue }
                $fn = $phaseFnMap[$nStr]
                
                if (Get-Command $fn -ErrorAction SilentlyContinue) {
                    Write-EntraLog "▶ Phase $nStr — $fn" Attack
                    $sync.LogQueue.Enqueue("PROGRESS`t$i`t$total`tPhase $nStr")
                    try {
                        $r = & $fn
                        if ($r) { $r | ForEach-Object { $sync.Results.Add($_) } }
                    } catch { Write-EntraLog "Phase $nStr error: $($_.Exception.Message)" Error }
                } else {
                    Write-EntraLog "Phase $nStr module not found — skipping" Warn
                }
            }
            $sync.Status = "Done"
            $sync.LogQueue.Enqueue("SCAN_DONE`t")
        } catch {
            $sync.Status = "Error"
            $sync.LogQueue.Enqueue("Error`tFatal: $($_.Exception.Message)")
            $sync.LogQueue.Enqueue("SCAN_DONE`t")
        }
    })
    $null = $ps.BeginInvoke()
}

# ─── 4. MESSAGE HANDLER (Page → PowerShell) ───────────────────────────────────
function Handle-Message([string]$raw) {
    try {
        try { $msg = $raw | ConvertFrom-Json } catch { return }
        switch ($msg.action) {
            "ready" {
                $cfg = Read-ScopeConfig
                if ($cfg) { Send-Page (@{ type="config"; data=$cfg } | ConvertTo-Json -Depth 10 -Compress) }
                Send-Page (@{ type="reportList"; data=@(Get-ReportList) } | ConvertTo-Json -Depth 5 -Compress)
                Send-Page (@{ type="status"; value="Idle"; root=$Root } | ConvertTo-Json -Compress)
                $mfPath = Join-Path $Root "reports\setup-manifest.json"
                Send-Page (@{ type="manifestExists"; exists=(Test-Path $mfPath) } | ConvertTo-Json -Compress)
            }
        "saveConfig" {
            try {
                Save-ScopeConfig $msg.data
                Send-Page (@{ type="toast"; message="Saved"; kind="success" } | ConvertTo-Json -Compress)
            } catch {
                Send-Page (@{ type="toast"; message="Save failed: $($_.Exception.Message)"; kind="error" } | ConvertTo-Json -Compress)
            }
        }
        "getConfig" {
            $cfg = Read-ScopeConfig
            if ($cfg) { Send-Page (@{ type="config"; data=$cfg } | ConvertTo-Json -Depth 10 -Compress) }
        }
        "startScan" {
            if ($script:sync.Status -eq "Running") {
                Send-Page (@{ type="toast"; message="Scan already running"; kind="warn" } | ConvertTo-Json -Compress)
                return
            }
            Start-Scan $msg
            Send-Page (@{ type="status"; value="Running" } | ConvertTo-Json -Compress)
            if ($script:drainTimer) { $script:drainTimer.Stop() }
            $script:drainTimer = Start-DrainTimer
        }
        "cancelScan" {
            $script:sync.Cancel = $true; $script:sync.Status = "Cancelled"
            Send-Page (@{ type="toast"; message="Cancellation requested..."; kind="warn" } | ConvertTo-Json -Compress)
        }
        "openReport" {
            if ($msg.path -and (Test-Path $msg.path)) { Start-Process $msg.path }
        }
        "openReportFolder" {
            $d = Join-Path $Root "reports"; $null = New-Item -ItemType Directory -Path $d -Force
            Start-Process explorer.exe $d
        }
        "pickConfigFile" {
            $dlg = [System.Windows.Forms.OpenFileDialog]::new()
            $dlg.Filter = "JSON (*.json)|*.json|All (*.*)|*.*"; $dlg.Title = "Select scope.json"
            if ($dlg.ShowDialog() -eq "OK") {
                Send-Page (@{ type="configPath"; path=$dlg.FileName } | ConvertTo-Json -Compress)
            }
        }
        "clearLog" { Send-Page (@{ type="clearLog" } | ConvertTo-Json -Compress) }
        "getReports" {
            Send-Page (@{ type="reportList"; data=@(Get-ReportList) } | ConvertTo-Json -Depth 5 -Compress)
        }
        "cleanupEnv" {
            $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $rs.ApartmentState = "MTA"; $rs.Open()
            $rs.SessionStateProxy.SetVariable("sync", $script:sync)
            $rs.SessionStateProxy.SetVariable("Root", $Root)
            $rs.SessionStateProxy.SetVariable("AccessToken", $script:AccessToken)
            $ps = [powershell]::Create(); $ps.Runspace = $rs
            $null = $ps.AddScript({
                try {
                    function Write-EntraLog { param([string]$Message,[string]$Level="Info"); $sync.LogQueue.Enqueue("$Level`t$Message") }
                    $script:AccessToken = $AccessToken
                    if (-not $script:AccessToken) { throw "Not authenticated. Session token missing." }
                    Write-EntraLog "Starting cleanup using existing session..." Info
                    $setupModule = Join-Path $Root "modules\SetupTestEnvironment.ps1"
                    if (Test-Path $setupModule) { . $setupModule }
                    $result = Remove-EntraScopeTestEnvironment
                    $sync.LogQueue.Enqueue("CLEANUP_DONE`t" + ($result | ConvertTo-Json -Depth 5 -Compress))
                } catch {
                    $sync.LogQueue.Enqueue("CLEANUP_DONE`t" + (@{ Success=$false; Message=$_.Exception.Message } | ConvertTo-Json -Compress))
                }
            })
            $null = $ps.BeginInvoke()
            Send-Page (@{ type="toast"; message="Cleanup starting..."; kind="success" } | ConvertTo-Json -Compress)
            if ($script:drainTimer) { $script:drainTimer.Stop() }
            $script:drainTimer = Start-DrainTimer
        }
        "getSetupManifest" {
            $mf = Join-Path $Root "reports\setup-manifest.json"
            if (Test-Path $mf) {
                $data = Get-Content $mf -Raw | ConvertFrom-Json
                Send-Page (@{ type="manifestForCleanup"; data=$data } | ConvertTo-Json -Depth 10 -Compress)
            } else {
                Send-Page (@{ type="toast"; message="No test environment found"; kind="warn" } | ConvertTo-Json -Compress)
            }
        }
    }
    } catch {
        $_ | Out-String | Add-Content (Join-Path $Root "debug.txt")
        Send-Page (@{ type="toast"; message="Internal error: $($_.Exception.Message)"; kind="error" } | ConvertTo-Json -Compress)
    }
}

# ─── 5. LOG DRAIN TIMER ───────────────────────────────────────────────────────
function Start-DrainTimer {
    $t = [System.Windows.Threading.DispatcherTimer]::new()
    $t.Interval = [TimeSpan]::FromMilliseconds(100)
    $t.Add_Tick({
        try {
            if (-not $script:webReady) { return }
            $line = ""
            while ($script:sync.LogQueue.TryDequeue([ref]$line)) {
                if ($null -eq $line) { continue }
                if ($line.StartsWith("PROGRESS`t")) {
                    $p = $line -split "`t"
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="progress"; current=[int]$p[1]; total=[int]$p[2]; phase=$p[3] } | ConvertTo-Json -Compress))
                    }
                } elseif ($line.StartsWith("SCAN_DONE`t")) {
                    $r    = @($script:sync.Results)
                    $pass = @($r | Where-Object Status -eq "PASS").Count
                    $fail = @($r | Where-Object Status -eq "FAIL").Count
                    $warn = @($r | Where-Object { $_.Status -in "WARNING","WARN" }).Count
                    $skip = @($r | Where-Object { $_.Status -in "SKIPPED","INFO","ERROR" }).Count
                    $sc   = [Math]::Round($pass / [Math]::Max($r.Count - $skip,1) * 100)
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="results"; data=$r } | ConvertTo-Json -Depth 10 -Compress))
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="complete"; score=$sc; pass=$pass; fail=$fail; warn=$warn } | ConvertTo-Json -Compress))
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="status"; value="Done" } | ConvertTo-Json -Compress))
                    }
                    try {
                        $d  = Join-Path $Root "reports"; $null = New-Item -ItemType Directory -Path $d -Force
                        $jp = Join-Path $d "EntraScope-$(Get-Date -Format yyyyMMdd-HHmm).json"
                        @{ Results=$r } | ConvertTo-Json -Depth 10 | Set-Content $jp -Encoding UTF8
                        if ($script:webView -and $script:webView.CoreWebView2) {
                            $script:webView.CoreWebView2.PostWebMessageAsJson(
                                (@{ type="toast"; message="Report saved: $([System.IO.Path]::GetFileName($jp))"; kind="success" } | ConvertTo-Json -Compress))
                        }
                    } catch {}
                    if ($script:drainTimer) { $script:drainTimer.Stop() }
                } elseif ($line.StartsWith("SETUP_DONE`t")) {
                    $jsonStr = $line.Substring(11)
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="setupResult"; data=($jsonStr | ConvertFrom-Json) } | ConvertTo-Json -Depth 10 -Compress))
                    }
                } elseif ($line.StartsWith("CLEANUP_DONE`t")) {
                    $jsonStr = $line.Substring(13)
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="cleanupResult"; data=($jsonStr | ConvertFrom-Json) } | ConvertTo-Json -Depth 10 -Compress))
                    }
                } elseif ($line.StartsWith("AUTH_CODE`t")) {
                    $p = $line -split "`t"
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="authCode"; code=$p[1]; url=$p[2] } | ConvertTo-Json -Compress))
                    }
                } else {
                    $p   = $line -split "`t", 2
                    $lv  = $p[0]; $lm = if ($p.Count -gt 1) { $p[1] } else { $line }
                    if ($script:webView -and $script:webView.CoreWebView2) {
                        $script:webView.CoreWebView2.PostWebMessageAsJson(
                            (@{ type="log"; level=$lv; message=$lm } | ConvertTo-Json -Compress))
                    }
                }
            }
        } catch {
            "TICK ERROR: $($_.Exception.Message)`n$($_.ScriptStackTrace)`n$($_.Exception.StackTrace)" | Add-Content (Join-Path $Root "tick-error.txt")
        }
    })
    $t.Start()
    return $t
}

# ─── 6. HTML/CSS/JS FRONTEND ──────────────────────────────────────────────────
$script:html = @'
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>EntraScope</title>
<style>
:root{--bg:#0a0e1a;--panel:#0f1929;--sb:#070b16;--mid:#131f35;--bdr:#1e3a6e;
  --tx:#c8d6ef;--dim:#78909c;--ac:#4fc3f7;--ok:#00c851;--fail:#ff4444;
  --warn:#ff8800;--purple:#ce93d8;font-family:'Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);height:100vh;display:flex;overflow:hidden}
/* sidebar */
.sb{width:64px;background:var(--sb);display:flex;flex-direction:column;align-items:center;
  padding:14px 0;border-right:1px solid var(--bdr);flex-shrink:0}
.logo{font-size:1.5rem;margin-bottom:18px;color:var(--ac)}
.nb{width:46px;height:46px;border-radius:10px;border:none;background:transparent;cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-size:1.2rem;margin:3px 0;
  color:var(--dim);transition:all .2s;position:relative}
.nb:hover{background:var(--mid);color:var(--ac)}
.nb.on{background:var(--ac);color:#000}
.nb .tip{position:absolute;left:56px;background:#1a2a4a;color:var(--ac);padding:4px 10px;
  border-radius:6px;font-size:.74rem;white-space:nowrap;pointer-events:none;opacity:0;
  transition:opacity .15s;border:1px solid var(--bdr);z-index:99}
.nb:hover .tip{opacity:1}
.sb-bot{margin-top:auto;color:var(--dim);font-size:.6rem;text-align:center;padding:8px}
/* main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{background:var(--panel);border-bottom:1px solid var(--bdr);padding:10px 20px;
  display:flex;align-items:center;gap:14px}
.topbar h1{font-size:1rem;font-weight:600;color:var(--ac);flex:1}
.pill{padding:3px 12px;border-radius:20px;font-size:.73rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.pill-idle{background:#1a2a4a;color:var(--dim)}
.pill-running{background:#0a2a0a;color:var(--ok);animation:blink 1.4s infinite}
.pill-done{background:#0a2a0a;color:var(--ok)}
.pill-error{background:#2a0a0a;color:var(--fail)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.45}}
.ttag{font-size:.73rem;color:var(--dim);background:var(--mid);padding:3px 10px;
  border-radius:20px;border:1px solid var(--bdr)}
.content{flex:1;overflow-y:auto;padding:22px}
/* views */
.view{display:none}.view.on{display:block}
/* cards */
.card{background:var(--panel);border:1px solid var(--bdr);border-radius:10px;padding:18px;margin-bottom:14px}
.card-hd{font-size:.73rem;text-transform:uppercase;letter-spacing:1px;color:var(--dim);margin-bottom:12px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
/* gauge */
.gauge-wrap{display:flex;align-items:center;gap:28px;flex-wrap:wrap}
.gsv{width:130px;height:130px}
.gbg{fill:none;stroke:#1e3a6e;stroke-width:10}
.grng{fill:none;stroke:var(--ac);stroke-width:10;stroke-linecap:round;
  transform-origin:60px 60px;transform:rotate(-90deg);
  transition:stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1),stroke .4s}
.glbl{fill:var(--tx);font-size:22px;font-weight:800;text-anchor:middle;dominant-baseline:central}
.gdet{flex:1}
.gdet h2{font-size:2rem;font-weight:800}
.gsub{font-size:.88rem;margin:4px 0 14px;color:var(--dim)}
/* stats */
.srow{display:flex;gap:10px;flex-wrap:wrap}
.stat{background:var(--mid);border:1px solid var(--bdr);border-radius:8px;
  padding:11px 14px;flex:1;min-width:80px;text-align:center}
.sv{font-size:1.8rem;font-weight:800}.sl{font-size:.68rem;text-transform:uppercase;color:var(--dim);margin-top:2px}
.st .sv{color:var(--ac)}.sp .sv{color:var(--ok)}.sf .sv{color:var(--fail)}
.sw .sv{color:var(--warn)}.sk .sv{color:var(--dim)}
/* phase mini */
.pmini{background:var(--mid);border:1px solid var(--bdr);border-radius:8px;padding:9px 12px}
.pmini .pn{font-size:.76rem;color:var(--tx);margin-bottom:5px;font-weight:600}
.pmini .pb{display:flex;gap:6px;font-size:.7rem}
.pok{color:var(--ok)}.pfl{color:var(--fail)}.pwn{color:var(--warn)}
/* form */
.fg{margin-bottom:12px}
.fg label{display:block;font-size:.76rem;color:var(--dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
.fg input,.fg select,.fg textarea{width:100%;background:var(--mid);border:1px solid var(--bdr);
  color:var(--tx);border-radius:6px;padding:7px 11px;font-size:.88rem;outline:none;font-family:inherit}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--ac)}
.fg input::placeholder,.fg textarea::placeholder{color:var(--dim)}
.rrow{display:flex;align-items:center;gap:10px}
.rrow input[type=range]{flex:1;accent-color:var(--ac)}
.rv{font-size:.83rem;color:var(--ac);min-width:50px}
.trow{display:flex;align-items:center;gap:9px}
input[type=checkbox]{accent-color:var(--ac);width:15px;height:15px;cursor:pointer}
.hlist{display:flex;flex-direction:column;gap:6px;margin-bottom:8px}
.hitem{display:flex;gap:8px;align-items:center}.hitem input{flex:1}
/* buttons */
.btn{padding:7px 16px;border-radius:7px;border:none;cursor:pointer;font-size:.83rem;font-weight:600;transition:all .2s}
.btn-p{background:var(--ac);color:#000}.btn-p:hover{filter:brightness(1.15)}
.btn-d{background:#7f1010;color:#ffcccc}.btn-d:hover{background:#a00}
.btn-g{background:transparent;color:var(--dim);border:1px solid var(--bdr)}
.btn-g:hover{border-color:var(--ac);color:var(--ac)}
.btn-s{padding:4px 11px;font-size:.76rem}
.btn:disabled{opacity:.35;cursor:not-allowed}
.bgrp{display:flex;gap:8px;flex-wrap:wrap}
/* auth selector */
.asel{display:flex;gap:8px;margin-bottom:12px}
.abtn{flex:1;padding:9px;border-radius:7px;border:1px solid var(--bdr);background:var(--mid);
  color:var(--dim);cursor:pointer;font-size:.83rem;transition:all .2s;text-align:center}
.abtn.on{background:var(--ac);color:#000;border-color:var(--ac);font-weight:700}
.abtn:hover:not(.on){border-color:var(--ac);color:var(--ac)}
.spf{display:none}.spf.on{display:block}
/* phase grid */
.pgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(195px,1fr));gap:8px;margin-bottom:12px}
.pc{background:var(--mid);border:1px solid var(--bdr);border-radius:7px;padding:9px 11px;
  cursor:pointer;transition:all .2s;display:flex;align-items:flex-start;gap:8px}
.pc:hover{border-color:var(--ac)}
.pc.on{border-color:var(--ac);background:#0d2035}
.pc input{accent-color:var(--ac);margin-top:2px}
.pnum{font-size:.68rem;background:var(--bdr);padding:2px 6px;border-radius:10px;color:var(--dim);white-space:nowrap}
.pnl{font-size:.8rem;color:var(--tx)}
.pnl small{display:block;font-size:.68rem;color:var(--dim);margin-top:2px}
/* run button */
.runbtn{width:100%;padding:15px;font-size:1rem;font-weight:700;border-radius:10px;border:none;
  cursor:pointer;background:var(--ac);color:#000;transition:all .3s;letter-spacing:.5px;margin-bottom:12px}
.runbtn:hover{filter:brightness(1.18);transform:translateY(-1px)}
.runbtn:disabled{opacity:.3;transform:none;cursor:not-allowed}
.runbtn.scan{background:linear-gradient(90deg,#00c851,#4fc3f7);animation:sp 2s infinite}
@keyframes sp{0%,100%{filter:brightness(1)}50%{filter:brightness(1.28)}}
/* progress */
.pwrap{height:6px;background:var(--mid);border-radius:4px;overflow:hidden;margin-bottom:5px}
.pbar{height:100%;background:linear-gradient(90deg,var(--ac),var(--ok));border-radius:4px;transition:width .4s;width:0}
.plbl{font-size:.73rem;color:var(--dim);margin-bottom:10px}
/* terminal */
.term{background:#050b14;border:1px solid var(--bdr);border-radius:8px;
  height:275px;overflow-y:auto;padding:11px;font-family:'Cascadia Code',Consolas,monospace;font-size:.76rem;line-height:1.6}
.term::-webkit-scrollbar{width:4px}.term::-webkit-scrollbar-thumb{background:var(--bdr)}
.ll{white-space:pre-wrap;word-break:break-all}
.lI{color:#4fc3f7}.lS{color:#00c851}.lW{color:#ff8800}.lE{color:#ff4444}.lA{color:#ce93d8}
/* auth code box */
.acbox{background:#0a1f0a;border:1px solid #1b5e20;border-radius:8px;padding:14px;margin-bottom:12px;display:none}
.acbox.on{display:block}
.acbox .code{font-size:2rem;font-weight:800;color:var(--ok);letter-spacing:4px;display:block;margin:8px 0}
.acbox .url{color:var(--ac);font-size:.88rem}
/* results */
.fbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.fc{padding:4px 13px;border-radius:20px;border:1px solid;background:transparent;cursor:pointer;font-size:.76rem;font-weight:600;transition:all .2s}
.fc-a{border-color:var(--ac);color:var(--ac)}.fc-f{border-color:var(--fail);color:var(--fail)}
.fc-w{border-color:var(--warn);color:var(--warn)}.fc-p{border-color:var(--ok);color:var(--ok)}
.fc-s{border-color:var(--dim);color:var(--dim)}
.fc.on{filter:brightness(1.5)}
.rc{background:var(--panel);border:1px solid var(--bdr);border-radius:8px;margin-bottom:9px;overflow:hidden;cursor:pointer;transition:border-color .2s}
.rc:hover{border-color:var(--ac)}
.rc.rf{border-left:3px solid var(--fail)}.rc.rp{border-left:3px solid var(--ok)}
.rc.rw{border-left:3px solid var(--warn)}.rc.rs{border-left:3px solid var(--dim)}
.rc.ri{border-left:3px solid var(--ac)}
.rch{display:flex;align-items:center;gap:9px;padding:10px 13px;flex-wrap:wrap}
.rid{font-family:monospace;font-size:.73rem;color:var(--dim);background:var(--mid);padding:2px 7px;border-radius:4px}
.rnm{flex:1;font-weight:600;font-size:.88rem}
.bdg{padding:2px 8px;border-radius:20px;font-size:.68rem;font-weight:700;text-transform:uppercase}
.bdg-p{background:#00c85120;color:var(--ok);border:1px solid #00c85140}
.bdg-f{background:#ff444420;color:var(--fail);border:1px solid #ff444440}
.bdg-w{background:#ff880020;color:var(--warn);border:1px solid #ff880040}
.bdg-s{background:#78909c20;color:var(--dim);border:1px solid #78909c40}
.bdg-i{background:#4fc3f720;color:var(--ac);border:1px solid #4fc3f740}
.sc{background:#b71c1c20;color:#ef5350;border:1px solid #b71c1c40}
.sh{background:#e6510020;color:#ff7043;border:1px solid #e6510040}
.sm{background:#f9a82520;color:#ffca28;border:1px solid #f9a82540}
.sl2{background:#1b5e2020;color:#66bb6a;border:1px solid #1b5e2040}
.rcb{padding:11px 13px;border-top:1px solid var(--bdr);display:none}
.rc.exp .rcb{display:block}
.rcd{color:var(--dim);font-size:.81rem;margin-bottom:7px}
.rcat{background:#1a0a1a;border:1px solid #4a1040;border-radius:5px;padding:7px 9px;font-size:.78rem;color:var(--purple);margin-bottom:7px}
.rcr{background:#0a1a0a;border:1px solid #1b5e20;border-radius:5px;padding:7px 9px;font-size:.83rem;color:#a5d6a7;margin-bottom:7px}
.rc.rf .rcr{background:#1a0a0a;border-color:#7f1010;color:#ef9a9a}
.rc.rw .rcr{background:#1a1000;border-color:#7f5000;color:#ffe082}
.rcfx{background:#0a1529;border:1px solid #0d47a1;border-radius:5px;padding:7px 9px;font-size:.78rem;color:#90caf9;margin-bottom:7px}
.no-r{text-align:center;color:var(--dim);padding:60px 20px}
/* report list */
.rpt{display:flex;align-items:center;gap:11px;padding:9px 13px;background:var(--mid);
  border:1px solid var(--bdr);border-radius:7px;margin-bottom:7px;cursor:pointer;transition:all .2s}
.rpt:hover{border-color:var(--ac)}
.rpt-n{flex:1;font-size:.83rem}.rpt-d{font-size:.73rem;color:var(--dim)}
/* toast */
#toast{position:fixed;bottom:18px;right:18px;padding:9px 16px;border-radius:8px;font-size:.83rem;
  font-weight:600;opacity:0;transition:opacity .3s;pointer-events:none;z-index:999}
#toast.on{opacity:1}
#toast.ts{background:var(--ok);color:#000}#toast.tw{background:var(--warn);color:#000}
#toast.te{background:var(--fail);color:#fff}#toast.ti{background:var(--ac);color:#000}
/* scrollbars */
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#2a4a8e}
/* Modal */
.modal-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;z-index:999}
.modal-box{background:var(--c1);border:1px solid var(--bdr);border-radius:12px;width:460px;max-width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.modal-hd{padding:16px 20px;font-weight:700;font-size:1.05rem;border-bottom:1px solid var(--bdr)}
.modal-body{padding:16px 20px}
.modal-foot{padding:12px 20px;border-top:1px solid var(--bdr);display:flex;gap:8px;justify-content:flex-end}
.setup-list{display:flex;flex-direction:column;gap:6px}
.setup-item{display:flex;align-items:center;gap:10px;padding:8px 12px;background:rgba(255,255,255,.03);border:1px solid var(--bdr);border-radius:8px;font-size:.83rem}
.setup-item .si-icon{font-size:1.1rem;width:24px;text-align:center}
.setup-item .si-name{color:var(--fg);font-weight:600}
.setup-item .si-desc{color:var(--dim);font-size:.75rem}
.setup-pwd{margin-top:12px;padding:10px;background:rgba(0,200,80,.06);border:1px solid rgba(0,200,80,.2);border-radius:8px}
.setup-pwd .sp-label{font-weight:700;color:var(--ok);font-size:.8rem;margin-bottom:6px}
.setup-pwd .sp-row{display:flex;justify-content:space-between;font-size:.78rem;padding:2px 0;font-family:'Cascadia Code','Fira Code',monospace}
.setup-pwd .sp-upn{color:var(--dim)}
.setup-pwd .sp-pw{color:var(--fg);user-select:all}
</style></head><body>

<!-- SIDEBAR -->
<nav class="sb">
  <div class="logo">⚡</div>
  <button class="nb on" id="nb-dash" onclick="nav('dash')" title="">🏠<span class="tip">Dashboard</span></button>
  <button class="nb" id="nb-cfg"  onclick="nav('cfg')"  title="">⚙️<span class="tip">Configure</span></button>
  <button class="nb" id="nb-run"  onclick="nav('run')"  title="">▶️<span class="tip">Run Scan</span></button>
  <button class="nb" id="nb-res"  onclick="nav('res')"  title="">📊<span class="tip">Results</span></button>
  <button class="nb" id="nb-log"  onclick="nav('log')"  title="">💻<span class="tip">Full Log</span></button>
  <div class="sb-bot">v1.0</div>
</nav>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <h1>⚡ EntraScope — Azure &amp; M365 Entra Pentest</h1>
    <span class="ttag" id="ttag">No tenant configured</span>
    <span class="pill pill-idle" id="pill">Idle</span>
  </div>
  <div class="content">

    <!-- DASHBOARD -->
    <div class="view on" id="v-dash">
      <div class="card">
        <div class="card-hd">Security Score — Last Scan</div>
        <div class="gauge-wrap">
          <svg class="gsv" viewBox="0 0 120 120">
            <circle class="gbg" cx="60" cy="60" r="50"/>
            <circle class="grng" id="grng" cx="60" cy="60" r="50" stroke-dasharray="314" stroke-dashoffset="314"/>
            <text class="glbl" id="glbl" x="60" y="65">—</text>
          </svg>
          <div class="gdet">
            <h2 id="gval" style="color:var(--tx)">No scan yet</h2>
            <div class="gsub" id="grat">Run a scan to see results</div>
            <div class="srow">
              <div class="stat st"><div class="sv" id="s-t">—</div><div class="sl">Total</div></div>
              <div class="stat sp"><div class="sv" id="s-p">—</div><div class="sl">Pass</div></div>
              <div class="stat sf"><div class="sv" id="s-f">—</div><div class="sl">Fail</div></div>
              <div class="stat sw"><div class="sv" id="s-w">—</div><div class="sl">Warn</div></div>
              <div class="stat sk"><div class="sv" id="s-k">—</div><div class="sl">Skip</div></div>
            </div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd">Phase Breakdown</div>
        <div class="g3" id="ph-bd"><div style="color:var(--dim);font-size:.83rem">Run a scan first</div></div>
      </div>
      <div class="card">
        <div class="card-hd">Reports</div>
        <div id="rpt-list"><div style="color:var(--dim);font-size:.83rem">No reports found</div></div>
        <div class="bgrp" style="margin-top:9px">
          <button class="btn btn-g btn-s" onclick="ps({action:'getReports'})">🔄 Refresh</button>
          <button class="btn btn-g btn-s" onclick="ps({action:'openReportFolder'})">📂 Open Folder</button>
        </div>
      </div>
    </div>

    <!-- CONFIGURE -->
    <div class="view" id="v-cfg">
      <div class="card">
        <div class="card-hd">Tenant</div>
        <div class="g2">
          <div class="fg"><label>Tenant Domain</label><input id="c-dom" placeholder="contoso.onmicrosoft.com"/></div>
          <div class="fg"><label>Tenant ID (auto-discovered if blank)</label><input id="c-tid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd">Honeypot Accounts (Phase 2 credential tests)</div>
        <div class="hlist" id="hlist"></div>
        <button class="btn btn-g btn-s" onclick="addH()">+ Add Account</button>
      </div>
      <div class="card">
        <div class="card-hd">Test Account (low-privilege — Phase 4 &amp; 6)</div>
        <div class="fg"><label>UPN</label><input id="c-tup" placeholder="svc-pentest-lowpriv@contoso.com"/></div>
      </div>
      <div class="card">
        <div class="card-hd">Azure Subscriptions</div>
        <div class="trow" style="margin-bottom:9px">
          <input type="checkbox" id="c-ad" checked/>
          <label for="c-ad" style="cursor:pointer;font-size:.83rem">Auto-discover subscriptions from auth account</label>
        </div>
        <div class="fg"><label>Specific Subscription IDs (one per line)</label>
          <textarea id="c-subs" rows="3" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></textarea></div>
      </div>
      <div class="card">
        <div class="card-hd">Options</div>
        <div class="g2">
          <div class="fg"><label>Rate Limit Between Auth Attempts</label>
            <div class="rrow">
              <input type="range" id="c-rl" min="500" max="10000" step="500" value="2000"
                oninput="document.getElementById('c-rlv').textContent=this.value+'ms'"/>
              <span class="rv" id="c-rlv">2000ms</span>
            </div>
          </div>
          <div class="fg"><label>Cleanup</label>
            <div class="trow">
              <input type="checkbox" id="c-cl" checked/>
              <label for="c-cl" style="cursor:pointer;font-size:.83rem">Clean up test objects after Phase 5</label>
            </div>
          </div>
        </div>
      </div>

      <!-- CLEANUP CONFIRMATION MODAL -->
      <div id="cleanup-modal" class="modal-overlay" style="display:none">
        <div class="modal-box">
          <div class="modal-hd">🧹 Cleanup Test Environment</div>
          <div class="modal-body">
            <div style="margin-bottom:12px;color:var(--dim);font-size:.85rem">
              This will permanently delete all EntraScope test objects from your tenant:
            </div>
            <div id="cleanup-preview" class="setup-list"></div>
          </div>
          <div class="modal-foot">
            <button class="btn btn-d" onclick="approveCleanup()">🗑 Remove All</button>
            <button class="btn btn-g" onclick="closeModal('cleanup-modal')">📋 Keep (Manual Cleanup)</button>
          </div>
        </div>
      </div>
      <div class="bgrp">
        <button class="btn btn-p" onclick="saveCfg()">💾 Save Configuration</button>
        <button class="btn btn-g" onclick="ps({action:'pickConfigFile'})">📂 Load from File</button>
      </div>
    </div>

    <!-- RUN SCAN -->
    <div class="view" id="v-run">
      <div class="card">
        <div class="card-hd">Authentication Method</div>
        <div class="asel">
          <div class="abtn on" id="a-int" onclick="selAuth('Interactive')">🔐 Sign In (Device Code)<br><small>Opens browser to authenticate</small></div>
          <div class="abtn" id="a-sp"  onclick="selAuth('ServicePrincipal')">🔑 Service Principal<br><small>Client ID + Secret</small></div>
          <div class="abtn" id="a-dev" onclick="selAuth('None')">🔍 Recon Only<br><small>No authentication</small></div>
        </div>
        <div class="spf" id="spf">
          <div class="g2">
            <div class="fg"><label>Client ID</label><input id="r-cid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></div>
            <div class="fg"><label>Client Secret</label><input id="r-sec" type="password" placeholder="your-secret"/></div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd">Phases to Run</div>
        <div class="pgrid" id="pgrid"></div>
        <div class="bgrp">
          <button class="btn btn-g btn-s" onclick="allP(true)">Select All</button>
          <button class="btn btn-g btn-s" onclick="allP(false)">Deselect All</button>
          <label class="trow" style="margin-left:auto">
            <input type="checkbox" id="r-dry"/>
            <span style="font-size:.83rem">Dry Run (no live API calls)</span>
          </label>
        </div>
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--bdr)">
          <label class="trow">
            <input type="checkbox" id="r-setup" checked/>
            <span style="font-size:.83rem">Auto-provision Test Environment (Requires Global Admin)</span>
          </label>
        </div>
      </div>
      <div class="acbox" id="acbox">
        <div style="color:var(--ok);font-weight:700;margin-bottom:4px">🔐 Sign in required</div>
        <div style="font-size:.83rem;color:var(--dim)">Go to <span class="url" id="acurl"></span> and enter:</div>
        <span class="code" id="accode">XXXXXXXX</span>
        <div style="font-size:.73rem;color:var(--dim)">Waiting for authentication...</div>
      </div>
      <div id="prog-sec" style="display:none">
        <div class="pwrap"><div class="pbar" id="pbar"></div></div>
        <div class="plbl" id="plbl">Initialising...</div>
      </div>
      <button class="runbtn" id="runbtn" onclick="startScan()">▶  RUN SCAN</button>
      <button class="btn btn-d" id="canbtn" style="display:none;width:100%;margin-bottom:12px" onclick="cancelScan()">⏹  Cancel Scan</button>


      <div class="card" style="padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px">
          <div class="card-hd" style="margin-bottom:0">Live Output</div>
          <button class="btn btn-g btn-s" onclick="clrLog()">Clear</button>
        </div>
        <div class="term" id="rlog"></div>
      </div>
    </div>

    <!-- RESULTS -->
    <div class="view" id="v-res">
      <div class="fbar" id="fbar">
        <button class="fc fc-a on" onclick="filt('all',this)">All</button>
        <button class="fc fc-f" onclick="filt('rf',this)">❌ Fail</button>
        <button class="fc fc-w" onclick="filt('rw',this)">⚠️ Warn</button>
        <button class="fc fc-p" onclick="filt('rp',this)">✅ Pass</button>
        <button class="fc fc-s" onclick="filt('rs',this)">⏭ Skip</button>
      </div>
      <div id="rlist"><div class="no-r">Run a scan to see results</div></div>
    </div>

    <!-- LOG -->
    <div class="view" id="v-log">
      <div class="card" style="padding:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px">
          <div class="card-hd" style="margin-bottom:0">Full Log</div>
          <div class="bgrp">
            <button class="btn btn-g btn-s" onclick="cpLog()">📋 Copy</button>
            <button class="btn btn-g btn-s" onclick="clrLog()">🗑 Clear</button>
          </div>
        </div>
        <div class="term" id="flog" style="height:calc(100vh - 190px)"></div>
      </div>
    </div>

  </div>
</div>
<div id="toast"></div>

<script>
const PH = [
  {n:1,name:'Recon',           desc:'Unauthenticated external recon'},
  {n:2,name:'Cred Attacks',    desc:'Password spray & legacy auth'},
  {n:3,name:'OAuth Abuse',     desc:'Device code, consent, token abuse'},
  {n:4,name:'Priv Escalation', desc:'Role assignment & PIM bypass'},
  {n:5,name:'Persistence',     desc:'Backdoor apps & stale grants'},
  {n:6,name:'Lateral Move',    desc:'Graph pillage & Key Vault'},
  {n:7,name:'Azure Resources', desc:'RBAC, managed identity, ARM'},
  {n:8,name:'Detection Gaps',  desc:'Sentinel, Defender, log coverage'}
];
let G={auth:'Interactive',results:[],logLines:[]};

// Phases grid
function initPhases(){
  document.getElementById('pgrid').innerHTML=PH.map(p=>`
    <label class="pc on" id="pc${p.n}">
      <input type="checkbox" checked onchange="pcls(${p.n},this.checked)"/>
      <div><div style="display:flex;align-items:center;gap:5px;margin-bottom:2px">
        <span class="pnum">${p.n}</span><span class="pnl">${p.name}<small>${p.desc}</small></span>
      </div></div>
    </label>`).join('');
}
function pcls(n,c){document.getElementById('pc'+n).classList.toggle('on',c)}
function allP(on){PH.forEach(p=>{const e=document.getElementById('pc'+p.n);e.querySelector('input').checked=on;e.classList.toggle('on',on)})}

// Nav
function nav(v){
  document.querySelectorAll('.view').forEach(e=>e.classList.remove('on'));
  document.querySelectorAll('.nb').forEach(e=>e.classList.remove('on'));
  document.getElementById('v-'+v).classList.add('on');
  document.getElementById('nb-'+v).classList.add('on');
}

// Auth
function selAuth(m){
  G.auth=m;
  document.querySelectorAll('.abtn').forEach(e=>e.classList.remove('on'));
  document.getElementById('a-'+(m==='Interactive'?'int':m==='DeviceCode'?'dev':'sp')).classList.add('on');
  document.getElementById('spf').classList.toggle('on',m==='ServicePrincipal');
}

// Config
function applyConfig(c){
  document.getElementById('c-dom').value=c.TenantDomain||c.tenantDomain||'';
  document.getElementById('c-tid').value=c.TenantId||c.tenantId||'';
  document.getElementById('c-tup').value=(c.TestAccount||c.testAccount||{}).UPN||'';
  document.getElementById('c-ad').checked=(c.AzureSubscriptions||c.azureSubscriptions||{}).AutoDiscover!==false;
  document.getElementById('c-subs').value=((c.AzureSubscriptions||c.azureSubscriptions||{}).SpecificSubscriptionIds||[]).join('\n');
  document.getElementById('c-rl').value=(c.Options||c.options||{}).RateLimitMs||2000;
  document.getElementById('c-rlv').textContent=((c.Options||c.options||{}).RateLimitMs||2000)+'ms';
  document.getElementById('c-cl').checked=(c.Options||c.options||{}).CleanupAfterTest!==false;
  renderH(c.HoneypotAccounts||c.honeypotAccounts||[]);
  document.getElementById('ttag').textContent=c.TenantDomain||c.tenantDomain||'No tenant';
}
function renderH(list){
  const c=document.getElementById('hlist');
  const arr=list.length?list:[{UPN:''}];
  c.innerHTML=arr.map((h,i)=>`<div class="hitem">
    <input type="text" placeholder="honeypot${i+1}@tenant.com" value="${esc(h.UPN||h.upn||'')}"/>
    <button class="btn btn-g btn-s" onclick="rmH(this)">✕</button>
  </div>`).join('');
}
function addH(){const c=document.getElementById('hlist');const d=document.createElement('div');d.className='hitem';const i=c.children.length;d.innerHTML=`<input type="text" placeholder="honeypot${i+1}@tenant.com"/><button class="btn btn-g btn-s" onclick="rmH(this)">✕</button>`;c.appendChild(d)}
function rmH(btn){const p=btn.parentElement;const l=document.getElementById('hlist');if(l.children.length>1)p.remove();else p.querySelector('input').value=''}
function saveCfg(){
  const hp=Array.from(document.querySelectorAll('#hlist input')).map(e=>({UPN:e.value,Purpose:'CredentialAttackTesting'})).filter(h=>h.UPN);
  const subs=document.getElementById('c-subs').value.trim().split('\n').map(s=>s.trim()).filter(Boolean);
  const cfg={
    TenantDomain:document.getElementById('c-dom').value.trim(),
    TenantId:document.getElementById('c-tid').value.trim(),
    HoneypotAccounts:hp,
    TestAccount:{UPN:document.getElementById('c-tup').value.trim()},
    AzureSubscriptions:{AutoDiscover:document.getElementById('c-ad').checked,SpecificSubscriptionIds:subs},
    Options:{RateLimitMs:+document.getElementById('c-rl').value,CleanupAfterTest:document.getElementById('c-cl').checked,LogLevel:'Verbose'}
  };
  ps({action:'saveConfig',data:cfg});
  document.getElementById('ttag').textContent=cfg.TenantDomain||'No tenant';
}

// Scan
function startScan(){
  try {
    const phases=PH.filter(p=>document.getElementById('pc'+p.n)?.querySelector('input')?.checked).map(p=>p.n);
    if(!phases.length){toast('Select at least one phase','tw');return}
    ps({action:'startScan',phases,authMethod:G.auth,dryRun:document.getElementById('r-dry').checked,
        clientId:document.getElementById('r-cid').value,clientSecret:document.getElementById('r-sec').value,
        autoProvision:document.getElementById('r-setup').checked});
  } catch (e) {
    toast('JS Error: ' + e.message, 'te');
  }
}
function cancelScan(){ps({action:'cancelScan'})}

// Log
function appendLog(lv,msg){
  const ts=new Date().toLocaleTimeString('en-GB');
  const cl={'Info':'lI','Success':'lS','Warn':'lW','Error':'lE','Attack':'lA'}[lv]||'lI';
  const l=document.createElement('div');l.className=`ll ${cl}`;l.textContent=`${ts}  ${msg}`;
  document.getElementById('rlog').appendChild(l.cloneNode(true));
  document.getElementById('flog').appendChild(l);
  document.getElementById('rlog').scrollTop=9999;document.getElementById('flog').scrollTop=9999;
  G.logLines.push(`${ts} [${lv}] ${msg}`);
}
function clrLog(){document.getElementById('rlog').innerHTML='';document.getElementById('flog').innerHTML='';G.logLines=[]}
function cpLog(){navigator.clipboard.writeText(G.logLines.join('\n')).then(()=>toast('Copied','ts')).catch(()=>toast('Copy failed','te'))}

// Results
function renderResults(results){
  G.results=results;
  const c=document.getElementById('rlist');
  if(!results||!results.length){c.innerHTML='<div class="no-r">No results</div>';return}
  const ord={FAIL:0,WARNING:1,WARN:1,ERROR:2,PASS:3,SKIPPED:4,INFO:5};
  const sorted=[...results].sort((a,b)=>(ord[a.Status]??5)-(ord[b.Status]??5));
  c.innerHTML=sorted.map(r=>{
    const sc=stcls(r.Status),svc=sevcls(r.Severity);
    return`<div class="rc r${sc}" onclick="this.classList.toggle('exp')">
      <div class="rch">
        <span class="rid">${esc(r.TestId)}</span>
        <span class="rnm">${esc(r.Name)}</span>
        <span class="bdg bdg-${sc}">${r.Status}</span>
        <span class="bdg ${svc}">${r.Severity}</span>
        <span style="font-size:.68rem;color:var(--dim);margin-left:auto">⏱ ${r.Duration||''}</span>
      </div>
      <div class="rcb">
        <div style="font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px">${esc(r.Phase)}</div>
        <div class="rcd">${esc(r.Description)}</div>
        <div class="rcat"><b>⚔️ Attack:</b> ${esc(r.AttackTechnique)}</div>
        <div class="rcr"><b>📋 Result:</b> ${esc(r.Result)}</div>
        ${r.Remediation?`<div class="rcfx"><b>🔧 Fix:</b> ${esc(r.Remediation)}</div>`:''}
      </div></div>`;
  }).join('');
  document.querySelectorAll('.rc.rf').forEach(e=>e.classList.add('exp'));
  updFilt(results);
}
function stcls(s){return{PASS:'p',FAIL:'f',WARNING:'w',WARN:'w',INFO:'i'}[s]||'s'}
function sevcls(s){return{Critical:'sc',High:'sh',Medium:'sm',Low:'sl2'}[s]||'sl2'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function filt(cls,btn){
  document.querySelectorAll('.fc').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  document.querySelectorAll('.rc').forEach(c=>{c.style.display=cls==='all'||c.classList.contains(cls)?'':'none'});
}
function updFilt(r){
  const cnt={all:r.length,f:0,w:0,p:0,s:0};
  r.forEach(x=>{const c=stcls(x.Status);if(c==='f')cnt.f++;else if(c==='w')cnt.w++;else if(c==='p')cnt.p++;else cnt.s++});
  const texts={all:`All (${cnt.all})`,f:`❌ Fail (${cnt.f})`,w:`⚠️ Warn (${cnt.w})`,p:`✅ Pass (${cnt.p})`,s:`⏭ Skip (${cnt.s})`};
  document.querySelectorAll('.fc').forEach(b=>{
    const cls=['all','f','w','p','s'].find(k=>b.className.includes('fc-'+k=='fc-a'?'a':k));
    // simpler: just match by data
    if(b.className.includes('fc-a'))b.textContent=texts.all;
    else if(b.className.includes('fc-f'))b.textContent=texts.f;
    else if(b.className.includes('fc-w'))b.textContent=texts.w;
    else if(b.className.includes('fc-p'))b.textContent=texts.p;
    else if(b.className.includes('fc-s'))b.textContent=texts.s;
  });
}

// Dashboard
function updDash(r){
  if(!r||!r.length)return;
  const t=r.length,p=r.filter(x=>x.Status==='PASS').length,f=r.filter(x=>x.Status==='FAIL').length;
  const w=r.filter(x=>['WARNING','WARN'].includes(x.Status)).length;
  const k=r.filter(x=>['SKIPPED','INFO','ERROR'].includes(x.Status)).length;
  const sc=Math.round(p/Math.max(t-k,1)*100);
  const col=sc>=85?'#00c851':sc>=60?'#ff8800':'#ff4444';
  const ring=document.getElementById('grng');
  ring.style.strokeDashoffset=314*(1-sc/100);ring.style.stroke=col;
  document.getElementById('glbl').textContent=sc+'%';
  document.getElementById('gval').textContent=sc+'%';document.getElementById('gval').style.color=col;
  document.getElementById('grat').textContent=sc>=85?'✅ Strong security posture':sc>=60?'⚠️ Moderate — remediation needed':'❌ At Risk — immediate action required';
  document.getElementById('s-t').textContent=t;document.getElementById('s-p').textContent=p;
  document.getElementById('s-f').textContent=f;document.getElementById('s-w').textContent=w;document.getElementById('s-k').textContent=k;
  const phases={};r.forEach(x=>{if(!phases[x.Phase])phases[x.Phase]={p:0,f:0,w:0};
    const c=stcls(x.Status);if(c==='p')phases[x.Phase].p++;else if(c==='f')phases[x.Phase].f++;else if(c==='w')phases[x.Phase].w++});
  document.getElementById('ph-bd').innerHTML=Object.entries(phases).map(([nm,c])=>
    `<div class="pmini"><div class="pn">${esc(nm)}</div><div class="pb"><span class="pok">✅${c.p}</span><span class="pfl">❌${c.f}</span><span class="pwn">⚠️${c.w}</span></div></div>`).join('');
}

// Report list
function renderRpts(files){
  const c=document.getElementById('rpt-list');
  if(!files||!files.length){c.innerHTML='<div style="color:var(--dim);font-size:.83rem">No reports found</div>';return}
  c.innerHTML=files.map(f=>`<div class="rpt" onclick="ps({action:'openReport',path:'${f.path.replace(/\\/g,'\\\\')}'})">
    <span style="font-size:1.1rem">📊</span><span class="rpt-n">${esc(f.name)}</span><span class="rpt-d">${f.date}</span>
  </div>`).join('');
}

// Status bar
function setStatus(v){
  const p=document.getElementById('pill');p.className=`pill pill-${v.toLowerCase()}`;p.textContent=v;
  const run=v==='Running';
  document.getElementById('runbtn').disabled=run;document.getElementById('runbtn').classList.toggle('scan',run);
  document.getElementById('canbtn').style.display=run?'':'none';
  document.getElementById('prog-sec').style.display=run?'':'none';
}

// Toast
let _tt;
function toast(msg,cls='ti'){
  const t=document.getElementById('toast');t.textContent=msg;t.className='on '+cls;
  clearTimeout(_tt);_tt=setTimeout(()=>t.className=cls,2600);
}

// Message bridge (PS → JS)
window.chrome.webview.addEventListener('message',ev=>{
  let m;try{m=typeof ev.data==='string'?JSON.parse(ev.data):ev.data}catch{return}
  switch(m.type){
    case 'config':   applyConfig(m.data); break;
    case 'status':   setStatus(m.value||'Idle'); if(m.root)document.getElementById('ttag').textContent=m.root; break;
    case 'log':      appendLog(m.level||'Info',m.message||''); break;
    case 'progress':
      const pct=Math.round((m.current/m.total)*100);
      document.getElementById('pbar').style.width=pct+'%';
      document.getElementById('plbl').textContent=`${m.phase} — ${m.current}/${m.total} phases`;
      break;
    case 'results':  renderResults(m.data); updDash(m.data); nav('res'); break;
    case 'complete': setStatus('Done'); toast(`Done — Score:${m.score}%  Fail:${m.fail}`,'ts'); if(document.getElementById('r-setup')?.checked){ps({action:'getSetupManifest'})}; break;
    case 'reportList': renderRpts(m.data); break;
    case 'toast':    toast(m.message,{success:'ts',warn:'tw',error:'te'}[m.kind]||'ti'); break;
    case 'clearLog': clrLog(); break;
    case 'authCode':
      document.getElementById('acurl').textContent=m.url||'';
      document.getElementById('accode').textContent=m.code||'';
      document.getElementById('acbox').classList.add('on'); break;
    case 'authDone': document.getElementById('acbox').classList.remove('on'); break;
    case 'configPath': toast('Config loaded','ti'); break;
    case 'setupResult': showSetupResult(m.data); break;
    case 'cleanupResult': showCleanupResult(m.data); break;
    case 'manifestForCleanup': showManifestForCleanup(m.data); break;
    case 'manifestExists': checkManifestOnLoad(m.exists); break;
  }
});

// Test Environment Setup
function requestSetup(){
  const dom=document.getElementById('c-dom').value.trim();
  if(!dom){toast('Set Tenant Domain in Config first','tw');return}
  const items=[
    {icon:'👤',name:'entrascope-honeypot1@'+dom,desc:'Honeypot account for credential tests'},
    {icon:'👤',name:'entrascope-honeypot2@'+dom,desc:'Second honeypot for spray detection'},
    {icon:'👤',name:'entrascope-testuser@'+dom,desc:'Low-privilege test user for priv-esc tests'},
    {icon:'📦',name:'EntraScope-TestApp-'+new Date().toISOString().slice(0,10).replace(/-/g,''),desc:'Test app registration for OAuth tests'}
  ];
  const el=document.getElementById('setup-preview');
  el.innerHTML=items.map(i=>`<div class="setup-item"><span class="si-icon">${i.icon}</span><div><div class="si-name">${esc(i.name)}</div><div class="si-desc">${esc(i.desc)}</div></div></div>`).join('');
  document.getElementById('setup-modal').style.display='flex';
}
function approveSetup(){
  closeModal('setup-modal');
  document.getElementById('setup-btn').disabled=true;
  document.getElementById('setup-btn').textContent='⏳ Setting up...';
  ps({action:'setupEnv'});
}
function requestCleanup(){
  ps({action:'getSetupManifest'});
}
function approveCleanup(){
  closeModal('cleanup-modal');
  document.getElementById('cleanup-btn').disabled=true;
  document.getElementById('cleanup-btn').textContent='⏳ Removing...';
  ps({action:'cleanupEnv'});
}
function closeModal(id){document.getElementById(id).style.display='none'}
function showSetupResult(data){
  const el=document.getElementById('setup-status');
  if(data.Success){
    let html='<div style="color:var(--ok);font-weight:700;margin-bottom:8px">✅ '+esc(data.Message)+'</div>';
    if(data.Passwords&&data.Passwords.length){
      html+='<div class="setup-pwd"><div class="sp-label">🔑 Account Passwords (shown once — save these!)</div>';
      data.Passwords.forEach(p=>{html+='<div class="sp-row"><span class="sp-upn">'+esc(p.UPN||p.upn)+'</span><span class="sp-pw">'+esc(p.Password||p.password)+'</span></div>'});
      html+='</div>';
    }
    el.innerHTML=html;
    document.getElementById('setup-btn').style.display='none';
    document.getElementById('cleanup-btn').style.display='';
    document.getElementById('cleanup-btn').disabled=false;
    document.getElementById('cleanup-btn').textContent='🗑 Remove Test Objects';
  } else {
    el.innerHTML='<div style="color:var(--err);font-weight:700">❌ Setup failed: '+esc(data.Message||'Unknown error')+'</div>';
    document.getElementById('setup-btn').disabled=false;
    document.getElementById('setup-btn').textContent='🔧 Setup Test Environment';
  }
}
function showCleanupResult(data){
  const el=document.getElementById('setup-status');
  if(data.Success){
    el.innerHTML='<div style="color:var(--ok);font-weight:700;margin-bottom:4px">✅ Cleanup complete: '+data.Removed+' objects removed</div>';
    document.getElementById('cleanup-btn').style.display='none';
    document.getElementById('setup-btn').style.display='';
    document.getElementById('setup-btn').disabled=false;
    document.getElementById('setup-btn').textContent='🔧 Setup Test Environment';
  } else {
    el.innerHTML='<div style="color:var(--err)">❌ Cleanup error: '+esc(data.Message||'Unknown')+'</div>';
    document.getElementById('cleanup-btn').disabled=false;
    document.getElementById('cleanup-btn').textContent='🗑 Remove Test Objects';
  }
}
function showManifestForCleanup(data){
  if(!data||!data.Objects){toast('No test environment found','tw');return}
  const el=document.getElementById('cleanup-preview');
  el.innerHTML=(data.Objects||data.objects||[]).map(o=>{
    const icon=o.Type==='User'?'👤':'📦';
    return`<div class="setup-item"><span class="si-icon">${icon}</span><div><div class="si-name">${esc(o.DisplayName||o.displayName)}</div><div class="si-desc">${esc(o.UPN||o.upn||o.Id||o.id)}</div></div></div>`
  }).join('');
  document.getElementById('cleanup-modal').style.display='flex';
}
function checkManifestOnLoad(exists){
  if(exists){
    document.getElementById('setup-btn').style.display='none';
    document.getElementById('cleanup-btn').style.display='';
    document.getElementById('setup-status').innerHTML='<div style="color:var(--ok);font-size:.83rem">✅ Test environment is provisioned</div>';
  }
}

function ps(obj){window.chrome.webview.postMessage(JSON.stringify(obj))}

// Boot
initPhases();
ps({action:'ready'});
</script>
</body></html>
'@

# ─── 7. WINDOW + WEBVIEW2 SETUP ───────────────────────────────────────────────
$window  = [System.Windows.Window]::new()
$window.Title        = "EntraScope  —  Azure & M365 Entra Pentest Toolkit"
$window.Width        = 1380
$window.Height       = 860
$window.MinWidth     = 900
$window.MinHeight    = 600
$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterScreen
$window.Background   = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(10, 14, 26)

$webView = [Microsoft.Web.WebView2.Wpf.WebView2]::new()
$window.Content = $webView

$app = [System.Windows.Application]::new()
$app.Add_DispatcherUnhandledException({
    param($s, $e)
    Write-Host "[GUI ERROR] $($e.Exception.Message)`n$($e.Exception.StackTrace)" -ForegroundColor Red
    $e.Handled = $true
})

# Explicitly create and retain the delegate so it doesn't get garbage-collected
# and bypasses the PowerShell event queue (which is blocked by ShowDialog).
$script:webMsgDelegate = [System.EventHandler[Microsoft.Web.WebView2.Core.CoreWebView2WebMessageReceivedEventArgs]] {
    param($EventSender, $EventArgs)
    try {
        $raw = $EventArgs.TryGetWebMessageAsString()
        Handle-Message $raw
    } catch {
        # Silent swallow for delegate crashes in prod
    }
}

$window.Add_Loaded({
    # Start the async initialisation
    $null = $webView.EnsureCoreWebView2Async($null)

    # Poll every 200 ms until CoreWebView2 is ready
    $script:initTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $script:initTimer.Interval = [TimeSpan]::FromMilliseconds(200)
    $script:initTimer.Add_Tick({
        if ($null -eq $webView.CoreWebView2) { return }   # not ready yet

        $script:initTimer.Stop()

        # Settings
        $webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = $false
        $webView.CoreWebView2.Settings.IsStatusBarEnabled            = $false
        $webView.CoreWebView2.Settings.AreDevToolsEnabled            = $false

        $script:webView = $webView
        $script:webReady = $true

        # Message bridge: JS → PowerShell
        $webView.CoreWebView2.add_WebMessageReceived($script:webMsgDelegate)

        # Mark ready and load page
        $webView.CoreWebView2.NavigateToString($script:html)

        Write-Host "[EntraScope GUI] WebView2 ready — UI loaded." -ForegroundColor Green
    })
    $script:initTimer.Start()
})

$window.Add_Closed({ $app.Shutdown() })

# ─── 8. LAUNCH ────────────────────────────────────────────────────────────────
Write-Host "[EntraScope GUI] Starting..." -ForegroundColor Cyan
Write-Host "  Root:    $Root"    -ForegroundColor Gray
Write-Host "  LibPath: $LibPath" -ForegroundColor Gray
Write-Host "  Close the window to exit.`n" -ForegroundColor Gray

$app.Run($window)
