#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 8 - Detection Gap Validation
.DESCRIPTION
    Verifies that logging, alerting, and detection controls are working.
    Tests Sentinel/Defender alerts, audit log completeness, and diagnostic
    settings. AUTHORIZED USE ONLY.
#>

function Invoke-DETECT01-DiagnosticSettings {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-01] Diagnostic Settings Coverage" -Level Attack

    $evidence = [ordered]@{}

    # Check Entra ID diagnostic settings via Graph
    if ($script:AccessToken) {
        try {
            $headers = @{ Authorization = "Bearer $script:AccessToken" }
            # Check sign-in log diagnostic settings
            $diagSettings = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/auditLogs/diagnosticSettings" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
            $evidence["EntradDiagnosticSettings"] = $diagSettings.value | Select-Object name, workspaceId, storageAccountId, eventHubAuthorizationRuleId
            $hasSentinel = $diagSettings.value | Where-Object { $_.workspaceId }
            $evidence["SignInLogToSentinel"] = ($hasSentinel.Count -gt 0)
        } catch { $evidence["EntraDiagError"] = $_.Exception.Message }
    }

    # Check ARM diagnostic settings for subscriptions
    if ($script:AzToken) {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $subDiag = @()

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 2)) {
            try {
                $diag = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                $subDiag += [PSCustomObject]@{
                    SubscriptionId      = $subId
                    DiagSettingsCount   = $diag.value.Count
                    HasWorkspace        = (($diag.value | Where-Object { $_.properties.workspaceId }) -ne $null)
                    HasStorageAccount   = (($diag.value | Where-Object { $_.properties.storageAccountId }) -ne $null)
                }
            } catch { $subDiag += [PSCustomObject]@{ SubscriptionId = $subId; Error = $_.Exception.Message } }
        }
        $evidence["SubscriptionDiagnosticSettings"] = $subDiag
    }

    # Key checks
    $issues = @()
    if ($evidence["SignInLogToSentinel"] -eq $false) { $issues += "Entra sign-in logs NOT flowing to Log Analytics/Sentinel" }
    if ($evidence["EntradDiagnosticSettings"].Count -eq 0) { $issues += "No diagnostic settings configured for Entra ID" }

    $subDiagIssues = $evidence["SubscriptionDiagnosticSettings"] | Where-Object { $_.DiagSettingsCount -eq 0 -or $_.HasWorkspace -eq $false }
    if ($subDiagIssues) { $issues += "Subscriptions without diagnostic settings configured" }

    $status = if ($issues.Count -gt 1) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

    return New-TestResult -TestId "DETECT-01" -Phase "Phase 8 - Detection Gaps" -Name "Diagnostic Settings Coverage" `
        -Severity "Critical" -Status $status `
        -Description "Verifies that sign-in logs, audit logs, and Azure activity logs are flowing to a SIEM (Log Analytics/Sentinel). Without this, attacks are invisible." `
        -AttackTechnique "An attacker benefits if diagnostic settings are missing - no sign-in logs in Sentinel means spray attacks, token abuse, and persistence are never alerted on." `
        -Result (if ($issues.Count -gt 0) { "DETECTION GAPS: $($issues -join '; ')" } else { "Diagnostic settings configured and logs flowing to monitoring workspace." }) `
        -Evidence ($evidence | ConvertTo-Json -Depth 5) `
        -Remediation "1) Configure Entra diagnostic settings to forward All logs to Log Analytics workspace. 2) Enable activity log export for each subscription. 3) Enable Microsoft Defender XDR connector in Sentinel. 4) Verify data ingestion in LA workspace." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-integrate-activity-logs-with-log-analytics" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-DETECT02-SentinelAlertValidation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-02] Sentinel Alert Rules Validation" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "DETECT-02" -Phase "Phase 8 - Detection Gaps" -Name "Sentinel Alert Rules" `
            -Severity "Critical" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "If Sentinel analytics rules aren't enabled, attacks execute undetected" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/sentinel/threat-detection" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $allRuleStats = @()
        $criticalMissingAlerts = @()

        # Find Sentinel workspaces across subscriptions
        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 3)) {
            try {
                # Find Log Analytics workspaces
                $workspaces = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.OperationalInsights/workspaces?api-version=2021-12-01-preview" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                foreach ($ws in $workspaces.value | Select-Object -First 2) {
                    $rg     = ($ws.id -split "/resourceGroups/")[1].Split("/")[0]
                    $wsName = $ws.name

                    # Check if Sentinel is installed
                    try {
                        $sentinel = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($wsName)?api-version=2015-11-01-preview" `
                            -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop

                        Write-EntraLog "    Found Sentinel workspace: $wsName" -Level Info

                        # Get analytics rules
                        $rules = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$wsName/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-01-01-preview" `
                            -Headers $armHeaders -TimeoutSec 20 -ErrorAction Stop

                        $enabled  = ($rules.value | Where-Object { $_.properties.enabled -eq $true }).Count
                        $disabled = ($rules.value | Where-Object { $_.properties.enabled -ne $true }).Count
                        $total    = $rules.value.Count

                        $allRuleStats += [PSCustomObject]@{
                            Workspace    = $wsName
                            TotalRules   = $total
                            EnabledRules = $enabled
                            DisabledRules = $disabled
                            EnabledPercent = if ($total -gt 0) { [Math]::Round($enabled / $total * 100, 0) } else { 0 }
                        }

                        # Check for critical alert categories
                        $criticalRuleNames = @("Password spray","Unusual sign-in","MFA","Privileged","New app","Service principal","Lateral","Device code")
                        foreach ($critRule in $criticalRuleNames) {
                            $found = $rules.value | Where-Object { $_.properties.displayName -match $critRule -and $_.properties.enabled }
                            if (-not $found) { $criticalMissingAlerts += "Missing enabled rule matching: '$critRule' in workspace $wsName" }
                        }
                    } catch {
                        # Not a Sentinel workspace or no access
                        $evidence["${wsName}_SentinelInstalled"] = $false
                    }
                }
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["AlertRuleStats"]          = $allRuleStats
        $evidence["CriticalMissingAlerts"]   = $criticalMissingAlerts | Select-Object -First 15
        $evidence["TotalSentinelWorkspaces"] = ($allRuleStats | Measure-Object).Count

        $lowCoverageWS = $allRuleStats | Where-Object { $_.EnabledPercent -lt 50 }
        $issues = @()
        if ($allRuleStats.Count -eq 0) { $issues += "No Sentinel workspaces found - SIEM may not be deployed" }
        if ($lowCoverageWS.Count -gt 0) { $issues += "Workspaces with <50% alert rules enabled: $($lowCoverageWS.Workspace -join ',')" }
        if ($criticalMissingAlerts.Count -gt 5) { $issues += "$($criticalMissingAlerts.Count) critical alert categories missing" }

        $status = if ($allRuleStats.Count -eq 0) { "FAIL" } elseif ($issues.Count -gt 1) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "DETECT-02" -Phase "Phase 8 - Detection Gaps" -Name "Sentinel Alert Rules" `
            -Severity "Critical" -Status $status `
            -Description "Validates Microsoft Sentinel analytics rules are deployed and enabled. Disabled rules mean attacks like password spray and lateral movement go undetected." `
            -AttackTechnique "Attacker benefits when detection rules are disabled - spray attacks, device code phishing, and lateral movement proceed without triggering alerts." `
            -Result "$($allRuleStats.Count) Sentinel workspace(s). Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Import Microsoft Sentinel Content Hub solutions (UEBA, Identity, Entra ID). 2) Enable all MS Entra ID analytics rules. 3) Target >80% rules enabled. 4) Configure scheduled alert rule review." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/sentinel/understand-threat-intelligence" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "DETECT-02" -Phase "Phase 8 - Detection Gaps" -Name "Sentinel Alert Rules" `
            -Severity "Critical" -Status "ERROR" -Description "Error validating Sentinel rules" `
            -AttackTechnique "ARM Sentinel API enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/sentinel/threat-detection" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-DETECT03-AuditLogRetention {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-03] Audit Log Retention Check" -Level Attack

    $evidence = [ordered]@{}

    if ($script:AccessToken) {
        try {
            $headers = @{ Authorization = "Bearer $script:AccessToken" }

            # Query how far back audit logs go
            $oldestDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $auditCheck = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1&`$orderby=activityDateTime asc&`$filter=activityDateTime ge $oldestDate" `
                -Headers $headers -TimeoutSec 15 -ErrorAction Stop

            if ($auditCheck.value.Count -gt 0) {
                $oldestEntry = $auditCheck.value[0].activityDateTime
                $daysAvailable = [Math]::Round(((Get-Date) - [datetime]$oldestEntry).TotalDays, 0)
                $evidence["AuditLogOldestEntry"]    = $oldestEntry
                $evidence["AuditLogDaysAvailable"]  = $daysAvailable
                $evidence["AuditLogRetentionNote"]  = "Entra Free/P1 = 30 days, P2 = 90 days in-portal. Sentinel extends indefinitely."
            } else {
                $evidence["AuditLogNote"] = "No entries found in 90-day query - may indicate less than P1 license or logs not retained"
            }

            # Check sign-in log retention
            $oldestSignIn = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $signInCheck = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1&`$orderby=createdDateTime asc&`$filter=createdDateTime ge $oldestSignIn" `
                -Headers $headers -TimeoutSec 15 -ErrorAction Stop

            if ($signInCheck.value.Count -gt 0) {
                $oldestSignIn = $signInCheck.value[0].createdDateTime
                $signInDays = [Math]::Round(((Get-Date) - [datetime]$oldestSignIn).TotalDays, 0)
                $evidence["SignInLogDaysAvailable"] = $signInDays
            }

        } catch { $evidence["Error"] = $_.Exception.Message }
    }

    $retentionDays = $evidence["AuditLogDaysAvailable"] ?? 0
    $issues = @()
    if ($retentionDays -lt 30)  { $issues += "Audit logs only retained for $retentionDays days - insufficient for investigations" }
    if ($retentionDays -lt 90)  { $issues += "Logs not retained 90 days - Entra P2 or Sentinel recommended for full retention" }

    $status = if ($retentionDays -lt 30) { "FAIL" } elseif ($retentionDays -lt 90) { "WARNING" } else { "PASS" }

    return New-TestResult -TestId "DETECT-03" -Phase "Phase 8 - Detection Gaps" -Name "Audit Log Retention" `
        -Severity "High" -Status $status `
        -Description "Checks audit log and sign-in log retention. Attackers who operate slowly are only detectable with sufficient log retention for incident investigation." `
        -AttackTechnique "A patient attacker who stays under the radar for 30+ days evades detection if log retention is insufficient. Password sprays over 60 days are invisible with 30-day retention." `
        -Result "Audit log retention: ~$retentionDays days. Issues: $($issues -join '; ')" `
        -Evidence ($evidence | ConvertTo-Json) `
        -Remediation "1) Export all logs to Log Analytics workspace (this extends retention to 730 days by default). 2) Entra P2 provides 90-day portal retention. 3) Configure Log Analytics workspace data retention to 1+ year for compliance. 4) Use Azure Storage archive for long-term retention." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-reports-data-retention" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-DETECT04-IdentityProtectionAlerts {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-04] Identity Protection Risk Coverage" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "DETECT-04" -Phase "Phase 8 - Detection Gaps" -Name "Identity Protection Coverage" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Without IP P2, spray attacks and AiTM won't generate risk events - no automated blocking" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Get recent risk detections
        $riskDetections = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$top=20&`$select=id,riskType,riskLevel,detectedDateTime,activity" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $evidence["RecentRiskDetectionsCount"] = $riskDetections.value.Count
        $evidence["RiskDetectionTypes"] = $riskDetections.value | Group-Object riskType | Select-Object Name, Count | Select-Object -First 10

        # Get risky users
        $riskyUsers = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=10&`$select=id,riskLevel,riskState,riskLastUpdatedDateTime" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $evidence["RiskyUsersCount"] = $riskyUsers.value.Count
        $evidence["HighRiskUsers"]   = ($riskyUsers.value | Where-Object { $_.riskLevel -eq "high" }).Count

        # Check if risk policies exist
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $userRiskPolicies   = $caPolicies.value | Where-Object { $_.conditions.userRiskLevels -and $_.state -eq "enabled" }
        $signInRiskPolicies = $caPolicies.value | Where-Object { $_.conditions.signInRiskLevels -and $_.state -eq "enabled" }

        $evidence["UserRiskPoliciesEnabled"]   = $userRiskPolicies.Count
        $evidence["SignInRiskPoliciesEnabled"]  = $signInRiskPolicies.Count
        $evidence["UserRiskPolicies"]   = $userRiskPolicies | Select-Object displayName, @{N="UserRiskLevels";E={$_.conditions.userRiskLevels}}
        $evidence["SignInRiskPolicies"] = $signInRiskPolicies | Select-Object displayName, @{N="SignInRiskLevels";E={$_.conditions.signInRiskLevels}}

        $issues = @()
        if ($userRiskPolicies.Count -eq 0)   { $issues += "No CA policy acts on User risk level - risky users are not blocked automatically" }
        if ($signInRiskPolicies.Count -eq 0)  { $issues += "No CA policy acts on Sign-in risk level - risky sign-ins are not blocked automatically" }
        $highRiskNotBlocked = $riskyUsers.value | Where-Object { $_.riskLevel -eq "high" -and $_.riskState -ne "remediatedAsCompromised" -and $_.riskState -ne "dismissed" }
        if ($highRiskNotBlocked.Count -gt 0) { $issues += "$($highRiskNotBlocked.Count) high-risk users not remediated" }

        $status = if ($issues.Count -gt 1) { "FAIL" } elseif ($issues.Count -eq 1) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "DETECT-04" -Phase "Phase 8 - Detection Gaps" -Name "Identity Protection Coverage" `
            -Severity "High" -Status $status `
            -Description "Verifies Entra ID Identity Protection risk policies are configured to automatically block or challenge risky sign-ins and compromised users." `
            -AttackTechnique "Without risk-based CA policies: an AiTM phishing token theft generates a risk detection but nothing automatically blocks the attacker. Manual intervention required." `
            -Result "Risky users: $($riskyUsers.value.Count). High risk: $($evidence['HighRiskUsers']). Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Create CA policy: User risk=High → Block access or Require password change + MFA. 2) Create CA policy: Sign-in risk=High → Require MFA. 3) Remediate existing high-risk users. 4) Entra P2 required for risk-based policies." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "DETECT-04" -Phase "Phase 8 - Detection Gaps" -Name "Identity Protection Coverage" `
            -Severity "High" -Status "ERROR" -Description "Error checking Identity Protection" `
            -AttackTechnique "Graph identityProtection API" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-DETECT05-DefenderForCloudCheck {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-05] Microsoft Defender for Cloud Coverage" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "DETECT-05" -Phase "Phase 8 - Detection Gaps" -Name "Defender for Cloud Coverage" `
            -Severity "High" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Without Defender for Cloud, IMDS abuse, lateral movement from VMs, and malware execution go undetected" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $planStatus = @()

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 3)) {
            try {
                # Get Defender for Cloud pricing tiers (plans)
                $pricing = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/pricings?api-version=2024-01-01" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                $criticalPlans = @("VirtualMachines","SqlServers","AppServices","StorageAccounts","Containers","KeyVaults","Dns","Arm")
                foreach ($plan in $pricing.value | Where-Object { $_.name -in $criticalPlans }) {
                    $planStatus += [PSCustomObject]@{
                        SubscriptionId = $subId
                        PlanName       = $plan.name
                        Tier           = $plan.properties.pricingTier  # Free or Standard
                        Enabled        = ($plan.properties.pricingTier -eq "Standard")
                    }
                }

                # Check security alerts
                $alerts = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Security/alerts?api-version=2022-01-01&`$top=10" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                $highAlerts = $alerts.value | Where-Object { $_.properties.severity -in @("High","Medium") }
                $evidence["Sub_${subId}_OpenAlerts"] = $alerts.value.Count
                $evidence["Sub_${subId}_HighAlerts"] = $highAlerts.Count
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["DefenderPlanStatus"] = $planStatus
        $freePlans = $planStatus | Where-Object { -not $_.Enabled }
        $enabledPlans = $planStatus | Where-Object { $_.Enabled }

        $issues = @()
        if ($freePlans.Count -gt 3) { $issues += "$($freePlans.Count) Defender plans on Free tier - coverage gaps" }
        if (-not ($enabledPlans | Where-Object { $_.PlanName -eq "VirtualMachines" })) { $issues += "Defender for Servers not enabled - IMDS abuse and malware undetected" }
        if (-not ($enabledPlans | Where-Object { $_.PlanName -eq "KeyVaults" })) { $issues += "Defender for Key Vault not enabled" }
        if (-not ($enabledPlans | Where-Object { $_.PlanName -eq "Containers" })) { $issues += "Defender for Containers not enabled" }

        $status = if ($issues.Count -gt 2) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "DETECT-05" -Phase "Phase 8 - Detection Gaps" -Name "Defender for Cloud Coverage" `
            -Severity "High" -Status $status `
            -Description "Checks Microsoft Defender for Cloud plan enablement across subscriptions. Free tier provides no threat detection - attackers can operate undetected on VMs, in storage, and via Key Vault access." `
            -AttackTechnique "Without Defender for Servers: IMDS token theft, cryptomining, lateral movement from VMs - all invisible. Without Defender for KV: secret exfiltration undetected." `
            -Result "$($freePlans.Count) plans on Free tier. $($enabledPlans.Count) plans enabled (Standard). Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "Enable Defender for Cloud Standard plans for: Servers, Key Vaults, Storage, Containers. Enable Microsoft Defender for Endpoint integration for VMs. Configure alert notification emails." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "DETECT-05" -Phase "Phase 8 - Detection Gaps" -Name "Defender for Cloud Coverage" `
            -Severity "High" -Status "ERROR" -Description "Error checking Defender for Cloud" `
            -AttackTechnique "ARM Security pricings API" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-DETECT06-MFARegistrationGap {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [DETECT-06] MFA Registration Coverage Audit" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "DETECT-06" -Phase "Phase 8 - Detection Gaps" -Name "MFA Registration Coverage" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Users without MFA registered = account compromised without any MFA friction" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-methods-activity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Get authentication methods registration report
        try {
            $regReport = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=200" `
                -Headers $headers -TimeoutSec 20 -ErrorAction Stop

            $totalUsers       = $regReport.value.Count
            $mfaRegistered    = ($regReport.value | Where-Object { $_.isMfaRegistered }).Count
            $mfaCapable       = ($regReport.value | Where-Object { $_.isMfaCapable }).Count
            $ssprRegistered   = ($regReport.value | Where-Object { $_.isSsprRegistered }).Count
            $adminUsers       = ($regReport.value | Where-Object { $_.isAdmin }).Count
            $adminWithoutMFA  = ($regReport.value | Where-Object { $_.isAdmin -and -not $_.isMfaRegistered }).Count

            $mfaPercent = if ($totalUsers -gt 0) { [Math]::Round($mfaRegistered / $totalUsers * 100, 1) } else { 0 }

            $evidence["TotalUsersInReport"]      = $totalUsers
            $evidence["MFARegisteredCount"]      = $mfaRegistered
            $evidence["MFARegistrationPercent"]  = $mfaPercent
            $evidence["MFACapableCount"]         = $mfaCapable
            $evidence["SSPRRegisteredCount"]     = $ssprRegistered
            $evidence["AdminCount"]              = $adminUsers
            $evidence["AdminsWithoutMFA"]        = $adminWithoutMFA

            # Get users without MFA (for admins only to avoid large sets)
            $adminsWithoutMFA = $regReport.value | Where-Object { $_.isAdmin -and -not $_.isMfaRegistered } |
                Select-Object userPrincipalName, isAdmin, isMfaRegistered | Select-Object -First 20
            $evidence["AdminsWithoutMFA_List"] = $adminsWithoutMFA

        } catch { $evidence["RegistrationReportError"] = $_.Exception.Message }

        $mfaPercent = $evidence["MFARegistrationPercent"] ?? 0
        $issues = @()
        if ($evidence["AdminsWithoutMFA"] -gt 0) { $issues += "CRITICAL: $($evidence['AdminsWithoutMFA']) admin account(s) without MFA registered" }
        if ($mfaPercent -lt 90) { $issues += "MFA registration only $mfaPercent% - $($evidence['TotalUsersInReport'] - $evidence['MFARegisteredCount']) users vulnerable" }
        if ($mfaPercent -lt 70) { $issues += "Very low MFA coverage - immediate action required" }

        $status = if ($evidence["AdminsWithoutMFA"] -gt 0) { "FAIL" } elseif ($mfaPercent -lt 90) { "FAIL" } elseif ($mfaPercent -lt 95) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "DETECT-06" -Phase "Phase 8 - Detection Gaps" -Name "MFA Registration Coverage" `
            -Severity "Critical" -Status $status `
            -Description "Audits what percentage of users have MFA registered. Users without MFA can be compromised with password alone - credential attacks succeed with 100% probability against them." `
            -AttackTechnique "Target the X% of users without MFA first. These accounts are immediately compromised with any found password - no MFA barrier whatsoever." `
            -Result "MFA coverage: $mfaPercent%. Admins without MFA: $($evidence['AdminsWithoutMFA']). Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Enforce MFA registration via CA policy (require MFA registration within 14 days). 2) Priority: ensure ALL admin accounts have MFA immediately. 3) Use Entra ID authentication methods activity report to identify gaps. 4) Run MFA registration campaign." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-registration-mfa-sspr-combined" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "DETECT-06" -Phase "Phase 8 - Detection Gaps" -Name "MFA Registration Coverage" `
            -Severity "Critical" -Status "ERROR" -Description "Error checking MFA registration" `
            -AttackTechnique "Graph authenticationMethods registration report" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-methods-activity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase8 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 8 - Detection Gap Validation     " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-DETECT01-DiagnosticSettings
    $phaseResults += Invoke-DETECT02-SentinelAlertValidation
    $phaseResults += Invoke-DETECT03-AuditLogRetention
    $phaseResults += Invoke-DETECT04-IdentityProtectionAlerts
    $phaseResults += Invoke-DETECT05-DefenderForCloudCheck
    $phaseResults += Invoke-DETECT06-MFARegistrationGap

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 8 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
