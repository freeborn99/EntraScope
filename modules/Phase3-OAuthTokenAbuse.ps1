#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 3 - OAuth & Token Abuse Testing
.DESCRIPTION
    Tests OAuth flow controls, token security, consent policies, and
    service principal CA bypass risks. AUTHORIZED USE ONLY.
#>

function Invoke-OAUTH01-DeviceCodeFlowBlock {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-01] Device Code Flow Block Test" -Level Attack

    $tenantId = $script:Config.TenantId
    $url      = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"

    if ($script:DryRun) {
        return New-TestResult -TestId "OAUTH-01" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Device Code Flow Block" `
            -Severity "Critical" -Status "INFO" `
            -Description "Would initiate device code request to test if CA blocks this flow" `
            -AttackTechnique "POST /oauth2/v2.0/devicecode - attacker generates code, tricks victim into entering it at microsoft.com/devicelogin, attacker gets token without MFA" `
            -Result "DRY RUN" -Evidence "" `
            -Remediation "Create CA policy blocking Device Code authentication flow" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    # Use multiple well-known public client IDs to check if any bypass CA
    $testClients = @(
        @{ Id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"; Name = "Azure CLI" }
        @{ Id = "1950a258-227b-4e31-a9cf-717495945fc2"; Name = "Azure PowerShell" }
    )

    $evidence  = [ordered]@{}
    $anyBlocked = $true  # Start pessimistic (assume all will succeed = fail)
    $anySucceeded = $false

    foreach ($client in $testClients) {
        try {
            $body = @{
                client_id = $client.Id
                scope     = "https://graph.microsoft.com/.default offline_access"
            }
            $resp = Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop

            # Got a device_code back = flow is NOT blocked = FAIL
            $evidence[$client.Name] = @{
                Status         = "FLOW_ALLOWED"
                DeviceCodePartial = ($resp.device_code -replace ".{10}$","[REDACTED]")
                UserCode       = $resp.user_code
                VerificationUri = $resp.verification_uri
                ExpiresIn      = $resp.expires_in
            }
            $anySucceeded = $true
            $anyBlocked   = $false
            Write-EntraLog "    [!!!] DEVICE CODE ISSUED for $($client.Name)! Flow NOT blocked." -Level Warn
        }
        catch {
            $errBody = $null
            try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            $aadsts = if ($errBody.error_description -match "(AADSTS\d+)") { $Matches[1] } else { "none" }

            $evidence[$client.Name] = @{
                Status    = "BLOCKED"
                AADSTSCode = $aadsts
                Error      = $errBody.error
                Description = ($errBody.error_description -split "`n")[0]
            }
            Write-EntraLog "    [+] $($client.Name) blocked: $aadsts" -Level Success
        }
        Start-Sleep -Milliseconds 1000
    }

    $status = if ($anySucceeded) { "FAIL" } else { "PASS" }

    return New-TestResult -TestId "OAUTH-01" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Device Code Flow Block" `
        -Severity "Critical" -Status $status `
        -Description "Tests whether Conditional Access blocks the Device Code OAuth flow. This flow is abused in 'Device Code Phishing' - attacker generates a code and tricks a user into entering it at microsoft.com/devicelogin, receiving a token without knowing the user's password." `
        -AttackTechnique "POST /oauth2/v2.0/devicecode with well-known public client IDs. Receive device_code + user_code. Social engineer victim to enter code at microsoft.com/devicelogin. Bypass MFA." `
        -Result $(if ($anySucceeded) { "DEVICE CODE FLOW NOT BLOCKED. Codes issued for: $($testClients | Where-Object {$evidence[$_.Name].Status -eq 'FLOW_ALLOWED'} | Select-Object -ExpandProperty Name) - Device code phishing attack is POSSIBLE." } else { "Device code flow BLOCKED by Conditional Access for all tested client IDs." }) `
        -Evidence ($evidence | ConvertTo-Json -Depth 4) `
        -Remediation "Create a Conditional Access policy: Users=All, Cloud Apps=All, Conditions=Authentication Flows (Device code flow), Access control=Block. This will prevent device code phishing." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/how-to-policy-authentication-flows" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-OAUTH02-UserConsentCheck {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-02] User Consent / Illicit Consent Grant Check" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-02" -Phase "Phase 3 - OAuth & Token Abuse" -Name "User Consent Grant Policy" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Illicit consent grant - user tricked into granting app permissions" -Result "SKIPPED - no token" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "OAUTH-02" -Phase "Phase 3 - OAuth & Token Abuse" -Name "User Consent Grant Policy" `
            -Severity "Critical" -Status "INFO" -Description "Would check authorization policy for user consent settings" `
            -AttackTechnique "Register malicious app, trick user into consent screen, gain persistent access bypassing MFA" `
            -Result "DRY RUN" -Evidence "" `
            -Remediation "Disable user consent or limit to verified publishers" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }

        # Get authorization policy
        $authPolicy = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        # Get permission grant policy
        $consentPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        # Get admin consent workflow
        $adminConsentWorkflow = $null
        try {
            $adminConsentWorkflow = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy" `
                -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        } catch {}

        $evidence = [ordered]@{
            DefaultUserRolePermissions = $authPolicy.defaultUserRolePermissions
            AllowedToCreateApps        = $authPolicy.defaultUserRolePermissions.allowedToCreateApps
            AllowedToCreateTenants     = $authPolicy.defaultUserRolePermissions.allowedToCreateTenants
            PermissionGrantPolicies    = ($consentPolicies.value | Select-Object id, displayName)
            AdminConsentWorkflowEnabled = $adminConsentWorkflow.isEnabled
        }

        $issues = @()
        # managePermissionGrantsForSelf.microsoft-user-default-legacy = users can consent to any app
        $hasLegacyConsent = $consentPolicies.value | Where-Object { $_.id -match "microsoft-user-default-legacy" }
        if ($hasLegacyConsent) { $issues += "Users can consent to any app (microsoft-user-default-legacy policy active)" }

        $hasLowRiskConsent = $consentPolicies.value | Where-Object { $_.id -match "microsoft-user-default-low" }
        if ($hasLowRiskConsent) { $issues += "Users can consent to low-risk apps - still exploitable with verified publisher phishing" }

        if (-not $adminConsentWorkflow -or $adminConsentWorkflow.isEnabled -eq $false) {
            $issues += "Admin consent request workflow is DISABLED - users who are blocked will have no way to request access"
        }

        $noUserConsent = (-not $hasLegacyConsent) -and (-not $hasLowRiskConsent)
        $status = if ($issues.Count -gt 1 -and -not $noUserConsent) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "OAUTH-02" -Phase "Phase 3 - OAuth & Token Abuse" -Name "User Consent Grant Policy" `
            -Severity "Critical" -Status $status `
            -Description "Checks if users can consent to OAuth applications themselves. Illicit consent grant attack: attacker registers app with Mail.Read, tricks user into consenting, gains persistent access even after password resets." `
            -AttackTechnique "Register app with high-privilege scopes. Craft OAuth consent URL. Social engineer user to click. User consent = attacker gets refresh token that survives password changes." `
            -Result $(if ($issues.Count -gt 0) { "CONSENT ISSUES FOUND: $($issues -join '; ')" } else { "User consent is properly restricted. Admin approval required for app permissions." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Set user consent to 'Do not allow user consent' (most secure) or 'Allow user consent for apps from verified publishers for selected permissions'. 2) Enable Admin consent request workflow so users can request access." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "OAUTH-02" -Phase "Phase 3 - OAuth & Token Abuse" -Name "User Consent Grant Policy" `
            -Severity "Critical" -Status "ERROR" -Description "Error checking consent policy" `
            -AttackTechnique "Review permissionGrantPolicies via Graph" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-OAUTH03-TokenScopeEscalation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-03] Token Scope Escalation Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-03" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Token Scope Escalation" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Call out-of-scope Graph API endpoints with existing token" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/permissions-reference" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $headers = @{ Authorization = "Bearer $script:AccessToken" }
    $endpoints = @(
        @{ Path = "/users?`$top=5&`$select=displayName,userPrincipalName"; Name = "User.Read.All"; Sensitivity = "High" }
        @{ Path = "/auditLogs/signIns?`$top=3"; Name = "AuditLog.Read.All"; Sensitivity = "High" }
        @{ Path = "/security/alerts_v2?`$top=3"; Name = "SecurityEvents.Read.All"; Sensitivity = "High" }
        @{ Path = "/groups?`$top=5&`$select=displayName,id"; Name = "Group.Read.All"; Sensitivity = "Medium" }
        @{ Path = "/servicePrincipals?`$top=5&`$select=displayName,id,appId"; Name = "Application.Read.All"; Sensitivity = "High" }
        @{ Path = "/roleManagement/directory/roleAssignments?`$top=5"; Name = "RoleManagement.Read.All"; Sensitivity = "Critical" }
        @{ Path = "/identity/conditionalAccess/policies"; Name = "Policy.Read.All"; Sensitivity = "High" }
    )

    $results   = [ordered]@{}
    $accessible = @()

    foreach ($ep in $endpoints) {
        try {
            $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0$($ep.Path)" `
                -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $count = if ($resp.value) { $resp.value.Count } else { 1 }
            $results[$ep.Name] = @{ Status = "ACCESSIBLE"; HTTPCode = 200; RecordsReturned = $count; Sensitivity = $ep.Sensitivity }
            $accessible += "$($ep.Name) [$($ep.Sensitivity)]"
            Write-EntraLog "    [!] $($ep.Name) - ACCESSIBLE ($count records)" -Level Warn
        }
        catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $results[$ep.Name] = @{ Status = "BLOCKED"; HTTPCode = $code; Sensitivity = $ep.Sensitivity }
            Write-EntraLog "    [+] $($ep.Name) - BLOCKED (HTTP $code)" -Level Success
        }
    }

    $criticalAccess = $accessible | Where-Object { $_ -match "Critical|High" }
    $status = if ($criticalAccess.Count -gt 3) { "FAIL" } elseif ($accessible.Count -gt 0) { "WARNING" } else { "PASS" }

    return New-TestResult -TestId "OAUTH-03" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Token Scope Escalation" `
        -Severity "High" -Status $status `
        -Description "Tests what sensitive Graph API endpoints are accessible with the current token. Verifies scope enforcement prevents over-privileged data access." `
        -AttackTechnique "Use acquired token to call high-sensitivity Graph endpoints beyond expected scope - test if Microsoft enforces token scopes correctly" `
        -Result "Accessible endpoints: $($accessible -join ', '). Total: $($accessible.Count)/$($endpoints.Count) sensitive APIs accessible." `
        -Evidence ($results | ConvertTo-Json -Depth 3) `
        -Remediation "Ensure tokens are requested with minimum required scopes. Use app-level CA policies to restrict what service principals can call. Review token scopes with your identity team." `
        -MSDocsLink "https://learn.microsoft.com/en-us/graph/permissions-reference" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-OAUTH04-RefreshTokenLifetime {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-04] Token Lifetime & Session Policy Check" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-04" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Token Lifetime Policies" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Stolen refresh tokens remain valid for extended period if no sign-in frequency policy" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Check token lifetime policies (legacy)
        try {
            $tokenLifetime = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/tokenLifetimePolicies" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $evidence["TokenLifetimePolicies"] = $tokenLifetime.value | Select-Object displayName, definition, isOrganizationDefault
        } catch { $evidence["TokenLifetimePolicies"] = "Error: $($_.Exception.Message)" }

        # Check CA sign-in frequency policies
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $signInFreqPolicies = $caPolicies.value | Where-Object {
            $_.sessionControls.signInFrequency -and $_.state -eq "enabled"
        }
        $persistentBrowserPolicies = $caPolicies.value | Where-Object {
            $_.sessionControls.persistentBrowser -and $_.state -eq "enabled"
        }

        $evidence["CASignInFrequencyPolicies"] = $signInFreqPolicies | Select-Object displayName,
            @{N="FrequencyValue";E={$_.sessionControls.signInFrequency.value}},
            @{N="FrequencyType";E={$_.sessionControls.signInFrequency.type}},
            @{N="Scope";E={$_.conditions.users.includeUsers}}
        $evidence["PersistentBrowserPolicies"]  = $persistentBrowserPolicies | Select-Object displayName,
            @{N="Mode";E={$_.sessionControls.persistentBrowser.mode}}

        $issues = @()
        if ($signInFreqPolicies.Count -eq 0) {
            $issues += "No sign-in frequency policy found - sessions persist indefinitely (stolen tokens valid for up to 90 days)"
        }
        $longSessions = $signInFreqPolicies | Where-Object { $_.sessionControls.signInFrequency.value -gt 24 -and $_.sessionControls.signInFrequency.type -eq "hours" }
        if ($longSessions.Count -gt 0) { $issues += "Sign-in frequency > 24 hours found - long window for token replay" }

        $neverExpire = $persistentBrowserPolicies | Where-Object { $_.sessionControls.persistentBrowser.mode -eq "always" }
        if ($neverExpire.Count -gt 0) { $issues += "Persistent browser sessions set to 'always' - users never re-authenticate" }

        $status = if ($issues.Count -ge 2) { "FAIL" } elseif ($issues.Count -eq 1) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "OAUTH-04" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Token Lifetime Policies" `
            -Severity "High" -Status $status `
            -Description "Reviews token lifetime and session policies. Stolen refresh tokens remain valid for up to 90 days if no sign-in frequency policy enforces re-authentication." `
            -AttackTechnique "Steal refresh token (via AiTM phishing, malware, or browser cookie theft). Replay token for up to 90 days - survives password changes." `
            -Result $(if ($issues.Count -gt 0) { "TOKEN LIFETIME ISSUES: $($issues -join '; ')" } else { "Session and token lifetime policies configured appropriately." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 5) `
            -Remediation "1) Create CA policy with Sign-in frequency set to 1-4 hours for privileged roles, 8 hours for all users. 2) Set Persistent browser session to 'Never persistent' for sensitive apps. 3) Enable Continuous Access Evaluation." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-session-lifetime" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "OAUTH-04" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Token Lifetime Policies" `
            -Severity "High" -Status "ERROR" -Description "Error checking token policies" `
            -AttackTechnique "Review token lifetime and CA session policies" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-session-lifetime" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-OAUTH05-CAETokenRevocation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-05] Continuous Access Evaluation (CAE) Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-05" -Phase "Phase 3 - OAuth & Token Abuse" -Name "CAE Token Revocation" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Stolen token continues working after account compromise if CAE not enforced" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $caePolicies = $caPolicies.value | Where-Object {
            $_.sessionControls.continuousAccessEvaluation -and $_.state -eq "enabled"
        }

        $evidence["TotalCAPolicies"]   = $caPolicies.value.Count
        $evidence["CAEPoliciesFound"]  = $caePolicies.Count
        $evidence["CAEPolicyDetails"]  = $caePolicies | Select-Object displayName,
            @{N="CAEMode";E={$_.sessionControls.continuousAccessEvaluation.mode}},
            @{N="Users";E={$_.conditions.users.includeUsers}}

        # Also check via tenant CAE settings
        try {
            $caeSettings = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/policies/continuousAccessEvaluationPolicy" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $evidence["TenantCAEPolicy"] = $caeSettings
        } catch { $evidence["TenantCAEPolicy"] = "Beta endpoint unavailable: $($_.Exception.Message)" }

        # Test revocation if we have a test user
        $revocationTest = "Not performed - no test user configured"
        if ($script:Config.TestAccount.UPN -and $script:AccessToken) {
            try {
                $testUser = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($script:Config.TestAccount.UPN)?`$select=id" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
                Write-EntraLog "    Revoking test user sessions..." -Level Info
                $revokeResp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($testUser.id)/revokeSignInSessions" -Method POST -Headers $headers -TimeoutSec 15 -ErrorAction Stop
                $revocationTest = "Session revocation API called. Result: $($revokeResp.value). If CAE is active, existing tokens should become invalid within 60-90 seconds."
            } catch { $revocationTest = "Revocation test failed: $($_.Exception.Message)" }
        }
        $evidence["RevocationTest"] = $revocationTest

        $strictCAE = $caePolicies | Where-Object { $_.sessionControls.continuousAccessEvaluation.mode -in @("strict","strictLocation") }
        $issues    = @()
        if ($caePolicies.Count -eq 0) { $issues += "No CAE policies found - stolen tokens may remain valid for up to 1 hour" }
        if ($caePolicies.Count -gt 0 -and $strictCAE.Count -eq 0) { $issues += "CAE exists but strict mode not enabled - IP location changes may not revoke tokens" }

        $status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "OAUTH-05" -Phase "Phase 3 - OAuth & Token Abuse" -Name "CAE Token Revocation" `
            -Severity "High" -Status $status `
            -Description "Verifies Continuous Access Evaluation (CAE) is configured. Without CAE, a stolen access token remains valid for up to 1 hour even after the account is disabled or the session is revoked." `
            -AttackTechnique "Steal access token. Even if victim changes password, token works for ~60 minutes unless CAE revokes it in near-real-time." `
            -Result $(if ($issues.Count -gt 0) { "CAE GAPS: $($issues -join '; ')" } else { "CAE policies found with appropriate coverage." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 5) `
            -Remediation "Enable CAE in Conditional Access session controls. Set mode to 'strict' for critical apps and privileged users. This enables near-real-time revocation of stolen tokens." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "OAUTH-05" -Phase "Phase 3 - OAuth & Token Abuse" -Name "CAE Token Revocation" `
            -Severity "High" -Status "ERROR" -Description "Error checking CAE configuration" `
            -AttackTechnique "Review CAE in CA session controls" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-OAUTH06-ServicePrincipalCABypass {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-06] Service Principal Conditional Access Bypass Check" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-06" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Service Principal CA Bypass" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Compromise SP credentials - SP tokens often bypass CA policies targeting users" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/workload-identity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Get CA policies
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        # Find policies that target workload identities / service principals
        $workloadPolicies = $caPolicies.value | Where-Object {
            $_.conditions.clientApplications -or $_.conditions.servicePrincipalRiskLevels
        }
        $evidence["WorkloadIdentityCAEPolicies"] = $workloadPolicies.Count

        # Count SPs that have high-privilege permissions
        $sps = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=100&`$select=id,displayName,appId,servicePrincipalType" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $evidence["TotalServicePrincipals"] = $sps.value.Count
        $evidence["WorkloadIdentityPolicies"] = $workloadPolicies | Select-Object displayName, state

        # Check for risky SPs - those with privileged Graph app roles
        $appRoleGrants = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$expand=appRoleAssignments&`$top=50" -Headers $headers -TimeoutSec 20 -ErrorAction Stop
        $dangerousPermissions = @("Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","User.ReadWrite.All","Mail.ReadWrite","Files.ReadWrite.All")

        $riskyApps = @()
        foreach ($sp in $appRoleGrants.value) {
            if ($sp.appRoleAssignments.Count -gt 0) {
                # Just check for non-zero app role assignments as a proxy
                $riskyApps += @{ SP = $sp.displayName; AppId = $sp.appId; GrantCount = $sp.appRoleAssignments.Count }
            }
        }
        $evidence["ServicePrincipalsWithAppRoleGrants"] = $riskyApps | Select-Object -First 10

        $issues = @()
        if ($workloadPolicies.Count -eq 0) { $issues += "NO Conditional Access policies target workload identities/SPs - all SPs bypass CA entirely" }
        if ($riskyApps.Count -gt 10)       { $issues += "$($riskyApps.Count) service principals have application permissions - large attack surface if any credential is stolen" }

        $status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "OAUTH-06" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Service Principal CA Bypass" `
            -Severity "High" -Status $status `
            -Description "Checks if Conditional Access policies apply to service principals (workload identities). Most CA policies target human users only - SPs authenticating with client secrets bypass them entirely." `
            -AttackTechnique "Steal/discover a service principal's client secret or certificate. Authenticate as SP via /token. Bypass all user-targeting CA policies since SPs are excluded." `
            -Result $(if ($issues.Count -gt 0) { "SP CA BYPASS RISK: $($issues -join '; ')" } else { "Workload identity CA policies in place." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "Requires Entra Workload Identities Premium license. Create CA policies targeting workload identities with conditions (IP ranges, etc). Regularly rotate SP credentials and monitor via Workload Identity risk detections." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/workload-identity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "OAUTH-06" -Phase "Phase 3 - OAuth & Token Abuse" -Name "Service Principal CA Bypass" `
            -Severity "High" -Status "ERROR" -Description "Error checking SP CA coverage" `
            -AttackTechnique "Review CA policies for workload identity coverage" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/workload-identity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-OAUTH07-AppOnlyPermissionScope {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [OAUTH-07] App-Only Permission Scope / App Access Policy Check" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "OAUTH-07" -Phase "Phase 3 - OAuth & Token Abuse" -Name "App-Only Permission Scope" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "App with Mail.Read app permission can read ALL users mailboxes without app access policy restricting it" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Find Graph service principal to query app role definitions
        $graphSP = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'Microsoft Graph'" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $graphSpId = $graphSP.value[0].id

        # Get all app role assignments granted to apps (application permissions)
        $appRoleAssignments = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo?`$top=100" -Headers $headers -TimeoutSec 20 -ErrorAction Stop

        # Get Graph app roles to map IDs to names
        $graphAppRoles = $graphSP.value[0].appRoles | Select-Object id, value, displayName

        # Map dangerous permission IDs
        $dangerousRoles = $graphAppRoles | Where-Object { $_.value -in @(
            "Mail.Read","Mail.ReadWrite","Mail.Send",
            "Files.ReadWrite.All","Sites.ReadWrite.All",
            "Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory",
            "User.ReadWrite.All","Application.ReadWrite.All",
            "Calendars.ReadWrite","Contacts.ReadWrite"
        )}
        $dangerousRoleIds = $dangerousRoles | Select-Object -ExpandProperty id

        $riskyAssignments = $appRoleAssignments.value | Where-Object { $_.appRoleId -in $dangerousRoleIds }

        # Enrich with SP names
        $enriched = foreach ($asgn in $riskyAssignments) {
            $roleName = ($graphAppRoles | Where-Object { $_.id -eq $asgn.appRoleId }).value
            [PSCustomObject]@{
                PrincipalId      = $asgn.principalId
                PrincipalDisplay = $asgn.principalDisplayName
                Permission       = $roleName
                CreatedTime      = $asgn.createdDateTime
            }
        }

        $evidence["DangerousAppRoleAssignments"] = $enriched
        $evidence["TotalDangerous"]  = $enriched.Count
        $evidence["DangerousRoles"]  = ($dangerousRoles | Select-Object value, displayName)

        # Check if mail app access policies exist (Exchange-specific)
        $mailApps = $enriched | Where-Object { $_.Permission -match "Mail\." }
        if ($mailApps.Count -gt 0) {
            $evidence["MailAccessNote"] = "Apps with Mail.* app permissions can read ALL mailboxes unless ApplicationAccessPolicy is configured in Exchange Online"
        }

        $status = if ($enriched.Count -gt 5) { "FAIL" } elseif ($enriched.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "OAUTH-07" -Phase "Phase 3 - OAuth & Token Abuse" -Name "App-Only Permission Scope" `
            -Severity "Critical" -Status $status `
            -Description "Apps with application (app-only) permissions like Mail.Read can access ALL users' data tenant-wide unless restricted by Exchange ApplicationAccessPolicy. A compromised app secret = all mailboxes readable." `
            -AttackTechnique "Compromise app credentials. Use app-only token. Call /users/{any-user}/messages to read ANY user's mailbox - no additional consent needed." `
            -Result "$($enriched.Count) apps found with dangerous app-only permissions. $($mailApps.Count) have mail access." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "For mail access: configure ApplicationAccessPolicy in Exchange Online to restrict which mailboxes each app can access. For all dangerous permissions: review each app's need. Prefer delegated permissions where possible." `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "OAUTH-07" -Phase "Phase 3 - OAuth & Token Abuse" -Name "App-Only Permission Scope" `
            -Severity "Critical" -Status "ERROR" -Description "Error checking app permissions" `
            -AttackTechnique "Review app role assignments to Microsoft Graph SP" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase3 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 3 - OAuth & Token Abuse          " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-OAUTH01-DeviceCodeFlowBlock
    $phaseResults += Invoke-OAUTH02-UserConsentCheck
    $phaseResults += Invoke-OAUTH03-TokenScopeEscalation
    $phaseResults += Invoke-OAUTH04-RefreshTokenLifetime
    $phaseResults += Invoke-OAUTH05-CAETokenRevocation
    $phaseResults += Invoke-OAUTH06-ServicePrincipalCABypass
    $phaseResults += Invoke-OAUTH07-AppOnlyPermissionScope

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 3 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
