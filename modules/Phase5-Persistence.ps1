#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 5 - Persistence Technique Simulation
.DESCRIPTION
    Simulates attacker persistence techniques. All tests create artifacts
    and clean them up in finally blocks. Verifies audit logging captures
    the activity. AUTHORIZED USE ONLY.
#>

function Invoke-PERSIST01-BackdoorAppRegistration {
    [CmdletBinding()]
    param()
    $start   = Get-Date
    $testTag = "EntraScope-Test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $appId   = $null
    $spId    = $null

    Write-EntraLog "  [PERSIST-01] Backdoor App Registration Simulation" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PERSIST-01" -Phase "Phase 5 - Persistence" -Name "Backdoor App Registration" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Register app + add secret + assign permissions = persistent API access surviving password changes" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/protect-against-consent-phishing" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $evidence = [ordered]@{}

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }

        if ($script:DryRun) {
            return New-TestResult -TestId "PERSIST-01" -Phase "Phase 5 - Persistence" -Name "Backdoor App Registration" `
                -Severity "Critical" -Status "INFO" `
                -Description "Would create a backdoor app registration with secret and check if audit log captures it" `
                -AttackTechnique "POST /applications + addPassword + assign permissions = persistent access even after victim PW change" `
                -Result "DRY RUN" -Evidence "" -Remediation "Ensure audit logs capture app registration events and alerts fire" `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/protect-against-consent-phishing" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        # Step 1: Create app registration
        $appBody = @{
            displayName = $testTag
            signInAudience = "AzureADMyOrg"
        } | ConvertTo-Json
        Write-EntraLog "    Creating test app: $testTag" -Level Warn

        $app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST -Body $appBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $appId = $app.id
        $evidence["AppCreated"] = @{ DisplayName = $app.displayName; AppId = $app.appId; ObjectId = $app.id; CreatedTime = (Get-Date -Format o) }

        Start-Sleep -Seconds 3

        # Step 2: Add a password credential (secret)
        $secretBody = @{
            passwordCredential = @{
                displayName = "EntraScope-Backdoor-Secret"
                endDateTime = (Get-Date).AddYears(2).ToString("o")
            }
        } | ConvertTo-Json
        $secret = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$appId/addPassword" `
            -Method POST -Body $secretBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $evidence["SecretAdded"] = @{ KeyId = $secret.keyId; ExpiresIn = "2 years"; SecretValueSample = "[REDACTED - NOT STORED]" }
        Write-EntraLog "    Secret added to app (2-year expiry)" -Level Warn

        # Step 3: Create SP and assign a permission
        $spBody = @{ appId = $app.appId } | ConvertTo-Json
        $sp     = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Method POST -Body $spBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $spId   = $sp.id
        $evidence["SPCreated"] = @{ DisplayName = $sp.displayName; Id = $sp.id }

        # Step 4: Check audit log (wait 15s for propagation)
        Start-Sleep -Seconds 15
        Write-EntraLog "    Checking audit log for registration event..." -Level Info

        $since    = $start.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $auditUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Add application' and activityDateTime ge $since&`$top=10"
        $audit    = Invoke-RestMethod -Uri $auditUri -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $ourAudit = $audit.value | Where-Object { $_.targetResources.displayName -contains $testTag }
        $evidence["AuditLogEntry"]  = if ($ourAudit) { $ourAudit | Select-Object id, activityDisplayName, activityDateTime, result } else { "Not found yet (may still be propagating)" }
        $evidence["AuditDetected"]  = ($ourAudit.Count -gt 0)

        $status = if ($ourAudit.Count -gt 0) { "WARNING" } else { "FAIL" }
        $resultMsg = if ($ourAudit.Count -gt 0) {
            "App registration simulated and DETECTED in audit log. Alert: does your SIEM/Sentinel alert on new app registrations?"
        } else {
            "App registration simulated but NOT YET in audit log. Audit log delay or detection gap present."
        }

        return New-TestResult -TestId "PERSIST-01" -Phase "Phase 5 - Persistence" -Name "Backdoor App Registration" `
            -Severity "Critical" -Status $status `
            -Description "Simulates an attacker registering a backdoor application with a long-lived secret. This provides persistent API access that survives password resets and MFA changes." `
            -AttackTechnique "POST /applications + addPassword (2-year expiry) + create SP. Attacker now has persistent Graph API access as a 'trusted app'." `
            -Result $resultMsg -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Alert on new app registrations in Sentinel/Defender. 2) Audit app registrations weekly. 3) Require admin approval for new app registrations in Entra. 4) Set conditional access for workload identities." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/protect-against-consent-phishing" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        $evidence["Error"] = $_.Exception.Message
        return New-TestResult -TestId "PERSIST-01" -Phase "Phase 5 - Persistence" -Name "Backdoor App Registration" `
            -Severity "Critical" -Status "ERROR" -Description "Error during backdoor app simulation" `
            -AttackTechnique "POST /applications + addPassword" -Result "Error: $($_.Exception.Message)" `
            -Evidence ($evidence | ConvertTo-Json) -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/protect-against-consent-phishing" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    finally {
        if ($script:Config.Options.CleanupAfterTest -and -not $script:DryRun) {
            $headers = @{ Authorization = "Bearer $script:AccessToken" }
            if ($spId)  {
                try { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId" -Method DELETE -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue } catch {}
                Write-EntraLog "    Cleaned up: SP $spId" -Level Info
            }
            if ($appId) {
                try { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$appId" -Method DELETE -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue } catch {}
                Write-EntraLog "    Cleaned up: App $appId" -Level Info
            }
        }
    }
}

function Invoke-PERSIST02-SPCredentialAddition {
    [CmdletBinding()]
    param()
    $start   = Get-Date
    $testTag = "EntraScope-CredTest-$(Get-Date -Format 'yyyyMMddHHmm')"
    $appId   = $null
    $spId    = $null

    Write-EntraLog "  [PERSIST-02] Service Principal Credential Addition (Persistence)" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PERSIST-02" -Phase "Phase 5 - Persistence" -Name "SP Credential Addition" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Add credential to existing high-privilege SP = persistent access without password change detection" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $evidence = [ordered]@{}

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }

        if ($script:DryRun) {
            return New-TestResult -TestId "PERSIST-02" -Phase "Phase 5 - Persistence" -Name "SP Credential Addition" `
                -Severity "High" -Status "INFO" -Description "Would create temp SP and add credential to verify audit logging" `
                -AttackTechnique "POST /servicePrincipals/{id}/addPassword - attacker adds cred to existing SP for stealth persistence" `
                -Result "DRY RUN" -Evidence "" `
                -Remediation "Alert on 'Add service principal credentials' audit events" `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        # Create a temp app + SP for testing
        $app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications" -Method POST `
            -Body (@{ displayName = $testTag; signInAudience = "AzureADMyOrg" } | ConvertTo-Json) `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $appId = $app.id
        Start-Sleep -Seconds 2

        $sp   = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Method POST `
            -Body (@{ appId = $app.appId } | ConvertTo-Json) `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $spId = $sp.id
        $evidence["SPCreated"] = @{ Id = $spId; DisplayName = $sp.displayName }

        Start-Sleep -Seconds 2

        # Add credential to SP
        $credBody = @{ passwordCredential = @{ displayName = "EntraScope-Persistence-Cred" } } | ConvertTo-Json
        $cred = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/addPassword" `
            -Method POST -Body $credBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $evidence["CredentialAdded"] = @{ KeyId = $cred.keyId; DisplayName = $cred.displayName }
        Write-EntraLog "    Credential added to test SP" -Level Warn

        # Check audit log
        Start-Sleep -Seconds 15
        $since    = $start.AddMinutes(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $auditUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Add service principal credentials' and activityDateTime ge $since&`$top=5"
        $audit    = Invoke-RestMethod -Uri $auditUri -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        $detected = $audit.value.Count -gt 0
        $evidence["AuditDetected"] = $detected
        $evidence["AuditEntries"]  = $audit.value | Select-Object -First 3 | Select-Object id, activityDisplayName, activityDateTime, result

        $status = if ($detected) { "WARNING" } else { "FAIL" }

        return New-TestResult -TestId "PERSIST-02" -Phase "Phase 5 - Persistence" -Name "SP Credential Addition" `
            -Severity "High" -Status $status `
            -Description "Simulates adding credentials to an existing service principal as a persistence mechanism. Attacker adds their own secret to a high-privilege SP - invisible to the SP's normal secret rotation." `
            -AttackTechnique "POST /servicePrincipals/{existingHighPrivSP}/addPassword. Attacker now authenticates as that SP. This survives password resets, MFA changes, and is hard to detect." `
            -Result $(if ($detected) { "SP credential addition detected in audit log. Ensure your SIEM alerts on 'Add service principal credentials' events." } else { "AUDIT GAP: SP credential addition NOT found in audit log within test window." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Alert on 'Add service principal credentials' and 'Add application password credential' in audit logs. 2) Review SP credentials regularly - unexpected secrets are a red flag. 3) Disable unused SPs." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PERSIST-02" -Phase "Phase 5 - Persistence" -Name "SP Credential Addition" `
            -Severity "High" -Status "ERROR" -Description "Error testing SP credential persistence" `
            -AttackTechnique "POST /servicePrincipals/{id}/addPassword" -Result "Error: $($_.Exception.Message)" `
            -Evidence ($evidence | ConvertTo-Json) -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    finally {
        if ($script:Config.Options.CleanupAfterTest -and -not $script:DryRun) {
            $h = @{ Authorization = "Bearer $script:AccessToken" }
            if ($spId)  { try { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId" -Method DELETE -Headers $h -TimeoutSec 10 -ErrorAction SilentlyContinue } catch {} }
            if ($appId) { try { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$appId" -Method DELETE -Headers $h -TimeoutSec 10 -ErrorAction SilentlyContinue } catch {} }
            Write-EntraLog "    Cleaned up test SP and App" -Level Info
        }
    }
}

function Invoke-PERSIST03-BreakGlassEnumeration {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PERSIST-03] Break-Glass Account Enumeration" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PERSIST-03" -Phase "Phase 5 - Persistence" -Name "Break-Glass Account Exposure" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" -Result "SKIPPED" `
            -AttackTechnique "Identify break-glass accounts (no MFA + excluded from CA) to target" -Evidence "" `
            -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Get CA policies and their exclusions
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        # Find users excluded from EVERY CA policy (classic break-glass pattern)
        $allExcludedUsers = @{}
        foreach ($policy in $caPolicies.value | Where-Object { $_.state -eq "enabled" }) {
            $excludedUsers = $policy.conditions.users.excludeUsers
            foreach ($userId in $excludedUsers) {
                if (-not $allExcludedUsers[$userId]) { $allExcludedUsers[$userId] = @() }
                $allExcludedUsers[$userId] += $policy.displayName
            }
        }

        $totalPolicies = ($caPolicies.value | Where-Object { $_.state -eq "enabled" }).Count
        $bgCandidates  = $allExcludedUsers.GetEnumerator() | Where-Object { $_.Value.Count -ge [Math]::Max($totalPolicies - 1, 1) }

        # Resolve user IDs to UPNs
        $bgDetails = @()
        foreach ($candidate in $bgCandidates | Select-Object -First 10) {
            try {
                $user = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($candidate.Key)?`$select=displayName,userPrincipalName,accountEnabled,createdDateTime" `
                    -Headers $headers -TimeoutSec 8 -ErrorAction Stop
                # Check MFA registration
                $mfaMethods = $null
                try {
                    $mfaMethods = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($candidate.Key)/authentication/methods" -Headers $headers -TimeoutSec 8 -ErrorAction Stop
                } catch {}

                $bgDetails += [PSCustomObject]@{
                    UserPrincipalName = $user.userPrincipalName
                    DisplayName       = $user.displayName
                    AccountEnabled    = $user.accountEnabled
                    CreatedDateTime   = $user.createdDateTime
                    ExcludedFromPolicies = $candidate.Value.Count
                    MFAMethodCount    = if ($mfaMethods) { $mfaMethods.value.Count } else { "Unknown" }
                    IsPotentialBreakGlass = $true
                }
            } catch { }
        }

        $evidence["TotalEnabledCAPolicies"] = $totalPolicies
        $evidence["UsersExcludedFromAllPolicies"] = $bgDetails.Count
        $evidence["PotentialBreakGlassAccounts"]  = $bgDetails

        $unmonitoredBG = $bgDetails | Where-Object { $_.MFAMethodCount -eq 0 }
        $issues = @()
        if ($bgDetails.Count -eq 0) { $issues += "No break-glass accounts identifiable (or none configured - verify BG accounts exist)" }
        if ($bgDetails.Count -gt 3) { $issues += "More than 3 accounts excluded from all CA policies - verify each is intentional" }
        if ($unmonitoredBG.Count -gt 0) { $issues += "$($unmonitoredBG.Count) CA-excluded accounts have no MFA registered - if not BG, these are high-risk" }

        $status = if ($unmonitoredBG.Count -gt 0 -and $bgDetails.Count -gt 2) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "PERSIST-03" -Phase "Phase 5 - Persistence" -Name "Break-Glass Account Exposure" `
            -Severity "High" -Status $status `
            -Description "Identifies accounts excluded from all Conditional Access policies (break-glass pattern). These are high-value attack targets - if compromised, MFA and CA policies don't protect them." `
            -AttackTechnique "Enumerate CA policy exclusions to find break-glass accounts. Target these accounts - they have no MFA protection and bypass all CA policies." `
            -Result "$($bgDetails.Count) potential break-glass/CA-excluded accounts found. Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 5) `
            -Remediation "1) Maintain only 2 break-glass accounts maximum. 2) Use very strong (20+ char) random passwords. 3) Monitor ALL sign-ins to BG accounts via Azure Monitor alerts. 4) Store credentials in physical safe. 5) Review and verify BG accounts monthly." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PERSIST-03" -Phase "Phase 5 - Persistence" -Name "Break-Glass Account Exposure" `
            -Severity "High" -Status "ERROR" -Description "Error enumerating break-glass accounts" `
            -AttackTechnique "Enumerate CA exclusions" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PERSIST04-StaleOAuthGrants {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PERSIST-04] Stale OAuth Grant Persistence Check" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PERSIST-04" -Phase "Phase 5 - Persistence" -Name "Stale OAuth Grants" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" -Result "SKIPPED" `
            -AttackTechnique "OAuth grants with high-privilege scopes persist across password resets" -Evidence "" `
            -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers   = @{ Authorization = "Bearer $script:AccessToken" }
        $grants    = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=100" -Headers $headers -TimeoutSec 20 -ErrorAction Stop
        $evidence  = [ordered]@{ TotalGrants = $grants.value.Count }

        $dangerousScopes = @("Mail.ReadWrite","Files.ReadWrite.All","User.ReadWrite.All","Directory.ReadWrite.All","Calendars.ReadWrite","Contacts.ReadWrite","Mail.Read","Sites.ReadWrite.All","offline_access")
        $allGrants    = $grants.value
        $riskyGrants  = @()
        $broadGrants  = @()

        foreach ($grant in $allGrants) {
            $scopes = $grant.scope -split " "
            $dangerousScopes_found = $scopes | Where-Object { $_ -in $dangerousScopes }
            if ($dangerousScopes_found.Count -gt 0) {
                $riskyGrants += [PSCustomObject]@{
                    ClientId     = $grant.clientId
                    ConsentType  = $grant.consentType
                    Scope        = $grant.scope
                    DangerousScopes = $dangerousScopes_found -join ", "
                    PrincipalId  = $grant.principalId
                }
            }
            if ($scopes.Count -gt 10) {
                $broadGrants += [PSCustomObject]@{ ClientId = $grant.clientId; ScopeCount = $scopes.Count; Scopes = $grant.scope }
            }
        }

        $evidence["RiskyGrants"]  = $riskyGrants | Select-Object -First 10
        $evidence["BroadGrants"]  = $broadGrants | Select-Object -First 5
        $evidence["RiskyCount"]   = $riskyGrants.Count
        $evidence["BroadCount"]   = $broadGrants.Count

        # All-user (admin consent) grants are especially dangerous
        $adminGrants = $riskyGrants | Where-Object { $_.ConsentType -eq "AllPrincipals" }
        $evidence["AdminConsentedDangerousGrants"] = $adminGrants.Count

        $issues = @()
        if ($adminGrants.Count -gt 0)  { $issues += "$($adminGrants.Count) admin-consented apps have dangerous scope grants (affect ALL users)" }
        if ($riskyGrants.Count -gt 5)  { $issues += "$($riskyGrants.Count) total apps with dangerous OAuth scopes" }
        if ($broadGrants.Count -gt 0)  { $issues += "$($broadGrants.Count) apps with 10+ permission scopes - overly broad" }

        $status = if ($adminGrants.Count -gt 0) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "PERSIST-04" -Phase "Phase 5 - Persistence" -Name "Stale OAuth Grants" `
            -Severity "High" -Status $status `
            -Description "Reviews OAuth permission grants for dangerous scopes. These grants persist across password resets and MFA changes - a compromised app with a Mail.Read grant reads all email indefinitely." `
            -AttackTechnique "OAuth delegated/application grants survive password resets. Attacker with compromised app client secret retains access to user data even after incident response." `
            -Result "$($riskyGrants.Count) grants with dangerous scopes. $($adminGrants.Count) are admin-consented (affect entire tenant). Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Review all OAuth grants in Entra > Enterprise Applications > All applications > Permissions. 2) Remove unused or overly broad grants. 3) Audit grants quarterly. 4) Revoke all grants for apps that are no longer in use." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PERSIST-04" -Phase "Phase 5 - Persistence" -Name "Stale OAuth Grants" `
            -Severity "High" -Status "ERROR" -Description "Error checking OAuth grants" `
            -AttackTechnique "GET /oauth2PermissionGrants" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PERSIST05-GuestBackdoor {
    [CmdletBinding()]
    param()
    $start       = Get-Date
    $testEmail   = "entrascope-testguest-$(Get-Date -Format 'yyyyMMddHHmm')@outlook.com"
    $invitationId = $null

    Write-EntraLog "  [PERSIST-05] Guest Invitation Backdoor Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PERSIST-05" -Phase "Phase 5 - Persistence" -Name "Guest Backdoor Invitation" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Invite attacker-controlled external account as guest - persists across tenant cleanup" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $evidence = [ordered]@{}

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }

        # First check the external collaboration policy
        try {
            $authPolicy = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $evidence["AllowInvitesFrom"] = $authPolicy.allowInvitesFrom
            $evidence["GuestUserRoleId"]  = $authPolicy.guestUserRoleId
            # GuestUserRoleId: 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest User (most restricted), a0b1b346-4d3e-4e8b-98f8-753987be4970 = Member-like (dangerous)
            $isMemberLike = $authPolicy.guestUserRoleId -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970"
            $evidence["GuestsHaveMemberPermissions"] = $isMemberLike
            if ($isMemberLike) { Write-EntraLog "    [!] Guests have Member-level permissions!" -Level Warn }
        } catch { $evidence["AuthPolicyError"] = $_.Exception.Message }

        if ($script:DryRun) {
            return New-TestResult -TestId "PERSIST-05" -Phase "Phase 5 - Persistence" -Name "Guest Backdoor Invitation" `
                -Severity "High" -Status "INFO" `
                -Description "Would attempt to invite an external account as guest to check if invitations are unrestricted" `
                -AttackTechnique "POST /invitations to invite attacker external account. If unrestricted, attacker can maintain persistent guest access." `
                -Result "DRY RUN - External collaboration policy: allowInvitesFrom=$($evidence['AllowInvitesFrom'])" `
                -Evidence ($evidence | ConvertTo-Json) `
                -Remediation "Restrict guest invitations to admins only" `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        # Attempt guest invitation
        $inviteBody = @{
            invitedUserEmailAddress = $testEmail
            inviteRedirectUrl       = "https://myapps.microsoft.com"
            sendInvitationMessage   = $false
        } | ConvertTo-Json
        Write-EntraLog "    Attempting guest invitation for: $testEmail" -Level Warn

        $invitation = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/invitations" `
            -Method POST -Body $inviteBody -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $invitationId = $invitation.invitedUser.id
        $evidence["InvitationResult"] = @{ Status = "SUCCEEDED"; GuestId = $invitationId; GuestEmail = $testEmail }
        Write-EntraLog "    [!] Guest invitation SUCCEEDED. Cleaning up..." -Level Warn

        $status = "FAIL"
        $resultMsg = "Guest invitation SUCCEEDED. External collaboration settings allow unrestricted invitations. An attacker with a compromised account can backdoor the tenant with an external identity."

        return New-TestResult -TestId "PERSIST-05" -Phase "Phase 5 - Persistence" -Name "Guest Backdoor Invitation" `
            -Severity "High" -Status $status `
            -Description "Tests whether an authenticated user can invite external accounts as guests without restriction." `
            -AttackTechnique "POST /invitations with attacker-controlled external email. Once accepted, attacker has persistent guest access even if original compromised account is removed." `
            -Result $resultMsg -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "Set 'Who can invite guests' to 'Only admins' or 'Admins and users with the Guest Inviter role'. Enable B2B cross-tenant access policies. Review and remove stale guest accounts regularly." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $status = if ($code -in @(400,403,401)) { "PASS" } else { "ERROR" }

        return New-TestResult -TestId "PERSIST-05" -Phase "Phase 5 - Persistence" -Name "Guest Backdoor Invitation" `
            -Severity "High" -Status $status `
            -Description "Tests whether an authenticated user can invite external accounts as guests without restriction." `
            -AttackTechnique "POST /invitations with external email - if blocked = guest invitation controls working" `
            -Result $(if ($status -eq "PASS") { "Guest invitation BLOCKED (HTTP $code). External collaboration controls working. Policy: allowInvitesFrom=$($evidence['AllowInvitesFrom'])" } else { "Error: $($_.Exception.Message)" }) `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "Good if blocked. Verify 'allowInvitesFrom' is set to 'adminsAndGuestInviters' or 'admins' only." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    finally {
        if ($invitationId -and $script:Config.Options.CleanupAfterTest -and -not $script:DryRun) {
            try {
                $h = @{ Authorization = "Bearer $script:AccessToken" }
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$invitationId" -Method DELETE -Headers $h -TimeoutSec 10 -ErrorAction SilentlyContinue
                Write-EntraLog "    Cleaned up guest account: $invitationId" -Level Info
            } catch {}
        }
    }
}

function Invoke-Phase5 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 5 - Persistence Simulation      " -Level Attack
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " All test artifacts will be auto-cleaned up" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-PERSIST01-BackdoorAppRegistration
    $phaseResults += Invoke-PERSIST02-SPCredentialAddition
    $phaseResults += Invoke-PERSIST03-BreakGlassEnumeration
    $phaseResults += Invoke-PERSIST04-StaleOAuthGrants
    $phaseResults += Invoke-PERSIST05-GuestBackdoor

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 5 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
