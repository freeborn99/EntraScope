#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 4 - Privilege Escalation Path Testing
.DESCRIPTION
    Tests privilege escalation paths using the configured test account.
    All attempts are expected to fail (PASS = blocked). AUTHORIZED USE ONLY.
#>

function Invoke-PRIVESC01-SelfRoleAssignment {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-01] Self Role Assignment Attempt" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-01" -Phase "Phase 4 - Privilege Escalation" -Name "Self Role Assignment" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Attempt to grant self a privileged directory role via Graph API" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/assign-roles-different-scopes" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "PRIVESC-01" -Phase "Phase 4 - Privilege Escalation" -Name "Self Role Assignment" `
            -Severity "Critical" -Status "INFO" `
            -Description "Would attempt to POST a role assignment for the current user to Global Admin" `
            -AttackTechnique "POST /roleManagement/directory/roleAssignments to add Global Admin to self" `
            -Result "DRY RUN" -Evidence "" -Remediation "Ensure non-admins cannot assign roles" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/assign-roles-different-scopes" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }

        # Get current user ID
        $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName" -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        # Get Global Admin role definition ID
        $roles = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        $globalAdminRole = $roles.value | Where-Object { $_.displayName -eq "Global Administrator" }
        if (-not $globalAdminRole) {
            # Activate via template ID
            $globalAdminTemplateId = "62e90394-69f5-4237-9190-012177145e10"
            $activateBody = @{ roleTemplateId = $globalAdminTemplateId } | ConvertTo-Json
            try {
                $globalAdminRole = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Method POST -Body $activateBody -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            } catch {}
        }

        $roleId = if ($globalAdminRole) { $globalAdminRole.id } else { "62e90394-69f5-4237-9190-012177145e10" }

        # Attempt to assign Global Admin to self
        $body = @{
            "@odata.type"     = "#microsoft.graph.unifiedRoleAssignment"
            roleDefinitionId  = $roleId
            principalId       = $me.id
            directoryScopeId  = "/"
        } | ConvertTo-Json

        Write-EntraLog "    Attempting self Global Admin assignment for $($me.userPrincipalName)" -Level Warn
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" `
            -Method POST -Body $body -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        # If we get here, assignment SUCCEEDED = FAIL
        # Clean up immediately
        try {
            Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$($result.id)" `
                -Method DELETE -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
        } catch {}

        return New-TestResult -TestId "PRIVESC-01" -Phase "Phase 4 - Privilege Escalation" -Name "Self Role Assignment" `
            -Severity "Critical" -Status "FAIL" `
            -Description "Tests whether a non-admin user can assign privileged roles to themselves via the Graph API." `
            -AttackTechnique "POST /roleManagement/directory/roleAssignments with self as principalId and Global Admin as role" `
            -Result "CRITICAL: Self role assignment SUCCEEDED. Global Admin role was assigned and immediately cleaned up." `
            -Evidence (@{ UserId = $me.id; UPN = $me.userPrincipalName; RoleAssigned = "Global Administrator"; Cleaned = $true } | ConvertTo-Json) `
            -Remediation "This should never succeed. Review your tenant's role assignment permissions immediately. Ensure only privileged role administrators can assign roles." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/assign-roles-different-scopes" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $status = if ($code -in @(403, 401)) { "PASS" } else { "ERROR" }

        return New-TestResult -TestId "PRIVESC-01" -Phase "Phase 4 - Privilege Escalation" -Name "Self Role Assignment" `
            -Severity "Critical" -Status $status `
            -Description "Tests whether a non-admin user can assign privileged roles to themselves via the Graph API." `
            -AttackTechnique "POST /roleManagement/directory/roleAssignments to add Global Admin role to current user" `
            -Result (if ($status -eq "PASS") { "BLOCKED (HTTP $code) - Role self-assignment correctly denied." } else { "Error: $($_.Exception.Message)" }) `
            -Evidence (@{ HTTPCode = $code; Error = $_.Exception.Message } | ConvertTo-Json) `
            -Remediation "No action needed if PASS. Regularly audit role assignment permissions." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/assign-roles-different-scopes" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PRIVESC02-ServicePrincipalOwnerAbuse {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-02] Service Principal Owner Credential Abuse" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-02" -Phase "Phase 4 - Privilege Escalation" -Name "SP Owner Credential Abuse" `
            -Severity "Critical" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Find owned SP, add credential, authenticate as SP to abuse its permissions" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-apps" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }
        $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id" -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        # Find SPs owned by current user
        $ownedSPs = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/ownedObjects?`$select=id,displayName,appId&`$filter=@odata.type eq '#microsoft.graph.servicePrincipal'" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $evidence = [ordered]@{
            CurrentUser     = $me.id
            OwnedSPCount    = $ownedSPs.value.Count
            OwnedSPs        = ($ownedSPs.value | Select-Object displayName, id, appId)
        }

        if ($ownedSPs.value.Count -eq 0) {
            return New-TestResult -TestId "PRIVESC-02" -Phase "Phase 4 - Privilege Escalation" -Name "SP Owner Credential Abuse" `
                -Severity "Critical" -Status "PASS" `
                -Description "Tests if current user owns any service principals that could be abused to escalate privileges by adding credentials." `
                -AttackTechnique "If you own an SP with Directory.ReadWrite.All: add new secret to it, auth as SP, abuse its permissions" `
                -Result "Current user owns 0 service principals. No SP ownership escalation path available." `
                -Evidence ($evidence | ConvertTo-Json) `
                -Remediation "Good - no owned SPs. Regularly audit SP ownership via GET /servicePrincipals and ensure all SPs have designated human owners who are monitored." `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        # Try to add credential to each owned SP
        $credAbuse = @()
        foreach ($sp in $ownedSPs.value | Select-Object -First 3) {
            try {
                $addCredBody = @{
                    passwordCredential = @{
                        displayName = "EntraScope-Test-DELETE-$(Get-Date -Format 'yyyyMMddHHmm')"
                        endDateTime = (Get-Date).AddHours(1).ToString("o")
                    }
                } | ConvertTo-Json

                $credResp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/addPassword" `
                    -Method POST -Body $addCredBody -Headers (@{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }) `
                    -TimeoutSec 15 -ErrorAction Stop

                # Credential added! Now remove it
                try {
                    $removeBody = @{ keyId = $credResp.keyId } | ConvertTo-Json
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/removePassword" `
                        -Method POST -Body $removeBody -Headers (@{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }) `
                        -TimeoutSec 10 -ErrorAction SilentlyContinue
                } catch {}

                $credAbuse += @{ SP = $sp.displayName; CredAdded = $true; KeyId = $credResp.keyId; Cleaned = $true }
                Write-EntraLog "    [!] Credential successfully added+removed to owned SP: $($sp.displayName)" -Level Warn
            }
            catch {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                $credAbuse += @{ SP = $sp.displayName; CredAdded = $false; HTTPCode = $code }
            }
        }

        $evidence["CredentialAbuseAttempts"] = $credAbuse
        $anySucceeded = $credAbuse | Where-Object { $_.CredAdded -eq $true }
        $status = if ($anySucceeded) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "PRIVESC-02" -Phase "Phase 4 - Privilege Escalation" -Name "SP Owner Credential Abuse" `
            -Severity "Critical" -Status $status `
            -Description "Tests if an owned service principal can have credentials added to it, enabling authentication as that SP to abuse its permissions." `
            -AttackTechnique "POST /servicePrincipals/{id}/addPassword - if SP has dangerous permissions, this = privilege escalation" `
            -Result (if ($anySucceeded) { "CREDENTIAL ADDED TO OWNED SP(S)! If those SPs have privileged permissions, this is a privilege escalation path. Credentials were cleaned up." } else { "Could not add credentials to owned SPs, or current user owns no SPs." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "Audit all SP ownerships. Remove test/dev accounts from owning production SPs. For sensitive SPs, use Azure AD Privileged Access to control who can modify them." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PRIVESC-02" -Phase "Phase 4 - Privilege Escalation" -Name "SP Owner Credential Abuse" `
            -Severity "Critical" -Status "ERROR" -Description "Error testing SP ownership" `
            -AttackTechnique "Enumerate owned objects and attempt addPassword" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PRIVESC03-GroupMembershipManipulation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-03] Privileged Group Membership Manipulation" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-03" -Phase "Phase 4 - Privilege Escalation" -Name "Group Membership Manipulation" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Add self to privileged group to inherit group permissions" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-settings-cmdlets" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }
        $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id" -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        # Find privileged-sounding groups
        $privGroups = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,'Global') or startswith(displayName,'Security') or startswith(displayName,'Admin') or startswith(displayName,'Privileged')&`$select=id,displayName,isAssignableToRole,membershipRule" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $evidence = [ordered]@{
            PrivilegedGroupsFound = $privGroups.value.Count
            Groups = $privGroups.value | Select-Object displayName, id, isAssignableToRole
        }

        $addResults = @()
        foreach ($group in $privGroups.value | Select-Object -First 5) {
            try {
                $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($me.id)" } | ConvertTo-Json
                Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/`$ref" `
                    -Method POST -Body $body -Headers (@{ Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }) `
                    -TimeoutSec 10 -ErrorAction Stop

                # If succeeded, remove self
                try {
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/$($me.id)/`$ref" `
                        -Method DELETE -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
                } catch {}

                $addResults += @{ Group = $group.displayName; Added = $true; Cleaned = $true }
                Write-EntraLog "    [!] Self-added to group: $($group.displayName)" -Level Warn
            }
            catch {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                $addResults += @{ Group = $group.displayName; Added = $false; HTTPCode = $code }
            }
        }

        $evidence["AddAttempts"] = $addResults
        $anyAdded = $addResults | Where-Object { $_.Added -eq $true }
        $status = if ($anyAdded) { "FAIL" } elseif ($privGroups.value.Count -eq 0) { "PASS" } else { "PASS" }

        return New-TestResult -TestId "PRIVESC-03" -Phase "Phase 4 - Privilege Escalation" -Name "Group Membership Manipulation" `
            -Severity "High" -Status $status `
            -Description "Tests whether an authenticated user can add themselves to privileged groups, inheriting group permissions and role assignments." `
            -AttackTechnique "POST /groups/{privilegedGroupId}/members/`$ref with current user ID - if group has privileged role assignments, immediate privilege escalation" `
            -Result (if ($anyAdded) { "PRIVILEGE ESCALATION: Successfully added to privileged group(s). Group membership was cleaned up." } else { "$($privGroups.value.Count) privileged groups found. None could be joined by current user." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "Enable group membership control via Microsoft Entra ID Governance. Set role-assignable groups to require owner approval for membership. Use PIM for Groups for JIT membership." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PRIVESC-03" -Phase "Phase 4 - Privilege Escalation" -Name "Group Membership Manipulation" `
            -Severity "High" -Status "ERROR" -Description "Error testing group membership" `
            -AttackTechnique "POST /groups/{id}/members/`$ref" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PRIVESC04-PIMActivationTest {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-04] PIM Role Activation Requirements Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-04" -Phase "Phase 4 - Privilege Escalation" -Name "PIM Activation Requirements" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Activate PIM role with stolen session token bypassing MFA requirement" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-change-default-settings" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }

        # Get current user's PIM eligible assignments
        $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        $eligibleAssignments = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($me.id)'" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $evidence = [ordered]@{ EligibleRoleCount = $eligibleAssignments.value.Count }

        if ($eligibleAssignments.value.Count -eq 0) {
            # Check all PIM policies regardless (admin view)
            $allPolicies = $null
            try {
                $allPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeType eq 'DirectoryRole'" `
                    -Headers $headers -TimeoutSec 15 -ErrorAction Stop
            } catch {}

            $evidence["Note"] = "Current user has no PIM eligible assignments. Checking all role management policies instead."
            if ($allPolicies) { $evidence["AllPoliciesCount"] = $allPolicies.value.Count }
        }

        # Get role management policies and check activation rules
        $pimIssues = @()
        $policyResults = @()

        try {
            $policies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeType eq 'DirectoryRole'&`$expand=rules" `
                -Headers $headers -TimeoutSec 20 -ErrorAction Stop

            foreach ($policy in $policies.value | Select-Object -First 10) {
                $mfaRule    = $policy.rules | Where-Object { $_.id -eq "AuthenticationContext_EndUser_Assignment" -or $_.ruleType -match "Authentication" }
                $approvalRule = $policy.rules | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }
                $mfaRequired = $policy.rules | Where-Object { $_.id -match "MfaRequired" -or ($_.additionalProperties.isEnabled -eq $true -and $_.ruleType -match "Multi") }

                $activationRule = $policy.rules | Where-Object { $_.id -eq "Enablement_EndUser_Assignment" }
                $mfaInActivation = $activationRule.additionalProperties.enabledRules -contains "MultiFactorAuthentication"

                $policyResults += [PSCustomObject]@{
                    PolicyId        = $policy.id
                    MFAInActivation = $mfaInActivation
                    ApprovalEnabled = $approvalRule.additionalProperties.isEnabled
                }

                if (-not $mfaInActivation) { $pimIssues += "Policy $($policy.id): MFA NOT required for activation" }
            }
        } catch { $evidence["PolicyCheckError"] = $_.Exception.Message }

        $evidence["PIMPolicyResults"] = $policyResults
        $evidence["Issues"] = $pimIssues

        $status = if ($pimIssues.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "PRIVESC-04" -Phase "Phase 4 - Privilege Escalation" -Name "PIM Activation Requirements" `
            -Severity "High" -Status $status `
            -Description "Checks if PIM role activation requires MFA and Authentication Context. Without these, a stolen session token can activate privileged roles." `
            -AttackTechnique "Steal user session token via AiTM. Use existing session to activate PIM role if MFA is not re-enforced at activation time - get Global Admin with stolen session." `
            -Result (if ($pimIssues.Count -gt 0) { "PIM ACTIVATION GAPS: $($pimIssues -join '; ')" } else { "PIM policies require MFA/Authentication Context for activation." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 5) `
            -Remediation "In PIM > Role settings for each privileged role: Require Azure MFA on activation. Require Conditional Access Authentication Context (step-up auth). Set maximum activation duration to 1-4 hours. Require approval for Global Admin activation." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-change-default-settings" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PRIVESC-04" -Phase "Phase 4 - Privilege Escalation" -Name "PIM Activation Requirements" `
            -Severity "High" -Status "ERROR" -Description "Error checking PIM policies" `
            -AttackTechnique "Review roleManagementPolicies via Graph" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-change-default-settings" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PRIVESC05-AppPermissionGrantAbuse {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-05] App Permission Grant Abuse Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-05" -Phase "Phase 4 - Privilege Escalation" -Name "App Permission Grant Abuse" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Low-priv user grants high-privilege OAuth scopes to a controlled app" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers = @{ Authorization = "Bearer $script:AccessToken" }
        $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id" -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        # Attempt to create an OAuth2 permission grant for a dangerous scope
        # Using Microsoft Graph SP ID as resource
        $graphSP = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'Microsoft Graph'&`$select=id" `
            -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        # Find Azure CLI client SP
        $azureCliSP = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '04b07795-8ddb-461a-bbee-02f9e1bf7b46'&`$select=id" `
            -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        $evidence = [ordered]@{}

        if ($azureCliSP.value.Count -eq 0) {
            $evidence["Note"] = "Azure CLI service principal not found in tenant (normal if not installed)"
            # Try to grant to a test app if available
            $evidence["TestResult"] = "Cannot test without a target SP in tenant"
            return New-TestResult -TestId "PRIVESC-05" -Phase "Phase 4 - Privilege Escalation" -Name "App Permission Grant Abuse" `
                -Severity "High" -Status "INFO" `
                -Description "Tests if a low-privilege user can grant dangerous OAuth scopes. Azure CLI SP not found - cannot perform active test." `
                -AttackTechnique "POST /oauth2PermissionGrants to grant User.ReadWrite.All delegated scope to an app controlled by attacker" `
                -Result "Test skipped - no suitable SP found. Check OAUTH-02 result for consent policy configuration." `
                -Evidence ($evidence | ConvertTo-Json) `
                -Remediation "Control user consent via authorization policy. See OAUTH-02 findings." `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        # Attempt to grant User.ReadWrite.All to Azure CLI for current user
        $grantBody = @{
            clientId    = $azureCliSP.value[0].id
            consentType = "Principal"
            principalId = $me.id
            resourceId  = $graphSP.value[0].id
            scope       = "User.ReadWrite.All Directory.ReadWrite.All"
        } | ConvertTo-Json

        Write-EntraLog "    Attempting to grant User.ReadWrite.All to Azure CLI SP for current user" -Level Warn

        $grantResult = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
            -Method POST -Body $grantBody -Headers (@{Authorization = "Bearer $script:AccessToken"; "Content-Type" = "application/json"}) `
            -TimeoutSec 15 -ErrorAction Stop

        # If we get here, grant succeeded
        # Clean up
        try {
            Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($grantResult.id)" `
                -Method DELETE -Headers $headers -TimeoutSec 10 -ErrorAction SilentlyContinue
        } catch {}

        $evidence["GrantResult"] = "SUCCEEDED - grant created and cleaned up"
        $evidence["GrantedScope"] = $grantResult.scope

        return New-TestResult -TestId "PRIVESC-05" -Phase "Phase 4 - Privilege Escalation" -Name "App Permission Grant Abuse" `
            -Severity "High" -Status "FAIL" `
            -Description "Tests if a user can grant dangerous OAuth permission scopes to applications, effectively escalating an app's access." `
            -AttackTechnique "POST /oauth2PermissionGrants with high-privilege scopes. If user can grant Directory.ReadWrite.All to a controlled app, attacker gains tenant admin via that app." `
            -Result "HIGH-PRIVILEGE GRANT SUCCEEDED: User was able to grant User.ReadWrite.All and Directory.ReadWrite.All. Grant was cleaned up." `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "Restrict user consent in authorization policy. Users should not be able to grant high-privilege scopes. Require admin approval for any scope beyond User.Read." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $status = if ($code -in @(400,403,401)) { "PASS" } else { "ERROR" }

        return New-TestResult -TestId "PRIVESC-05" -Phase "Phase 4 - Privilege Escalation" -Name "App Permission Grant Abuse" `
            -Severity "High" -Status $status `
            -Description "Tests if a user can grant dangerous OAuth permission scopes to applications." `
            -AttackTechnique "POST /oauth2PermissionGrants with high-privilege scopes" `
            -Result (if ($status -eq "PASS") { "BLOCKED (HTTP $code) - User cannot grant high-privilege OAuth scopes without admin approval." } else { "Error: $($_.Exception.Message)" }) `
            -Evidence (@{ HTTPCode = $code; Error = $_.Exception.Message } | ConvertTo-Json) `
            -Remediation "Good if blocked. Ensure admin consent workflow is enabled so users can request approval." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-PRIVESC06-RoleAssignmentEnumeration {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [PRIVESC-06] Privileged Role Assignment Enumeration by Non-Admins" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "PRIVESC-06" -Phase "Phase 4 - Privilege Escalation" -Name "Role Assignment Visibility" `
            -Severity "Medium" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Low-priv user enumerates who has Global Admin to target them for phishing/escalation" -Result "SKIPPED" `
            -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Enumerate role assignments visible to current user
        $roleAssignments = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal&`$top=50" `
            -Headers $headers -TimeoutSec 20 -ErrorAction Stop

        # Get role definitions to map IDs to names
        $roleDefinitions = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged" `
            -Headers $headers -TimeoutSec 10 -ErrorAction Stop

        $roleDefMap = @{}
        foreach ($def in $roleDefinitions.value) { $roleDefMap[$def.id] = $def.displayName }

        $privilegedAssignments = $roleAssignments.value | Where-Object {
            $roleName = $roleDefMap[$_.roleDefinitionId]
            $roleName -match "Global Admin|Security Admin|Privileged Role|Exchange Admin|SharePoint Admin|Teams Admin|Billing Admin|User Admin"
        }

        $evidence["TotalRoleAssignmentsVisible"] = $roleAssignments.value.Count
        $evidence["PrivilegedAssignmentsVisible"] = $privilegedAssignments.Count
        $evidence["PrivilegedAdmins"] = $privilegedAssignments | Select-Object `
            @{N="Role";E={$roleDefMap[$_.roleDefinitionId]}},
            @{N="PrincipalType";E={$_.principal."@odata.type" -replace "#microsoft.graph.",""}},
            @{N="PrincipalName";E={$_.principal.displayName}},
            @{N="PrincipalUPN";E={$_.principal.userPrincipalName}}

        # Check: can we see UPNs of Global Admins?
        $globalAdmins = $privilegedAssignments | Where-Object { $roleDefMap[$_.roleDefinitionId] -eq "Global Administrator" }
        $upnsVisible  = $globalAdmins | Where-Object { $_.principal.userPrincipalName }
        $evidence["GlobalAdminCount"]    = $globalAdmins.Count
        $evidence["GlobalAdminUPNsVisible"] = $upnsVisible.Count

        $issues = @()
        if ($globalAdmins.Count -gt 5)       { $issues += "WARNING: $($globalAdmins.Count) Global Admins found - recommended maximum is 5" }
        if ($upnsVisible.Count -gt 0)        { $issues += "Global Admin UPNs visible to all authenticated users - can be targeted for spear phishing" }

        $status = if ($globalAdmins.Count -gt 5) { "FAIL" } elseif ($issues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "PRIVESC-06" -Phase "Phase 4 - Privilege Escalation" -Name "Role Assignment Visibility" `
            -Severity "Medium" -Status $status `
            -Description "Tests what role assignment information is visible to all authenticated users. Attackers enumerate privileged users to target for phishing or credential attacks." `
            -AttackTechnique "GET /roleManagement/directory/roleAssignments - identify Global Admin UPNs to target with spear phishing, credential stuffing, or AiTM" `
            -Result "$($roleAssignments.value.Count) role assignments visible. $($globalAdmins.Count) Global Admins identifiable. Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Reduce Global Admin count to 2-5 maximum. 2) Use cloud-only accounts for Global Admins (separate from daily-use accounts). 3) Consider hiding admin accounts from global address list. 4) Use PIM so admins only have active roles when needed." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "PRIVESC-06" -Phase "Phase 4 - Privilege Escalation" -Name "Role Assignment Visibility" `
            -Severity "Medium" -Status "ERROR" -Description "Error enumerating role assignments" `
            -AttackTechnique "GET /roleManagement/directory/roleAssignments" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase4 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 4 - Privilege Escalation Testing " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-PRIVESC01-SelfRoleAssignment
    $phaseResults += Invoke-PRIVESC02-ServicePrincipalOwnerAbuse
    $phaseResults += Invoke-PRIVESC03-GroupMembershipManipulation
    $phaseResults += Invoke-PRIVESC04-PIMActivationTest
    $phaseResults += Invoke-PRIVESC05-AppPermissionGrantAbuse
    $phaseResults += Invoke-PRIVESC06-RoleAssignmentEnumeration

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 4 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
