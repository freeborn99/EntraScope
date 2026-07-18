#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 7 - Azure Resource & RBAC Attack Testing
.DESCRIPTION
    Tests Azure subscription security: RBAC misconfigs, managed identity
    risks, automation account exposure, policy compliance. AUTHORIZED USE ONLY.
#>

function Invoke-AZ01-RBACEnumeration {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-01] Azure RBAC Dangerous Assignment Enumeration" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-01" -Phase "Phase 7 - Azure Resources" -Name "Azure RBAC Dangerous Assignments" `
            -Severity "Critical" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Enumerate subscription-level Owner/UAA assignments to identify privilege escalation targets" `
            -Result "SKIPPED - no ARM token" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $allDangerous = @()

        foreach ($subId in $script:DiscoveredSubscriptions) {
            # Get all role assignments at subscription scope
            $assignments = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()" `
                -Headers $armHeaders -TimeoutSec 20 -ErrorAction Stop

            # Get role definitions for dangerous roles
            $dangerousRoleIds = @{
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = "Owner"
                "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" = "User Access Administrator"
                "b24988ac-6180-42a0-ab88-20f7382dd24c" = "Contributor"
            }

            $dangerousAssignments = $assignments.value | Where-Object { $_.properties.roleDefinitionId -match ($dangerousRoleIds.Keys -join "|") }

            foreach ($asgn in $dangerousAssignments) {
                $roleId   = $asgn.properties.roleDefinitionId.Split("/")[-1]
                $roleName = $dangerousRoleIds[$roleId] ?? "Unknown-$roleId"
                $principalType = $asgn.properties.principalType
                $principalId   = $asgn.properties.principalId
                $scope         = $asgn.properties.scope

                # Direct user Owner/UAA at subscription = Critical
                $isCritical = ($principalType -eq "User") -and ($roleName -in @("Owner","User Access Administrator")) -and ($scope -match "/subscriptions/[^/]+$")

                $allDangerous += [PSCustomObject]@{
                    SubscriptionId = $subId
                    RoleName       = $roleName
                    PrincipalType  = $principalType
                    PrincipalId    = $principalId
                    Scope          = $scope
                    IsCritical     = $isCritical
                }
            }

            # Check for classic (legacy) role assignments
            try {
                $classic = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-07-01" `
                    -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop
                $evidence["Sub_${subId}_ClassicAdmins"] = $classic.value.Count
                if ($classic.value.Count -gt 0) {
                    $allDangerous += $classic.value | ForEach-Object {
                        [PSCustomObject]@{
                            SubscriptionId = $subId; RoleName = "Classic-$($_.properties.role)"
                            PrincipalType  = "Classic"; PrincipalId = $_.properties.emailAddress; Scope = "Subscription"; IsCritical = $true
                        }
                    }
                }
            } catch {}
        }

        $criticalCount = ($allDangerous | Where-Object { $_.IsCritical }).Count
        $evidence["DangerousAssignments"] = $allDangerous
        $evidence["CriticalCount"]        = $criticalCount

        $status = if ($criticalCount -gt 0) { "FAIL" } elseif ($allDangerous.Count -gt 5) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "AZ-01" -Phase "Phase 7 - Azure Resources" -Name "Azure RBAC Dangerous Assignments" `
            -Severity "Critical" -Status $status `
            -Description "Enumerates dangerous Azure RBAC role assignments (Owner, User Access Administrator) directly assigned to users at subscription scope. These bypass PIM JIT controls." `
            -AttackTechnique "Enumerate role assignments. Direct Owner = full subscription control including creating backdoor SPs, reading all secrets, modifying all resources." `
            -Result "$($allDangerous.Count) dangerous RBAC assignments found. $criticalCount CRITICAL (direct user Owner/UAA at subscription scope)." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Remove permanent Owner role for individual users - use PIM eligible assignments instead. 2) Remove all classic administrator assignments. 3) Use groups for role assignments, not direct user assignments. 4) Apply least-privilege roles (Contributor instead of Owner where possible)." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-01" -Phase "Phase 7 - Azure Resources" -Name "Azure RBAC Dangerous Assignments" `
            -Severity "Critical" -Status "ERROR" -Description "Error enumerating RBAC" `
            -AttackTechnique "ARM role assignment enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-AZ02-ManagedIdentityRisks {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-02] Managed Identity Over-Privilege Check" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-02" -Phase "Phase 7 - Azure Resources" -Name "Managed Identity Over-Privilege" `
            -Severity "Critical" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Compromise VM, call IMDS 169.254.169.254, get managed identity token, abuse subscription-level permissions" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $riskyIdentities = @()

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 3)) {
            # Find VMs with managed identities
            try {
                $vms = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01&`$select=id,name,identity" `
                    -Headers $armHeaders -TimeoutSec 20 -ErrorAction Stop

                $vmsWithMI = $vms.value | Where-Object { $_.identity -and $_.identity.type -ne "None" }
                $evidence["Sub_${subId}_VMsWithManagedIdentity"] = $vmsWithMI.Count

                foreach ($vm in $vmsWithMI | Select-Object -First 5) {
                    # Get role assignments for this VM's managed identity
                    $principalId = $vm.identity.principalId ?? ($vm.identity.userAssignedIdentities.Values | Select-Object -First 1).principalId
                    if (-not $principalId) { continue }

                    try {
                        $miRoles = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$principalId'" `
                            -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop

                        $dangerousRoles = @("8e3af657-a8ff-443c-a75c-2fe8c4bcb635","b24988ac-6180-42a0-ab88-20f7382dd24c","18d7d88d-d35e-4fb5-a5c3-7773c20a72d9") # Owner, Contributor, UAA
                        $dangerousMIRoles = $miRoles.value | Where-Object { $_.properties.roleDefinitionId -match ($dangerousRoles -join "|") }

                        if ($dangerousMIRoles.Count -gt 0) {
                            $riskyIdentities += [PSCustomObject]@{
                                VMName       = $vm.name
                                PrincipalId  = $principalId
                                IdentityType = $vm.identity.type
                                DangerousRoleCount = $dangerousMIRoles.Count
                                Scopes       = $dangerousMIRoles.properties.scope -join "; "
                            }
                            Write-EntraLog "    [!] VM $($vm.name) has dangerous managed identity roles!" -Level Warn
                        }
                    } catch {}
                }
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["RiskyManagedIdentities"]  = $riskyIdentities
        $evidence["IMDSNote"] = "IMDS (169.254.169.254) endpoint is only accessible from within Azure VMs. From a compromised VM: curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata:true'"
        $status = if ($riskyIdentities.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "AZ-02" -Phase "Phase 7 - Azure Resources" -Name "Managed Identity Over-Privilege" `
            -Severity "Critical" -Status $status `
            -Description "Identifies Azure VMs whose managed identities have dangerous subscription-level RBAC roles. From a compromised VM, an attacker calls IMDS to get a token and abuses these roles." `
            -AttackTechnique "Compromise VM via RCE/SSRF. Call http://169.254.169.254/metadata/identity/oauth2/token. Get managed identity access token. Use token with ARM API to enumerate/modify subscription resources." `
            -Result "$($riskyIdentities.Count) VMs with over-privileged managed identities found." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Apply least privilege to managed identity role assignments. 2) Never assign Owner or Contributor at subscription scope to a managed identity unless absolutely required. 3) Prefer User-Assigned Managed Identities for better lifecycle control. 4) Enable Defender for Servers to detect IMDS abuse." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/managed-identities-faq" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-02" -Phase "Phase 7 - Azure Resources" -Name "Managed Identity Over-Privilege" `
            -Severity "Critical" -Status "ERROR" -Description "Error checking managed identities" `
            -AttackTechnique "ARM VM and RBAC enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-AZ03-AutomationAccountAudit {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-03] Automation Account Security Audit" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-03" -Phase "Phase 7 - Azure Resources" -Name "Automation Account Audit" `
            -Severity "High" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Find RunAs accounts with over-privileged SP creds, or hardcoded secrets in runbooks" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $allIssues  = @()

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 3)) {
            try {
                $automationAccounts = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                $evidence["Sub_${subId}_AutomationAccounts"] = $automationAccounts.value.Count

                foreach ($account in $automationAccounts.value | Select-Object -First 3) {
                    $rg   = ($account.id -split "/resourceGroups/")[1].Split("/")[0]
                    $name = $account.name
                    Write-EntraLog "    Auditing Automation Account: $name" -Level Info

                    # Check for RunAs accounts (legacy - deprecated but still exist)
                    try {
                        $connections = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$name/connections?api-version=2023-11-01" `
                            -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop
                        $runAsConns = $connections.value | Where-Object { $_.properties.connectionType.name -eq "AzureServicePrincipal" }
                        if ($runAsConns.Count -gt 0) {
                            $allIssues += "CRITICAL: Automation Account '$name' has legacy RunAs account (SP credentials stored in Azure). Deprecated and should be replaced with Managed Identity."
                            $evidence["${name}_RunAsAccounts"] = $runAsConns.Count
                        }
                    } catch {}

                    # List runbooks and check content for credential patterns
                    try {
                        $runbooks = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$name/runbooks?api-version=2023-11-01" `
                            -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop
                        $evidence["${name}_RunbookCount"] = $runbooks.value.Count

                        $credentialPatterns = @("password\s*=","secret\s*=","-Password\s","ApiKey\s*=","ConnectionString\s*=","pwd\s*=","clientSecret\s*=")
                        foreach ($rb in $runbooks.value | Select-Object -First 5) {
                            try {
                                $content = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$name/runbooks/$($rb.name)/content?api-version=2023-11-01" `
                                    -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop
                                $contentStr = [string]$content
                                $hits = $credentialPatterns | Where-Object { $contentStr -match $_ }
                                if ($hits.Count -gt 0) {
                                    $allIssues += "HIGH: Runbook '$($rb.name)' in '$name' contains credential-like patterns: $($hits -join ', ')"
                                }
                            } catch {}
                        }
                    } catch {}
                }
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["Issues"] = $allIssues
        $criticalIssues = $allIssues | Where-Object { $_ -match "CRITICAL" }
        $status = if ($criticalIssues.Count -gt 0) { "FAIL" } elseif ($allIssues.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "AZ-03" -Phase "Phase 7 - Azure Resources" -Name "Automation Account Audit" `
            -Severity "High" -Status $status `
            -Description "Audits Azure Automation Accounts for legacy RunAs accounts (over-privileged SPs) and hardcoded credentials in runbook code." `
            -AttackTechnique "Find RunAs account SP credentials or hardcoded creds in runbook content. Automation accounts often have Contributor/Owner at subscription level." `
            -Result "$($allIssues.Count) issues found. $($criticalIssues.Count) critical." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Migrate all RunAs accounts to System-Assigned Managed Identities. 2) Never hardcode credentials in runbooks - use Azure Key Vault or Automation encrypted variables. 3) Review runbook permissions - apply least privilege." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/automation/migrate-run-as-accounts-managed-identity" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-03" -Phase "Phase 7 - Azure Resources" -Name "Automation Account Audit" `
            -Severity "High" -Status "ERROR" -Description "Error auditing automation accounts" `
            -AttackTechnique "ARM automation account enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-AZ04-ResourceLockValidation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-04] Resource Lock Validation" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-04" -Phase "Phase 7 - Azure Resources" -Name "Resource Lock Validation" `
            -Severity "Medium" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Delete critical resources without lock protection - ransomware/sabotage" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}
        $unlockedCritical = @()

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 2)) {
            # Get all locks
            try {
                $locks = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/locks?api-version=2020-05-01" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop
                $evidence["Sub_${subId}_LocksCount"] = $locks.value.Count
                $evidence["Sub_${subId}_LockTypes"] = $locks.value | Group-Object { $_.properties.level } | Select-Object Name, Count

                # Get critical resource types
                $criticalTypes = @("Microsoft.KeyVault/vaults","Microsoft.Storage/storageAccounts","Microsoft.Sql/servers","Microsoft.RecoveryServices/vaults")
                foreach ($resourceType in $criticalTypes) {
                    $resources = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resources?`$filter=resourceType eq '$resourceType'&api-version=2021-04-01" `
                        -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop

                    foreach ($resource in $resources.value | Select-Object -First 5) {
                        $resourceLock = $locks.value | Where-Object { $resource.id -like "$($_.id -replace '/providers/Microsoft.Authorization/locks/.*','')*" }
                        if (-not $resourceLock) {
                            $unlockedCritical += [PSCustomObject]@{
                                ResourceName = $resource.name
                                ResourceType = $resource.type
                                ResourceGroup = ($resource.id -split "/resourceGroups/")[1].Split("/")[0]
                                HasLock = $false
                            }
                        }
                    }
                }
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["UnlockedCriticalResources"] = $unlockedCritical | Select-Object -First 20
        $status = if ($unlockedCritical.Count -gt 10) { "FAIL" } elseif ($unlockedCritical.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "AZ-04" -Phase "Phase 7 - Azure Resources" -Name "Resource Lock Validation" `
            -Severity "Medium" -Status $status `
            -Description "Checks if critical resources (Key Vaults, Storage Accounts, SQL Servers, Recovery Vaults) have delete locks applied. Without locks, an attacker with Contributor can delete them." `
            -AttackTechnique "Attacker with Contributor role deletes Key Vaults, storage accounts, or backup vaults - causes data loss and business disruption even without Owner-level access." `
            -Result "$($unlockedCritical.Count) critical resources without delete locks." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "Apply CanNotDelete or ReadOnly locks to all production critical resources (Key Vaults, Storage, SQL, Recovery Vaults). Use Azure Policy to enforce locks are applied." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-04" -Phase "Phase 7 - Azure Resources" -Name "Resource Lock Validation" `
            -Severity "Medium" -Status "ERROR" -Description "Error checking resource locks" `
            -AttackTechnique "ARM lock enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-AZ05-PolicyComplianceCheck {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-05] Azure Policy Compliance Check" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-05" -Phase "Phase 7 - Azure Resources" -Name "Policy Compliance" `
            -Severity "High" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Non-compliant resources = security controls bypassed or missing" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/policy/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}

        foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 2)) {
            try {
                # Get policy summary
                $summary = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&`$top=5" `
                    -Method POST -Headers $armHeaders -ContentType "application/json" -Body "{}" -TimeoutSec 20 -ErrorAction Stop

                $totalAssessments    = $summary.value[0].results.resourceDetails.Count
                $nonCompliantCount   = ($summary.value[0].results.resourceDetails | Where-Object { $_.complianceState -eq "NonCompliant" }).Count
                $compliancePercent   = if ($totalAssessments -gt 0) { [Math]::Round(100 - ($nonCompliantCount / $totalAssessments * 100), 1) } else { 100 }

                $evidence["Sub_${subId}_CompliancePercent"] = $compliancePercent
                $evidence["Sub_${subId}_NonCompliantCount"] = $nonCompliantCount
                $evidence["Sub_${subId}_PolicySummary"]     = @{
                    TotalAssessed   = $totalAssessments
                    NonCompliant    = $nonCompliantCount
                    CompliancePct   = $compliancePercent
                }

                # Get policy assignments to check security baselines
                $assignments = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                $securityPolicies = $assignments.value | Where-Object {
                    $_.properties.displayName -match "Security|CIS|NIST|ISO|Azure Defender|Defender|Microsoft Cloud|Benchmark"
                }
                $evidence["Sub_${subId}_SecurityPolicyAssignments"] = $securityPolicies | Select-Object -ExpandProperty properties | Select-Object displayName | Select-Object -First 10

            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $lowestCompliance = ($evidence.Keys | Where-Object { $_ -match "CompliancePercent" } | ForEach-Object { $evidence[$_] } | Measure-Object -Minimum).Minimum
        $noSecurityPolicies = -not ($evidence.Keys | Where-Object { $_ -match "SecurityPolicyAssignments" })
        $status = if ($lowestCompliance -lt 70) { "FAIL" } elseif ($lowestCompliance -lt 85 -or $noSecurityPolicies) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "AZ-05" -Phase "Phase 7 - Azure Resources" -Name "Policy Compliance" `
            -Severity "High" -Status $status `
            -Description "Checks Azure Policy compliance percentage and verifies security baseline policies are assigned. Low compliance = security controls are not enforced across resources." `
            -AttackTechnique "Non-compliant resources often have disabled logging, open network rules, weak encryption - each is a potential attack vector" `
            -Result "Lowest subscription compliance: $lowestCompliance%. Security baseline policies assigned: $(if ($noSecurityPolicies) { 'NO' } else { 'YES' })" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Assign Microsoft Cloud Security Benchmark initiative to all subscriptions. 2) Target >90% compliance. 3) Use Azure Policy Remediation tasks to auto-fix non-compliant resources. 4) Set up email alerts for compliance drops." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-05" -Phase "Phase 7 - Azure Resources" -Name "Policy Compliance" `
            -Severity "High" -Status "ERROR" -Description "Error checking policy compliance" `
            -AttackTechnique "ARM policy insights API" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/policy/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-AZ06-ManagementGroupEscalation {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [AZ-06] Management Group Scope Escalation Check" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "AZ-06" -Phase "Phase 7 - Azure Resources" -Name "Management Group Escalation" `
            -Severity "High" -Status "SKIPPED" -Description "ARM token required" `
            -AttackTechnique "Owner at management group scope = Owner on ALL subscriptions in the group" `
            -Result "SKIPPED" -Evidence "" `
            -Remediation "Authenticate with ARM scope" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
        $evidence   = [ordered]@{}

        $mgGroups = Invoke-RestMethod -Uri "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-05-01" `
            -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

        $evidence["ManagementGroupCount"] = $mgGroups.value.Count

        $mgRoleIssues = @()
        foreach ($mg in $mgGroups.value | Select-Object -First 5) {
            try {
                $mgRoles = Invoke-RestMethod -Uri "https://management.azure.com$($mg.id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" `
                    -Headers $armHeaders -TimeoutSec 10 -ErrorAction Stop

                $dangerousAtMG = $mgRoles.value | Where-Object {
                    $_.properties.roleDefinitionId -match "8e3af657|18d7d88d" -and   # Owner or UAA
                    $_.properties.principalType -eq "User"
                }

                if ($dangerousAtMG.Count -gt 0) {
                    $mgRoleIssues += [PSCustomObject]@{
                        ManagementGroup = $mg.displayName
                        DangerousAssignments = $dangerousAtMG.Count
                        PrincipalIds = $dangerousAtMG.properties.principalId -join "; "
                    }
                }

                $evidence["MG_$($mg.displayName)_Assignments"] = $mgRoles.value.Count
            } catch { $evidence["MG_$($mg.displayName)_Error"] = "Access denied or error" }
        }

        $evidence["DangerousManagementGroupAssignments"] = $mgRoleIssues
        $status = if ($mgRoleIssues.Count -gt 0) { "FAIL" } elseif ($mgGroups.value.Count -gt 0) { "PASS" } else { "INFO" }

        return New-TestResult -TestId "AZ-06" -Phase "Phase 7 - Azure Resources" -Name "Management Group Escalation" `
            -Severity "High" -Status $status `
            -Description "Checks for dangerous RBAC assignments at Management Group scope. A single Owner assignment at MG scope grants Owner on ALL subscriptions within it." `
            -AttackTechnique "Find user with Owner at Management Group scope. This equals Owner across potentially dozens of subscriptions - worst case blast radius." `
            -Result "$($mgGroups.value.Count) management group(s). $($mgRoleIssues.Count) with dangerous direct user assignments." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Minimize role assignments at management group scope. 2) Use PIM for eligible MG-level assignments. 3) Reserve Owner at MG scope for break-glass only. 4) Prefer group-based assignments with tight membership controls." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "AZ-06" -Phase "Phase 7 - Azure Resources" -Name "Management Group Escalation" `
            -Severity "High" -Status "ERROR" -Description "Error checking management groups" `
            -AttackTechnique "ARM management group role assignment enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/governance/management-groups/overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase7 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 7 - Azure Resource Attacks       " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-AZ01-RBACEnumeration
    $phaseResults += Invoke-AZ02-ManagedIdentityRisks
    $phaseResults += Invoke-AZ03-AutomationAccountAudit
    $phaseResults += Invoke-AZ04-ResourceLockValidation
    $phaseResults += Invoke-AZ05-PolicyComplianceCheck
    $phaseResults += Invoke-AZ06-ManagementGroupEscalation

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 7 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
