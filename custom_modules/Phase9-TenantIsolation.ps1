<#
.SYNOPSIS
    EntraScope Phase 9: Custom Modules - B2B Tenant Isolation Bypass
.DESCRIPTION
    Tests for cross-tenant data leakage and guest user enumeration vulnerabilities.
#>

Write-Host "`n[+] Starting Phase 9: Custom Modules (B2B Tenant Isolation)" -ForegroundColor Cyan

function Invoke-CUST01-GuestUserEnumeration {
    Write-EntraLog "Running CUST-01: Guest User Enumeration Restrictions..." -Level Info
    $start = Get-Date

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Check authorizationPolicy for guestUserRoleId
        $policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $evidence["GuestUserRoleId"] = $policy.guestUserRoleId
        
        # guestUserRoleId map:
        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest users have same access as members (Vulnerable)
        # 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest users have limited access (Default/Okay)
        # 2db81185-e46c-4002-856e-005fa52280d1 = Guest user access is restricted to properties and memberships of their own directory objects (Most Secure)

        $status = "PASS"
        $severity = "Low"
        $desc = "Guest users have limited access to enumerate the directory."
        
        if ($policy.guestUserRoleId -eq "10dae51f-b6af-4016-8d66-8c2a99b929b3") {
            $status = "FAIL"
            $severity = "High"
            $desc = "Guest users have the same access as members. A compromised guest account can enumerate all users, groups, and apps in the tenant."
        } elseif ($policy.guestUserRoleId -eq "2af84b1e-32c8-42b7-82bc-daa82404023b") {
            $status = "WARNING"
            $severity = "Medium"
            $desc = "Guest users have limited access. They can still see all users and some group memberships. Consider restricting fully."
        }

        return New-TestResult -TestId "CUST-01" -Phase "Phase 9 - Custom Modules" -Name "Guest User Enumeration" `
            -Severity $severity -Status $status -Description $desc `
            -AttackTechnique "Adversaries can use a compromised B2B guest account to perform full directory reconnaissance if guest access is not restricted." `
            -Result "GuestUserRoleId: $($policy.guestUserRoleId)" -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "Update the External collaboration settings to 'Guest user access is restricted to properties and memberships of their own directory objects'." `
            -MSDocsLink "https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "CUST-01" -Phase "Phase 9 - Custom Modules" -Name "Guest User Enumeration" `
            -Severity "Medium" -Status "ERROR" -Description "Failed to check guest access settings." `
            -AttackTechnique "N/A" -Result $_.Exception.Message -Evidence "" -Remediation "" -MSDocsLink "" -Duration "0s"
    }
}

function Invoke-CUST02-CrossTenantAccessSettings {
    Write-EntraLog "Running CUST-02: Cross-Tenant Access Policy..." -Level Info
    $start = Get-Date

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        $crossTenant = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default" `
            -Headers $headers -TimeoutSec 15 -ErrorAction Stop

        $inboundState = $crossTenant.b2bCollaborationInbound.usersAndGroups.accessType
        $outboundState = $crossTenant.b2bCollaborationOutbound.usersAndGroups.accessType

        $evidence["B2B_Inbound_Default"] = $inboundState
        $evidence["B2B_Outbound_Default"] = $outboundState

        if ($inboundState -eq "allowed" -and $outboundState -eq "allowed") {
            $status = "WARNING"
            $desc = "Both Inbound and Outbound B2B collaboration are allowed by default for all external tenants. This increases the attack surface for cross-tenant lateral movement."
        } else {
            $status = "PASS"
            $desc = "Cross-tenant access defaults have been hardened to restrict inbound or outbound collaboration."
        }

        return New-TestResult -TestId "CUST-02" -Phase "Phase 9 - Custom Modules" -Name "Cross-Tenant B2B Defaults" `
            -Severity "Medium" -Status $status -Description $desc `
            -AttackTechnique "If a user is phished, attackers can invite them into a malicious attacker-controlled tenant if outbound B2B is allowed." `
            -Result "Inbound: $inboundState | Outbound: $outboundState" -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "Configure Cross-tenant access settings to block inbound/outbound access by default, and explicitly allow only trusted partner tenants." `
            -MSDocsLink "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "CUST-02" -Phase "Phase 9 - Custom Modules" -Name "Cross-Tenant B2B Defaults" `
            -Severity "Medium" -Status "ERROR" -Description "Failed to check cross-tenant settings." `
            -AttackTechnique "N/A" -Result $_.Exception.Message -Evidence "" -Remediation "" -MSDocsLink "" -Duration "0s"
    }
}

function Invoke-Phase9 {
    $results = @()
    $results += Invoke-CUST01-GuestUserEnumeration
    $results += Invoke-CUST02-CrossTenantAccessSettings
    return $results
}
