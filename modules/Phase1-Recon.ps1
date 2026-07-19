#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 1 - Unauthenticated External Reconnaissance
.DESCRIPTION
    Performs reconnaissance against Azure/Entra ID tenant using ONLY
    publicly accessible endpoints. No credentials required.
    AUTHORIZED USE ONLY - Run only against tenants you own or have written permission to test.
#>

function Invoke-RECON01-TenantDiscovery {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-01] Tenant Discovery via OpenID Configuration" -Level Attack

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-01" -Phase "Phase 1 - Unauthenticated Recon" -Name "Tenant Discovery" `
            -Severity "Info" -Status "INFO" -Description "Would query OpenID config endpoint to discover tenant metadata" `
            -AttackTechnique "GET https://login.microsoftonline.com/{domain}/.well-known/openid-configuration" `
            -Result "DRY RUN - No request made" -Evidence "" -Remediation "None - informational only" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $domain = $script:Config.TenantDomain
        $url = "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        Write-EntraLog "    GET $url" -Level Info
        $response = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 15 -ErrorAction Stop

        $tenantId = $response.issuer -replace "https://sts.windows.net/","" -replace "/",""
        if (-not $script:Config.TenantId -and $tenantId) {
            $script:Config.TenantId = $tenantId
            Write-EntraLog "    [+] Auto-populated TenantId: $tenantId" -Level Success
        }

        $evidence = [ordered]@{
            TenantId        = $tenantId
            Issuer          = $response.issuer
            AuthEndpoint    = $response.authorization_endpoint
            TokenEndpoint   = $response.token_endpoint
            DeviceAuthEndpoint = $response.device_authorization_endpoint
            SupportedScopes = $response.scopes_supported -join ", "
        }

        return New-TestResult -TestId "RECON-01" -Phase "Phase 1 - Unauthenticated Recon" -Name "Tenant Discovery" `
            -Severity "Info" -Status "INFO" `
            -Description "Enumerates publicly available tenant metadata from the OpenID Connect configuration endpoint." `
            -AttackTechnique "GET $url" `
            -Result "Tenant ID resolved: $tenantId. All standard OIDC metadata is publicly accessible." `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "None - this information is by design public. Ensure tenant ID alone cannot enable further attacks." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "RECON-01" -Phase "Phase 1 - Unauthenticated Recon" -Name "Tenant Discovery" `
            -Severity "Info" -Status "ERROR" -Description "Tenant discovery failed" `
            -AttackTechnique "GET OpenID config endpoint" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-RECON02-HomeRealmDiscovery {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-02] Home Realm Discovery (HRD)" -Level Attack

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-02" -Phase "Phase 1 - Unauthenticated Recon" -Name "Home Realm Discovery" `
            -Severity "Medium" -Status "INFO" -Description "Would query GetCredentialType to determine federation type" `
            -AttackTechnique "POST /common/GetCredentialType" -Result "DRY RUN" -Evidence "" `
            -Remediation "Consider enabling HRD obfuscation" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $domain = $script:Config.TenantDomain
        $url = "https://login.microsoftonline.com/common/GetCredentialType"
        $body = @{ username = "admin@$domain"; isOtherIdpSupported = $true } | ConvertTo-Json
        Write-EntraLog "    POST $url for admin@$domain" -Level Info

        $response = Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/json" -TimeoutSec 15 -ErrorAction Stop

        $namespaceType = $response.EstsProperties.UserTenantBranding.NameSpaceType
        $isFederated   = $response.EstsProperties.UserTenantBranding.DomainType -eq "Federated" -or $namespaceType -eq "Federated"
        $authUrl       = $response.Credentials.FederationRedirectUrl

        $status    = if ($isFederated) { "WARNING" } else { "PASS" }
        $severity  = if ($isFederated) { "Medium" } else { "Info" }
        $resultMsg = if ($isFederated) {
            "FEDERATED tenant detected. Federation URL: $authUrl. Exposes ADFS infrastructure details."
        } else {
            "MANAGED (cloud-only) tenant. No federation exposure."
        }

        $evidence = [ordered]@{
            NameSpaceType        = $namespaceType
            IsFederated          = $isFederated
            FederationRedirectUrl = $authUrl
            DomainType           = $response.EstsProperties.UserTenantBranding.DomainType
            ThrottleStatus       = $response.ThrottleStatus
        }

        return New-TestResult -TestId "RECON-02" -Phase "Phase 1 - Unauthenticated Recon" -Name "Home Realm Discovery" `
            -Severity $severity -Status $status `
            -Description "Determines if tenant is Managed (cloud-only) or Federated (on-prem ADFS). Federated tenants expose additional infrastructure." `
            -AttackTechnique "POST $url with target email - returns namespace type without authentication" `
            -Result $resultMsg -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "If federated, ensure ADFS servers are hardened and metadata endpoint is locked down. Consider migrating to Pass-Through Auth or Password Hash Sync." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "RECON-02" -Phase "Phase 1 - Unauthenticated Recon" -Name "Home Realm Discovery" `
            -Severity "Medium" -Status "ERROR" -Description "HRD query failed" `
            -AttackTechnique "POST /common/GetCredentialType" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-RECON03-UserExistenceEnumeration {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-03] User Existence Enumeration via GetCredentialType" -Level Attack

    $domain = $script:Config.TenantDomain
    $testUsers = @(
        @{ UPN = "admin@$domain";               Type = "AdminPattern" }
        @{ UPN = "administrator@$domain";        Type = "AdminPattern" }
        @{ UPN = "nonexistent99887766@$domain";  Type = "ShouldNotExist" }
    )
    if ($script:Config.HoneypotAccounts -and $script:Config.HoneypotAccounts.Count -gt 0) {
        $testUsers += @{ UPN = $script:Config.HoneypotAccounts[0].UPN; Type = "KnownExisting" }
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-03" -Phase "Phase 1 - Unauthenticated Recon" -Name "User Existence Enumeration" `
            -Severity "High" -Status "INFO" -Description "Would test UPN enumeration via GetCredentialType" `
            -AttackTechnique "POST /common/GetCredentialType for multiple UPNs, compare IfExistsResult codes" `
            -Result "DRY RUN" -Evidence "" `
            -Remediation "Results vary — see full run" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $url = "https://login.microsoftonline.com/common/GetCredentialType"
    $results = @{}

    foreach ($user in $testUsers) {
        try {
            $body = @{ username = $user.UPN; isOtherIdpSupported = $true } | ConvertTo-Json
            $response = Invoke-RestMethod -Uri $url -Method POST -Body $body -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
            $results[$user.UPN] = @{
                Type          = $user.Type
                IfExistsResult = $response.IfExistsResult
                # 0=exists, 1=not found, 5=exists no MFA, 6=exists with MFA
                ThrottleStatus = $response.ThrottleStatus
            }
            Write-EntraLog "    $($user.UPN) -> IfExistsResult: $($response.IfExistsResult)" -Level Info
            Start-Sleep -Milliseconds $script:Config.Options.RateLimitMs
        }
        catch {
            $results[$user.UPN] = @{ Type = $user.Type; Error = $_.Exception.Message }
        }
    }

    # Analyze: do responses differ between existing and non-existing?
    $existingCodes     = $results.Values | Where-Object { $_.Type -eq "KnownExisting" } | Select-Object -ExpandProperty IfExistsResult
    $nonExistentCodes  = $results.Values | Where-Object { $_.Type -eq "ShouldNotExist" } | Select-Object -ExpandProperty IfExistsResult
    $leaksExistence    = ($existingCodes -ne $null) -and ($nonExistentCodes -ne $null) -and ($existingCodes -ne $nonExistentCodes)

    $status    = if ($leaksExistence) { "FAIL" } else { "PASS" }
    $severity  = "High"
    $resultMsg = if ($leaksExistence) {
        "TENANT LEAKS USER EXISTENCE. Existing users return IfExistsResult=$existingCodes, non-existing return IfExistsResult=$nonExistentCodes. Attackers can enumerate valid accounts."
    } else {
        "Responses are consistent — user existence cannot be reliably determined from this endpoint alone."
    }

    return New-TestResult -TestId "RECON-03" -Phase "Phase 1 - Unauthenticated Recon" -Name "User Existence Enumeration" `
        -Severity $severity -Status $status `
        -Description "Tests whether the Microsoft login endpoint leaks user existence via different response codes for valid vs invalid accounts." `
        -AttackTechnique "POST $url with multiple UPNs - compare IfExistsResult field (0=exists, 1=not found, 5/6=exists+MFA state)" `
        -Result $resultMsg -Evidence ($results | ConvertTo-Json -Depth 3) `
        -Remediation "Microsoft does not consider this a vulnerability. Mitigate by enabling Smart Lockout to prevent follow-on password spray, and enforce MFA so enumerated accounts cannot be brute forced." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-smart-lockout" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-RECON04-FederationMetadata {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-04] Federation Metadata Exposure Check" -Level Attack

    $domain = $script:Config.TenantDomain

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-04" -Phase "Phase 1 - Unauthenticated Recon" -Name "Federation Metadata Exposure" `
            -Severity "Medium" -Status "INFO" -Description "Would probe ADFS metadata endpoints if tenant is federated" `
            -AttackTechnique "GET /FederationMetadata/2007-06/FederationMetadata.xml" -Result "DRY RUN" -Evidence "" `
            -Remediation "Restrict federation metadata endpoint access" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $probeTargets = @(
        "https://adfs.$domain/FederationMetadata/2007-06/FederationMetadata.xml"
        "https://sts.$domain/FederationMetadata/2007-06/FederationMetadata.xml"
        "https://fs.$domain/FederationMetadata/2007-06/FederationMetadata.xml"
        "https://adfs.$domain/adfs/ls/idpinitiatedsignon.aspx"
    )

    $findings = @()
    $anyExposed = $false

    foreach ($target in $probeTargets) {
        try {
            Write-EntraLog "    Probing: $target" -Level Info
            $resp = Invoke-WebRequest -Uri $target -TimeoutSec 8 -ErrorAction Stop -SkipCertificateCheck
            if ($resp.StatusCode -eq 200) {
                $anyExposed = $true
                $serverHeader = $resp.Headers["Server"]
                $findings += [PSCustomObject]@{ URL = $target; StatusCode = 200; Server = $serverHeader; Exposed = $true }
                Write-EntraLog "    [!] EXPOSED: $target (Server: $serverHeader)" -Level Warn
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $findings += [PSCustomObject]@{ URL = $target; StatusCode = $statusCode; Server = "N/A"; Exposed = $false }
        }
    }

    $status   = if ($anyExposed) { "FAIL" } else { "PASS" }
    $severity = "Medium"

    return New-TestResult -TestId "RECON-04" -Phase "Phase 1 - Unauthenticated Recon" -Name "Federation Metadata Exposure" `
        -Severity $severity -Status $status `
        -Description "Checks if ADFS federation metadata XML is publicly accessible, which exposes server version and configuration." `
        -AttackTechnique "GET common ADFS metadata paths on known subdomains" `
        -Result $(if ($anyExposed) { "Federation metadata endpoint(s) publicly accessible. Exposes ADFS version and token signing certificates." } else { "No accessible federation metadata endpoints found on common subdomains." }) `
        -Evidence ($findings | ConvertTo-Json) `
        -Remediation "Restrict /FederationMetadata access to known IP ranges. Update ADFS servers to latest version. Consider migrating from ADFS to Entra ID native auth." `
        -MSDocsLink "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-RECON05-AutodiscoverDomains {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-05] Autodiscover Domain Mapping" -Level Attack

    $domain = $script:Config.TenantDomain

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-05" -Phase "Phase 1 - Unauthenticated Recon" -Name "Autodiscover Domain Mapping" `
            -Severity "Info" -Status "INFO" -Description "Would query Autodiscover to map email routing" `
            -AttackTechnique "GET Autodiscover JSON endpoints" -Result "DRY RUN" -Evidence "" `
            -Remediation "None - informational" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $urls = @(
        "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/$domain"
        "https://outlook.office365.com/autodiscover/autodiscover.json?Email=test@$domain&Protocol=Autodiscoverv1"
    )

    $findings = @{}
    foreach ($url in $urls) {
        try {
            Write-EntraLog "    GET $url" -Level Info
            $resp = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop
            $findings[$url] = $resp
        }
        catch {
            $findings[$url] = "HTTP $([int]$_.Exception.Response.StatusCode) - $($_.Exception.Message)"
        }
    }

    return New-TestResult -TestId "RECON-05" -Phase "Phase 1 - Unauthenticated Recon" -Name "Autodiscover Domain Mapping" `
        -Severity "Info" -Status "INFO" `
        -Description "Queries Autodiscover endpoints to map M365 service configuration and additional domains." `
        -AttackTechnique "GET Autodiscover JSON API - reveals email hosting, protocols, EWS endpoints" `
        -Result "Autodiscover data collected. Review evidence for service exposure details." `
        -Evidence ($findings | ConvertTo-Json -Depth 4) `
        -Remediation "None required. Autodiscover is a necessary service. Ensure EWS is not unnecessarily exposed if unused." `
        -MSDocsLink "https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-RECON06-DanglingDNS {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-06] Azure Subdomain Dangling DNS Check" -Level Attack

    $domain    = $script:Config.TenantDomain
    $orgName   = $domain.Split(".")[0]
    $subdomains = @(
        "$orgName.azurewebsites.net"
        "$orgName-dev.azurewebsites.net"
        "$orgName-prod.azurewebsites.net"
        "$orgName-staging.azurewebsites.net"
        "$orgName.blob.core.windows.net"
        "$orgName.azurefd.net"
        "$orgName.trafficmanager.net"
        "$orgName.azurecontainer.io"
        "www.$domain.azurewebsites.net"
    )

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-06" -Phase "Phase 1 - Unauthenticated Recon" -Name "Dangling DNS Check" `
            -Severity "High" -Status "INFO" -Description "Would check Azure subdomains for dangling DNS entries" `
            -AttackTechnique "DNS resolution + HTTP probe of common Azure subdomains" -Result "DRY RUN" -Evidence "" `
            -Remediation "Remove DNS records for decommissioned Azure services" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $dangling = @()
    $findings = @()

    foreach ($sub in $subdomains) {
        try {
            $dns = Resolve-DnsName -Name $sub -ErrorAction Stop -Type A
            # DNS resolves — now probe HTTP
            try {
                $http = Invoke-WebRequest -Uri "https://$sub" -TimeoutSec 6 -ErrorAction Stop -SkipCertificateCheck
                $findings += [PSCustomObject]@{ Subdomain = $sub; DNSResolves = $true; HTTPStatus = $http.StatusCode; Dangling = $false }
            }
            catch {
                $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                # DNS resolves but HTTP returns Azure error page = potentially dangling
                if ($statusCode -in @(0,404,503) -or $_.Exception.Message -match "Azure|not found|no site") {
                    $dangling += $sub
                    $findings += [PSCustomObject]@{ Subdomain = $sub; DNSResolves = $true; HTTPStatus = $statusCode; Dangling = $true }
                    Write-EntraLog "    [!] POTENTIALLY DANGLING: $sub" -Level Warn
                } else {
                    $findings += [PSCustomObject]@{ Subdomain = $sub; DNSResolves = $true; HTTPStatus = $statusCode; Dangling = $false }
                }
            }
        }
        catch {
            $findings += [PSCustomObject]@{ Subdomain = $sub; DNSResolves = $false; HTTPStatus = "N/A"; Dangling = $false }
        }
    }

    $status = if ($dangling.Count -gt 0) { "FAIL" } else { "PASS" }

    return New-TestResult -TestId "RECON-06" -Phase "Phase 1 - Unauthenticated Recon" -Name "Dangling DNS / Subdomain Takeover" `
        -Severity "High" -Status $status `
        -Description "Checks for Azure subdomains that resolve in DNS but no longer have a backing Azure resource (subdomain takeover risk)." `
        -AttackTechnique "Resolve common Azure subdomains for your org name, probe HTTP - dangling entries can be claimed by attackers" `
        -Result $(if ($dangling.Count -gt 0) { "DANGLING SUBDOMAINS FOUND: $($dangling -join ', '). These may be claimable by an attacker." } else { "No dangling Azure subdomains detected on common patterns." }) `
        -Evidence ($findings | ConvertTo-Json) `
        -Remediation "Remove DNS records for any Azure resources that have been decommissioned. Use Azure Defender for DNS or third-party tools to monitor for dangling DNS." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-RECON07-PublicBlobStorage {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-07] Public Azure Blob Storage Enumeration" -Level Attack

    $domain  = $script:Config.TenantDomain
    $orgName = $domain.Split(".")[0]

    $storageNames = @(
        $orgName
        "${orgName}data"
        "${orgName}backup"
        "${orgName}files"
        "${orgName}media"
        "${orgName}public"
        "${orgName}assets"
        "${orgName}logs"
        "${orgName}archive"
    )

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-07" -Phase "Phase 1 - Unauthenticated Recon" -Name "Public Blob Storage Enumeration" `
            -Severity "Critical" -Status "INFO" -Description "Would probe common storage account names for public access" `
            -AttackTechnique "GET https://{account}.blob.core.windows.net/?comp=list" -Result "DRY RUN" -Evidence "" `
            -Remediation "Disable public blob access at storage account and subscription level" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $publicBlobs = @()
    $findings    = @()

    foreach ($name in $storageNames) {
        $url = "https://$name.blob.core.windows.net/?comp=list"
        try {
            Write-EntraLog "    Probing: $url" -Level Info
            $resp = Invoke-WebRequest -Uri $url -TimeoutSec 6 -ErrorAction Stop
            if ($resp.StatusCode -eq 200 -and $resp.Content -match "<EnumerationResults") {
                $publicBlobs += $name
                $findings += [PSCustomObject]@{ StorageAccount = $name; Public = $true; StatusCode = 200; Notes = "Container listing accessible!" }
                Write-EntraLog "    [!!!] PUBLIC BLOB CONTAINER LISTING: $name" -Level Warn
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            $findings += [PSCustomObject]@{ StorageAccount = $name; Public = $false; StatusCode = $statusCode; Notes = "" }
        }
    }

    $status = if ($publicBlobs.Count -gt 0) { "FAIL" } else { "PASS" }

    return New-TestResult -TestId "RECON-07" -Phase "Phase 1 - Unauthenticated Recon" -Name "Public Azure Blob Storage" `
        -Severity "Critical" -Status $status `
        -Description "Probes common storage account naming patterns for publicly accessible blob containers." `
        -AttackTechnique "GET https://{orgname-variations}.blob.core.windows.net/?comp=list - no credentials needed for public containers" `
        -Result $(if ($publicBlobs.Count -gt 0) { "PUBLIC BLOB CONTAINERS FOUND: $($publicBlobs -join ', ')" } else { "No publicly accessible blob containers found on $($storageNames.Count) naming patterns." }) `
        -Evidence ($findings | ConvertTo-Json) `
        -Remediation "Set 'Allow Blob public access' to DISABLED at the storage account level. Use Azure Policy to enforce this across subscriptions." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-RECON08-M365ServiceDiscovery {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [RECON-08] M365 Service Discovery via DNS" -Level Attack

    $domain = $script:Config.TenantDomain

    if ($script:DryRun) {
        return New-TestResult -TestId "RECON-08" -Phase "Phase 1 - Unauthenticated Recon" -Name "M365 Service Discovery" `
            -Severity "Info" -Status "INFO" -Description "Would enumerate DNS records to map M365 services" `
            -AttackTechnique "DNS MX, SRV, TXT record enumeration" -Result "DRY RUN" -Evidence "" `
            -Remediation "None - informational" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $dnsFindings = [ordered]@{}

    # MX records
    try {
        $mx = Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue
        $dnsFindings["MX"] = $mx | Select-Object -ExpandProperty NameExchange
    } catch { $dnsFindings["MX"] = "Query failed" }

    # SPF
    try {
        $txt = Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue
        $spf = $txt | Where-Object { $_.Strings -match "v=spf1" } | Select-Object -ExpandProperty Strings
        $dnsFindings["SPF"] = $spf
        $dnsFindings["SPF_HasO365"] = ($spf -match "spf.protection.outlook.com") -as [bool]
    } catch { $dnsFindings["SPF"] = "Query failed" }

    # DMARC
    try {
        $dmarc = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction SilentlyContinue
        $dnsFindings["DMARC"] = ($dmarc | Select-Object -ExpandProperty Strings)
        $dnsFindings["DMARC_Policy"] = if ($dmarc.Strings -match "p=reject") { "reject" } elseif ($dmarc.Strings -match "p=quarantine") { "quarantine" } else { "none/missing" }
    } catch { $dnsFindings["DMARC"] = "Not configured" }

    # DKIM (common selector)
    foreach ($selector in @("selector1", "selector2", "k1")) {
        try {
            $dkim = Resolve-DnsName -Name "$selector._domainkey.$domain" -Type TXT -ErrorAction SilentlyContinue
            if ($dkim) { $dnsFindings["DKIM_$selector"] = $dkim.Strings }
        } catch {}
    }

    # SRV records
    foreach ($srv in @("_sip._tls", "_sipfederationtls._tcp", "_autodiscover._tcp")) {
        try {
            $srvRec = Resolve-DnsName -Name "$srv.$domain" -Type SRV -ErrorAction SilentlyContinue
            if ($srvRec) { $dnsFindings[$srv] = "$($srvRec.NameTarget):$($srvRec.Port)" }
        } catch {}
    }

    $dmarcPolicy  = $dnsFindings["DMARC_Policy"]
    $status       = if ($dmarcPolicy -notin @("reject","quarantine")) { "WARNING" } else { "PASS" }

    return New-TestResult -TestId "RECON-08" -Phase "Phase 1 - Unauthenticated Recon" -Name "M365 Service Discovery" `
        -Severity "Info" -Status $status `
        -Description "Enumerates DNS records to discover M365 service configuration and email security posture." `
        -AttackTechnique "Public DNS queries for MX, SPF, DMARC, DKIM, SRV records — no credentials required" `
        -Result "DNS reconnaissance complete. DMARC policy: $dmarcPolicy. See evidence for full service map." `
        -Evidence ($dnsFindings | ConvertTo-Json) `
        -Remediation "Ensure DMARC is set to 'p=reject', DKIM is configured for all sending domains, SPF is tight (use -all not ~all)." `
        -MSDocsLink "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-Phase1 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 1 - Unauthenticated Recon       " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-RECON01-TenantDiscovery
    $phaseResults += Invoke-RECON02-HomeRealmDiscovery
    $phaseResults += Invoke-RECON03-UserExistenceEnumeration
    $phaseResults += Invoke-RECON04-FederationMetadata
    $phaseResults += Invoke-RECON05-AutodiscoverDomains
    $phaseResults += Invoke-RECON06-DanglingDNS
    $phaseResults += Invoke-RECON07-PublicBlobStorage
    $phaseResults += Invoke-RECON08-M365ServiceDiscovery

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 1 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
