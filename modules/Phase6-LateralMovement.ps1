#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 6 - Lateral Movement Testing
.DESCRIPTION
    Tests what an attacker can access and pivot to after compromising
    a standard user account. AUTHORIZED USE ONLY.
#>

function Invoke-LAT01-GraphAPIPillage {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [LAT-01] Graph API Data Pillage Test" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "LAT-01" -Phase "Phase 6 - Lateral Movement" -Name "Graph API Data Pillage" `
            -Severity "High" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Use compromised user token to read sensitive directory data and other users' resources" `
            -Result "SKIPPED" -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/permissions-reference" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}
        $findings = @()

        # Test 1: Own mailbox (expected to work)
        try {
            $myMail = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=1&`$select=id,subject,from" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $evidence["OwnMailbox"] = @{ Accessible = $true; Count = $myMail.value.Count }
            $findings += "Own mailbox: accessible (expected)"
        } catch { $evidence["OwnMailbox"] = @{ Accessible = $false; Error = $_.Exception.Message } }

        # Test 2: Directory-wide user details (sensitive fields)
        try {
            $allUsers = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=5&`$select=displayName,userPrincipalName,mobilePhone,officeLocation,jobTitle,department,city,manager" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $hasMobile = $allUsers.value | Where-Object { $_.mobilePhone }
            $evidence["DirectoryUserData"] = @{
                Accessible    = $true
                UserCount     = $allUsers.value.Count
                MobilesVisible = $hasMobile.Count
                Sample = $allUsers.value | Select-Object displayName, jobTitle, department | Select-Object -First 3
            }
            if ($hasMobile.Count -gt 0) { $findings += "SENSITIVE: Mobile phone numbers visible to all users" }
        } catch { $evidence["DirectoryUserData"] = @{ Accessible = $false; HTTPCode = [int]$_.Exception.Response.StatusCode } }

        # Test 3: Try another user's mailbox
        $otherUsers = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=5&`$select=id,userPrincipalName&`$filter=userType eq 'Member'" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        $myId = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=id" -Headers $headers -TimeoutSec 5).id
        $otherUser = $otherUsers.value | Where-Object { $_.id -ne $myId } | Select-Object -First 1

        if ($otherUser) {
            try {
                $otherMail = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($otherUser.id)/messages?`$top=1" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
                $evidence["OtherUserMailbox"] = @{ Accessible = $true; TargetUser = $otherUser.userPrincipalName }
                $findings += "CRITICAL: Can read other user's mailbox! User: $($otherUser.userPrincipalName)"
            } catch {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                $evidence["OtherUserMailbox"] = @{ Accessible = $false; HTTPCode = $code; TargetUser = $otherUser.userPrincipalName }
                $findings += "Other user mailbox blocked (HTTP $code) - correct"
            }
        }

        # Test 4: Manager chain / org structure
        try {
            $dirReports = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$top=5&`$expand=manager(`$select=displayName,userPrincipalName)&`$select=displayName,userPrincipalName" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
            $evidence["OrgStructure"] = @{ Accessible = $true; Sample = $dirReports.value | Select-Object displayName, @{N="Manager";E={$_.manager.displayName}} | Select-Object -First 3 }
        } catch { $evidence["OrgStructure"] = @{ Accessible = $false } }

        $criticalFindings = $findings | Where-Object { $_ -match "CRITICAL|SENSITIVE" }
        $status = if ($criticalFindings.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "LAT-01" -Phase "Phase 6 - Lateral Movement" -Name "Graph API Data Pillage" `
            -Severity "High" -Status $status `
            -Description "Tests what sensitive data is accessible via Graph API with a standard user token. Attackers use this to harvest credentials, PII, and org structure for targeted attacks." `
            -AttackTechnique "Use compromised user token to harvest: user mobile numbers, org chart, manager chains, email content - use for spear phishing and credential stuffing" `
            -Result "Accessible data: $($findings -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 5) `
            -Remediation "1) Use Entra ID tenant settings to restrict users from reading other users' full profiles. 2) Remove mobile phone numbers from directory or restrict visibility. 3) Consider restricted user read permissions in authorization policy." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "LAT-01" -Phase "Phase 6 - Lateral Movement" -Name "Graph API Data Pillage" `
            -Severity "High" -Status "ERROR" -Description "Error during data pillage test" `
            -AttackTechnique "Graph API user/mail enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/graph/permissions-reference" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-LAT02-TeamsMessageEnumeration {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [LAT-02] Teams Message Enumeration" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "LAT-02" -Phase "Phase 6 - Lateral Movement" -Name "Teams Message Enumeration" `
            -Severity "Medium" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Read Teams DMs and channel messages from compromised account to find credentials, secrets, or sensitive info" `
            -Result "SKIPPED" -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/microsoftteams/security-compliance-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # List own chats
        try {
            $chats = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/chats?`$select=id,chatType,topic" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
            $evidence["MyChatsCount"] = $chats.value.Count
            $evidence["ChatTypes"]    = ($chats.value | Group-Object chatType | Select-Object Name, Count)

            # Read messages from a chat
            if ($chats.value.Count -gt 0) {
                $firstChat = $chats.value[0]
                try {
                    $messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/chats/$($firstChat.id)/messages?`$top=3&`$select=id,messageType,body,from" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
                    $evidence["ChatMessagesAccessible"] = $true
                    $evidence["SampleMessageCount"] = $messages.value.Count
                } catch { $evidence["ChatMessagesAccessible"] = $false }
            }
        } catch { $evidence["ChatsError"] = $_.Exception.Message }

        # List Teams membership
        try {
            $teams = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/joinedTeams?`$select=id,displayName,visibility" -Headers $headers -TimeoutSec 15 -ErrorAction Stop
            $evidence["JoinedTeamsCount"] = $teams.value.Count
            $evidence["PublicTeams"]      = ($teams.value | Where-Object { $_.visibility -eq "Public" }).Count
            $evidence["TeamsSample"]      = $teams.value | Select-Object displayName, visibility | Select-Object -First 5
        } catch { $evidence["TeamsError"] = $_.Exception.Message }

        # Try to enumerate channels in joined teams and check for sensitive content patterns
        $credentialKeywords = @("password","secret","api key","token","credential","pwd=","pass=","apikey")
        $sensitiveFindings  = @()

        foreach ($team in ($teams.value | Select-Object -First 2)) {
            try {
                $channels = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$($team.id)/channels?`$select=id,displayName" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
                $evidence["Team_$($team.displayName)_Channels"] = $channels.value.Count
                foreach ($channel in $channels.value | Select-Object -First 2) {
                    try {
                        $msgs = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$($team.id)/channels/$($channel.id)/messages?`$top=20&`$select=id,body" -Headers $headers -TimeoutSec 10 -ErrorAction Stop
                        foreach ($msg in $msgs.value) {
                            if ($msg.body.content) {
                                $content = $msg.body.content.ToLower()
                                $hit = $credentialKeywords | Where-Object { $content -match $_ }
                                if ($hit) { $sensitiveFindings += "Team: $($team.displayName), Channel: $($channel.displayName), Keywords: $($hit -join ',')" }
                            }
                        }
                    } catch {}
                }
            } catch {}
        }

        $evidence["SensitiveContentKeywords"] = $sensitiveFindings | Select-Object -First 5
        $status = if ($sensitiveFindings.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "LAT-02" -Phase "Phase 6 - Lateral Movement" -Name "Teams Message Enumeration" `
            -Severity "Medium" -Status $status `
            -Description "Tests accessibility of Teams messages and checks for sensitive content (passwords, API keys) shared in Teams channels - a common data exfiltration source." `
            -AttackTechnique "Enumerate Teams chats and channels with compromised user token. Search for credentials shared in chat (common in dev teams). Use for lateral movement to systems mentioned." `
            -Result "Joined teams: $($teams.value.Count). Sensitive content patterns found in $($sensitiveFindings.Count) channel(s)." `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Train users NOT to share passwords/tokens in Teams. 2) Use Microsoft Purview Communication Compliance to scan for sensitive data patterns. 3) Enable DLP policies for Teams." `
            -MSDocsLink "https://learn.microsoft.com/en-us/microsoftteams/dlp-microsoft-teams" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "LAT-02" -Phase "Phase 6 - Lateral Movement" -Name "Teams Message Enumeration" `
            -Severity "Medium" -Status "ERROR" -Description "Error enumerating Teams" `
            -AttackTechnique "Graph Teams enumeration" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/microsoftteams/security-compliance-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-LAT03-SharePointAccess {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [LAT-03] SharePoint Site Access Enumeration" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "LAT-03" -Phase "Phase 6 - Lateral Movement" -Name "SharePoint Access Enumeration" `
            -Severity "Medium" -Status "SKIPPED" -Description "Graph token required" `
            -AttackTechnique "Enumerate SharePoint sites to find sensitive documents accessible beyond user's role" `
            -Result "SKIPPED" -Evidence "" -Remediation "Authenticate first" `
            -MSDocsLink "https://learn.microsoft.com/en-us/sharepoint/deploy-file-collaboration" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # Search for all sites
        $sites = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites?search=*&`$select=id,displayName,webUrl,isPersonalSite" -Headers $headers -TimeoutSec 20 -ErrorAction Stop
        $evidence["TotalSitesVisible"]  = $sites.value.Count
        $evidence["SitesSample"]        = $sites.value | Where-Object { -not $_.isPersonalSite } | Select-Object displayName, webUrl | Select-Object -First 10

        $personalSites = $sites.value | Where-Object { $_.isPersonalSite }
        $teamSites     = $sites.value | Where-Object { -not $_.isPersonalSite }
        $evidence["PersonalSitesVisible"] = $personalSites.Count
        $evidence["TeamSitesVisible"]     = $teamSites.Count

        # Check for sensitive site names
        $sensitiveSiteNames = @("hr","finance","payroll","executive","board","legal","confidential","salary","acquisition","merger")
        $sensitiveSites     = $teamSites | Where-Object { $name = $_.displayName.ToLower(); $sensitiveSiteNames | Where-Object { $name -match $_ } }
        $evidence["PotentiallySensitiveSites"] = $sensitiveSites | Select-Object displayName, webUrl

        # Check external sharing on a few sites
        $externalSites = @()
        foreach ($site in $teamSites | Select-Object -First 3) {
            try {
                $siteDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)?`$select=sharingCapability" -Headers $headers -TimeoutSec 8 -ErrorAction Stop
                if ($siteDetails.sharingCapability -in @("ExternalUserAndGuestSharing","ExternalUserSharingOnly")) {
                    $externalSites += @{ Site = $site.displayName; SharingLevel = $siteDetails.sharingCapability }
                }
            } catch {}
        }
        $evidence["SitesWithExternalSharing"] = $externalSites

        $issues = @()
        if ($sensitiveSites.Count -gt 0) { $issues += "$($sensitiveSites.Count) potentially sensitive sites (HR/Finance/Legal) accessible" }
        if ($externalSites.Count -gt 0)  { $issues += "$($externalSites.Count) sites have external sharing enabled" }
        if ($personalSites.Count -gt 0)  { $issues += "$($personalSites.Count) OneDrive sites visible via site search" }

        $status = if ($sensitiveSites.Count -gt 0 -or $externalSites.Count -gt 0) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "LAT-03" -Phase "Phase 6 - Lateral Movement" -Name "SharePoint Access Enumeration" `
            -Severity "Medium" -Status $status `
            -Description "Enumerates accessible SharePoint sites and checks for sensitive data exposure. Attackers use compromised accounts to locate financial, HR, and executive documents." `
            -AttackTechnique "GET /sites?search=* to enumerate all sites. Look for HR/Finance/Legal sites. Check external sharing. Download sensitive documents for data exfiltration." `
            -Result "$($sites.value.Count) sites visible. Issues: $($issues -join '; ')" `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Review SharePoint site permissions regularly. 2) Restrict external sharing at tenant level and per site. 3) Use Microsoft Purview sensitivity labels to protect confidential documents. 4) Enable SharePoint access reviews in Entra ID Governance." `
            -MSDocsLink "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "LAT-03" -Phase "Phase 6 - Lateral Movement" -Name "SharePoint Access Enumeration" `
            -Severity "Medium" -Status "ERROR" -Description "Error enumerating SharePoint sites" `
            -AttackTechnique "GET /sites?search=*" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-LAT04-KeyVaultAccess {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [LAT-04] Azure Key Vault Access Test" -Level Attack

    if (-not $script:AzToken) {
        return New-TestResult -TestId "LAT-04" -Phase "Phase 6 - Lateral Movement" -Name "Key Vault Access Test" `
            -Severity "Critical" -Status "SKIPPED" `
            -Description "Azure Resource Manager token required (use -AuthMethod Interactive to get ARM token)" `
            -AttackTechnique "Enumerate Key Vaults with compromised account, extract secrets for lateral movement" `
            -Result "SKIPPED - no ARM token" -Evidence "" `
            -Remediation "Authenticate with ARM scope to enable this test" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        $armHeaders  = @{ Authorization = "Bearer $script:AzToken" }
        $evidence    = [ordered]@{}
        $vaultAccess = @()

        foreach ($subId in $script:DiscoveredSubscriptions) {
            try {
                $kvaults = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2021-04-01" `
                    -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop
                $evidence["Sub_${subId}_VaultCount"] = $kvaults.value.Count

                foreach ($vault in $kvaults.value | Select-Object -First 5) {
                    $vaultName = $vault.name
                    Write-EntraLog "    Probing Key Vault: $vaultName" -Level Info

                    # Try to list secrets (data plane)
                    try {
                        $kvToken = $null
                        # Get KV-specific token
                        $kvTokenBody = @{
                            grant_type    = "urn:ietf:params:oauth:grant-type:device_code"
                            resource      = "https://vault.azure.net"
                        }
                        # Use ARM token to try accessing KV directly - will work if RBAC is set
                        $kvHeaders = @{ Authorization = "Bearer $script:AzToken" }
                        $secrets = Invoke-RestMethod -Uri "https://$vaultName.vault.azure.net/secrets?api-version=7.4" `
                            -Headers $kvHeaders -TimeoutSec 10 -ErrorAction Stop
                        $vaultAccess += @{ Vault = $vaultName; SecretListAccessible = $true; SecretCount = $secrets.value.Count }
                        Write-EntraLog "    [!!!] Key Vault $vaultName secrets ACCESSIBLE!" -Level Warn
                    }
                    catch {
                        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                        $vaultAccess += @{ Vault = $vaultName; SecretListAccessible = $false; HTTPCode = $code }
                    }
                }
            } catch { $evidence["Sub_${subId}_Error"] = $_.Exception.Message }
        }

        $evidence["KeyVaultProbes"] = $vaultAccess
        $accessible = $vaultAccess | Where-Object { $_.SecretListAccessible -eq $true }
        $status = if ($accessible.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "LAT-04" -Phase "Phase 6 - Lateral Movement" -Name "Key Vault Access Test" `
            -Severity "Critical" -Status $status `
            -Description "Tests whether compromised user credentials can access Azure Key Vault secrets. Key Vaults often contain database passwords, API keys, and certificates enabling further lateral movement." `
            -AttackTechnique "Enumerate Key Vaults via ARM. Attempt secret list/get operations. KV secrets often contain: DB connection strings, storage keys, API credentials for downstream systems." `
            -Result $(if ($accessible.Count -gt 0) { "CRITICAL: $($accessible.Count) Key Vault(s) have accessible secrets! Data plane access confirmed." } else { "Key Vault access denied for all probed vaults. RBAC controls in place." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "1) Use Azure RBAC for Key Vault (not legacy vault access policies). 2) Grant minimum permissions - prefer Key Vault Reader not Key Vault Secrets Officer for most users. 3) Enable Key Vault firewall to restrict to known IPs/VNets. 4) Enable audit logging for all secret access." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "LAT-04" -Phase "Phase 6 - Lateral Movement" -Name "Key Vault Access Test" `
            -Severity "Critical" -Status "ERROR" -Description "Error testing Key Vault access" `
            -AttackTechnique "ARM + KV data plane access" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-LAT05-StorageSASAbuse {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [LAT-05] Storage Account SAS Abuse / Public Access Check" -Level Attack

    $evidence = [ordered]@{}

    try {
        # Part 1: Check for public storage (no auth required)
        $domain  = $script:Config.TenantDomain
        $orgName = $domain.Split(".")[0]
        $publicFindings = @()

        $storagePatterns = @("${orgName}data", "${orgName}backup", "${orgName}files", "${orgName}logs", "${orgName}archive", "${orgName}storage")

        foreach ($name in $storagePatterns) {
            try {
                $url = "https://$name.blob.core.windows.net/?comp=list&restype=container"
                $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 -ErrorAction Stop
                if ($resp.StatusCode -eq 200) {
                    $publicFindings += @{ StorageAccount = $name; PublicContainerList = $true }
                    Write-EntraLog "    [!!!] Public storage found: $name" -Level Warn
                }
            } catch {}
        }

        $evidence["PublicBlobStorage"] = $publicFindings

        # Part 2: Via ARM - check storage accounts if we have ARM token
        if ($script:AzToken) {
            $armHeaders = @{ Authorization = "Bearer $script:AzToken" }
            $storageAccounts = @()

            foreach ($subId in ($script:DiscoveredSubscriptions | Select-Object -First 2)) {
                try {
                    $accounts = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01" `
                        -Headers $armHeaders -TimeoutSec 15 -ErrorAction Stop

                    foreach ($sa in $accounts.value | Select-Object -First 10) {
                        $publicAccess = $sa.properties.allowBlobPublicAccess
                        $httpsOnly    = $sa.properties.supportsHttpsTrafficOnly
                        $tlsVersion   = $sa.properties.minimumTlsVersion
                        $sharedKey    = $sa.properties.allowSharedKeyAccess

                        $storageAccounts += [PSCustomObject]@{
                            Name              = $sa.name
                            PublicBlobAccess  = $publicAccess
                            HTTPSOnly         = $httpsOnly
                            MinTLSVersion     = $tlsVersion
                            SharedKeyAllowed  = $sharedKey
                            ResourceGroup     = ($sa.id -split "/resourceGroups/")[1].Split("/")[0]
                        }
                    }
                } catch { }
            }

            $riskyStorage = $storageAccounts | Where-Object { $_.PublicBlobAccess -eq $true -or $_.HTTPSOnly -eq $false -or $_.SharedKeyAllowed -eq $true }
            $evidence["StorageAccountsFound"]     = $storageAccounts.Count
            $evidence["RiskyStorageAccounts"]     = $riskyStorage | Select-Object -First 10
            $evidence["StorageAccountsSample"]    = $storageAccounts | Select-Object -First 5
        }

        $anyPublic  = $publicFindings.Count -gt 0
        $anyRisky   = $evidence["RiskyStorageAccounts"].Count -gt 0
        $status = if ($anyPublic) { "FAIL" } elseif ($anyRisky) { "WARNING" } else { "PASS" }

        return New-TestResult -TestId "LAT-05" -Phase "Phase 6 - Lateral Movement" -Name "Storage Account SAS / Public Access" `
            -Severity "Critical" -Status $status `
            -Description "Checks for publicly accessible Azure Blob containers and storage accounts with insecure configurations (public access, HTTP, shared key auth)." `
            -AttackTechnique "1) Public containers: no auth needed for data exfiltration. 2) Shared key enabled: if key is discovered (e.g. in code), full storage access. 3) HTTP: credentials transmitted in plaintext." `
            -Result $(if ($anyPublic) { "CRITICAL: $($publicFindings.Count) publicly accessible storage container(s) found!" } elseif ($anyRisky) { "WARNING: $($evidence['RiskyStorageAccounts'].Count) storage accounts have insecure configurations." } else { "No public or insecure storage accounts detected." }) `
            -Evidence ($evidence | ConvertTo-Json -Depth 4) `
            -Remediation "1) Set 'Allow Blob public access' to FALSE on all storage accounts. 2) Enable 'Secure transfer required' (HTTPS only). 3) Set minimum TLS to 1.2. 4) Consider disabling Shared Key access and using Azure AD auth exclusively. 5) Apply Azure Policy to enforce these settings." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "LAT-05" -Phase "Phase 6 - Lateral Movement" -Name "Storage Account SAS / Public Access" `
            -Severity "Critical" -Status "ERROR" -Description "Error testing storage access" `
            -AttackTechnique "Storage account enumeration and public access check" -Result "Error: $($_.Exception.Message)" `
            -Evidence ($evidence | ConvertTo-Json) -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase6 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 6 - Lateral Movement             " -Level Attack
    Write-EntraLog "========================================" -Level Info

    $phaseResults = @()
    $phaseResults += Invoke-LAT01-GraphAPIPillage
    $phaseResults += Invoke-LAT02-TeamsMessageEnumeration
    $phaseResults += Invoke-LAT03-SharePointAccess
    $phaseResults += Invoke-LAT04-KeyVaultAccess
    $phaseResults += Invoke-LAT05-StorageSASAbuse

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 6 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
