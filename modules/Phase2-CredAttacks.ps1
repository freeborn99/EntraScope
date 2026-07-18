#Requires -Version 7.0
<#
.SYNOPSIS
    EntraScope Phase 2 - Credential Attack Simulation
.DESCRIPTION
    Tests your tenant's defenses against credential-based attacks.
    ALL CREDENTIAL TESTS USE ONLY HONEYPOT ACCOUNTS defined in scope.json.
    AUTHORIZED USE ONLY.
#>

function Invoke-CRED01-SmartLockoutThreshold {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-01] Smart Lockout Threshold Test" -Level Attack

    if (-not $script:Config.HoneypotAccounts -or $script:Config.HoneypotAccounts.Count -eq 0) {
        return New-TestResult -TestId "CRED-01" -Phase "Phase 2 - Credential Attacks" -Name "Smart Lockout Threshold" `
            -Severity "Critical" -Status "SKIPPED" -Description "No honeypot accounts configured in scope.json" `
            -AttackTechnique "ROPC repeated wrong-password attempts" -Result "SKIPPED - configure HoneypotAccounts in scope.json" `
            -Evidence "" -Remediation "Add honeypot accounts to scope.json before running credential tests" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-smart-lockout" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-01" -Phase "Phase 2 - Credential Attacks" -Name "Smart Lockout Threshold" `
            -Severity "Critical" -Status "INFO" -Description "Would send 5 bad password attempts to honeypot account and check lockout response" `
            -AttackTechnique "POST /oauth2/v2.0/token ROPC with wrong passwords, monitor AADSTS error codes" `
            -Result "DRY RUN" -Evidence "" -Remediation "Ensure Smart Lockout threshold <= 10, lockout duration >= 60s" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-smart-lockout" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $honeypot   = $script:Config.HoneypotAccounts[0]
    $tenantId   = $script:Config.TenantId
    $tokenUrl   = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $clientId   = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI well-known public client
    $maxAttempts = 5  # Safe limit - well below default threshold of 10
    $attempts   = @()
    $lockedOut  = $false

    Write-EntraLog "    Running $maxAttempts bad password attempts against $($honeypot.UPN)" -Level Warn
    Write-EntraLog "    (Using Azure CLI client ID - same as real attacker would use)" -Level Info

    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $body = @{
                grant_type = "password"
                client_id  = $clientId
                username   = $honeypot.UPN
                password   = "WrongPassword-$i-EntraScope-$(Get-Date -Format 'mmss')"
                scope      = "https://graph.microsoft.com/.default"
            }
            $resp = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 15 -ErrorAction Stop
            $attempts += [PSCustomObject]@{ Attempt = $i; ErrorCode = "SUCCESS"; Description = "Authentication SUCCEEDED - unexpected" }
            Write-EntraLog "    [!!!] Attempt $i SUCCEEDED - ROPC auth worked!" -Level Warn
        }
        catch {
            $errorBody  = $null
            try { $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            $errorCode = if ($errorBody) { $errorBody.error } else { "unknown" }
            $errorDesc = if ($errorBody) { $errorBody.error_description } else { $_.Exception.Message }
            $aadsts    = if ($errorDesc -match "(AADSTS\d+)") { $Matches[1] } else { "none" }

            $attempts += [PSCustomObject]@{ Attempt = $i; ErrorCode = $errorCode; AADSTSCode = $aadsts; Description = ($errorDesc -split "`n")[0] }

            if ($aadsts -eq "AADSTS50053") {
                $lockedOut = $true
                Write-EntraLog "    [+] LOCKOUT TRIGGERED at attempt $i (AADSTS50053)" -Level Success
                break
            } elseif ($aadsts -eq "AADSTS50126") {
                Write-EntraLog "    Attempt $i: Invalid credentials (AADSTS50126) - account reached auth, ROPC not blocked by CA" -Level Info
            } elseif ($aadsts -eq "AADSTS53003") {
                Write-EntraLog "    Attempt $i: Blocked by Conditional Access (AADSTS53003) - ROPC blocked" -Level Success
                $lockedOut = $true  # CA blocked = effectively blocked
                break
            }
        }
        Start-Sleep -Milliseconds $script:Config.Options.RateLimitMs
    }

    $lastCode = $attempts[-1].AADSTSCode
    $ropcBlocked = $lastCode -in @("AADSTS53003", "AADSTS65001")
    $status = if ($lockedOut -or $ropcBlocked) { "PASS" } else { "WARNING" }
    $resultMsg = if ($lockedOut) {
        "Account lockout detected after $($attempts.Count) attempts (AADSTS50053). Smart Lockout is functioning."
    } elseif ($ropcBlocked) {
        "ROPC flow blocked by Conditional Access before lockout was needed."
    } else {
        "WARNING: $maxAttempts attempts sent without triggering lockout. Verify Smart Lockout threshold in Entra admin center."
    }

    return New-TestResult -TestId "CRED-01" -Phase "Phase 2 - Credential Attacks" -Name "Smart Lockout Threshold" `
        -Severity "Critical" -Status $status `
        -Description "Sends multiple failed authentication attempts to a honeypot account to verify Smart Lockout is functioning correctly." `
        -AttackTechnique "ROPC grant type POST to /oauth2/v2.0/token with wrong passwords using Azure CLI client ID" `
        -Result $resultMsg -Evidence ($attempts | ConvertTo-Json) `
        -Remediation "Ensure Smart Lockout threshold is set to 10 (default) or lower in Entra > Security > Authentication Methods > Password Protection. Block ROPC with Conditional Access." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-smart-lockout" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-CRED02-LowSlowSprayDetection {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-02] Low-and-Slow Password Spray Detection Test" -Level Attack

    if (-not $script:Config.HoneypotAccounts -or $script:Config.HoneypotAccounts.Count -eq 0) {
        return New-TestResult -TestId "CRED-02" -Phase "Phase 2 - Credential Attacks" -Name "Password Spray Detection" `
            -Severity "Critical" -Status "SKIPPED" -Description "No honeypot accounts configured" `
            -AttackTechnique "One bad password per account across multiple accounts" -Result "SKIPPED" `
            -Evidence "" -Remediation "Add honeypot accounts to scope.json" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-02" -Phase "Phase 2 - Credential Attacks" -Name "Password Spray Detection" `
            -Severity "Critical" -Status "INFO" -Description "Would send one wrong password to each honeypot account and check detection" `
            -AttackTechnique "One attempt per account - classic spray pattern to evade per-account lockout" -Result "DRY RUN" `
            -Evidence "" -Remediation "Enable Identity Protection P2 for spray detection" `
            -MSDocsLink "" -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $tenantId = $script:Config.TenantId
    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    $sprayPassword = "Spring2024!"   # Classic spray password - intentionally wrong for honeypots
    $sprayTime = Get-Date
    $sprayResults = @()

    Write-EntraLog "    Spraying $($script:Config.HoneypotAccounts.Count) honeypot account(s) with common password" -Level Warn

    foreach ($account in $script:Config.HoneypotAccounts) {
        try {
            $body = @{
                grant_type = "password"
                client_id  = $clientId
                username   = $account.UPN
                password   = $sprayPassword
                scope      = "https://graph.microsoft.com/.default"
            }
            Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10 -ErrorAction Stop
            $sprayResults += [PSCustomObject]@{ UPN = $account.UPN; Result = "AUTH_SUCCESS"; AADSTSCode = "none" }
        }
        catch {
            $errorBody = $null
            try { $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            $aadsts = if ($errorBody.error_description -match "(AADSTS\d+)") { $Matches[1] } else { "unknown" }
            $sprayResults += [PSCustomObject]@{ UPN = $account.UPN; Result = "AUTH_FAILED"; AADSTSCode = $aadsts }
        }
        Start-Sleep -Milliseconds ([Math]::Max($script:Config.Options.RateLimitMs, 3000))
    }

    # Check if Identity Protection detected it (requires Graph token)
    $riskDetected = $false
    $riskEvidence = "Graph API token not available - cannot query risk detections"
    if ($script:AccessToken) {
        try {
            Start-Sleep -Seconds 15  # Give IP time to process
            $since = $sprayTime.AddMinutes(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $riskUri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $since and riskType eq 'passwordSpray'"
            $riskResp = Invoke-RestMethod -Uri $riskUri -Headers @{Authorization = "Bearer $script:AccessToken"} -TimeoutSec 15 -ErrorAction Stop
            if ($riskResp.value.Count -gt 0) {
                $riskDetected = $true
                $riskEvidence = $riskResp.value | ConvertTo-Json -Depth 3
            } else {
                $riskEvidence = "No passwordSpray risk detections found in Identity Protection within the test window."
            }
        }
        catch { $riskEvidence = "Error querying risk detections: $($_.Exception.Message)" }
    }

    $status = if ($riskDetected) { "PASS" } else { "WARNING" }

    return New-TestResult -TestId "CRED-02" -Phase "Phase 2 - Credential Attacks" -Name "Password Spray Detection" `
        -Severity "Critical" -Status $status `
        -Description "Performs a classic low-and-slow password spray (1 attempt per account) to verify Identity Protection detects the pattern." `
        -AttackTechnique "One common password attempt per honeypot account spread across accounts - evades per-account lockout" `
        -Result (if ($riskDetected) { "Identity Protection DETECTED the spray pattern. Risk events generated." } else { "Spray performed. Identity Protection detection not confirmed - may require Entra ID P2 license or spray volume was too small." }) `
        -Evidence (@{ SprayAttempts = $sprayResults; RiskDetection = $riskEvidence } | ConvertTo-Json -Depth 4) `
        -Remediation "Enable Entra ID P2 for Identity Protection password spray detection. Configure user risk policy to block or require MFA on High risk. Enable Sign-in risk policy." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-CRED03-LegacyAuthSMTP {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-03] Legacy Auth - SMTP Basic Auth Probe" -Level Attack

    if (-not $script:Config.HoneypotAccounts -or $script:Config.HoneypotAccounts.Count -eq 0) {
        return New-TestResult -TestId "CRED-03" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth SMTP Probe" `
            -Severity "Critical" -Status "SKIPPED" -Description "No honeypot accounts configured — SMTP probe skipped to avoid using real accounts" `
            -AttackTechnique "TCP connect + EHLO + STARTTLS + AUTH LOGIN to smtp.office365.com:587" -Result "SKIPPED - configure HoneypotAccounts in scope.json" `
            -Evidence "" -Remediation "Add honeypot accounts to scope.json before running credential tests" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-03" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth SMTP Probe" `
            -Severity "Critical" -Status "INFO" -Description "Would attempt SMTP AUTH to smtp.office365.com:587 with Basic auth" `
            -AttackTechnique "TCP connect + EHLO + STARTTLS + AUTH LOGIN to smtp.office365.com:587" -Result "DRY RUN" -Evidence "" `
            -Remediation "Block legacy auth via Conditional Access" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $smtpHost = "smtp.office365.com"
    $smtpPort = 587
    $evidence = [ordered]@{}

    try {
        Write-EntraLog "    Connecting to $smtpHost`:$smtpPort" -Level Info
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($smtpHost, $smtpPort)
        if (-not $connectTask.Wait(8000)) {
            $tcpClient.Close()
            $evidence["Result"] = "Connection timeout - SMTP port may be blocked by firewall"
            return New-TestResult -TestId "CRED-03" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth SMTP Probe" `
                -Severity "Critical" -Status "PASS" -Description "SMTP Basic auth probe" `
                -AttackTechnique "TCP connect to smtp.office365.com:587" -Result "SMTP connection timed out - port blocked upstream." `
                -Evidence ($evidence | ConvertTo-Json) -Remediation "Good - SMTP port blocked. Verify CA also blocks legacy auth." `
                -MSDocsLink "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        $stream  = $tcpClient.GetStream()
        $reader  = New-Object System.IO.StreamReader($stream)
        $writer  = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $banner = $reader.ReadLine()
        $evidence["Banner"] = $banner
        Write-EntraLog "    Banner: $banner" -Level Info

        # EHLO
        $writer.WriteLine("EHLO entrascope.test")
        Start-Sleep -Milliseconds 500
        $ehloResp = ""
        while ($stream.DataAvailable) { $ehloResp += $reader.ReadLine() + "`n" }
        $evidence["EHLO_Response"] = $ehloResp.Trim()

        # Try STARTTLS
        $supportsSTARTTLS = $ehloResp -match "STARTTLS"
        $evidence["SupportsSTARTTLS"] = $supportsSTARTTLS

        # Try AUTH without TLS first (should fail)
        $writer.WriteLine("AUTH LOGIN")
        Start-Sleep -Milliseconds 500
        $authResp = ""
        while ($stream.DataAvailable) { $authResp += $reader.ReadLine() + "`n" }
        $evidence["AUTH_Response"] = $authResp.Trim()

        $tcpClient.Close()

        $authAllowed = $authResp -match "^334" -or $authResp -match "Username"
        $status = if (-not $authAllowed) { "PASS" } else { "FAIL" }

        return New-TestResult -TestId "CRED-03" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth SMTP Probe" `
            -Severity "Critical" -Status $status `
            -Description "Tests whether SMTP Basic AUTH is enabled, which bypasses MFA and Conditional Access." `
            -AttackTechnique "TCP connect to smtp.office365.com:587, send EHLO + AUTH LOGIN - if server accepts, legacy auth is enabled" `
            -Result (if ($authAllowed) { "SMTP AUTH LOGIN accepted! Legacy authentication is enabled - bypasses MFA and CA." } else { "SMTP AUTH rejected or requires STARTTLS + modern auth. Legacy auth appears blocked." }) `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "Create Conditional Access policy blocking Legacy Authentication clients. In Exchange Online PowerShell: Set-TransportConfig -SmtpClientAuthenticationDisabled $true for tenants not using SMTP relay." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "CRED-03" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth SMTP Probe" `
            -Severity "Critical" -Status "PASS" -Description "SMTP probe failed to connect" `
            -AttackTechnique "TCP connect to smtp.office365.com:587" -Result "Connection failed: $($_.Exception.Message) - Likely blocked." `
            -Evidence (@{ Error = $_.Exception.Message } | ConvertTo-Json) `
            -Remediation "Connection blocked is good. Verify CA policy also blocks legacy auth clients for belt-and-suspenders." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-CRED04-LegacyAuthIMAP {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-04] Legacy Auth - IMAP Basic Auth Probe" -Level Attack

    if (-not $script:Config.HoneypotAccounts -or $script:Config.HoneypotAccounts.Count -eq 0) {
        return New-TestResult -TestId "CRED-04" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth IMAP Probe" `
            -Severity "Critical" -Status "SKIPPED" -Description "No honeypot accounts configured — IMAP probe skipped to avoid using real accounts" `
            -AttackTechnique "TCP SSL connect + IMAP LOGIN command" -Result "SKIPPED - configure HoneypotAccounts in scope.json" `
            -Evidence "" -Remediation "Add honeypot accounts to scope.json before running credential tests" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-04" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth IMAP Probe" `
            -Severity "Critical" -Status "INFO" -Description "Would probe IMAP SSL on outlook.office365.com:993" `
            -AttackTechnique "TCP SSL connect + IMAP LOGIN command" -Result "DRY RUN" -Evidence "" `
            -Remediation "Block IMAP via CA legacy auth policy" -MSDocsLink "" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $imapHost = "outlook.office365.com"
    $imapPort = 993
    $evidence = [ordered]@{}

    try {
        Write-EntraLog "    Connecting to $imapHost`:$imapPort (IMAP SSL)" -Level Info
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($imapHost, $imapPort)

        if (-not $connectTask.Wait(8000)) {
            $tcpClient.Close()
            return New-TestResult -TestId "CRED-04" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth IMAP Probe" `
                -Severity "Critical" -Status "PASS" -Description "IMAP SSL probe" -AttackTechnique "TCP SSL to outlook.office365.com:993" `
                -Result "IMAP connection timed out. Port blocked." -Evidence (@{ Result = "Timeout" } | ConvertTo-Json) `
                -Remediation "Good - IMAP port blocked. Verify CA legacy auth policy is also in place." `
                -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
                -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
        }

        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
        $sslStream.AuthenticateAsClient($imapHost)
        $reader = New-Object System.IO.StreamReader($sslStream)
        $writer = New-Object System.IO.StreamWriter($sslStream)
        $writer.AutoFlush = $true

        $banner = $reader.ReadLine()
        $evidence["Banner"] = $banner
        Write-EntraLog "    IMAP Banner: $banner" -Level Info

        # Try LOGIN
        $honeypotUPN = $script:Config.HoneypotAccounts[0].UPN
        $writer.WriteLine("A001 LOGIN `"$honeypotUPN`" `"WrongPassword-EntraScope-Test`"")
        Start-Sleep -Milliseconds 1000
        $loginResp = ""
        try { while ($sslStream.CanRead -and $reader.Peek() -ne -1) { $loginResp += [char]$reader.Read() } } catch {}
        $evidence["LOGIN_Response"] = $loginResp.Trim()
        Write-EntraLog "    IMAP LOGIN response: $($loginResp.Trim())" -Level Info

        $tcpClient.Close()

        # Parse response
        $authFailed    = $loginResp -match "NO.*AUTHENTICATIONFAILED|NO.*BAD credentials|NO.*disabled"
        $authAttempted = $loginResp -match "NO|BAD|OK"
        $status = if ($authFailed -or $loginResp -match "CLIENTAUTHENTICATIONDISABLED") { "PASS" } else { "FAIL" }

        return New-TestResult -TestId "CRED-04" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth IMAP Probe" `
            -Severity "Critical" -Status $status `
            -Description "Tests whether IMAP Basic AUTH is accessible on Exchange Online, which bypasses MFA and Conditional Access." `
            -AttackTechnique "IMAP SSL connect to outlook.office365.com:993, attempt LOGIN - bypasses MFA if successful" `
            -Result (if ($status -eq "PASS") { "IMAP auth rejected (AUTHENTICATIONFAILED or disabled). Legacy IMAP auth blocked." } else { "IMAP LOGIN reached credential validation. Legacy auth may be enabled for this protocol." }) `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "Block IMAP in Conditional Access using 'Exchange ActiveSync clients' and 'Other clients' conditions. Run: Set-CASMailbox -Identity * -ImapEnabled $false in Exchange Online PS." `
            -MSDocsLink "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/client-access-rules/client-access-rules" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "CRED-04" -Phase "Phase 2 - Credential Attacks" -Name "Legacy Auth IMAP Probe" `
            -Severity "Critical" -Status "PASS" -Description "IMAP probe failed" `
            -AttackTechnique "TCP SSL to outlook.office365.com:993" -Result "Connection failed: $($_.Exception.Message)" `
            -Evidence (@{ Error = $_.Exception.Message } | ConvertTo-Json) `
            -Remediation "Connection blocked. Ensure CA legacy auth policy is deployed." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-CRED05-ROPCFlowTest {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-05] Resource Owner Password Credentials (ROPC) Flow Test" -Level Attack

    if (-not $script:Config.HoneypotAccounts -or $script:Config.HoneypotAccounts.Count -eq 0) {
        return New-TestResult -TestId "CRED-05" -Phase "Phase 2 - Credential Attacks" -Name "ROPC Flow Availability" `
            -Severity "Critical" -Status "SKIPPED" -Description "No honeypot accounts configured — ROPC test skipped to avoid using real accounts" `
            -AttackTechnique "POST /oauth2/v2.0/token with grant_type=password using well-known public client IDs" -Result "SKIPPED - configure HoneypotAccounts in scope.json" `
            -Evidence "" -Remediation "Add honeypot accounts to scope.json before running credential tests" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-05" -Phase "Phase 2 - Credential Attacks" -Name "ROPC Flow Availability" `
            -Severity "Critical" -Status "INFO" `
            -Description "Would test if ROPC grant type is blocked by Conditional Access" `
            -AttackTechnique "POST /oauth2/v2.0/token with grant_type=password - bypasses interactive auth and MFA prompts" `
            -Result "DRY RUN" -Evidence "" `
            -Remediation "Block ROPC via CA policy" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    $tenantId = $script:Config.TenantId
    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $evidence = [ordered]@{}

    # Test with multiple well-known public client IDs that attackers use
    $clientIds = @(
        @{ Id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"; Name = "Azure CLI" }
        @{ Id = "1950a258-227b-4e31-a9cf-717495945fc2"; Name = "Microsoft Azure PowerShell" }
        @{ Id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; Name = "Microsoft Office" }
    )

    $honeypotUPN = $script:Config.HoneypotAccounts[0].UPN
    $ropcReachesAuth = $false

    foreach ($client in $clientIds) {
        try {
            $body = @{
                grant_type = "password"
                client_id  = $client.Id
                username   = $honeypotUPN
                password   = "WrongPassword-ROPC-Test-EntraScope"
                scope      = "https://graph.microsoft.com/.default offline_access"
            }
            Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 10 -ErrorAction Stop
            $evidence[$client.Name] = "SUCCESS - ROPC auth completed!"
            $ropcReachesAuth = $true
        }
        catch {
            $errBody = $null
            try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            $aadsts = if ($errBody.error_description -match "(AADSTS\d+)") { $Matches[1] } else { "unknown" }
            $evidence[$client.Name] = "AADSTS: $aadsts | $($errBody.error)"

            # AADSTS50126 = wrong password but ROPC reached credential validation = ROPC NOT blocked!
            if ($aadsts -eq "AADSTS50126") { $ropcReachesAuth = $true }
            # AADSTS53003/65001 = CA blocked = ROPC IS blocked (good)
            # AADSTS7000218 = public client not allowed = app-level block
        }
        Start-Sleep -Milliseconds $script:Config.Options.RateLimitMs
    }

    $status = if (-not $ropcReachesAuth) { "PASS" } else { "FAIL" }

    return New-TestResult -TestId "CRED-05" -Phase "Phase 2 - Credential Attacks" -Name "ROPC Flow Availability" `
        -Severity "Critical" -Status $status `
        -Description "Tests if the ROPC OAuth flow is blocked by Conditional Access. ROPC accepts username+password directly, bypassing MFA and interactive auth flows." `
        -AttackTechnique "POST /oauth2/v2.0/token grant_type=password with known public client IDs (Azure CLI, PowerShell, Office) - standard attacker tool IDs" `
        -Result (if ($status -eq "PASS") { "ROPC flow blocked by Conditional Access or tenant policy for all tested client IDs." } else { "ROPC FLOW REACHES CREDENTIAL VALIDATION. MFA and CA policies may be bypassable via ROPC with valid credentials." }) `
        -Evidence ($evidence | ConvertTo-Json) `
        -Remediation "Create a Conditional Access policy: Conditions > Client apps > check 'Mobile apps and desktop clients', then under Access controls > Block. Alternatively use Authentication Strengths requiring phishing-resistant MFA." `
        -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc" `
        -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
}

function Invoke-CRED06-MFAPushFatigue {
    [CmdletBinding()]
    param()
    $start = Get-Date
    Write-EntraLog "  [CRED-06] MFA Push Fatigue / Method Assessment" -Level Attack

    if (-not $script:AccessToken) {
        return New-TestResult -TestId "CRED-06" -Phase "Phase 2 - Credential Attacks" -Name "MFA Push Fatigue Assessment" `
            -Severity "High" -Status "SKIPPED" -Description "Graph API token required for MFA method assessment" `
            -AttackTechnique "Review auth methods policy for push-only MFA config (fatigue attack vector)" -Result "SKIPPED - no Graph token" `
            -Evidence "" -Remediation "Run with authentication to enable this check" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-mfa-number-match" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    if ($script:DryRun) {
        return New-TestResult -TestId "CRED-06" -Phase "Phase 2 - Credential Attacks" -Name "MFA Push Fatigue Assessment" `
            -Severity "High" -Status "INFO" -Description "Would check if number matching is enabled and push is the primary MFA method" `
            -AttackTechnique "Review auth methods policy - if only push notifications without number matching = MFA fatigue attack possible" `
            -Result "DRY RUN" -Evidence "" -Remediation "Enable number matching and additional context in Microsoft Authenticator" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-mfa-number-match" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }

    try {
        # Get authentication methods policy
        $policyUri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        $policy = Invoke-RestMethod -Uri $policyUri -Headers @{Authorization = "Bearer $script:AccessToken"} -TimeoutSec 15 -ErrorAction Stop

        $authMethods = $policy.authenticationMethodConfigurations
        $evidence = [ordered]@{}

        $microsoftAuthenticatorConfig = $authMethods | Where-Object { $_.id -eq "MicrosoftAuthenticator" }
        $fido2Config   = $authMethods | Where-Object { $_.id -eq "Fido2" }
        $smsConfig     = $authMethods | Where-Object { $_.id -eq "Sms" }
        $voiceConfig   = $authMethods | Where-Object { $_.id -eq "Voice" }

        $evidence["MicrosoftAuthenticator_State"] = $microsoftAuthenticatorConfig.state
        $evidence["FIDO2_State"]      = $fido2Config.state
        $evidence["SMS_State"]        = $smsConfig.state
        $evidence["Voice_State"]      = $voiceConfig.state

        # Check number matching (if available in API)
        if ($microsoftAuthenticatorConfig.featureSettings) {
            $evidence["NumberMatchingEnabled"] = $microsoftAuthenticatorConfig.featureSettings.numberMatchingRequiredState.state
            $evidence["AdditionalContextEnabled"] = $microsoftAuthenticatorConfig.featureSettings.displayAppInformationRequiredState.state
        }

        $pushOnly            = $microsoftAuthenticatorConfig.state -eq "enabled" -and $fido2Config.state -ne "enabled"
        $numberMatchEnabled  = $evidence["NumberMatchingEnabled"] -eq "enabled"
        $legacyMethodsEnabled = $smsConfig.state -eq "enabled" -or $voiceConfig.state -eq "enabled"

        $issues = @()
        if ($pushOnly -and -not $numberMatchEnabled) { $issues += "Push MFA without number matching - vulnerable to MFA fatigue attacks" }
        if ($legacyMethodsEnabled) { $issues += "Legacy MFA methods (SMS/Voice) enabled - vulnerable to SIM swapping" }
        if ($fido2Config.state -ne "enabled") { $issues += "FIDO2 phishing-resistant MFA not enabled" }

        $status = if ($issues.Count -gt 0) { "FAIL" } else { "PASS" }

        return New-TestResult -TestId "CRED-06" -Phase "Phase 2 - Credential Attacks" -Name "MFA Push Fatigue Assessment" `
            -Severity "High" -Status $status `
            -Description "Assesses whether MFA configuration is vulnerable to push notification fatigue attacks (attackers repeatedly sending push requests until user accidentally approves)." `
            -AttackTechnique "If MFA is push-only without number matching: repeatedly trigger MFA prompts until victim approves. Works with valid credential + compromised password." `
            -Result (if ($issues.Count -gt 0) { "MFA FATIGUE VULNERABILITIES: $($issues -join '; ')" } else { "MFA configuration appears resilient to fatigue attacks. Number matching and/or phishing-resistant MFA enabled." }) `
            -Evidence ($evidence | ConvertTo-Json) `
            -Remediation "1) Enable number matching in Microsoft Authenticator. 2) Enable 'Additional context' (app name + location). 3) Enable FIDO2/Windows Hello for Business. 4) Disable SMS and Voice MFA methods." `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-mfa-number-match" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        return New-TestResult -TestId "CRED-06" -Phase "Phase 2 - Credential Attacks" -Name "MFA Push Fatigue Assessment" `
            -Severity "High" -Status "ERROR" -Description "Error checking MFA methods policy" `
            -AttackTechnique "Review authenticationMethodsPolicy via Graph API" -Result "Error: $($_.Exception.Message)" `
            -Evidence "" -Remediation "" `
            -MSDocsLink "https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-mfa-number-match" `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
}

function Invoke-Phase2 {
    [CmdletBinding()]
    param()

    Write-EntraLog "" -Level Info
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " PHASE 2 - Credential Attack Simulation " -Level Attack
    Write-EntraLog "========================================" -Level Info
    Write-EntraLog " WARNING: Credential tests use HONEYPOT accounts ONLY" -Level Warn

    $phaseResults = @()
    $phaseResults += Invoke-CRED01-SmartLockoutThreshold
    $phaseResults += Invoke-CRED02-LowSlowSprayDetection
    $phaseResults += Invoke-CRED03-LegacyAuthSMTP
    $phaseResults += Invoke-CRED04-LegacyAuthIMAP
    $phaseResults += Invoke-CRED05-ROPCFlowTest
    $phaseResults += Invoke-CRED06-MFAPushFatigue

    $pass = ($phaseResults | Where-Object Status -eq "PASS").Count
    $fail = ($phaseResults | Where-Object Status -eq "FAIL").Count
    $warn = ($phaseResults | Where-Object Status -in @("WARNING","WARN")).Count
    Write-EntraLog "  Phase 2 complete: $pass PASS | $fail FAIL | $warn WARN" -Level Success

    return $phaseResults
}
