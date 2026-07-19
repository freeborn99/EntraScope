# ═══════════════════════════════════════════════════════════════
# EntraScope - Test Environment Setup & Teardown
# Creates temporary test objects for security assessment.
# All objects are tagged and can be removed automatically.
# REQUIRES: Global Administrator or User Administrator + Application Administrator
# ═══════════════════════════════════════════════════════════════

#Requires -Version 7.0

<#
.SYNOPSIS
    EntraScope Test Environment - Provisioning & Teardown
.DESCRIPTION
    Provisions and removes temporary test objects (honeypot users, test users,
    app registrations) in an Azure/Entra ID tenant for the EntraScope security
    testing toolkit. All created objects are tracked via a manifest file and
    can be fully cleaned up with Remove-EntraScopeTestEnvironment.
    AUTHORIZED USE ONLY - Run only against tenants you own or have written permission to test.
#>

# ───────────────────────────────────────────────────────────────
# Helper: Generate a cryptographically random password
# ───────────────────────────────────────────────────────────────
function New-RandomPassword {
    [CmdletBinding()]
    param(
        [int]$Length = 16
    )

    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower   = 'abcdefghijklmnopqrstuvwxyz'
    $digits  = '0123456789'
    $symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?'

    # Guarantee at least one from each category
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(4)

    $rng.GetBytes($bytes)
    $passwordChars = [System.Collections.Generic.List[char]]::new()
    $passwordChars.Add($upper[$bytes[0] % $upper.Length])
    $passwordChars.Add($lower[$bytes[1] % $lower.Length])
    $passwordChars.Add($digits[$bytes[2] % $digits.Length])
    $passwordChars.Add($symbols[$bytes[3] % $symbols.Length])

    # Fill remaining characters from the full pool
    $allChars = $upper + $lower + $digits + $symbols
    $remaining = $Length - 4
    $fillBytes = [byte[]]::new($remaining)
    $rng.GetBytes($fillBytes)

    for ($i = 0; $i -lt $remaining; $i++) {
        $passwordChars.Add($allChars[$fillBytes[$i] % $allChars.Length])
    }

    # Shuffle with Fisher-Yates
    $shuffleBytes = [byte[]]::new($passwordChars.Count)
    $rng.GetBytes($shuffleBytes)
    for ($i = $passwordChars.Count - 1; $i -gt 0; $i--) {
        $j = $shuffleBytes[$i] % ($i + 1)
        $temp = $passwordChars[$i]
        $passwordChars[$i] = $passwordChars[$j]
        $passwordChars[$j] = $temp
    }

    $rng.Dispose()
    return -join $passwordChars
}

# ───────────────────────────────────────────────────────────────
# Function 1: New-EntraScopeTestEnvironment
# ───────────────────────────────────────────────────────────────
function New-EntraScopeTestEnvironment {
    <#
    .SYNOPSIS
        Provisions test objects (honeypot users, test user, app registration) in Entra ID.
    .DESCRIPTION
        Creates 2 honeypot user accounts, 1 low-privilege test user, and 1 app registration
        in the target tenant. All objects are tracked in a manifest for automated cleanup.
    #>
    [CmdletBinding()]
    param()

    $tenantDomain = $script:Config.TenantDomain
    $graphBase    = "https://graph.microsoft.com/v1.0"
    $headers      = @{
        Authorization  = "Bearer " + $script:AccessToken
        'Content-Type' = "application/json"
    }

    $manifestObjects  = [System.Collections.Generic.List[object]]::new()
    $manifestPasswords = [System.Collections.Generic.List[object]]::new()
    $createdCount     = 0

    Write-EntraLog "═══════════════════════════════════════════════════════════════" -Level Info
    Write-EntraLog "  [SETUP] Provisioning EntraScope test environment" -Level Info
    Write-EntraLog "  Tenant: $tenantDomain" -Level Info
    Write-EntraLog "═══════════════════════════════════════════════════════════════" -Level Info

    # ── Define user accounts to create ──────────────────────────
    $userDefinitions = @(
        @{
            UPN         = "entrascope-honeypot1@" + $tenantDomain
            DisplayName = "EntraScope Honeypot 1"
            MailNickname = "entrascope-honeypot1"
        },
        @{
            UPN         = "entrascope-honeypot2@" + $tenantDomain
            DisplayName = "EntraScope Honeypot 2"
            MailNickname = "entrascope-honeypot2"
        },
        @{
            UPN         = "entrascope-testuser@" + $tenantDomain
            DisplayName = "EntraScope Test User"
            MailNickname = "entrascope-testuser"
        }
    )

    # ── Create user accounts ────────────────────────────────────
    foreach ($userDef in $userDefinitions) {
        $password = New-RandomPassword -Length 16

        $userBody = @{
            accountEnabled    = $true
            displayName       = $userDef.DisplayName
            mailNickname      = $userDef.MailNickname
            userPrincipalName = $userDef.UPN
            jobTitle          = "EntraScope Test Account - Safe to Delete"
            usageLocation     = "US"
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $false
                password                      = $password
            }
        } | ConvertTo-Json -Depth 5

        try {
            $checkUrl = $graphBase + "/users/" + $userDef.UPN
            try {
                $existingUser = Invoke-RestMethod -Uri $checkUrl -Method GET -Headers $headers -ErrorAction Stop
                Write-EntraLog ("  [SETUP] User already exists: " + $userDef.UPN) -Level Info
                $manifestObjects.Add([PSCustomObject]@{
                    type        = "User"
                    id          = $existingUser.id
                    displayName = $existingUser.displayName
                    upn         = $existingUser.userPrincipalName
                })
                $manifestPasswords.Add([PSCustomObject]@{
                    upn      = $existingUser.userPrincipalName
                    password = "Unknown (Pre-existing)"
                })
                continue
            } catch {}

            $url = $graphBase + "/users"
            Write-EntraLog ("  [SETUP] Creating user: " + $userDef.UPN) -Level Info

            $response = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $userBody -ErrorAction Stop

            $manifestObjects.Add([PSCustomObject]@{
                type        = "User"
                id          = $response.id
                displayName = $response.displayName
                upn         = $response.userPrincipalName
            })

            $manifestPasswords.Add([PSCustomObject]@{
                upn      = $response.userPrincipalName
                password = $password
            })

            $createdCount++
            Write-EntraLog ("  [+] Created user: " + $response.userPrincipalName + " (id: " + $response.id + ")") -Level Success
        }
        catch {
            Write-EntraLog ("  [!] Failed to create user " + $userDef.UPN + ": " + $_.Exception.Message) -Level Error
            throw
        }
    }

    # ── Create app registration ─────────────────────────────────
    $dateSuffix = (Get-Date).ToString("yyyyMMdd")
    $appName    = "EntraScope-TestApp-" + $dateSuffix

    $appBody = @{
        displayName = $appName
        notes       = "EntraScope Test App - Safe to Delete"
    } | ConvertTo-Json -Depth 5

    try {
        $checkAppUrl = $graphBase + "/applications?`$filter=displayName eq '" + $appName + "'"
        $appExists = $false
        try {
            $existingAppSearch = Invoke-RestMethod -Uri $checkAppUrl -Method GET -Headers $headers -ErrorAction Stop
            if ($existingAppSearch.value -and $existingAppSearch.value.Count -gt 0) {
                $existingApp = $existingAppSearch.value[0]
                Write-EntraLog ("  [SETUP] App registration already exists: " + $appName) -Level Info
                
                $manifestObjects.Add([PSCustomObject]@{
                    type        = "Application"
                    id          = $existingApp.id
                    displayName = $existingApp.displayName
                    upn         = $null
                })

                $manifestPasswords.Add([PSCustomObject]@{
                    upn      = $existingApp.displayName
                    password = "Unknown (Pre-existing)"
                })
                $appExists = $true
            }
        } catch {}

        if (-not $appExists) {
            $url = $graphBase + "/applications"
            Write-EntraLog ("  [SETUP] Creating app registration: " + $appName) -Level Info

            $appResponse = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $appBody -ErrorAction Stop

        Write-EntraLog ("  [+] Created app: " + $appResponse.displayName + " (id: " + $appResponse.id + ")") -Level Success

        # Add a password credential to the app
        $passwordUrl  = $graphBase + "/applications/" + $appResponse.id + "/addPassword"
        $passwordBody = @{
            passwordCredential = @{
                displayName = "EntraScope Test Secret"
            }
        } | ConvertTo-Json -Depth 5

        $credResponse = Invoke-RestMethod -Uri $passwordUrl -Method POST -Headers $headers -Body $passwordBody -ErrorAction Stop
        Write-EntraLog ("  [+] Added password credential to app: " + $appResponse.displayName) -Level Success

        $manifestObjects.Add([PSCustomObject]@{
            type        = "Application"
            id          = $appResponse.id
            displayName = $appResponse.displayName
            upn         = $null
        })

            $manifestPasswords.Add([PSCustomObject]@{
                upn      = $appResponse.displayName
                password = $credResponse.secretText
            })

            $createdCount++
        }
    }
    catch {
        Write-EntraLog ("  [!] Failed to create app registration " + $appName + ": " + $_.Exception.Message) -Level Error
        throw
    }

    # ── Save manifest ───────────────────────────────────────────
    $manifest = [PSCustomObject]@{
        TenantDomain = $tenantDomain
        CreatedAt    = (Get-Date).ToString("o")
        objects      = $manifestObjects.ToArray()
        passwords    = $manifestPasswords.ToArray()
    }

    $manifestDir  = Join-Path $Root "reports"
    $manifestPath = Join-Path $Root "reports\setup-manifest.json"

    if (-not (Test-Path $manifestDir)) {
        New-Item -Path $manifestDir -ItemType Directory -Force | Out-Null
    }

    $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8
    Write-EntraLog ("  [+] Manifest saved to: " + $manifestPath) -Level Success

    # ── Update scope.json ───────────────────────────────────────
    $scopePath = Join-Path $Root "config\scope.json"

    try {
        $scopeContent = Get-Content -Path $scopePath -Raw | ConvertFrom-Json

        $honeypot1Upn = "entrascope-honeypot1@" + $tenantDomain
        $honeypot2Upn = "entrascope-honeypot2@" + $tenantDomain
        $testUserUpn  = "entrascope-testuser@" + $tenantDomain

        $scopeContent.HoneypotAccounts = @(
            [PSCustomObject]@{ UPN = $honeypot1Upn },
            [PSCustomObject]@{ UPN = $honeypot2Upn }
        )

        if (-not $scopeContent.TestAccount) {
            $scopeContent | Add-Member -NotePropertyName "TestAccount" -NotePropertyValue ([PSCustomObject]@{ UPN = "" }) -Force
        }
        $scopeContent.TestAccount.UPN = $testUserUpn

        $scopeContent | ConvertTo-Json -Depth 10 | Set-Content -Path $scopePath -Encoding UTF8
        Write-EntraLog ("  [+] Updated scope.json with test account UPNs") -Level Success
    }
    catch {
        Write-EntraLog ("  [!] Failed to update scope.json: " + $_.Exception.Message) -Level Error
    }

    # ── Return result ───────────────────────────────────────────
    Write-EntraLog ("  [SETUP] Provisioning complete. Created " + $createdCount + " objects.") -Level Success

    return [PSCustomObject]@{
        Success  = $true
        Manifest = $manifest
        Message  = "Created " + $createdCount + " objects"
    }
}

# ───────────────────────────────────────────────────────────────
# Function 2: Remove-EntraScopeTestEnvironment
# ───────────────────────────────────────────────────────────────
function Remove-EntraScopeTestEnvironment {
    <#
    .SYNOPSIS
        Tears down all test objects created by New-EntraScopeTestEnvironment.
    .DESCRIPTION
        Reads the setup manifest and deletes all tracked users and app registrations
        from the tenant. Continues on individual failures and reports a summary.
    #>
    [CmdletBinding()]
    param()

    $graphBase    = "https://graph.microsoft.com/v1.0"
    $headers      = @{
        Authorization  = "Bearer " + $script:AccessToken
        'Content-Type' = "application/json"
    }

    $manifestPath = Join-Path $Root "reports\setup-manifest.json"

    Write-EntraLog "═══════════════════════════════════════════════════════════════" -Level Info
    Write-EntraLog "  [TEARDOWN] Removing EntraScope test environment" -Level Info
    Write-EntraLog "═══════════════════════════════════════════════════════════════" -Level Info

    # ── Load manifest ───────────────────────────────────────────
    if (-not (Test-Path $manifestPath)) {
        Write-EntraLog "  [!] No manifest found at: $manifestPath" -Level Error
        Write-EntraLog "  [!] Nothing to remove. Run New-EntraScopeTestEnvironment first." -Level Error
        return [PSCustomObject]@{
            Success = $false
            Removed = 0
            Failed  = 0
        }
    }

    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    $removedCount = 0
    $failedCount  = 0

    # ── Delete each object ──────────────────────────────────────
    foreach ($obj in $manifest.objects) {
        $objType = $obj.type
        $objId   = $obj.id
        $objName = $(if ($obj.upn) { $obj.upn } else { $obj.displayName })

        try {
            $deleteUrl = $(if ($objType -eq "User") {
                $graphBase + "/users/" + $objId
            } else {
                $graphBase + "/applications/" + $objId
            })

            Write-EntraLog ("  [TEARDOWN] Deleting " + $objType + ": " + $objName + " (id: " + $objId + ")") -Level Info

            Invoke-RestMethod -Uri $deleteUrl -Method DELETE -Headers $headers -ErrorAction Stop

            $removedCount++
            Write-EntraLog ("  [+] Deleted " + $objType + ": " + $objName) -Level Success
        }
        catch {
            $failedCount++
            Write-EntraLog ("  [!] Failed to delete " + $objType + " " + $objName + ": " + $_.Exception.Message) -Level Error
        }
    }

    # ── Clean up manifest file ──────────────────────────────────
    try {
        Remove-Item -Path $manifestPath -Force
        Write-EntraLog "  [+] Manifest file removed" -Level Success
    }
    catch {
        Write-EntraLog ("  [!] Failed to remove manifest file: " + $_.Exception.Message) -Level Error
    }

    # ── Clear scope.json ────────────────────────────────────────
    $scopePath = Join-Path $Root "config\scope.json"

    try {
        $scopeContent = Get-Content -Path $scopePath -Raw | ConvertFrom-Json

        $scopeContent.HoneypotAccounts = @()

        if ($scopeContent.TestAccount) {
            $scopeContent.TestAccount.UPN = ""
        }

        $scopeContent | ConvertTo-Json -Depth 10 | Set-Content -Path $scopePath -Encoding UTF8
        Write-EntraLog "  [+] Cleared HoneypotAccounts and TestAccount.UPN from scope.json" -Level Success
    }
    catch {
        Write-EntraLog ("  [!] Failed to update scope.json: " + $_.Exception.Message) -Level Error
    }

    # ── Return result ───────────────────────────────────────────
    $totalAttempted = $removedCount + $failedCount
    Write-EntraLog ("  [TEARDOWN] Complete. Removed: " + $removedCount + ", Failed: " + $failedCount + " of " + $totalAttempted + " objects.") -Level Info

    return [PSCustomObject]@{
        Success = $($failedCount -eq 0)
        Removed = $removedCount
        Failed  = $failedCount
    }
}

# ───────────────────────────────────────────────────────────────
# Function 3: Get-EntraScopeTestEnvironment
# ───────────────────────────────────────────────────────────────
function Get-EntraScopeTestEnvironment {
    <#
    .SYNOPSIS
        Returns the current test environment manifest, or $null if none exists.
    .DESCRIPTION
        Checks for the presence of reports/setup-manifest.json and returns its
        parsed contents. Use this to verify whether a test environment is active.
    #>
    [CmdletBinding()]
    param()

    $manifestPath = Join-Path $Root "reports\setup-manifest.json"

    if (-not (Test-Path $manifestPath)) {
        Write-EntraLog "  [INFO] No test environment manifest found." -Level Info
        return $null
    }

    try {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        Write-EntraLog ("  [INFO] Test environment manifest loaded. Created at: " + $manifest.CreatedAt) -Level Info
        Write-EntraLog ("  [INFO] Objects in manifest: " + $manifest.objects.Count) -Level Info
        return $manifest
    }
    catch {
        Write-EntraLog ("  [!] Failed to read manifest: " + $_.Exception.Message) -Level Error
        return $null
    }
}
