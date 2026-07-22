# Creating Custom Modules

EntraScope allows you to expand the toolkit by writing your own security tests and modules. Custom modules are placed in the `custom_modules/` directory and are automatically loaded into the engine.

## 1. Directory Structure

Place your custom PowerShell scripts inside the `custom_modules/` directory.

```
EntraScope/
├── EntraScope.ps1
├── gui/
├── modules/
└── custom_modules/         <-- Drop new modules here
    └── Phase9-MyCustomModule.ps1
```

## 2. Module Template

Every custom module needs an overarching function (e.g., `Invoke-Phase9`) that the engine calls, and individual test functions that return a `New-TestResult` object.

Here is the standard template for building a test:

```powershell
<#
.SYNOPSIS
    EntraScope Phase 9: Custom Modules
#>

Write-Host "`n[+] Starting Phase 9: Custom Security Checks" -ForegroundColor Cyan

function Invoke-CUST01-MyNewTest {
    Write-EntraLog "Running CUST-01: Checking configuration..." -Level Info
    $start = Get-Date

    try {
        # 1. Prepare Authorization Header (Uses the authenticated session)
        $headers  = @{ Authorization = "Bearer $script:AccessToken" }
        $evidence = [ordered]@{}

        # 2. Perform Microsoft Graph API Call
        # $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/..." -Headers $headers -ErrorAction Stop

        # 3. Evaluate Security Posture
        $status = "PASS"   # Use: PASS, FAIL, WARNING, INFO, SKIPPED, ERROR
        $severity = "Low"  # Use: Critical, High, Medium, Low, Info
        $desc = "The configuration looks secure."

        # if ($response.isVulnerable) {
        #     $status = "FAIL"
        #     $severity = "High"
        #     $desc = "A vulnerability was found."
        # }

        # 4. Return Standardized Result Object
        return New-TestResult -TestId "CUST-01" -Phase "Phase 9 - Custom Modules" -Name "My Custom Test" `
            -Severity $severity -Status $status -Description $desc `
            -AttackTechnique "Description of how this misconfiguration could be abused." `
            -Result "Summary of what the script saw." -Evidence ($evidence | ConvertTo-Json -Depth 3) `
            -Remediation "Actionable steps to fix the issue." `
            -MSDocsLink "https://learn.microsoft.com/..." `
            -Duration "$([int]((Get-Date)-$start).TotalSeconds)s"
    }
    catch {
        # 5. Handle Errors Gracefully
        return New-TestResult -TestId "CUST-01" -Phase "Phase 9 - Custom Modules" -Name "My Custom Test" `
            -Severity "Medium" -Status "ERROR" -Description "Script encountered an error." `
            -AttackTechnique "N/A" -Result $_.Exception.Message -Evidence "" -Remediation "" -MSDocsLink "" -Duration "0s"
    }
}

# The wrapper function that the EntraScope engine will invoke
function Invoke-Phase9 {
    $results = @()
    $results += Invoke-CUST01-MyNewTest
    return $results
}
```

## 3. Hooking into the Engine (CLI)

The `EntraScope.ps1` file automatically attempts to run `Invoke-Phase9` if it detects it. If you create a `Phase10` or `Phase11`, you will need to add it to the `$phaseMap` inside `EntraScope.ps1`:

```powershell
    $phaseMap = @{
        1 = { Invoke-Phase1 }
        # ...
        9 = { if (Get-Command Invoke-Phase9 -ErrorAction SilentlyContinue) { Invoke-Phase9 } }
        10 = { if (Get-Command Invoke-Phase10 -ErrorAction SilentlyContinue) { Invoke-Phase10 } }
    }
```

## 4. Publishing to the GUI Marketplace

To make your custom module available for download in the EntraScope GUI "Extensions" tab:

1. Upload the `.ps1` file to the `custom_modules/` folder in your GitHub repository.
2. Edit the `modules.json` file in the root of the repository to include your new module's metadata:

```json
[
  {
    "Name": "My Custom Test Module",
    "Description": "Checks for X, Y, and Z misconfigurations.",
    "Author": "Your Name",
    "Version": "1.0.0",
    "FileName": "Phase9-MyCustomModule.ps1",
    "DownloadUrl": "https://raw.githubusercontent.com/YourUsername/EntraScope/beta/custom_modules/Phase9-MyCustomModule.ps1"
  }
]
```

When users launch the GUI and navigate to the Extensions tab, they can click "Refresh Modules" to download the latest `modules.json` manifest. Clicking "Install" will automatically pull the script from the `DownloadUrl` and save it to their local machine.
