# EntraScope — Account Setup Guide

## Overview

EntraScope uses two categories of special accounts to safely run penetration tests against your Azure / Microsoft 365 Entra tenant **without touching real user accounts or production credentials**.

| Account Type | Purpose | Tests that use it |
|---|---|---|
| **Honeypot Accounts** | Decoy accounts that receive simulated credential attacks (wrong passwords, sprays, legacy-auth probes). Should never be used by real humans. | CRED-01 · CRED-02 · CRED-03 · CRED-04 · CRED-05 |
| **Test Account (Low-Privilege)** | A real but minimally privileged user account used to simulate what an attacker can do after compromising a standard employee account. | PRIVESC-04 · PRIVESC-06 · Phase 6 lateral movement tests |

> [!CAUTION]
> **Never configure real employee accounts as honeypot accounts.** The tool will deliberately send incorrect passwords to honeypot accounts multiple times. A real employee account could be locked out.

---

## Part 1 — Honeypot Accounts

### What They Are

A honeypot account is a **disabled or cloud-only account with no mailbox access, no licenses, and no real data**. It exists solely as a target for credential attack simulations. When EntraScope fires bad password attempts at these accounts, it:

- Verifies Smart Lockout is working (CRED-01)
- Verifies password spray detection triggers (CRED-02)
- Tests whether SMTP / IMAP legacy auth is reachable (CRED-03 / CRED-04)
- Tests whether ROPC OAuth flow is blocked (CRED-05)

### Minimum Requirements

- At least **1 honeypot account** (2–3 recommended for spray simulation)
- Must be **cloud-only** (not synced from on-prem AD — synced accounts complicate lockout behaviour)
- Must have **no licenses** assigned (no Exchange mailbox needed; these accounts are never signed into)
- Must be **enabled** in Entra — disabled accounts return early errors that mask the real test result
- UPN should be **realistic-looking** (e.g. `svc-monitor01@yourdomain.com`) so they blend in as bait accounts in sign-in logs
- Password must be set to something **complex and unique** — it will never be used to log in, so make it a long random string

### Step-by-Step: Create a Honeypot Account

#### Option A — Entra Admin Centre (Browser)

1. Sign in to [https://entra.microsoft.com](https://entra.microsoft.com) as a **User Administrator** or **Global Administrator**
2. Go to **Identity → Users → All users → + New user → Create new user**
3. Fill in the form:

   | Field | Value |
   |---|---|
   | User principal name | `honeypot01@yourdomain.onmicrosoft.com` |
   | Display name | `EntraScope Honeypot 01` |
   | Auto-generate password | Yes (copy it once, you will never use it again) |
   | Account enabled | Yes (required for tests) |

4. Click **Create**
5. Go to the new user → **Licenses** → confirm **no licenses are assigned**
6. Go to the new user → **Properties** → add a note in **Job title**: `EntraScope Honeypot — Do Not Use`
7. Repeat for a second account: `honeypot02@yourdomain.onmicrosoft.com`

#### Option B — PowerShell (Microsoft Graph)

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"

$password = -join ((65..90)+(97..122)+(48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_}) + "!Aa1"

$params = @{
    DisplayName       = "EntraScope Honeypot 01"
    UserPrincipalName = "honeypot01@yourdomain.onmicrosoft.com"
    MailNickname      = "honeypot01"
    AccountEnabled    = $true
    JobTitle          = "EntraScope Honeypot -- Do Not Use"
    PasswordProfile   = @{
        Password                      = $password
        ForceChangePasswordNextSignIn = $false
    }
}

$user = New-MgUser @params
Write-Host "Created: $($user.UserPrincipalName)  |  ID: $($user.Id)"
```

Run twice for `honeypot01` and `honeypot02`.

### Recommended Conditional Access Exclusions

> [!IMPORTANT]
> If you have a CA policy that **blocks all sign-ins for unknown locations**, you may need to **exclude** your honeypot accounts from it — otherwise every CRED test will return `AADSTS53003 (CA blocked)` before Smart Lockout can even be tested.
>
> However, do **not** exclude them from MFA policies — you want to see what an attacker hits when they target these accounts without MFA.

To exclude from a specific CA policy:
1. Entra Admin Centre → **Protection → Conditional Access → Policies**
2. Open your location-restriction policy
3. **Users → Exclude → Users and groups** → add the honeypot accounts
4. Save

---

## Part 2 — Test Account (Low-Privilege)

### What It Is

The test account simulates a **compromised standard employee**. EntraScope uses this account to test:

- Whether a regular user can escalate privileges (PRIVESC-04, PRIVESC-06)
- What data is accessible from a standard account (Phase 6 lateral movement)
- What Graph API endpoints a standard user can reach

This account **is signed into** during testing, so it needs:
- A valid password you control
- MFA registered (to authenticate interactively or via Device Code)
- Minimal permissions — no admin roles, no sensitive group memberships

### Minimum Requirements

- **Cloud-only account** (not synced)
- **No admin roles** — it should look like a standard employee
- **No access to sensitive data** — do not add it to privileged groups, HR SharePoint sites, executive Teams channels, etc.
- **MFA registered** using Microsoft Authenticator (needed to complete Device Code authentication in EntraScope)
- Assigned a **Microsoft 365 E3 or E5 license** (or any license that includes Exchange Online + Teams) so Phase 6 tests have realistic services to probe
- Named clearly so you recognise it in logs: e.g. `svc-pentest-lowpriv@yourdomain.com`

### Step-by-Step: Create the Test Account

#### Option A — Entra Admin Centre

1. Go to **Identity → Users → All users → + New user → Create new user**
2. Fill in:

   | Field | Value |
   |---|---|
   | User principal name | `svc-pentest-lowpriv@yourdomain.onmicrosoft.com` |
   | Display name | `EntraScope Test Account (Low-Priv)` |
   | Password | Set a strong, unique password you control |
   | Account enabled | Yes |

3. Click **Create**
4. Go to the user → **Licenses** → assign **Microsoft 365 E3** (or equivalent)
5. Go to **Roles** → confirm **no directory roles are assigned**
6. Do **not** add this account to any privileged security group

#### Option B — PowerShell

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"

$params = @{
    DisplayName       = "EntraScope Test Account (Low-Priv)"
    UserPrincipalName = "svc-pentest-lowpriv@yourdomain.onmicrosoft.com"
    MailNickname      = "svc-pentest-lowpriv"
    AccountEnabled    = $true
    JobTitle          = "EntraScope Test Account -- Authorized Pentest Use Only"
    Department        = "IT Security"
    PasswordProfile   = @{
        Password                      = "ReplaceWithStrongPassword123!"
        ForceChangePasswordNextSignIn = $false
    }
}

$user = New-MgUser @params
Write-Host "Created: $($user.UserPrincipalName)  |  ID: $($user.Id)"
```

### Register MFA on the Test Account

The test account needs MFA to authenticate via Device Code flow:

1. Sign in to [https://aka.ms/mfasetup](https://aka.ms/mfasetup) **as the test account**
2. Add **Microsoft Authenticator** as the primary method
3. Optionally add a TOTP app as backup
4. Sign out

> [!TIP]
> Use a dedicated phone or a secondary Microsoft Authenticator profile to hold the test account's MFA registrations. Keep it separate from your own admin account's MFA.

---

## Part 3 — Configure Accounts in EntraScope

### Via the GUI (Recommended)

1. Launch EntraScope:
   ```powershell
   pwsh -STA -File "EntraScope\gui\wpf\EntraScopeGUI.ps1"
   ```
2. Click **Configure** (gear icon) in the left sidebar
3. Fill in **Tenant Domain**: `contoso.onmicrosoft.com`
4. Under **Honeypot Accounts**, click **+ Add Account** for each honeypot UPN:
   - `honeypot01@contoso.onmicrosoft.com`
   - `honeypot02@contoso.onmicrosoft.com`
5. Under **Test Account (Low-Privilege)**, enter:
   - `svc-pentest-lowpriv@contoso.onmicrosoft.com`
6. Click **Save Configuration**

### Via scope.json (Direct Edit)

The configuration file lives at:
```
EntraScope\config\scope.json
```

Full working example with both account types:

```json
{
  "TenantDomain": "contoso.onmicrosoft.com",
  "TenantId": "",
  "HoneypotAccounts": [
    {
      "UPN": "honeypot01@contoso.onmicrosoft.com",
      "Purpose": "CredentialAttackTesting"
    },
    {
      "UPN": "honeypot02@contoso.onmicrosoft.com",
      "Purpose": "CredentialAttackTesting"
    }
  ],
  "TestAccount": {
    "UPN": "svc-pentest-lowpriv@contoso.onmicrosoft.com"
  },
  "AzureSubscriptions": {
    "AutoDiscover": true,
    "SpecificSubscriptionIds": []
  },
  "Options": {
    "RateLimitMs": 2000,
    "CleanupAfterTest": true,
    "LogLevel": "Verbose"
  }
}
```

> [!NOTE]
> Leave `TenantId` blank — EntraScope auto-discovers it from the tenant domain via the OpenID Connect discovery endpoint on first run. You can also paste it in directly to skip that step.

---

## Part 4 — What Happens When Accounts Are Not Configured

EntraScope will **never guess or fall back** to unverified account names. If a required account type is missing, the relevant tests skip cleanly with a human-readable status in the Results view:

| Missing configuration | Tests skipped | Status shown |
|---|---|---|
| No honeypot accounts | CRED-01, 02, 03, 04, 05 | `SKIPPED — configure HoneypotAccounts in scope.json` |
| No authentication token | CRED-06, all Phase 3–8 Graph tests | `SKIPPED — authenticate first` |
| No ARM token | LAT-04 Key Vault, LAT-05 Storage (ARM part), Phase 7 | `SKIPPED — no ARM token` |

Phase 1 (unauthenticated external recon) always runs regardless — no accounts needed.

---

## Part 5 — Security and Post-Test Cleanup

### During Testing

- Honeypot accounts will appear in **Entra sign-in logs** with failed authentication entries — this is expected and intentional
- If you have **Microsoft Sentinel** or **Defender for Identity** alerts, you may see them fire during Phase 2 — this is a good sign: it confirms detection is working
- The test account generates Graph API activity in audit logs

### After Each Test Run

| Task | Where |
|---|---|
| Disable the test account between runs | Entra Admin Centre → User → Account enabled → Off |
| Review audit log entries for test activity | Entra Admin Centre → Monitoring → Audit logs |
| Review any auto-created app registrations | Entra Admin Centre → App registrations → All (filter by date) |
| Check Phase 5 cleanup completed | EntraScope results → PERSIST-01/02 should show "cleaned up" |

> [!WARNING]
> If a test run is interrupted (e.g. closed mid-scan), Phase 5 may have created a temporary app registration that was not cleaned up. Search Entra App Registrations for any app with `EntraScope-Test-DELETE-ME` in the name and delete it manually.

### Long-term Honeypot Monitoring

Once created, your honeypot accounts serve as **permanent canary accounts**. Any successful sign-in to a honeypot account is a genuine security alert — real users should never authenticate with these accounts.

| Monitor for | Where to set it up |
|---|---|
| Any successful sign-in to honeypot UPN | Entra → Identity Protection → Risky sign-ins alert |
| Any failed sign-in NOT from EntraScope | Sentinel → Analytics rule on honeypot UPN |
| Honeypot account password reset | Entra Audit log alert |
| Honeypot account license assignment | Entra Audit log alert |

---

## Quick Reference

```
EntraScope\
├── config\
│   └── scope.json                    <- Edit this to add your accounts
├── docs\
│   └── ACCOUNT-SETUP.md              <- This file
├── gui\wpf\
│   └── EntraScopeGUI.ps1             <- Configure via GUI -> Configure tab
└── modules\
    ├── Phase2-CredAttacks.ps1         <- Uses HoneypotAccounts (CRED-01 to 05)
    ├── Phase4-PrivEsc.ps1             <- Uses auth token (no separate test account UPN required)
    └── Phase6-LateralMovement.ps1    <- Uses auth token
```

### Fastest Path to First Scan

| Goal | What you need | Time |
|---|---|---|
| Safe smoke test | Nothing — tick Dry Run | 2 minutes |
| External recon only (Phase 1) | Tenant domain in scope.json | 5 minutes |
| Full credential testing (Phase 2) | 2 honeypot accounts + admin auth | 30 minutes setup |
| All 8 phases | Honeypots + test account + MFA on test account | 1 hour setup |
