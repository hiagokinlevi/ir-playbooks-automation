<#
.SYNOPSIS
    Revoke all active Azure AD / Entra ID sessions for a compromised user account.

.DESCRIPTION
    This script invalidates all refresh tokens and active sessions for a specified
    Azure AD user by calling the Microsoft Graph API revoke endpoint.

    What it does:
      1. Connects to Microsoft Graph (requires AzureAD or Microsoft.Graph module)
      2. Looks up the user by UPN or Object ID
      3. Calls revokeSignInSessions to invalidate all active tokens
      4. Tags the action in the Azure AD audit log (native behavior)
      5. Outputs a structured result for the incident record

    IMPORTANT:
      - This action takes effect within ~1 minute but may take up to 15 minutes
        to propagate across all Microsoft services.
      - The user will be signed out of all Microsoft apps and services immediately.
      - Notify the account owner via a secure out-of-band channel before executing.
      - Requires the following Azure AD roles: User Administrator or Security Administrator.

    After running this script:
      - Force a password reset for the affected user
      - Require MFA re-enrollment before allowing access
      - Monitor authentication logs for re-authentication attempts from suspect IPs

.PARAMETER UserPrincipalName
    The UPN (email address) of the compromised user account. Example: jdoe@company.com

.PARAMETER IncidentId
    The IR ticket ID for tracking. Example: INC-20250101-001

.PARAMETER DryRun
    If specified, validates connectivity and user lookup but does not revoke sessions.
    Always test with -DryRun first in new environments.

.EXAMPLE
    # Dry run — validate without making changes
    .\revoke_azure_sessions.ps1 -UserPrincipalName "jdoe@company.com" -IncidentId "INC-20250101-001" -DryRun

.EXAMPLE
    # Execute revocation (requires confirmation prompt)
    .\revoke_azure_sessions.ps1 -UserPrincipalName "jdoe@company.com" -IncidentId "INC-20250101-001"

.NOTES
    Required modules: Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
    Required scopes: User.ReadWrite.All, Directory.ReadWrite.All
    Tested on: PowerShell 7.x, Microsoft.Graph 2.x
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    # UPN or Object ID of the Azure AD user to act on
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    # IR ticket ID for audit trail purposes
    [Parameter(Mandatory = $true)]
    [string]$IncidentId,

    # When set, validates prerequisites but takes no action
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"   # Treat all errors as terminating — fail fast

# Record execution start time for the audit log
$StartedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "[k1n-ir] Azure AD Session Revocation" -ForegroundColor Cyan
Write-Host "[k1n-ir] Incident ID : $IncidentId" -ForegroundColor Cyan
Write-Host "[k1n-ir] Target User : $UserPrincipalName" -ForegroundColor Cyan
Write-Host "[k1n-ir] Started At  : $StartedAt" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "[k1n-ir] MODE: DRY RUN — No changes will be made" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 1: Verify the Microsoft.Graph module is available
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph")) {
    throw "Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
}

# ---------------------------------------------------------------------------
# Step 2: Connect to Microsoft Graph with the required scopes
#   - User.ReadWrite.All: required for revokeSignInSessions
#   - AuditLog.Read.All: optional, for pulling sign-in logs after revocation
# ---------------------------------------------------------------------------
Write-Host "[k1n-ir] Connecting to Microsoft Graph..." -ForegroundColor Gray

$RequiredScopes = @("User.ReadWrite.All", "AuditLog.Read.All")

try {
    # Connect interactively or via service principal depending on environment
    # For automated pipelines, use -ClientSecretCredential or -CertificateThumbprint
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    Write-Host "[k1n-ir] Connected to Microsoft Graph" -ForegroundColor Green
} catch {
    throw "Failed to connect to Microsoft Graph: $_"
}

# ---------------------------------------------------------------------------
# Step 3: Look up the target user
# ---------------------------------------------------------------------------
Write-Host "[k1n-ir] Looking up user: $UserPrincipalName" -ForegroundColor Gray

try {
    $User = Get-MgUser -UserId $UserPrincipalName -Property "Id,DisplayName,UserPrincipalName,AccountEnabled"
} catch {
    throw "User '$UserPrincipalName' not found in Azure AD: $_"
}

Write-Host "[k1n-ir] User found: $($User.DisplayName) ($($User.Id))" -ForegroundColor Green
Write-Host "[k1n-ir] Account enabled: $($User.AccountEnabled)" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Step 4: Dry run exit point — stop here if -DryRun was specified
# ---------------------------------------------------------------------------
if ($DryRun) {
    Write-Host "[k1n-ir] DRY RUN complete. User validated. No sessions revoked." -ForegroundColor Yellow
    Write-Output @{
        DryRun          = $true
        UserPrincipalName = $UserPrincipalName
        UserId          = $User.Id
        DisplayName     = $User.DisplayName
        IncidentId      = $IncidentId
        ExecutedAt      = $StartedAt
    }
    Disconnect-MgGraph | Out-Null
    exit 0
}

# ---------------------------------------------------------------------------
# Step 5: Confirmation prompt before executing destructive action
# ---------------------------------------------------------------------------
$Confirm = Read-Host "[k1n-ir] WARNING: This will sign out '$($User.DisplayName)' from ALL sessions. Type 'CONFIRM' to proceed"
if ($Confirm -ne "CONFIRM") {
    Write-Host "[k1n-ir] Revocation cancelled by operator." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    exit 0
}

# ---------------------------------------------------------------------------
# Step 6: Revoke all sign-in sessions
#   revokeSignInSessions invalidates all refresh tokens and session cookies
# ---------------------------------------------------------------------------
Write-Host "[k1n-ir] Revoking sign-in sessions for $UserPrincipalName..." -ForegroundColor Yellow

try {
    # This call forces re-authentication on next access attempt
    $RevokeResult = Invoke-MgRevokeUserSignInSession -UserId $User.Id

    $RevokedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "[k1n-ir] Sessions revoked successfully at $RevokedAt" -ForegroundColor Green
} catch {
    throw "Failed to revoke sessions for '$UserPrincipalName': $_"
}

# ---------------------------------------------------------------------------
# Step 7: Output result for incident record
# ---------------------------------------------------------------------------
$Result = @{
    DryRun            = $false
    UserPrincipalName = $UserPrincipalName
    UserId            = $User.Id
    DisplayName       = $User.DisplayName
    IncidentId        = $IncidentId
    SessionsRevoked   = $true
    RevokedAt         = $RevokedAt
    NextSteps         = @(
        "Force password reset for the user",
        "Require MFA re-enrollment before restoring access",
        "Monitor sign-in logs for re-authentication from suspect IPs",
        "Review Azure AD audit log: sign-ins for this user in the past 72h"
    )
}

Write-Host ""
Write-Host "[k1n-ir] === REVOCATION COMPLETE ===" -ForegroundColor Green
Write-Host "[k1n-ir] User         : $($Result.UserPrincipalName)" -ForegroundColor Green
Write-Host "[k1n-ir] Revoked At   : $($Result.RevokedAt)" -ForegroundColor Green
Write-Host "[k1n-ir] Incident ID  : $($Result.IncidentId)" -ForegroundColor Green
Write-Host ""
Write-Host "[k1n-ir] Next Steps:" -ForegroundColor Cyan
foreach ($step in $Result.NextSteps) {
    Write-Host "  - $step" -ForegroundColor Cyan
}

# Clean up the Graph session
Disconnect-MgGraph | Out-Null

Write-Output $Result
