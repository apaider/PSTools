<#
.SYNOPSIS
Standardizes the DisplayName of Active Directory users to 'GivenName Surname'.

.DESCRIPTION
This script iterates through all Active Directory users, verifies that they have
both a GivenName (First Name) and Surname (Last Name), and updates their
DisplayName attribute to the format: "First Name Last Name".
It logs all changes and skips users that are already correctly formatted.

.PARAMETER ApplyChanges
If specified, the script will execute Set-ADUser commands to apply the changes.
If omitted, the script runs in -WhatIf mode, showing only what *would* be changed.

.NOTES
Requires the Active Directory PowerShell Module.
Run with appropriate permissions (e.g., Domain Admin or User Management role).
#>
param(
    [switch]$ApplyChanges
)

# --- Configuration ---
$ReportPath = ".\AD_DisplayName_Update_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Log = @()
$TotalUsersProcessed = 0
$UsersUpdated = 0
$UsersSkipped = 0
# ---------------------

# 1. Check for and import the Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The Active Directory module is not installed or available on this system. Cannot proceed."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# Define the Set-ADUser parameter set based on the $ApplyChanges switch
$SetADUserParams = @{}
if (-not $ApplyChanges) {
    $SetADUserParams.Add('WhatIf', $true)
    Write-Host "--- Running in PREVIEW mode. No changes will be saved. To apply changes, run the script with -ApplyChanges ---" -ForegroundColor Yellow
} else {
    Write-Host "--- Running in APPLY mode. Changes WILL be saved to Active Directory. ---" -ForegroundColor Red
}

Write-Host "Retrieving all Active Directory users..." -ForegroundColor Cyan

# 2. Retrieve all users, ensuring we get the necessary properties
$ADUsers = Get-ADUser -Filter {Enabled -eq $True -and SamAccountName -notlike "*-*"} -Properties GivenName, Surname, DisplayName -ErrorAction Stop

Write-Host "Found $($ADUsers.Count) enabled users to process." -ForegroundColor Cyan

# 3. Loop through each user
foreach ($User in $ADUsers) {
    $TotalUsersProcessed++

    $FirstName = $User.GivenName
    $LastName = $User.Surname
    $CurrentDisplayName = $User.DisplayName

    # Skip users missing crucial name fields (likely service accounts or incomplete entries)
    if ([string]::IsNullOrEmpty($FirstName) -or [string]::IsNullOrEmpty($LastName)) {
        $LogEntry = [PSCustomObject]@{
            SamAccountName   = $User.SamAccountName
            Status           = "Skipped (Missing Name Data)"
            CurrentName      = $CurrentDisplayName
            NewNameProposed  = "N/A"
            Reason           = "Missing GivenName or Surname"
        }
        $Log += $LogEntry
        $UsersSkipped++
        continue
    }

    # 4. Construct the desired display name
    $NewDisplayName = "$FirstName $LastName"

    # 5. Compare and update only if necessary
    if ($CurrentDisplayName -ne $NewDisplayName) {
        Write-Host "Updating $($User.SamAccountName): '$CurrentDisplayName' -> '$NewDisplayName'" -ForegroundColor Green

        try {
            # 6. Perform the update using splatting for conditional parameters
            Set-ADUser -Identity $User.SamAccountName -DisplayName $NewDisplayName @SetADUserParams -ErrorAction Stop
            $UsersUpdated++
            $Status = "Updated"
            $Reason = "Name mismatch"

        } catch {
            Write-Error "Failed to update $($User.SamAccountName): $($_.Exception.Message)"
            $Status = "Failed"
            $Reason = $_.Exception.Message
        }
    } else {
        # 7. Log users that are already correct
        Write-Host "Skipping $($User.SamAccountName): DisplayName is already correct ('$CurrentDisplayName')" -ForegroundColor Gray
        $UsersSkipped++
        $Status = "Skipped (Already Correct)"
        $Reason = "DisplayName matches 'GivenName Surname'"
    }

    # Record the action in the log
    $LogEntry = [PSCustomObject]@{
        SamAccountName   = $User.SamAccountName
        Status           = $Status
        CurrentName      = $CurrentDisplayName
        NewNameProposed  = $NewDisplayName
        Reason           = $Reason
    }
    $Log += $LogEntry
}

# 8. Final Report
Write-Host ""
Write-Host "--- SCRIPT SUMMARY ---" -ForegroundColor Yellow
Write-Host "Total Users Processed: $TotalUsersProcessed" -ForegroundColor White
Write-Host "Users Updated: $UsersUpdated" -ForegroundColor Green
Write-Host "Users Skipped: $UsersSkipped" -ForegroundColor Cyan
Write-Host "Full detailed report saved to: $ReportPath" -ForegroundColor Magenta

# Export the log to a CSV file
$Log | Export-Csv -Path $ReportPath -NoTypeInformation

# 9. Instruction for user based on mode
if (-not $ApplyChanges) {
    Write-Host ""
    Write-Host "To apply these changes, run the script again with the '-ApplyChanges' switch." -ForegroundColor Red
}
