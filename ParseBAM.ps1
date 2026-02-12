#Requires Administrator privileges to access HKLM\SYSTEM
#Wrapper to ensure the script runs as Admin
#Collects Local Background Activity Monitor Registry Keys for all users and then outputs CSV file in same directory named BAM_Activity_Report.csv with Columns SID, User, Application, Time (UTC)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges to access the Registry. Please run PowerShell as Administrator."
    Break
}

# Define the BAM Registry Path
$BamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

# Initialize an array to hold the results
$Results = @()

# Check if the path exists
if (Test-Path $BamPath) {
    # Get all User SIDs (Subkeys)
    $UserSids = Get-ChildItem -Path $BamPath

    foreach ($SidKey in $UserSids) {
        $SidString = $SidKey.PSChildName
        
        # Attempt to resolve SID to Username
        try {
            $ObjSID = New-Object System.Security.Principal.SecurityIdentifier($SidString)
            $ObjUser = $ObjSID.Translate([System.Security.Principal.NTAccount])
            $UserName = $ObjUser.Value
        }
        catch {
            $UserName = "Unknown/Deleted User"
        }

        # Get all values (Application Paths) under the SID key
        $RegValues = Get-ItemProperty -Path $SidKey.PSPath

        # Iterate through each property (Application Path)
        foreach ($Property in $RegValues.PSObject.Properties) {
            $AppName = $Property.Name
            $BinaryData = $Property.Value

            # Filter out default PowerShell properties and BAM metadata
            if ($AppName -match "^(PSPath|PSParentPath|PSChildName|PSDrive|PSProvider|SequenceNumber|Version)$") {
                continue
            }

            # BAM timestamps are 64-bit FILETIME structures. 
            # They are usually found in the first 8 bytes of the binary data.
            $UtcTime = $null
            
            if ($BinaryData -is [byte[]] -and $BinaryData.Length -ge 8) {
                try {
                    # Convert the first 8 bytes to an Int64
                    $FileTimeInt = [System.BitConverter]::ToInt64($BinaryData, 0)
                    
                    # Convert FileTime to DateTime (UTC)
                    $UtcTime = [DateTime]::FromFileTimeUtc($FileTimeInt)
                }
                catch {
                    $UtcTime = "Error Parsing Time"
                }
            }
            elseif ($BinaryData -is [long] -or $BinaryData -is [int]) {
                 # Occasionally stored directly as integer
                 try {
                    $UtcTime = [DateTime]::FromFileTimeUtc($BinaryData)
                 } catch {
                    $UtcTime = "Error Parsing Time"
                 }
            }

            # Create a custom object for the row
            $Object = [PSCustomObject]@{
                SID           = $SidString
                User          = $UserName
                Application   = $AppName
                'Time (UTC)'  = $UtcTime
            }

            $Results += $Object
        }
    }

    # Define Output File Name
    $OutputFile = ".\BAM_Activity_Report.csv"

    # Export to CSV
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    
    Write-Host "Success! Report generated at: $OutputFile" -ForegroundColor Green
    Write-Host "Total entries found: $($Results.Count)"
}
else {
    Write-Error "BAM Registry path not found. This feature might not be active on this version of Windows."
}
