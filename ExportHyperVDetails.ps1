<#
.SYNOPSIS
    Exports critical documentation for a Hyper-V host and its virtual machines
    (including networking settings) to a single HTML report.

.DESCRIPTION
    Run this directly on the Hyper-V host in an elevated (Administrator)
    PowerShell session. It collects:

      - Host details: OS, hardware, CPU/memory, Hyper-V settings, live migration config
      - Host physical NICs and NIC teams / switch-embedded teams
      - Virtual switches (type, uplinks, embedded teaming, extensions)
      - Per-VM configuration: generation, vCPU, memory (static/dynamic), state,
        integration services, checkpoints, auto start/stop actions, replication
      - Per-VM networking: vNICs, connected switch, MAC (static/dynamic),
        VLAN mode/ID, guest IP addresses, advanced features (DHCP guard,
        router guard, port mirroring, MAC spoofing)
      - Per-VM storage: VHD/VHDX paths, type, format, sizes, controller mapping

.PARAMETER OutputPath
    Folder where the report is written. Defaults to C:\HyperV-Docs.

.EXAMPLE
    .\Export-HyperVDocumentation.ps1
    .\Export-HyperVDocumentation.ps1 -OutputPath D:\Runbooks
#>

[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\HyperV-Docs'
)

#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

$ErrorActionPreference = 'Stop'
$timestamp  = Get-Date -Format 'yyyy-MM-dd_HHmm'
$hostName   = $env:COMPUTERNAME
$reportFile = Join-Path $OutputPath "HyperV-Documentation_${hostName}_$timestamp.html"

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "Collecting Hyper-V documentation for host '$hostName'..." -ForegroundColor Cyan

# ---------------------------------------------------------------- Host details
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$vmHost = Get-VMHost

$hostInfo = [PSCustomObject]@{
    'Host Name'                  = $hostName
    'Manufacturer / Model'       = "$($cs.Manufacturer) $($cs.Model)"
    'Serial Number'              = $bios.SerialNumber
    'Operating System'           = "$($os.Caption) (Build $($os.BuildNumber))"
    'Last Boot'                  = $os.LastBootUpTime
    'Logical Processors'         = $vmHost.LogicalProcessorCount
    'Total Memory (GB)'          = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    'Default VM Path'            = $vmHost.VirtualMachinePath
    'Default VHD Path'           = $vmHost.VirtualHardDiskPath
    'Live Migrations Enabled'    = $vmHost.VirtualMachineMigrationEnabled
    'Simultaneous Live Migrations' = $vmHost.MaximumVirtualMachineMigrations
    'Simultaneous Storage Migrations' = $vmHost.MaximumStorageMigrations
    'Migration Auth Type'        = $vmHost.VirtualMachineMigrationAuthenticationType
    'NUMA Spanning Enabled'      = $vmHost.NumaSpanningEnabled
    'Enhanced Session Mode'      = $vmHost.EnableEnhancedSessionMode
}

# ------------------------------------------------- Host physical NICs & teams
$physNics = Get-NetAdapter -Physical | Sort-Object Name | ForEach-Object {
    $ipconf = Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue |
              Where-Object { $_.AddressFamily -eq 'IPv4' }
    [PSCustomObject]@{
        'Adapter'      = $_.Name
        'Description'  = $_.InterfaceDescription
        'Status'       = $_.Status
        'Speed'        = $_.LinkSpeed
        'MAC'          = $_.MacAddress
        'IPv4 Address' = ($ipconf.IPAddress -join ', ')
        'VLAN'         = $_.VlanID
    }
}

$nicTeams = Get-NetLbfoTeam -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        'Team Name'    = $_.Name
        'Members'      = ($_.Members -join ', ')
        'Teaming Mode' = $_.TeamingMode
        'LB Algorithm' = $_.LoadBalancingAlgorithm
        'Status'       = $_.Status
    }
}

# ------------------------------------------------------------ Virtual switches
$vSwitches = Get-VMSwitch | ForEach-Object {
    $sw = $_
    $uplink = switch ($sw.SwitchType) {
        'External' {
            if ($sw.EmbeddedTeamingEnabled) {
                (Get-VMSwitchTeam -Name $sw.Name -ErrorAction SilentlyContinue).NetAdapterInterfaceDescription -join ', '
            } else {
                $sw.NetAdapterInterfaceDescription
            }
        }
        default { 'n/a' }
    }
    [PSCustomObject]@{
        'Switch Name'        = $sw.Name
        'Type'               = $sw.SwitchType
        'Uplink Adapter(s)'  = $uplink
        'SET Enabled'        = $sw.EmbeddedTeamingEnabled
        'Allow Mgmt OS'      = $sw.AllowManagementOS
        'Bandwidth Mode'     = $sw.BandwidthReservationMode
        'IOV Enabled'        = $sw.IovEnabled
        'Notes'              = $sw.Notes
    }
}

# ---------------------------------------------------------------- VM inventory
$vms = Get-VM | Sort-Object Name

$vmSummary = $vms | ForEach-Object {
    $mem = if ($_.DynamicMemoryEnabled) {
        "Dynamic: $([math]::Round($_.MemoryMinimum/1GB,1))-$([math]::Round($_.MemoryMaximum/1GB,1)) GB (startup $([math]::Round($_.MemoryStartup/1GB,1)) GB)"
    } else {
        "Static: $([math]::Round($_.MemoryStartup/1GB,1)) GB"
    }
    [PSCustomObject]@{
        'VM Name'        = $_.Name
        'State'          = $_.State
        'Generation'     = $_.Generation
        'vCPU'           = $_.ProcessorCount
        'Memory'         = $mem
        'Version'        = $_.Version
        'Checkpoint Type' = $_.CheckpointType
        'Auto Start'     = $_.AutomaticStartAction
        'Auto Stop'      = $_.AutomaticStopAction
        'Replication'    = $_.ReplicationState
        'Config Path'    = $_.ConfigurationLocation
        'Uptime'         = if ($_.State -eq 'Running') { $_.Uptime.ToString('d\.hh\:mm') } else { '-' }
    }
}

# ------------------------------------------------------------- VM networking
$vmNetwork = foreach ($vm in $vms) {
    foreach ($nic in (Get-VMNetworkAdapter -VM $vm)) {
        $vlan = Get-VMNetworkAdapterVlan -VMNetworkAdapter $nic
        $vlanText = switch ($vlan.OperationMode) {
            'Access'  { "Access, VLAN $($vlan.AccessVlanId)" }
            'Trunk'   { "Trunk, Native $($vlan.NativeVlanId), Allowed $($vlan.AllowedVlanIdList)" }
            'Private' { "Private, $($vlan.PrivateVlanMode)" }
            default   { 'Untagged' }
        }
        [PSCustomObject]@{
            'VM Name'       = $vm.Name
            'Adapter'       = $nic.Name
            'Virtual Switch' = if ($nic.SwitchName) { $nic.SwitchName } else { 'Not connected' }
            'MAC Address'   = $nic.MacAddress
            'MAC Type'      = if ($nic.DynamicMacAddressEnabled) { 'Dynamic' } else { 'Static' }
            'VLAN'          = $vlanText
            'Guest IP(s)'   = ($nic.IPAddresses | Where-Object { $_ -notmatch '^fe80' }) -join ', '
            'MAC Spoofing'  = $nic.MacAddressSpoofing
            'DHCP Guard'    = $nic.DhcpGuard
            'Router Guard'  = $nic.RouterGuard
            'Port Mirroring' = $nic.PortMirroringMode
            'VMQ Weight'    = $nic.VmqWeight
        }
    }
}

# ---------------------------------------------------------------- VM storage
$vmStorage = foreach ($vm in $vms) {
    foreach ($drive in (Get-VMHardDiskDrive -VM $vm)) {
        $vhdInfo = $null
        if ($drive.Path -and (Test-Path $drive.Path)) {
            $vhdInfo = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
        }
        [PSCustomObject]@{
            'VM Name'        = $vm.Name
            'Controller'     = "$($drive.ControllerType) $($drive.ControllerNumber):$($drive.ControllerLocation)"
            'Path'           = $drive.Path
            'Format'         = $vhdInfo.VhdFormat
            'Type'           = $vhdInfo.VhdType
            'Current Size (GB)' = if ($vhdInfo) { [math]::Round($vhdInfo.FileSize/1GB,1) } else { $null }
            'Max Size (GB)'  = if ($vhdInfo) { [math]::Round($vhdInfo.Size/1GB,1) } else { $null }
        }
    }
}

# ---------------------------------------------------- Integration services
$vmIntegration = foreach ($vm in $vms) {
    $svc = Get-VMIntegrationService -VM $vm
    [PSCustomObject]@{
        'VM Name'  = $vm.Name
        'Enabled'  = ($svc | Where-Object Enabled  | Select-Object -ExpandProperty Name) -join ', '
        'Disabled' = ($svc | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name) -join ', '
    }
}

# ------------------------------------------------------------ Checkpoints
$vmCheckpoints = foreach ($vm in $vms) {
    foreach ($cp in (Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue)) {
        [PSCustomObject]@{
            'VM Name'      = $vm.Name
            'Checkpoint'   = $cp.Name
            'Type'         = $cp.SnapshotType
            'Created'      = $cp.CreationTime
            'Parent'       = $cp.ParentSnapshotName
        }
    }
}

# --------------------------------------------------------------- Build HTML
$style = @"
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; margin: 2em; color: #1a1a2e; }
  h1    { color: #0f3460; border-bottom: 3px solid #0f3460; padding-bottom: 6px; }
  h2    { color: #16537e; margin-top: 2em; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; margin: 0.5em 0 1.5em; font-size: 13px; }
  th    { background: #0f3460; color: #fff; text-align: left; padding: 7px 10px; }
  td    { border: 1px solid #d0d0d0; padding: 6px 10px; vertical-align: top; }
  tr:nth-child(even) td { background: #f4f6fa; }
  .meta { color: #666; font-size: 12px; }
  .empty { color: #888; font-style: italic; }
</style>
"@

function ConvertTo-Section {
    param([string]$Title, $Data, [switch]$Vertical)
    $html = "<h2>$Title</h2>"
    if (-not $Data) { return $html + "<p class='empty'>None found.</p>" }
    if ($Vertical) {
        $html += ($Data | ConvertTo-Html -Fragment -As List) -join "`n"
    } else {
        $html += ($Data | ConvertTo-Html -Fragment) -join "`n"
    }
    return $html
}

$body = @(
    "<h1>Hyper-V Host Documentation &mdash; $hostName</h1>"
    "<p class='meta'>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $env:USERDOMAIN\$env:USERNAME &bull; $($vms.Count) VM(s) found</p>"
    (ConvertTo-Section 'Host Details' $hostInfo -Vertical)
    (ConvertTo-Section 'Host Physical Network Adapters' $physNics)
    (ConvertTo-Section 'NIC Teams (LBFO)' $nicTeams)
    (ConvertTo-Section 'Virtual Switches' $vSwitches)
    (ConvertTo-Section 'Virtual Machines' $vmSummary)
    (ConvertTo-Section 'VM Network Adapters' $vmNetwork)
    (ConvertTo-Section 'VM Storage (VHD/VHDX)' $vmStorage)
    (ConvertTo-Section 'VM Integration Services' $vmIntegration)
    (ConvertTo-Section 'VM Checkpoints' $vmCheckpoints)
) -join "`n"

ConvertTo-Html -Head $style -Body $body -Title "Hyper-V Documentation - $hostName" |
    Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Done. Report written to:`n  $reportFile" -ForegroundColor Green