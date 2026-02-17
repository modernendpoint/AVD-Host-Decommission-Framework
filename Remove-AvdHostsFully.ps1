<#
.SYNOPSIS
Fully removes AVD session hosts + Azure VM resources + Entra ID device + Intune device.

.DESCRIPTION
Default mode is DRY RUN (WhatIf). Use -Execute to actually delete.
Best-effort: if modules/PSGallery blocked, script will skip unavailable steps and continue.

Requires (auto-installed if possible):
- Az.Accounts, Az.Compute, Az.Network, Az.DesktopVirtualization
- Microsoft.Graph (Device + Intune scopes)

EXAMPLE:
.\Remove-AvdHostsFully.ps1 `
  -SubscriptionId "<sub>" `
  -AvdResourceGroup "RG-AVD" `
  -HostPoolName "POOL" `
  -VmNames @("VM1","VM2") `
  -WaitForZeroSessions `
  -TimeoutMinutes 30 `
  -Execute

BULK EXAMPLE (CSV with VmName column):
.\Remove-AvdHostsFully.ps1 `
  -SubscriptionId "<sub>" `
  -AvdResourceGroup "RG-AVD" `
  -HostPoolName "POOL" `
  -BulkFile "C:\Temp\vms.csv" `
  -Execute

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$AvdResourceGroup,

    [Parameter(Mandatory)]
    [string]$HostPoolName,

    [string[]]$VmNames,

    [string]$BulkFile,

    [switch]$WaitForZeroSessions,

    # If enabled, will attempt to logoff existing sessions before waiting.
    [switch]$ForceLogoffSessions,

    [int]$TimeoutMinutes = 30,

    # Optional: attempt to delete NIC-attached NSGs only if they are NOT referenced anywhere else
    [switch]$RemoveNsgIfUnshared,

    # Execute deletions (default is DRY RUN)
    [switch]$Execute,

    [string]$LogPath = "C:\Temp\AVD-Cleanup\Remove-AvdHostsFully.log"
)

# ------------------ Bulk --------------------
function Get-BulkVmNames {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return @() }
    if (-not (Test-Path $Path)) { throw "BulkFile not found: $Path" }

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($ext -eq ".csv") {
        $rows = Import-Csv -Path $Path
        if (-not ($rows | Get-Member -Name "VmName" -MemberType NoteProperty)) {
            throw "CSV must contain a column named 'VmName'."
        }
        return @(
            $rows |
            ForEach-Object { $_.VmName } |
            Where-Object { $_ -and $_.Trim() } |
            ForEach-Object { $_.Trim() } |
            Select-Object -Unique
        )
    }

    return @(
        Get-Content -Path $Path -ErrorAction Stop |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") } |
        Select-Object -Unique
    )
}

# ------------------ Logging ------------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue } catch {}
}

# ------------------ Helpers ------------------
function Escape-ODataString {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    return $Value.Replace("'", "''")
}

# ------------------ Module bootstrap (best effort) ------------------
function Ensure-Modules {
    param(
        [switch]$SkipGraph,
        [switch]$SkipAz
    )

    function Ensure-PSGalleryTrusted {
        try {
            $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
            if (-not $nuget -or $nuget.Version -lt [version]"2.8.5.201") {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
            }
        } catch {}

        try {
            $repo = Get-PSRepository -Name "PSGallery" -ErrorAction Stop
            if ($repo.InstallationPolicy -ne "Trusted") {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted | Out-Null
            }
        } catch {}
    }

    function Ensure-Module {
        param(
            [Parameter(Mandatory)][string]$Name,
            [string]$MinimumVersion = $null
        )

        $found = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
        if ($found) { return $true }

        Ensure-PSGalleryTrusted

        try {
            Write-Log "Module '$Name' missing. Attempting install (CurrentUser)..." "WARN"
            if ($MinimumVersion) {
                Install-Module $Name -Scope CurrentUser -Force -AllowClobber -MinimumVersion $MinimumVersion -ErrorAction Stop
            } else {
                Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            return $true
        } catch {
            Write-Log "Failed to install module '$Name': $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    $global:AzReady = $true
    if (-not $SkipAz) {
        $azMods = @("Az.Accounts","Az.Compute","Az.Network","Az.DesktopVirtualization")
        foreach ($m in $azMods) {
            if (-not (Ensure-Module -Name $m)) { $global:AzReady = $false }
        }
        if (-not $global:AzReady) {
            Write-Log "Az modules not fully available. Azure/AVD operations may be skipped." "ERROR"
        }
    } else {
        $global:AzReady = $false
    }

    $global:GraphReady = $true
    if (-not $SkipGraph) {
        if (-not (Ensure-Module -Name "Microsoft.Graph")) {
            $global:GraphReady = $false
            Write-Log "Microsoft.Graph module not available. Entra/Intune deletion will be skipped." "WARN"
        }
    } else {
        $global:GraphReady = $false
    }
}

function Connect-Contexts {
    if ($global:AzReady) {
        Write-Log "Connecting to Azure..."
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        } catch {
            $global:AzReady = $false
            Write-Log "Azure connection failed: $($_.Exception.Message). Azure/AVD steps will be skipped." "ERROR"
        }
    } else {
        Write-Log "Az modules not ready. Skipping Azure login." "WARN"
    }

    if ($global:GraphReady) {
        Write-Log "Connecting to Microsoft Graph..."
        try {
            $scopes = @(
                "Device.ReadWrite.All",
                "DeviceManagementManagedDevices.ReadWrite.All"
            )
            Connect-MgGraph -Scopes $scopes -ErrorAction Stop | Out-Null
        } catch {
            $global:GraphReady = $false
            Write-Log "Graph connection failed: $($_.Exception.Message). Entra/Intune steps will be skipped." "WARN"
        }
    } else {
        Write-Log "Graph module not ready. Skipping Graph login." "WARN"
    }
}

# ------------------ AVD helpers ------------------
function Resolve-AvdSessionHostName {
    param(
        [string]$AvdRg,
        [string]$Pool,
        [string]$VmName
    )

    if (-not $global:AzReady) { return $null }

    $hosts = Get-AzWvdSessionHost -ResourceGroupName $AvdRg -HostPoolName $Pool -ErrorAction SilentlyContinue
    if (-not $hosts) { return $null }

    foreach ($h in $hosts) {
        $name = [string]$h.Name

        $leaf = if ($name -match "/sessionHosts/") {
            ($name -split "/sessionHosts/")[-1]
        } elseif ($name -match "/") {
            ($name -split "/")[-1]
        } else {
            $name
        }

        if ($leaf -ieq $VmName -or $leaf -like "$VmName*") {
            return $leaf
        }
    }
    return $null
}

function Set-DrainMode {
    param([string]$AvdRg, [string]$Pool, [string]$SessionHostName)

    if (-not $global:AzReady) { return }

    if ($PSCmdlet.ShouldProcess("AVD SessionHost '$SessionHostName'", "Set AllowNewSession = false")) {
        Write-Log "Setting drain mode for '$SessionHostName'..."
        Update-AzWvdSessionHost -ResourceGroupName $AvdRg -HostPoolName $Pool -Name $SessionHostName -AllowNewSession:$false -ErrorAction SilentlyContinue
    }
}

function Get-HostSessions {
    param([string]$AvdRg, [string]$Pool, [string]$SessionHostName)

    if (-not $global:AzReady) { return @() }

    $sessions = Get-AzWvdUserSession -ResourceGroupName $AvdRg -HostPoolName $Pool -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionHostName -ieq $SessionHostName }

    return @($sessions)
}

function Logoff-HostSessions {
    param([string]$AvdRg, [string]$Pool, [string]$SessionHostName)

    if (-not $global:AzReady) { return }

    $sessions = Get-HostSessions -AvdRg $AvdRg -Pool $Pool -SessionHostName $SessionHostName
    foreach ($s in $sessions) {
        # Some tenants expose session id differently; best-effort attempt
        $sid = $s.Id
        if (-not $sid) { continue }

        if ($PSCmdlet.ShouldProcess("UserSession '$sid' on '$SessionHostName'", "Remove-AzWvdUserSession (logoff)")) {
            Write-Log "Logging off session Id: $sid on $SessionHostName"
            try {
                Remove-AzWvdUserSession -ResourceGroupName $AvdRg -HostPoolName $Pool -SessionHostName $SessionHostName -Id $sid -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Failed to logoff session '$sid' on '$SessionHostName': $($_.Exception.Message)" "WARN"
            }
        }
    }
}

function Wait-ZeroSessions {
    param([string]$AvdRg, [string]$Pool, [string]$SessionHostName, [int]$TimeoutMin)

    if (-not $global:AzReady) { return $false }

    $deadline = (Get-Date).AddMinutes($TimeoutMin)
    while ((Get-Date) -lt $deadline) {
        $sessions = Get-HostSessions -AvdRg $AvdRg -Pool $Pool -SessionHostName $SessionHostName
        $count = $sessions.Count
        Write-Log "Sessions on '$SessionHostName': $count"
        if ($count -eq 0) { return $true }
        Start-Sleep -Seconds 15
    }
    return $false
}

function Remove-FromAvdHostPool {
    param([string]$AvdRg, [string]$Pool, [string]$SessionHostName)

    if (-not $global:AzReady) {
        Write-Log "Az not ready. Skipping AVD removal for '$SessionHostName'." "WARN"
        return
    }

    if ($PSCmdlet.ShouldProcess("AVD SessionHost '$SessionHostName'", "Remove-AzWvdSessionHost")) {
        Write-Log "Removing session host '$SessionHostName' from host pool '$Pool'..."
        Remove-AzWvdSessionHost -ResourceGroupName $AvdRg -HostPoolName $Pool -Name $SessionHostName -Force -ErrorAction SilentlyContinue
    }
}

# ------------------ Azure resource deletion ------------------
function Remove-AzureVmAndResources {
    param([string]$Rg, [string]$VmName, [switch]$RemoveNsgIfUnshared)

    if (-not $global:AzReady) {
        Write-Log "Az not ready. Skipping Azure VM/resource deletion for '$VmName'." "WARN"
        return
    }

    $vm = Get-AzVM -ResourceGroupName $Rg -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Log "VM '$VmName' not found in RG '$Rg'. Skipping Azure VM resource deletion." "WARN"
        return
    }

    $osDiskName = $vm.StorageProfile.OsDisk.Name
    $dataDiskNames = @($vm.StorageProfile.DataDisks | ForEach-Object { $_.Name })

    $nicIds = @($vm.NetworkProfile.NetworkInterfaces.Id)
    $nicObjs = foreach ($nicId in $nicIds) {
        Get-AzNetworkInterface -ResourceId $nicId -ErrorAction SilentlyContinue
    } | Where-Object { $_ }

    $nsgCandidates = @()
    foreach ($nic in $nicObjs) {
        if ($nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id) {
            $nsg = Get-AzNetworkSecurityGroup -ResourceId $nic.NetworkSecurityGroup.Id -ErrorAction SilentlyContinue
            if ($nsg) { $nsgCandidates += $nsg }
        }
    }
    $nsgCandidates = @($nsgCandidates | Select-Object -Unique)

    if ($PSCmdlet.ShouldProcess("Azure VM '$VmName' in '$Rg'", "Remove-AzVM")) {
        Write-Log "Deleting VM '$VmName'..."
        Remove-AzVM -ResourceGroupName $Rg -Name $VmName -Force -ErrorAction Stop
    }

    if ($osDiskName -and $PSCmdlet.ShouldProcess("OS Disk '$osDiskName'", "Remove-AzDisk")) {
        Write-Log "Deleting OS disk '$osDiskName'..."
        Remove-AzDisk -ResourceGroupName $Rg -DiskName $osDiskName -Force -ErrorAction SilentlyContinue
    }

    foreach ($dd in $dataDiskNames) {
        if ($dd -and $PSCmdlet.ShouldProcess("Data Disk '$dd'", "Remove-AzDisk")) {
            Write-Log "Deleting data disk '$dd'..."
            Remove-AzDisk -ResourceGroupName $Rg -DiskName $dd -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($nic in $nicObjs) {
        $pipIds = @()
        foreach ($ipcfg in $nic.IpConfigurations) {
            if ($ipcfg.PublicIpAddress -and $ipcfg.PublicIpAddress.Id) { $pipIds += $ipcfg.PublicIpAddress.Id }
        }

        if ($PSCmdlet.ShouldProcess("NIC '$($nic.Name)'", "Remove-AzNetworkInterface")) {
            Write-Log "Deleting NIC '$($nic.Name)'..."
            Remove-AzNetworkInterface -ResourceGroupName $Rg -Name $nic.Name -Force -ErrorAction SilentlyContinue
        }

        foreach ($pipId in $pipIds) {
            $pip = Get-AzPublicIpAddress -ResourceId $pipId -ErrorAction SilentlyContinue
            if ($pip -and $PSCmdlet.ShouldProcess("Public IP '$($pip.Name)'", "Remove-AzPublicIpAddress")) {
                Write-Log "Deleting Public IP '$($pip.Name)'..."
                Remove-AzPublicIpAddress -ResourceGroupName $Rg -Name $pip.Name -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($RemoveNsgIfUnshared -and $nsgCandidates.Count -gt 0) {
        foreach ($nsg in $nsgCandidates) {
            $stillUsed = $false

            $allNics = Get-AzNetworkInterface -ResourceGroupName $Rg -ErrorAction SilentlyContinue
            if ($allNics | Where-Object { $_.NetworkSecurityGroup -and $_.NetworkSecurityGroup.Id -eq $nsg.Id }) { $stillUsed = $true }

            $vnets = Get-AzVirtualNetwork -ResourceGroupName $Rg -ErrorAction SilentlyContinue
            foreach ($v in $vnets) {
                foreach ($s in $v.Subnets) {
                    if ($s.NetworkSecurityGroup -and $s.NetworkSecurityGroup.Id -eq $nsg.Id) { $stillUsed = $true }
                }
            }

            if (-not $stillUsed -and $PSCmdlet.ShouldProcess("NSG '$($nsg.Name)'", "Remove-AzNetworkSecurityGroup")) {
                Write-Log "Deleting NSG '$($nsg.Name)' (appears unshared)..."
                Remove-AzNetworkSecurityGroup -ResourceGroupName $Rg -Name $nsg.Name -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "NSG '$($nsg.Name)' appears shared/in-use. Skipping." "WARN"
            }
        }
    }
}

# ------------------ Entra + Intune deletion ------------------
function Remove-FromEntraAndIntune {
    param([string]$VmName)

    if (-not $global:GraphReady) {
        Write-Log "Graph not ready. Skipping Entra/Intune deletion for '$VmName'." "WARN"
        return
    }

    $safeName = Escape-ODataString $VmName

    # Entra ID device
    try {
        $entra = @()
        $entra += Get-MgDevice -Filter "displayName eq '$safeName'" -All -ErrorAction SilentlyContinue
        if ($entra.Count -eq 0) {
            $entra += Get-MgDevice -Filter "startsWith(displayName,'$safeName')" -All -ErrorAction SilentlyContinue
        }

        foreach ($d in $entra | Select-Object -Unique) {
            if ($PSCmdlet.ShouldProcess("Entra Device '$($d.DisplayName)' ($($d.Id))", "Remove-MgDevice")) {
                Write-Log "Deleting Entra device '$($d.DisplayName)' (Id: $($d.Id))..."
                Remove-MgDevice -DeviceId $d.Id -ErrorAction SilentlyContinue
            }
        }

        if ($entra.Count -eq 0) { Write-Log "Entra device '$VmName' not found. Skipping." "WARN" }
    } catch {
        Write-Log "Failed Entra lookup/remove for '$VmName': $($_.Exception.Message)" "WARN"
    }

    # Intune managed device
    try {
        $intune = @()
        $intune += Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$safeName'" -All -ErrorAction SilentlyContinue
        if ($intune.Count -eq 0) {
            $intune += Get-MgDeviceManagementManagedDevice -Filter "startsWith(deviceName,'$safeName')" -All -ErrorAction SilentlyContinue
        }

        foreach ($md in $intune | Select-Object -Unique) {
            if ($PSCmdlet.ShouldProcess("Intune ManagedDevice '$($md.DeviceName)' ($($md.Id))", "Remove-MgDeviceManagementManagedDevice")) {
                Write-Log "Deleting Intune managed device '$($md.DeviceName)' (Id: $($md.Id))..."
                Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $md.Id -ErrorAction SilentlyContinue
            }
        }

        if ($intune.Count -eq 0) { Write-Log "Intune managed device '$VmName' not found. Skipping." "WARN" }
    } catch {
        Write-Log "Failed Intune lookup/remove for '$VmName': $($_.Exception.Message)" "WARN"
    }
}

# ------------------ MAIN ------------------
$logDir = Split-Path $LogPath
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log "=== START Remove-AvdHostsFully ==="

try {
    Ensure-Modules

    if (-not $Execute) {
        Write-Log "Running in DRY RUN mode (WhatIf). Use -Execute to actually delete." "WARN"
        $WhatIfPreference = $true
    } else {
        Write-Log "Running in EXECUTE mode. Deletions will occur." "WARN"
        $WhatIfPreference = $false
    }

    Connect-Contexts

    $finalVmNames = @()
    if ($VmNames) { $finalVmNames += $VmNames }
    if ($BulkFile) {
        $bulk = Get-BulkVmNames -Path $BulkFile
        $finalVmNames += $bulk
        Write-Log "Loaded $($bulk.Count) VM names from BulkFile: $BulkFile"
    }

    $finalVmNames = @($finalVmNames | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)

    if (-not $finalVmNames -or $finalVmNames.Count -eq 0) {
        throw "No VM names provided. Use -VmNames or -BulkFile."
    }

    Write-Log "Total unique VM names to process: $($finalVmNames.Count)"

    $results = @()

    foreach ($vmName in $finalVmNames) {
        $row = [ordered]@{
            VmName = $vmName
            AvdRemoved = $false
            AzureDeleted = $false
            EntraAttempted = $false
            IntuneAttempted = $false
            Error = $null
        }

        try {
            Write-Log "----- Processing VM: $vmName -----"

            $sessionHostName = Resolve-AvdSessionHostName -AvdRg $AvdResourceGroup -Pool $HostPoolName -VmName $vmName
            Write-Log "Resolved session host name for '$vmName' => '$sessionHostName'"

            if ($sessionHostName) {
                # 1) Drain
                Set-DrainMode -AvdRg $AvdResourceGroup -Pool $HostPoolName -SessionHostName $sessionHostName

                # 2) Optional: force logoff + wait for 0 sessions
                if ($WaitForZeroSessions) {
                    if ($ForceLogoffSessions) {
                        Write-Log "ForceLogoffSessions enabled. Attempting logoff..."
                        Logoff-HostSessions -AvdRg $AvdResourceGroup -Pool $HostPoolName -SessionHostName $sessionHostName
                    }

                    Write-Log "Waiting up to $TimeoutMinutes minutes for sessions to reach 0..."
                    $ok = Wait-ZeroSessions -AvdRg $AvdResourceGroup -Pool $HostPoolName -SessionHostName $sessionHostName -TimeoutMin $TimeoutMinutes
                    if (-not $ok) { throw "Timeout waiting for zero sessions on '$sessionHostName'." }
                }

                # 3) Remove from host pool
                Remove-FromAvdHostPool -AvdRg $AvdResourceGroup -Pool $HostPoolName -SessionHostName $sessionHostName
                $row.AvdRemoved = $true
            } else {
                Write-Log "AVD session host for VM '$vmName' was not found in host pool '$HostPoolName'. Continuing with Azure/Entra/Intune deletion." "WARN"
            }

            # 4) Azure VM + dependent resources
            Remove-AzureVmAndResources -Rg $AvdResourceGroup -VmName $vmName -RemoveNsgIfUnshared:$RemoveNsgIfUnshared
            $row.AzureDeleted = $true

            # 5) Entra + Intune
            Remove-FromEntraAndIntune -VmName $vmName
            $row.EntraAttempted = $true
            $row.IntuneAttempted = $true

            Write-Log "----- Done VM: $vmName -----"
        }
        catch {
            $row.Error = $_.Exception.Message
            Write-Log "ERROR on '$vmName': $($row.Error)" "ERROR"
        }

        $results += [pscustomobject]$row
    }

    Write-Log "=== SUMMARY ==="
    ($results | Format-Table -AutoSize | Out-String) -split "`r?`n" | ForEach-Object {
        if ($_) { Write-Log $_ }
    }

    Write-Log "=== COMPLETE ==="
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    throw
}
