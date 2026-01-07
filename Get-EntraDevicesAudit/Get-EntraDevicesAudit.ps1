<#
.SYNOPSIS
    Gets Entra (Azure AD) devices and their Intune status to identify stale or duplicate devices.

.DESCRIPTION
    This script retrieves all Entra devices and correlates them with Intune managed device data
    to identify devices that may be stale (removed by Intune cleanup rules) or duplicates.
    It also checks for recovery keys (BitLocker for Windows, FileVault for macOS) that should
    be backed up before device deletion. Results are exported to CSV for analysis.

.PARAMETER Platform
    Optional. Filter devices by platform. Valid values: Windows, macOS, iOS, Android, Linux, All
    Default: All

.PARAMETER JoinType
    Optional. Filter devices by join type. Valid values: AzureADJoined, AzureADRegistered, HybridAzureADJoined, All
    Default: All

.PARAMETER StaleThresholdDays
    Optional. Number of days since last activity to consider a device stale.
    Default: 90

.PARAMETER OutputPath
    Optional. Path for the CSV export file.
    Default: .\EntraDevices_<timestamp>.csv

.PARAMETER IncludeIntuneDetails
    Optional switch. When specified, includes additional Intune device details.

.PARAMETER SkipRecoveryKeyCheck
    Optional switch. When specified, skips checking for BitLocker/FileVault recovery keys.
    Use this for faster execution if recovery key status is not needed.

.EXAMPLE
    .\Get-EntraDevicesAudit.ps1
    Gets all Entra devices with default settings.

.EXAMPLE
    .\Get-EntraDevicesAudit.ps1 -Platform Windows -JoinType HybridAzureADJoined
    Gets only Windows devices that are Hybrid Azure AD Joined.

.EXAMPLE
    .\Get-EntraDevicesAudit.ps1 -Platform macOS,iOS -StaleThresholdDays 60 -IncludeIntuneDetails
    Gets macOS and iOS devices, marks those inactive for 60+ days as stale, includes Intune details.

.EXAMPLE
    .\Get-EntraDevicesAudit.ps1 -SkipRecoveryKeyCheck
    Gets all devices without checking for recovery keys (faster execution).

.NOTES
    Author: Josh Bird
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement modules
    Permissions Required: 
        - Device.Read.All
        - DeviceManagementManagedDevices.Read.All
        - BitlockerKey.Read.All (for BitLocker recovery keys)
        - DeviceManagementConfiguration.Read.All (for FileVault keys via Intune)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Windows', 'macOS', 'iOS', 'Android', 'Linux', 'All')]
    [string[]]$Platform = @('All'),

    [Parameter(Mandatory = $false)]
    [ValidateSet('AzureADJoined', 'AzureADRegistered', 'HybridAzureADJoined', 'All')]
    [string[]]$JoinType = @('All'),

    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntuneDetails,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRecoveryKeyCheck
)

#region Functions

function Test-ModuleInstalled {
    param(
        [string]$ModuleName
    )
    
    $module = Get-Module -ListAvailable -Name $ModuleName
    return $null -ne $module
}

function Install-RequiredModules {
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.DeviceManagement',
        'Microsoft.Graph.Identity.SignIns'
    )

    foreach ($module in $requiredModules) {
        if (-not (Test-ModuleInstalled -ModuleName $module)) {
            Write-Host "Installing module: $module" -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-Host "Successfully installed: $module" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install module $module. Error: $_"
                throw
            }
        }
        else {
            Write-Verbose "Module already installed: $module"
        }
    }
}

function Connect-ToGraph {
    param(
        [string[]]$Platform = @('All'),
        [switch]$SkipRecoveryKeyCheck
    )
    
    $requiredScopes = @(
        'Device.Read.All',
        'DeviceManagementManagedDevices.Read.All'
    )
    
    if (-not $SkipRecoveryKeyCheck) {
        # Only request BitLocker scopes if Windows is in scope
        if ('All' -in $Platform -or 'Windows' -in $Platform) {
            $requiredScopes += 'BitlockerKey.ReadBasic.All'
        }
        # Only request FileVault/Intune scopes if macOS is in scope
        if ('All' -in $Platform -or 'macOS' -in $Platform) {
            $requiredScopes += 'DeviceManagementConfiguration.Read.All'
        }
    }

    try {
        $context = Get-MgContext
        if ($null -eq $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
        else {
            # Check if we have required scopes
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
            if ($missingScopes.Count -gt 0) {
                Write-Host "Reconnecting with required scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph | Out-Null
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            }
        }
        Write-Host "Connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph. Error: $_"
        throw
    }
}

function Get-EntraDevices {
    Write-Host "Retrieving Entra devices..." -ForegroundColor Cyan
    
    $properties = @(
        'Id',
        'DeviceId',
        'DisplayName',
        'OperatingSystem',
        'OperatingSystemVersion',
        'TrustType',
        'ApproximateLastSignInDateTime',
        'AccountEnabled',
        'IsManaged',
        'IsCompliant',
        'RegisteredOwners',
        'DeviceOwnership',
        'EnrollmentType',
        'ManagementType',
        'CreatedDateTime',
        'ProfileType'
    )

    try {
        $devices = Get-MgDevice -All -Property $properties | Select-Object $properties
        Write-Host "Retrieved $($devices.Count) Entra devices" -ForegroundColor Green
        return $devices
    }
    catch {
        Write-Error "Failed to retrieve Entra devices. Error: $_"
        throw
    }
}

function Get-IntuneManagedDevices {
    Write-Host "Retrieving Intune managed devices..." -ForegroundColor Cyan
    
    try {
        $intuneDevices = Get-MgDeviceManagementManagedDevice -All
        Write-Host "Retrieved $($intuneDevices.Count) Intune managed devices" -ForegroundColor Green
        return $intuneDevices
    }
    catch {
        Write-Error "Failed to retrieve Intune managed devices. Error: $_"
        throw
    }
}

function Get-DeviceJoinType {
    param(
        [string]$TrustType,
        [string]$ProfileType
    )

    switch ($TrustType) {
        'AzureAd' { 
            if ($ProfileType -eq 'RegisteredDevice') {
                return 'AzureADRegistered'
            }
            return 'AzureADJoined' 
        }
        'ServerAd' { return 'HybridAzureADJoined' }
        'Workplace' { return 'AzureADRegistered' }
        default { return 'Unknown' }
    }
}

function Get-NormalizedPlatform {
    param(
        [string]$OperatingSystem
    )

    switch -Regex ($OperatingSystem) {
        'Windows' { return 'Windows' }
        'macOS|Mac OS|MacMDM' { return 'macOS' }
        'iOS|iPhone|iPad' { return 'iOS' }
        'Android' { return 'Android' }
        'Linux' { return 'Linux' }
        default { return $OperatingSystem }
    }
}

function Get-BitLockerRecoveryKeys {
    Write-Host "Retrieving BitLocker recovery keys..." -ForegroundColor Cyan
    
    try {
        # Get all BitLocker recovery keys
        $bitlockerKeys = Get-MgInformationProtectionBitlockerRecoveryKey -All
        Write-Host "Retrieved $($bitlockerKeys.Count) BitLocker recovery keys" -ForegroundColor Green
        
        # Create hashtable for quick lookup by device ID (AzureADDeviceId)
        $keyHash = @{}
        foreach ($key in $bitlockerKeys) {
            if ($key.DeviceId) {
                if (-not $keyHash.ContainsKey($key.DeviceId)) {
                    $keyHash[$key.DeviceId] = @()
                }
                $keyHash[$key.DeviceId] += $key
            }
        }
        return $keyHash
    }
    catch {
        Write-Warning "Failed to retrieve BitLocker recovery keys. Error: $_"
        Write-Warning "Continuing without BitLocker key information..."
        return @{}
    }
}

function Get-FileVaultRecoveryKeys {
    param(
        [array]$IntuneDevices
    )
    
    Write-Host "Checking FileVault recovery keys for macOS devices..." -ForegroundColor Cyan
    
    $fileVaultHash = @{}
    $macDevices = $IntuneDevices | Where-Object { $_.OperatingSystem -match 'macOS|Mac OS' }
    
    if ($macDevices.Count -eq 0) {
        Write-Host "No macOS devices found in Intune" -ForegroundColor Yellow
        return $fileVaultHash
    }
    
    $processedCount = 0
    foreach ($device in $macDevices) {
        try {
            # Try to get FileVault key - if it exists, the device has FileVault enabled
            $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$($device.Id)?`$select=id,deviceName,hardwareInformation"
            $deviceInfo = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction SilentlyContinue
            
            # Check if device is encrypted via hardware information
            if ($deviceInfo.hardwareInformation.isEncrypted) {
                $fileVaultHash[$device.AzureADDeviceId] = @{
                    HasFileVault = $true
                    IsEncrypted = $true
                }
            }
            else {
                $fileVaultHash[$device.AzureADDeviceId] = @{
                    HasFileVault = $false
                    IsEncrypted = $false
                }
            }
            $processedCount++
        }
        catch {
            # Device may not have FileVault or we don't have access
            $fileVaultHash[$device.AzureADDeviceId] = @{
                HasFileVault = $null
                IsEncrypted = $null
            }
        }
    }
    
    Write-Host "Processed FileVault status for $processedCount macOS devices" -ForegroundColor Green
    return $fileVaultHash
}

function Get-DeviceRecoveryKeyInfo {
    param(
        [string]$AzureADDeviceId,
        [string]$Platform,
        [hashtable]$BitLockerKeys,
        [hashtable]$FileVaultKeys
    )
    
    $result = @{
        HasRecoveryKey = $false
        RecoveryKeyType = 'N/A'
        RecoveryKeyCount = 0
        RequiresKeyBackup = $false
    }
    
    switch ($Platform) {
        'Windows' {
            if ($BitLockerKeys.ContainsKey($AzureADDeviceId)) {
                $keys = $BitLockerKeys[$AzureADDeviceId]
                $result.HasRecoveryKey = $true
                $result.RecoveryKeyType = 'BitLocker'
                $result.RecoveryKeyCount = $keys.Count
                $result.RequiresKeyBackup = $true
            }
            else {
                # Windows device without BitLocker key in Entra
                $result.RecoveryKeyType = 'BitLocker (Not Found)'
                $result.RequiresKeyBackup = $false
            }
        }
        'macOS' {
            if ($FileVaultKeys.ContainsKey($AzureADDeviceId)) {
                $fvInfo = $FileVaultKeys[$AzureADDeviceId]
                if ($fvInfo.IsEncrypted -eq $true) {
                    $result.HasRecoveryKey = $true
                    $result.RecoveryKeyType = 'FileVault'
                    $result.RecoveryKeyCount = 1

                    $result.RequiresKeyBackup = $true
                }
                elseif ($null -eq $fvInfo.IsEncrypted) {
                    $result.RecoveryKeyType = 'FileVault (Unknown)'
                    $result.RequiresKeyBackup = $true
                }
                else {
                    $result.RecoveryKeyType = 'FileVault (Not Encrypted)'
                }
            }
            else {
                $result.RecoveryKeyType = 'FileVault (Not Found)'
                $result.RequiresKeyBackup = $false
            }
        }
        'iOS' {
            # iOS uses Activation Lock, not recovery keys - Not being checked
            $result.RecoveryKeyType = 'N/A'
            $result.RequiresKeyBackup = $false
        }
        'Android' {
            # Android typically doesn't have cloud-escrowed recovery keys
            $result.RecoveryKeyType = 'N/A'
            $result.RequiresKeyBackup = $false
        }
        default {
            $result.RecoveryKeyType = 'Unknown'
            $result.RequiresKeyBackup = $false
        }
    }
    
    return $result
}

function Find-DuplicateDevices {
    param(
        [array]$Devices
    )

    # Group by device name to identify potential duplicates
    $grouped = $Devices | Group-Object -Property DisplayName | Where-Object { $_.Count -gt 1 }
    
    $duplicateDeviceNames = @{}
    foreach ($group in $grouped) {
        $duplicateDeviceNames[$group.Name] = $group.Count
    }

    return $duplicateDeviceNames
}

#endregion Functions

#region Main Script

try {
    # Set default output path if not specified
    if ([string]::IsNullOrEmpty($OutputPath)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "EntraDevices_$timestamp.csv"
    }

    # Install required modules
    Write-Host "`n=== Checking Required Modules ===" -ForegroundColor Magenta
    Install-RequiredModules

    # Import modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

    # Connect to Graph
    Write-Host "`n=== Connecting to Microsoft Graph ===" -ForegroundColor Magenta
    Connect-ToGraph -Platform $Platform -SkipRecoveryKeyCheck:$SkipRecoveryKeyCheck

    # Get devices
    Write-Host "`n=== Retrieving Device Data ===" -ForegroundColor Magenta
    $entraDevices = Get-EntraDevices
    $intuneDevices = Get-IntuneManagedDevices

    # Get recovery keys if not skipped
    $bitLockerKeys = @{}
    $fileVaultKeys = @{}
    if (-not $SkipRecoveryKeyCheck) {
        $needsBitLocker = 'All' -in $Platform -or 'Windows' -in $Platform
        $needsFileVault = 'All' -in $Platform -or 'macOS' -in $Platform

        if ($needsBitLocker -or $needsFileVault) {
            Write-Host "`n=== Retrieving Recovery Key Data ===" -ForegroundColor Magenta
            
            if ($needsBitLocker) {
                $bitLockerKeys = Get-BitLockerRecoveryKeys
            }
            else {
                Write-Host "Skipping BitLocker keys (Windows not in platform filter)" -ForegroundColor Yellow
            }
            
            if ($needsFileVault) {
                Write-Host "Skipping FileVault keys (Not Implemented yet...)" -ForegroundColor Yellow
                #$fileVaultKeys = Get-FileVaultRecoveryKeys -IntuneDevices $intuneDevices
            }
            else {
                Write-Host "Skipping FileVault keys (macOS not in platform filter)" -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "`nSkipping recovery key check as requested" -ForegroundColor Yellow
    }

    # Create hashtable of Intune devices for quick lookup by Azure AD Device ID
    $intuneDeviceHash = @{}
    foreach ($device in $intuneDevices) {
        if ($device.AzureADDeviceId) {
            $intuneDeviceHash[$device.AzureADDeviceId] = $device
        }
    }

    # Find duplicate device names
    $duplicates = Find-DuplicateDevices -Devices $entraDevices

    # Process and enrich device data
    Write-Host "`n=== Processing Device Data ===" -ForegroundColor Magenta
    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)
    $results = @()

    foreach ($device in $entraDevices) {
        $normalizedPlatform = Get-NormalizedPlatform -OperatingSystem $device.OperatingSystem
        $deviceJoinType = Get-DeviceJoinType -TrustType $device.TrustType -ProfileType $device.ProfileType

        # Apply platform filter
        if ('All' -notin $Platform -and $normalizedPlatform -notin $Platform) {
            continue
        }

        # Apply join type filter
        if ('All' -notin $JoinType -and $deviceJoinType -notin $JoinType) {
            continue
        }

        # Check for matching Intune device
        $intuneDevice = $intuneDeviceHash[$device.DeviceId]
        $isInIntune = $null -ne $intuneDevice

        # Determine last activity date (use Intune last sync if available, otherwise Entra sign-in)
        $lastActivity = $device.ApproximateLastSignInDateTime
        if ($isInIntune -and $intuneDevice.LastSyncDateTime) {
            # Use the more recent of the two dates
            if ($intuneDevice.LastSyncDateTime -gt $lastActivity) {
                $lastActivity = $intuneDevice.LastSyncDateTime
            }
        }

        # Calculate days since last activity
        $daysSinceActivity = if ($lastActivity) {
            [math]::Round(((Get-Date) - $lastActivity).TotalDays)
        }
        else {
            $null
        }

        # Determine if device is stale
        $isStale = if ($lastActivity) {
            $lastActivity -lt $staleDate
        }
        else {
            $true  # No activity date = consider stale
        }

        # Check for duplicate
        $isDuplicate = $duplicates.ContainsKey($device.DisplayName)
        $duplicateCount = if ($isDuplicate) { $duplicates[$device.DisplayName] } else { 1 }

        # Get recovery key information
        $recoveryKeyInfo = if (-not $SkipRecoveryKeyCheck) {
            Get-DeviceRecoveryKeyInfo -AzureADDeviceId $device.DeviceId -Platform $normalizedPlatform -BitLockerKeys $bitLockerKeys -FileVaultKeys $fileVaultKeys
        }
        else {
            @{ HasRecoveryKey = $null; RecoveryKeyType = 'Not Checked'; RecoveryKeyCount = $null; RecoveryKeyBackedUp = $null; RequiresKeyBackup = $null }
        }

        # Build result object
        $result = [PSCustomObject]@{
            DeviceName                    = $device.DisplayName
            EntraObjectId                 = $device.Id
            EntraDeviceId                 = $device.DeviceId
            Platform                      = $normalizedPlatform
            OperatingSystem               = $device.OperatingSystem
            OperatingSystemVersion        = $device.OperatingSystemVersion
            JoinType                      = $deviceJoinType
            TrustType                     = $device.TrustType
            AccountEnabled                = $device.AccountEnabled
            IsManaged                     = $device.IsManaged
            IsCompliant                   = $device.IsCompliant
            IsInIntune                    = $isInIntune
            EntraLastSignIn               = $device.ApproximateLastSignInDateTime
            IntuneLastSync                = if ($isInIntune) { $intuneDevice.LastSyncDateTime } else { $null }
            LastActivity                  = $lastActivity
            DaysSinceActivity             = $daysSinceActivity
            IsStale                       = $isStale
            StaleThresholdDays            = $StaleThresholdDays
            IsPotentialDuplicate          = $isDuplicate
            DuplicateCount                = $duplicateCount
            HasRecoveryKey                = $recoveryKeyInfo.HasRecoveryKey
            RecoveryKeyType               = $recoveryKeyInfo.RecoveryKeyType
            RecoveryKeyCount              = $recoveryKeyInfo.RecoveryKeyCount
            RequiresKeyBackup             = $recoveryKeyInfo.RequiresKeyBackup
            DeviceOwnership               = $device.DeviceOwnership
            EnrollmentType                = $device.EnrollmentType
            CreatedDateTime               = $device.CreatedDateTime
        }

        # Add Intune details if requested
        if ($IncludeIntuneDetails -and $isInIntune) {
            $result | Add-Member -NotePropertyName 'IntuneDeviceId' -NotePropertyValue $intuneDevice.Id
            $result | Add-Member -NotePropertyName 'IntuneDeviceName' -NotePropertyValue $intuneDevice.DeviceName
            $result | Add-Member -NotePropertyName 'IntuneEnrollmentDate' -NotePropertyValue $intuneDevice.EnrolledDateTime
            $result | Add-Member -NotePropertyName 'IntuneComplianceState' -NotePropertyValue $intuneDevice.ComplianceState
            $result | Add-Member -NotePropertyName 'IntuneManagementAgent' -NotePropertyValue $intuneDevice.ManagementAgent
            $result | Add-Member -NotePropertyName 'IntunePrimaryUser' -NotePropertyValue $intuneDevice.UserPrincipalName
            $result | Add-Member -NotePropertyName 'IntuneSerialNumber' -NotePropertyValue $intuneDevice.SerialNumber
            $result | Add-Member -NotePropertyName 'IntuneModel' -NotePropertyValue $intuneDevice.Model
            $result | Add-Member -NotePropertyName 'IntuneManufacturer' -NotePropertyValue $intuneDevice.Manufacturer
        }

        $results += $result
    }

    # Generate summary
    Write-Host "`n=== Summary ===" -ForegroundColor Magenta
    Write-Host "Total devices processed: $($results.Count)" -ForegroundColor White
    Write-Host "Stale devices (>$StaleThresholdDays days): $($results | Where-Object { $_.IsStale } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    Write-Host "Devices in Intune: $($results | Where-Object { $_.IsInIntune } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
    Write-Host "Devices NOT in Intune: $($results | Where-Object { -not $_.IsInIntune } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
    Write-Host "Potential duplicates: $($results | Where-Object { $_.IsPotentialDuplicate } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    
    if (-not $SkipRecoveryKeyCheck) {
        Write-Host "`nRecovery Key Status:" -ForegroundColor Cyan
        Write-Host "  Devices with recovery keys: $($results | Where-Object { $_.HasRecoveryKey -eq $true } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor White
        Write-Host "  BitLocker keys found: $($results | Where-Object { $_.RecoveryKeyType -eq 'BitLocker' } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor White
        Write-Host "  FileVault keys found: $($results | Where-Object { $_.RecoveryKeyType -eq 'FileVault' } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor White
        Write-Host "  Devices requiring key backup review: $($results | Where-Object { $_.RequiresKeyBackup -eq $true -and $_.HasRecoveryKey -ne $true } | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow
    }

    # Platform breakdown
    Write-Host "`nPlatform Breakdown:" -ForegroundColor Cyan
    $results | Group-Object -Property Platform | Sort-Object -Property Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
    }

    # Join type breakdown
    Write-Host "`nJoin Type Breakdown:" -ForegroundColor Cyan
    $results | Group-Object -Property JoinType | Sort-Object -Property Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
    }

    # Export to CSV
    Write-Host "`n=== Exporting Results ===" -ForegroundColor Magenta
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputPath" -ForegroundColor Green

    # Return results for pipeline use
    return $results
}
catch {
    Write-Error "Script execution failed. Error: $_"
    throw
}
finally {
    Write-Host "`nScript completed." -ForegroundColor Cyan
}

#endregion Main Script