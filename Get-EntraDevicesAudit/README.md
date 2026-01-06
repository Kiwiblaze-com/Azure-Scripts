# Get-EntraDevicesAudit

A PowerShell script to identify stale and duplicate devices in Microsoft Entra ID (Azure AD) by correlating with Intune managed device data. The script also checks for BitLocker and FileVault recovery keys to ensure critical data is backed up before device deletion.

## Overview

This script helps IT administrators:
- Identify devices that have been inactive for a specified period
- Detect duplicate device registrations
- Find devices that exist in Entra ID but have been removed from Intune (cleanup rules)
- Verify BitLocker (Windows) and FileVault (macOS) recovery keys are escrowed
- Export comprehensive device data to CSV for analysis and remediation

## Requirements

### PowerShell Modules
The script will automatically install these modules if not present:
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Identity.DirectoryManagement`
- `Microsoft.Graph.DeviceManagement`
- `Microsoft.Graph.Identity.SignIns`

### Microsoft Graph Permissions
The account running the script needs these permissions:

| Permission | Purpose |
|------------|---------|
| `Device.Read.All` | Read Entra ID device objects |
| `DeviceManagementManagedDevices.Read.All` | Read Intune managed devices |
| `BitlockerKey.Read.All` | Read BitLocker recovery keys (optional) |
| `DeviceManagementConfiguration.Read.All` | Read FileVault encryption status (optional) |

> **Note:** Recovery key permissions are only required if not using the `-SkipRecoveryKeyCheck` switch.

## Installation

1. Clone or download this repository
2. Open PowerShell as Administrator (for module installation)
3. Navigate to the script directory

```powershell
cd "C:\Github\Azure-Scripts\Get-EntraDevicesAudit"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Platform` | String[] | `All` | Filter by platform: `Windows`, `macOS`, `iOS`, `Android`, `Linux`, or `All` |
| `-JoinType` | String[] | `All` | Filter by join type: `AzureADJoined`, `AzureADRegistered`, `HybridAzureADJoined`, or `All` |
| `-StaleThresholdDays` | Int | `90` | Days of inactivity to consider a device stale |
| `-OutputPath` | String | Auto-generated | Custom path for CSV export |
| `-IncludeIntuneDetails` | Switch | `$false` | Include additional Intune device properties |
| `-SkipRecoveryKeyCheck` | Switch | `$false` | Skip BitLocker/FileVault recovery key checks for faster execution |

## Usage Examples

### Basic Usage
Get all devices with default settings (90-day stale threshold):
```powershell
.\Get-EntraDevicesAudit.ps1
```

### Filter by Platform
Get only Windows devices:
```powershell
.\Get-EntraDevicesAudit.ps1 -Platform Windows
```

Get Windows and macOS devices:
```powershell
.\Get-EntraDevicesAudit.ps1 -Platform Windows, macOS
```

### Filter by Join Type
Get only Hybrid Azure AD Joined devices:
```powershell
.\Get-EntraDevicesAudit.ps1 -JoinType HybridAzureADJoined
```

### Custom Stale Threshold
Mark devices as stale after 60 days of inactivity:
```powershell
.\Get-EntraDevicesAudit.ps1 -StaleThresholdDays 60
```

### Include Extended Intune Details
Get additional Intune properties in the export:
```powershell
.\Get-EntraDevicesAudit.ps1 -IncludeIntuneDetails
```

### Skip Recovery Key Check
For faster execution when recovery key status is not needed:
```powershell
.\Get-EntraDevicesAudit.ps1 -SkipRecoveryKeyCheck
```

### Combined Example
Get Windows Hybrid Joined devices with 30-day stale threshold and full details:
```powershell
.\Get-EntraDevicesAudit.ps1 -Platform Windows -JoinType HybridAzureADJoined -StaleThresholdDays 30 -IncludeIntuneDetails
```

### Custom Output Path
Export to a specific location:
```powershell
.\Get-EntraDevicesAudit.ps1 -OutputPath "C:\Reports\StaleDevices.csv"
```

## Output

### Console Summary
The script displays a summary including:
- Total devices processed
- Stale device count
- Intune enrollment status breakdown
- Duplicate device count
- Recovery key statistics
- Platform and join type breakdowns

### CSV Export Columns

#### Core Device Information
| Column | Description |
|--------|-------------|
| `DeviceName` | Display name of the device |
| `EntraDeviceId` | Entra ID object ID |
| `AzureADDeviceId` | Azure AD device ID (GUID) |
| `Platform` | Normalized platform (Windows, macOS, iOS, Android, Linux) |
| `OperatingSystem` | Full OS name as reported |
| `OperatingSystemVersion` | OS version string |

#### Join and Trust Information
| Column | Description |
|--------|-------------|
| `JoinType` | Friendly join type (AzureADJoined, AzureADRegistered, HybridAzureADJoined) |
| `TrustType` | Raw trust type value |

#### Status Flags
| Column | Description |
|--------|-------------|
| `AccountEnabled` | Whether the device account is enabled |
| `IsManaged` | Whether device is marked as managed |
| `IsCompliant` | Compliance status |
| `IsInIntune` | Whether device exists in Intune |

#### Activity Tracking
| Column | Description |
|--------|-------------|
| `EntraLastSignIn` | Last sign-in time in Entra ID |
| `IntuneLastSync` | Last sync time with Intune |
| `LastActivity` | Most recent activity (max of above) |
| `DaysSinceActivity` | Days since last activity |
| `IsStale` | Whether device exceeds stale threshold |
| `StaleThresholdDays` | Threshold used for stale calculation |

#### Duplicate Detection
| Column | Description |
|--------|-------------|
| `IsPotentialDuplicate` | Whether device name appears multiple times |
| `DuplicateCount` | Number of devices with same name |

#### Recovery Key Information
| Column | Description |
|--------|-------------|
| `HasRecoveryKey` | Whether a recovery key was found in Entra/Intune |
| `RecoveryKeyType` | Type of key (BitLocker, FileVault, Activation Lock, N/A) |
| `RecoveryKeyCount` | Number of recovery keys found |
| `RecoveryKeyBackedUp` | Whether key is escrowed to cloud |
| `RequiresKeyBackup` | Whether this platform typically requires key backup |

#### Additional Fields
| Column | Description |
|--------|-------------|
| `DeviceOwnership` | Corporate vs Personal |
| `EnrollmentType` | How device was enrolled |
| `CreatedDateTime` | When device was registered |

#### Extended Intune Details (with `-IncludeIntuneDetails`)
| Column | Description |
|--------|-------------|
| `IntuneDeviceId` | Intune device ID |
| `IntuneDeviceName` | Device name in Intune |
| `IntuneEnrollmentDate` | Enrollment date |
| `IntuneComplianceState` | Compliance state |
| `IntuneManagementAgent` | Management agent type |
| `IntunePrimaryUser` | Primary user UPN |
| `IntuneSerialNumber` | Device serial number |
| `IntuneModel` | Device model |
| `IntuneManufacturer` | Device manufacturer |

## Recovery Key Details

### BitLocker (Windows)
- Checks for BitLocker recovery keys escrowed to Entra ID
- Requires `BitlockerKey.Read.All` permission
- Displays count of recovery keys per device

### FileVault (macOS)
- Checks encryption status via Intune device hardware information
- Requires `DeviceManagementConfiguration.Read.All` permission
- Identifies whether FileVault is enabled

### Other Platforms
- **iOS**: Notes that Activation Lock is used (not cloud-escrowed keys)
- **Android**: Notes that cloud recovery keys are typically not applicable

## Common Use Cases

### Finding Devices Removed by Intune Cleanup
```powershell
# Get all devices, then filter in Excel/PowerShell for:
# IsInIntune = FALSE and IsStale = TRUE
.\Get-EntraDevicesAudit.ps1 | Where-Object { -not $_.IsInIntune -and $_.IsStale }
```

### Pre-Deletion Audit
Before deleting stale devices, identify those with recovery keys:
```powershell
.\Get-EntraDevicesAudit.ps1 | Where-Object { $_.IsStale -and $_.HasRecoveryKey }
```

### Duplicate Device Cleanup
Find all duplicate device registrations:
```powershell
.\Get-EntraDevicesAudit.ps1 | Where-Object { $_.IsPotentialDuplicate } | Sort-Object DeviceName
```

## Troubleshooting

### Permission Errors
If you receive permission errors:
1. Ensure you have the required Graph permissions
2. Try disconnecting and reconnecting: `Disconnect-MgGraph` then re-run the script
3. For recovery key permissions, verify `BitlockerKey.Read.All` is consented

### Module Installation Issues
If module installation fails:
```powershell
# Run PowerShell as Administrator
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

### Slow Execution
For large environments, consider:
- Using `-SkipRecoveryKeyCheck` if recovery key status isn't needed
- Filtering by platform or join type to reduce scope

## Author
Josh Bird

## License
This project is provided as-is for internal use.
