<#
.SYNOPSIS
    Retrieves storage account details including Blob and File storage usage across multiple Azure subscriptions.

.DESCRIPTION
    This script iterates through a list of Azure subscriptions, retrieves all storage accounts,
    and collects detailed information including storage capacity metrics for Blob and File services.
    Implements retry logic with exponential backoff for rate limiting.

.PARAMETER SubscriptionIds
    An array of Azure subscription IDs to query.

.PARAMETER MaxRetries
    Maximum number of retry attempts for rate-limited requests. Default is 5.

.PARAMETER InitialDelaySeconds
    Initial delay in seconds before retrying. Uses exponential backoff. Default is 2.

.PARAMETER OutputPath
    Optional path to export results to CSV file.

.EXAMPLE
    .\Get-AzureStorageAccountSummary.ps1 -SubscriptionIds @("sub-id-1", "sub-id-2") -MaxRetries 3

.EXAMPLE
    .\Get-AzureStorageAccountSummary.ps1 -SubscriptionIds @("sub-id-1") -OutputPath "C:\Reports\storage-summary.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 5,

    [Parameter(Mandatory = $false)]
    [int]$InitialDelaySeconds = 2,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

#region Helper Functions

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic and exponential backoff for rate limiting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Operation",

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelaySeconds = 2
    )

    $retryCount = 0
    $completed = $false
    $result = $null

    while (-not $completed -and $retryCount -le $MaxRetries) {
        try {
            $result = & $ScriptBlock
            $completed = $true
        }
        catch {
            $errorMessage = $_.Exception.Message
            
            # Check if it's a rate limiting error (HTTP 429) or throttling error
            $isRateLimited = $errorMessage -match "429" -or 
                            $errorMessage -match "Too Many Requests" -or
                            $errorMessage -match "throttl" -or
                            $errorMessage -match "rate limit" -or
                            $errorMessage -match "RequestsThrottled" -or
                            $errorMessage -match "An error occurred while sending the request"

            if ($isRateLimited -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $delaySeconds = $InitialDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                
                # Check for Retry-After header in the error
                if ($errorMessage -match "Retry-After[:\s]+(\d+)") {
                    $retryAfter = [int]$Matches[1]
                    $delaySeconds = [Math]::Max($delaySeconds, $retryAfter)
                }

                Write-Warning "[$OperationName] Rate limited. Retry $retryCount of $MaxRetries in $delaySeconds seconds..."
                Start-Sleep -Seconds $delaySeconds
            }
            elseif ($retryCount -lt $MaxRetries -and ($errorMessage -match "5\d{2}" -or $errorMessage -match "timeout" -or $errorMessage -match "temporarily unavailable")) {
                # Retry on server errors and timeouts
                $retryCount++
                $delaySeconds = $InitialDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                Write-Warning "[$OperationName] Transient error. Retry $retryCount of $MaxRetries in $delaySeconds seconds..."
                Start-Sleep -Seconds $delaySeconds
            }
            else {
                # Non-retryable error or max retries exceeded
                if ($retryCount -ge $MaxRetries) {
                    Write-Error "[$OperationName] Max retries ($MaxRetries) exceeded. Last error: $errorMessage"
                }
                else {
                    Write-Error "[$OperationName] Non-retryable error: $errorMessage"
                }
                throw
            }
        }
    }

    return $result
}

function Convert-BytesToReadable {
    <#
    .SYNOPSIS
        Converts bytes to a human-readable format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Bytes
    )

    if ($null -eq $Bytes -or $Bytes -eq 0) {
        return "0 B"
    }

    $sizes = @("B", "KB", "MB", "GB", "TB", "PB")
    $order = [Math]::Floor([Math]::Log($Bytes, 1024))
    $order = [Math]::Min($order, $sizes.Count - 1)
    $size = $Bytes / [Math]::Pow(1024, $order)
    
    return "{0:N2} {1}" -f $size, $sizes[$order]
}

function Get-StorageAccountMetrics {
    <#
    .SYNOPSIS
        Retrieves storage metrics for a storage account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $true)]
        [int]$MaxRetries,

        [Parameter(Mandatory = $true)]
        [int]$InitialDelaySeconds
    )

    $metrics = @{
        BlobCapacityBytes = $null
        BlobCapacityReadable = "N/A"
        BlobContainerCount = $null
        FileCapacityBytes = $null
        FileCapacityReadable = "N/A"
        FileShareCount = $null
        TableCapacityBytes = $null
        TableCapacityReadable = "N/A"
        QueueCapacityBytes = $null
        QueueCapacityReadable = "N/A"
    }

    $endTime = (Get-Date).ToUniversalTime()
    $startTime = $endTime.AddDays(-1)

    # Get Blob Capacity
    try {
        $blobMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default" `
                -MetricName "BlobCapacity" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get Blob Capacity for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($blobMetric.Data) {
            $maxValue = ($blobMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.BlobCapacityBytes = [long]$maxValue
                $metrics.BlobCapacityReadable = Convert-BytesToReadable -Bytes $metrics.BlobCapacityBytes
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve blob metrics for $StorageAccountName : $_"
    }

    # Get Blob Container Count
    try {
        $containerCountMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default" `
                -MetricName "ContainerCount" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get Container Count for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($containerCountMetric.Data) {
            $maxValue = ($containerCountMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.BlobContainerCount = [int]$maxValue
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve container count for $StorageAccountName : $_"
    }

    # Get File Capacity
    try {
        $fileMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default" `
                -MetricName "FileCapacity" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get File Capacity for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($fileMetric.Data) {
            $maxValue = ($fileMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.FileCapacityBytes = [long]$maxValue
                $metrics.FileCapacityReadable = Convert-BytesToReadable -Bytes $metrics.FileCapacityBytes
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve file metrics for $StorageAccountName : $_"
    }

    # Get File Share Count
    try {
        $fileShareCountMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default" `
                -MetricName "FileShareCount" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get File Share Count for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($fileShareCountMetric.Data) {
            $maxValue = ($fileShareCountMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.FileShareCount = [int]$maxValue
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve file share count for $StorageAccountName : $_"
    }

    # Get Table Capacity
    try {
        $tableMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/tableServices/default" `
                -MetricName "TableCapacity" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get Table Capacity for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($tableMetric.Data) {
            $maxValue = ($tableMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.TableCapacityBytes = [long]$maxValue
                $metrics.TableCapacityReadable = Convert-BytesToReadable -Bytes $metrics.TableCapacityBytes
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve table metrics for $StorageAccountName : $_"
    }

    # Get Queue Capacity
    try {
        $queueMetric = Invoke-WithRetry -ScriptBlock {
            Get-AzMetric -ResourceId "/subscriptions/$((Get-AzContext).Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/queueServices/default" `
                -MetricName "QueueCapacity" `
                -StartTime $startTime `
                -EndTime $endTime `
                -TimeGrain 01:00:00 `
                -AggregationType Average `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop
        } -OperationName "Get Queue Capacity for $StorageAccountName" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if ($queueMetric.Data) {
            $maxValue = ($queueMetric.Data | Where-Object { $null -ne $_.Average } | Measure-Object -Property Average -Maximum).Maximum
            if ($null -ne $maxValue) {
                $metrics.QueueCapacityBytes = [long]$maxValue
                $metrics.QueueCapacityReadable = Convert-BytesToReadable -Bytes $metrics.QueueCapacityBytes
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve queue metrics for $StorageAccountName : $_"
    }

    return $metrics
}

#endregion

#region Main Script

# Verify Az module is installed
$requiredModules = @("Az.Accounts", "Az.Storage", "Az.Monitor")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Please install it using: Install-Module -Name $module -Scope CurrentUser"
        exit 1
    }
}

# Check if connected to Azure
$context = Get-AzContext
if (-not $context) {
    Write-Host "Not connected to Azure. Please run Connect-AzAccount first." -ForegroundColor Yellow
    Connect-AzAccount
}

$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalSubscriptions = $SubscriptionIds.Count
$currentSubscription = 0

foreach ($subscriptionId in $SubscriptionIds) {
    $currentSubscription++
    Write-Host "`n[$currentSubscription/$totalSubscriptions] Processing subscription: $subscriptionId" -ForegroundColor Cyan

    try {
        # Set the subscription context with retry
        $null = Invoke-WithRetry -ScriptBlock {
            Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop
        } -OperationName "Set Subscription Context" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        $subscriptionName = (Get-AzContext).Subscription.Name
        Write-Host "  Subscription Name: $subscriptionName" -ForegroundColor Gray

        # Get all storage accounts in the subscription with retry
        $storageAccounts = Invoke-WithRetry -ScriptBlock {
            Get-AzStorageAccount -ErrorAction Stop
        } -OperationName "Get Storage Accounts" -MaxRetries $MaxRetries -InitialDelaySeconds $InitialDelaySeconds

        if (-not $storageAccounts -or $storageAccounts.Count -eq 0) {
            Write-Host "  No storage accounts found in this subscription." -ForegroundColor Yellow
            continue
        }

        Write-Host "  Found $($storageAccounts.Count) storage account(s)" -ForegroundColor Green

        $accountCount = 0
        foreach ($storageAccount in $storageAccounts) {
            $accountCount++
            Write-Host "    [$accountCount/$($storageAccounts.Count)] Processing: $($storageAccount.StorageAccountName)" -ForegroundColor White

            # Get storage metrics
            $metrics = Get-StorageAccountMetrics `
                -ResourceGroupName $storageAccount.ResourceGroupName `
                -StorageAccountName $storageAccount.StorageAccountName `
                -MaxRetries $MaxRetries `
                -InitialDelaySeconds $InitialDelaySeconds

            # Create result object
            $result = [PSCustomObject]@{
                SubscriptionId            = $subscriptionId
                SubscriptionName          = $subscriptionName
                ResourceGroupName         = $storageAccount.ResourceGroupName
                StorageAccountName        = $storageAccount.StorageAccountName
                Location                  = $storageAccount.Location
                SkuName                   = $storageAccount.Sku.Name
                SkuTier                   = $storageAccount.Sku.Tier
                Kind                      = $storageAccount.Kind
                AccessTier                = $storageAccount.AccessTier
                ProvisioningState         = $storageAccount.ProvisioningState
                CreationTime              = $storageAccount.CreationTime
                PrimaryLocation           = $storageAccount.PrimaryLocation
                SecondaryLocation         = $storageAccount.SecondaryLocation
                EnableHttpsTrafficOnly    = $storageAccount.EnableHttpsTrafficOnly
                MinimumTlsVersion         = $storageAccount.MinimumTlsVersion
                AllowBlobPublicAccess     = $storageAccount.AllowBlobPublicAccess
                BlobCapacityBytes         = $metrics.BlobCapacityBytes
                BlobCapacity              = $metrics.BlobCapacityReadable
                BlobContainerCount        = $metrics.BlobContainerCount
                FileCapacityBytes         = $metrics.FileCapacityBytes
                FileCapacity              = $metrics.FileCapacityReadable
                FileShareCount            = $metrics.FileShareCount
                TableCapacityBytes        = $metrics.TableCapacityBytes
                TableCapacity             = $metrics.TableCapacityReadable
                QueueCapacityBytes        = $metrics.QueueCapacityBytes
                QueueCapacity             = $metrics.QueueCapacityReadable
                TotalCapacityBytes        = ($metrics.BlobCapacityBytes + $metrics.FileCapacityBytes + $metrics.TableCapacityBytes + $metrics.QueueCapacityBytes)
                TotalCapacity             = Convert-BytesToReadable -Bytes ($metrics.BlobCapacityBytes + $metrics.FileCapacityBytes + $metrics.TableCapacityBytes + $metrics.QueueCapacityBytes)
            }

            $allResults.Add($result)

            # Brief pause between storage accounts to avoid rate limiting
            Start-Sleep -Milliseconds 200
        }
    }
    catch {
        Write-Error "Error processing subscription $subscriptionId : $_"
    }
}

#endregion

#region Output Results

Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

Write-Host "`nTotal subscriptions processed: $totalSubscriptions"
Write-Host "Total storage accounts found: $($allResults.Count)"

if ($allResults.Count -gt 0) {
    $totalBlobBytes = ($allResults | Measure-Object -Property BlobCapacityBytes -Sum).Sum
    $totalFileBytes = ($allResults | Measure-Object -Property FileCapacityBytes -Sum).Sum

    Write-Host "`nAggregate Storage Usage:"
    Write-Host "  Total Blob Storage: $(Convert-BytesToReadable -Bytes $totalBlobBytes)"
    Write-Host "  Total File Storage: $(Convert-BytesToReadable -Bytes $totalFileBytes)"
    Write-Host "  Total All Storage:  $(Convert-BytesToReadable -Bytes ($totalBlobBytes + $totalFileBytes))"

    # Display results in table format
    Write-Host "`nStorage Account Details:" -ForegroundColor Yellow
    $allResults | Format-Table -Property SubscriptionName, StorageAccountName, Location, Kind, BlobCapacity, FileCapacity, TotalCapacity -AutoSize

    # Export to CSV if path specified
    if ($OutputPath) {
        try {
            $allResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export results to CSV: $_"
        }
    }
}

# Return results for pipeline usage
return $allResults

#endregion
