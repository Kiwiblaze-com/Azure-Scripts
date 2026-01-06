param (
    [Parameter(Mandatory=$true)]
    [string] $subscriptionId,

    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop")]
    [string] $action
)

# Connect to Azure
Write-Output "Connecting to Azure..."
Connect-AzAccount -Identity

# Set the subscription context
Write-Output "Setting context to subscription: $subscriptionId"
Set-AzContext -SubscriptionId $subscriptionId

# Get all VMs in the subscription
Write-Output "Retrieving all VMs in subscription..."
$vms = Get-AzVM


$vms | ForEach-Object -Parallel {
    $vmName = $_.Name
    $resourceGroup = $_.ResourceGroupName
    $vmStatus = (Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName -Status).Statuses[1].Code

    if ($using:action -eq "start") {
        if ($vmStatus -ne "PowerState/running") {
            Write-Output "Starting VM: $vmName in RG: $resourceGroup"
            Start-AzVM -ResourceGroupName $resourceGroup -Name $vmName
        } else {
            Write-Output "VM $vmName is already running."
        }
    } elseif ($using:action -eq "stop") {
        if ($vmStatus -ne "PowerState/deallocated") {
            Write-Output "Stopping VM: $vmName in RG: $resourceGroup"
            Stop-AzVM -ResourceGroupName $resourceGroup -Name $vmName -Force
        } else {
            Write-Output "VM $vmName is already deallocated."
        }
    }
} -ThrottleLimit 5

