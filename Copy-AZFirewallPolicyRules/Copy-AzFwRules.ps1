[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Validatescript({
            if (-not ($_ -like "*/providers/Microsoft.Network/FirewallPolicies/*")) {
                throw "The SourceAzFwPolicyID parameter must be a valid Azure Firewall Policy ID."
            }
            return $true
        }
    )]
    [string]$SourceAzFwPolicyID,
    [Parameter(Mandatory = $true)]
    [Validatescript({
            if (-not ($_ -Like "*/providers/Microsoft.Network/FirewallPolicies/*")) {
                throw "The TargetAzFwPolicyID parameter must be a valid Azure Firewall Policy ID."
            }
            return $true
        }
    )]
    [string]$TargetAzFwPolicyID
)

# set default error action preference
$ErrorActionPreference = "Stop"

$sourceSubscriptionId = $SourceAzFwPolicyID.Split("/")[2]
$targetSubscriptionId = $TargetAzFwPolicyID.Split("/")[2]

# validate the source and target firewall policy IDs are different
if ($TargetAzFwPolicyID -eq $SourceAzFwPolicyID) {
    Write-Error "The SourceAzFwPolicyID and TargetAzFwPolicyID parameters must be different."
}

# validate if we need to swtich context to source firewall policy subscription
Write-Host "Checking current context..."
$CurrentAzContext = Get-AzContext

if (!$CurrentAzContext) {
    Write-Error "Failed to get current Azure context."
}

if ($CurrentAzContext.Subscription.Id -ne $sourceSubscriptionId) {
    $sourceSubscription = Get-AzSubscription -SubscriptionId $sourceSubscriptionId
    write-host "Switching to source subscription: $($sourceSubscription.Name)"
    $CurrentAzContext = Set-AzContext -Subscription $sourceSubscription
}
else {
    Write-Host "Current context is already in the correct subscription: $($CurrentAzContext.Subscription.Name)" -ForegroundColor Green
}

# get the source and target firewall policies
Write-Verbose "Getting Azure Firewall Policy: $($SourceAzFwPolicyID)"
$SourceAzFwPolicy = Get-AzFirewallPolicy -ResourceId $SourceAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $SourceAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Source Policy: $($SourceAzFwPolicyID)."
}

if ($CurrentAzContext.Subscription.Id -ne $targetSubscriptionId) {
    $targetSubscription = Get-AzSubscription -SubscriptionId $targetSubscriptionId
    write-host "Switching to target subscription: $($targetSubscription.Name)"
    $CurrentAzContext = Set-AzContext -Subscription $targetSubscription
}
else {
    Write-Host "Current context is already in the correct subscription: $($CurrentAzContext.Subscription.Name)" -ForegroundColor Green
}

Write-Verbose "Getting Azure Firewall Policy: $($TargetAzFwPolicyID)"
$TargetAzFwPolicy = Get-AzFirewallPolicy -ResourceId $TargetAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $TargetAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Target Policy: $($TargetAzFwPolicyID)."
}

# Copy Rules
Write-Host "Getting Rule Collection Groups..."
foreach ($SourceAzFwPolicyRuleCollectionGroup in $SourceAzFwPolicy.RuleCollectionGroups) {
    # get the source firewall policy rule collection group
    $RuleCollectionGroup = Get-AzFirewallPolicyRuleCollectionGroup -AzureFirewallPolicyName $SourceAzFwPolicy.Name -ResourceGroupName $SourceAzFwPolicy.ResourceGroupName -Name ($SourceAzFwPolicyRuleCollectionGroup.id).Split("/")[-1]

    Write-Host "Copying Rule Collection Group: $($RuleCollectionGroup.Name)..."
    #Check if empty, if so skip
    $RuleCollectionGroup.Properties.RuleCollection
    if(!($RuleCollectionGroup.Properties.RuleCollection)){
        Write-Host "Rule Collection Group is empty - Skipping" -ForegroundColor Yellow
        continue
    }

    write-verbose "Copying Rule Collection(s): $($RuleCollectionGroup.Properties.RuleCollection.name) with a total of $(($RuleCollectionGroup.Properties.RuleCollection.rules).Count) rule(s)"
    # set the target firewall policy rule collection group
    $newRuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name $RuleCollectionGroup.Name -ResourceGroupName $TargetAzFwPolicy.ResourceGroupName -FirewallPolicyName $TargetAzFwPolicy.Name -Priority $RuleCollectionGroup.Properties.Priority -RuleCollection $RuleCollectionGroup.Properties.RuleCollection
    
    if ($newRuleCollectionGroup) {
        Write-Host "Rule Collection Group $($RuleCollectionGroup.Name) copied successfully." -ForegroundColor Green
    }
    else {
        Write-Error "Failed to copy Rule Collection Group $($RuleCollectionGroup.Name)."
    }
}