# Get-AzureStorageAccountSummary.ps1

## Overview
This PowerShell script retrieves detailed information about all Azure Storage Accounts across one or more Azure subscriptions. It collects key metrics, including Blob and File storage usage, and implements robust retry logic to handle rate limiting and transient errors.

## Features
- Supports multiple Azure subscriptions in a single run
- Retrieves:
  - Storage account properties (name, SKU, location, etc.)
  - Blob and File storage usage (capacity in bytes and human-readable format)
  - Container and file share counts
  - Table and Queue storage usage
  - Aggregated totals across all accounts
- Implements exponential backoff and retry for rate limiting and transient errors
- Exports results to CSV (optional)

## Prerequisites
- PowerShell 5.1 or later
- Azure PowerShell modules:
  - `Az.Accounts`
  - `Az.Storage`
  - `Az.Monitor`

Install the Az modules if needed:
```powershell
Install-Module -Name Az -Scope CurrentUser
```

## Usage
1. **Connect to Azure** (if not already connected):
   ```powershell
   Connect-AzAccount
   ```

2. **Run the script:**
   ```powershell
   .\Get-AzureStorageAccountSummary.ps1 -SubscriptionIds @("sub-id-1", "sub-id-2")
   ```
   Replace `sub-id-1`, `sub-id-2`, etc. with your actual Azure subscription IDs.

3. **Optional parameters:**
   - `-MaxRetries`: Maximum retry attempts for rate-limited requests (default: 5)
   - `-InitialDelaySeconds`: Initial delay before retrying (default: 2)
   - `-OutputPath`: Path to export results as CSV

   **Example:**
   ```powershell
   .\Get-AzureStorageAccountSummary.ps1 -SubscriptionIds @("sub-id-1") -MaxRetries 3 -OutputPath "C:\Reports\storage-summary.csv"
   ```

## Output
- Results are displayed in the console as a summary table.
- If `-OutputPath` is specified, results are exported to a CSV file.
- The script returns all results as an array of objects for further pipeline processing.

## Notes
- The script queries metrics for the last 24 hours and selects the maximum value to avoid missing or zeroed data points.
- If you encounter errors about missing modules, install them as shown above.
- For large environments, the script may take several minutes to complete.

## Example Output
```
SUMMARY
================================================================================
Total subscriptions processed: 2
Total storage accounts found: 8

Aggregate Storage Usage:
  Total Blob Storage: 1.23 TB
  Total File Storage: 456.78 GB
  Total All Storage:  1.68 TB

Storage Account Details:
SubscriptionName  StorageAccountName  Location  Kind   BlobCapacity  FileCapacity  TotalCapacity
----------------  ------------------ --------  -----  ------------ ------------- -------------
MySub1            mystorage1          eastus    StorageV2  500.00 GB   100.00 GB    600.00 GB
MySub2            mystorage2          westeurope StorageV2  700.00 GB   356.78 GB   1.03 TB
...
```

## License
MIT
