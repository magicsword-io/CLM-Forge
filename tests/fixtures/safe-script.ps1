# Safe script - no CLM-restricted constructs
# This script should produce zero Critical or High findings

param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [int]$Timeout = 30
)

# Basic cmdlet usage (all CLM-safe)
$services = Get-Service | Where-Object { $_.Status -eq 'Running' }
Write-Output "Found $($services.Count) running services on $ComputerName"

# PSCustomObject (CLM-safe alternative to classes)
$report = [PSCustomObject]@{
    ComputerName = $ComputerName
    Timestamp    = Get-Date
    ServiceCount = $services.Count
    OSVersion    = $PSVersionTable.OS
}

# Hashtable and array usage
$config = @{
    LogPath    = Join-Path $env:TEMP 'audit.log'
    MaxRetries = 3
    Enabled    = $true
}

$items = @('Alpha', 'Bravo', 'Charlie')
foreach ($item in $items) {
    Write-Verbose "Processing: $item"
}

# File operations via cmdlets (CLM-safe)
$logPath = Join-Path $env:TEMP 'clm-test.log'
"Test entry at $(Get-Date)" | Out-File -FilePath $logPath -Append

# Pipeline operations
$topProcesses = Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5
$topProcesses | Format-Table Name, Id, WorkingSet64 -AutoSize

# Error handling
try {
    $content = Get-Content -Path $logPath -ErrorAction Stop
    Write-Output "Log has $($content.Count) lines"
}
catch {
    Write-Warning "Could not read log: $_"
}
finally {
    if (Test-Path $logPath) {
        Remove-Item $logPath -Force
    }
}

# Function definition (CLM-safe)
function Get-SystemInfo {
    [CmdletBinding()]
    param()

    @{
        Hostname = $env:COMPUTERNAME
        User     = $env:USERNAME
        Domain   = $env:USERDOMAIN
        PSVersion = $PSVersionTable.PSVersion.ToString()
    }
}

$info = Get-SystemInfo
Write-Output "System: $($info.Hostname) ($($info.PSVersion))"
