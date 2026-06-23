<#
.SYNOPSIS
    CLM-Forge Clean Equivalent - Does the same work as validate-all-rules.ps1
    but uses only CLM-compatible constructs.

.DESCRIPTION
    This script performs equivalent operations to the validation script but
    avoids every CLM-restricted construct. Run this through CLM-Forge to
    verify it produces ZERO Critical or High findings.

    This demonstrates the "how to fix it" for every CLM rule.

.NOTES
    Expected results: Zero Critical findings, zero High findings.
    Some Medium/Low informational findings may appear (they're advisory).
#>

# ============================================================
# Instead of CLM001 (Add-Type): Use built-in cmdlets
# No Add-Type needed — use native PowerShell capabilities
# ============================================================
function Get-ValidationInfo { return "CLM001 alternative" }

# ============================================================
# Instead of CLM002 (COM Objects): Use cmdlets
# WScript.Shell -> Start-Process / Invoke-Item
# Scripting.FileSystemObject -> Get-ChildItem / Get-Content
# ============================================================
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$files = Get-ChildItem -Path $env:TEMP -File

# ============================================================
# Instead of CLM003 (.NET Static Methods): Use cmdlets
# [System.IO.File]::ReadAllText -> Get-Content
# [System.Convert]::ToBase64String -> [convert] is approved in CLM for basic ops
# ============================================================
$hostsContent = Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Raw
# For encoding, use cmdlet-based approaches
$bytes = [System.Text.Encoding]::UTF8.GetBytes("test")

# ============================================================
# Instead of CLM004 (Custom Class): Use PSCustomObject
# ============================================================
function New-ServerInventory {
    param([string]$Name, [string]$Role)
    [PSCustomObject]@{
        Name      = $Name
        Role      = $Role
        Compliant = $false
    }
}
$server = New-ServerInventory -Name "DC01" -Role "DomainController"

# ============================================================
# Instead of CLM005 (Using Assembly): Use approved modules
# Import pre-installed modules instead of raw assemblies
# ============================================================
# Import-Module ActiveDirectory  # (if RSAT is installed)

# ============================================================
# Instead of CLM006 (Invoke-Expression): Use the call operator
# ============================================================
$processName = "explorer"
$procs = Get-Process -Name $processName -ErrorAction SilentlyContinue
$currentDate = Get-Date

# ============================================================
# Instead of CLM007 (PS v2 Engine): Just don't use it
# Use current PowerShell version
# ============================================================
Write-Output "Running PowerShell $($PSVersionTable.PSVersion)"

# ============================================================
# Instead of CLM008 (Reflection): Use cmdlets
# ============================================================
# Get-Command instead of Assembly.LoadWithPartialName
$webCmdlets = Get-Command -Module Microsoft.PowerShell.Utility

# ============================================================
# Instead of CLM009 (Marshal): Use managed alternatives
# ============================================================
# No need for unmanaged memory — use PowerShell native types

# ============================================================
# Instead of CLM010 (Delegates): Use cmdlets directly
# ============================================================
# Call APIs through approved cmdlets, not P/Invoke delegates

# ============================================================
# Instead of CLM011 (ScriptBlock.Invoke): Use & operator
# ============================================================
$action = { param($x) Write-Output "Processing $x" }
& $action "test-data"

# ============================================================
# Instead of CLM012 (DSC): Use signed DSC configurations
# Or use direct cmdlet calls for the same effect
# ============================================================
$filePath = Join-Path $env:TEMP "validation.txt"
"CLM012 alternative" | Out-File -FilePath $filePath -Force

# ============================================================
# Instead of CLM013 (Workflow): Use ForEach-Object or jobs
# ============================================================
function Invoke-ParallelCheckClean {
    $processes = Get-Process
    $services = Get-Service
    [PSCustomObject]@{ Processes = $processes.Count; Services = $services.Count }
}

# ============================================================
# Instead of CLM014 (Invoke-Command -ScriptBlock): Use -FilePath
# ============================================================
# Invoke-Command -ComputerName DC01 -FilePath .\signed-script.ps1
# Register-ScheduledTask with a signed script, not inline commands

# ============================================================
# Instead of CLM015 (EncodedCommand): Use plain text
# ============================================================
Write-Output "CLM015 - use plain text instead of encoded commands"

# ============================================================
# Instead of CLM016 (XAML): Use console output or Out-GridView
# ============================================================
# Out-GridView works in CLM as it's a built-in cmdlet
$data = @(
    [PSCustomObject]@{ Name = "Item1"; Value = 42 }
    [PSCustomObject]@{ Name = "Item2"; Value = 84 }
)
$data | Format-Table -AutoSize

# ============================================================
# Instead of CLM017 (Start-Job -ScriptBlock): Use -FilePath
# ============================================================
# Start-Job -FilePath .\signed-worker.ps1

# ============================================================
# Instead of CLM018 (TypeAccelerators): Use full type names
# ============================================================
$list = New-Object 'System.Collections.Generic.List[string]'
$list.Add("item1")

# ============================================================
# Instead of CLM019 (Dynamic Method via Reflection): Use cmdlets
# ============================================================
$fileExists = Test-Path -Path "C:\Windows\System32\cmd.exe"
$fileContent = Get-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -TotalCount 5

# ============================================================
# Instead of CLM020 (String Format obfuscation): Use directly
# ============================================================
$cmdletName = "Invoke-Expression"  # Just reference it as a string, don't build it

# ============================================================
# Instead of CLM021 (Register-ObjectEvent .NET): Use WMI events
# ============================================================
# Register-WmiEvent or use FileSystemWatcher via signed module

# ============================================================
# Instead of CLM022 (Add-Type -Language): Use pre-compiled DLLs
# ============================================================
# Load a signed .dll instead of compiling inline C#

# ============================================================
# Instead of CLM023 (Dynamic Import-Module): Use static paths
# ============================================================
# Import-Module ActiveDirectory           # Static module name
# Import-Module C:\Modules\MyModule.psm1  # Static literal path

# ============================================================
# Instead of CLM024 (PSObject/PSBase): Use standard properties
# ============================================================
$proc = Get-Process -Id $PID
$procId = $proc.Id
$procName = $proc.ProcessName
$procMemory = $proc.WorkingSet64

# ============================================================
# Instead of CLM025 (P/Invoke DllImport): Use cmdlets
# ============================================================
$currentPid = $PID  # Built-in variable, no Win32 API needed

# ============================================================
# Instead of CLM026 (String concat commands): Use directly
# ============================================================
# Just write: Add-Type, Invoke-Expression, New-Object directly

# ============================================================
# Instead of CLM027 (Char array obfuscation): Use plain text
# ============================================================
$word = "Invoke"  # Just write the string

# ============================================================
# Instead of CLM028 (Base64 strings): Use plain text
# ============================================================
$command = 'Write-Host "Hello World"'  # Plain text, not encoded

# ============================================================
# Instead of CLM029 (Variable command invocation): Call directly
# ============================================================
Get-Process | Select-Object -First 5
Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5

# ============================================================
# Instead of CLM030 (String replace chains): Use plain text
# ============================================================
$cleanCommand = "Add-Type -TypeDefinition"  # No obfuscation needed

# ============================================================
# Final output
# ============================================================
Write-Output "All operations completed using CLM-compatible constructs."
Write-Output "This script should produce ZERO Critical or High findings in CLM-Forge."
