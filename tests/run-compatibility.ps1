#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'

function Assert-CLMCondition {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$modulePath = Join-Path (Join-Path $RepoRoot 'CLM-Forge') 'CLM-Forge.psd1'
$fixtureRoot = Join-Path (Join-Path $RepoRoot 'tests') 'fixtures'
$safePath = Join-Path $fixtureRoot 'safe-script.ps1'
$unsafePath = Join-Path $fixtureRoot 'unsafe-script.ps1'

Assert-CLMCondition (Test-Path -Path $modulePath -PathType Leaf) "Module manifest not found: $modulePath"
Assert-CLMCondition (Test-Path -Path $safePath -PathType Leaf) "Safe fixture not found: $safePath"
Assert-CLMCondition (Test-Path -Path $unsafePath -PathType Leaf) "Unsafe fixture not found: $unsafePath"

Import-Module $modulePath -Force
$module = Get-Module CLM-Forge
Assert-CLMCondition ($null -ne $module) 'CLM-Forge module did not import.'

$expectedFunctions = @(
    'Invoke-CLMForge',
    'Invoke-CLMCheck',
    'Test-CLMEnvironment',
    'Test-ScriptCLMCompatibility',
    'Test-ScriptHostExecution',
    'Test-ScriptWDACTrust',
    'Get-WDACPolicyInfo',
    'Test-CLMCOMRestrictions',
    'Test-CLMTypeRestrictions',
    'Get-SecurityFeatureStatus',
    'Get-CLMEventLogs',
    'New-CLMReport'
)

foreach ($functionName in $expectedFunctions) {
    Assert-CLMCondition ($module.ExportedFunctions.ContainsKey($functionName)) "Missing exported function: $functionName"
}

Assert-CLMCondition ($module.ExportedAliases.ContainsKey('clmforge')) 'Missing clmforge alias.'
Assert-CLMCondition ($module.ExportedAliases.ContainsKey('clmcheck')) 'Missing clmcheck alias.'

$unsafeResults = Test-ScriptCLMCompatibility -ScriptPath $unsafePath
Assert-CLMCondition (($unsafeResults | Where-Object { $_.TestName -match 'CLM001' }).Count -gt 0) 'Unsafe fixture did not trigger CLM001.'
Assert-CLMCondition (($unsafeResults | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }).Count -gt 0) 'Unsafe fixture did not produce critical failures.'

$safeResults = Test-ScriptCLMCompatibility -ScriptPath $safePath
Assert-CLMCondition (($safeResults | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }).Count -eq 0) 'Safe fixture produced critical failures.'
Assert-CLMCondition (($safeResults | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'Fail' }).Count -eq 0) 'Safe fixture produced high failures.'

$reportDir = Join-Path ([System.IO.Path]::GetTempPath()) "clm-forge-compat-$([System.Guid]::NewGuid().ToString('N'))"
try {
    $report = $safeResults | New-CLMReport -Format 'JSON', 'HTML' -OutputDirectory $reportDir -Quiet
    Assert-CLMCondition ($report.ReportPaths.ContainsKey('JSON')) 'JSON report path missing.'
    Assert-CLMCondition ($report.ReportPaths.ContainsKey('HTML')) 'HTML report path missing.'
    Assert-CLMCondition (Test-Path -Path $report.ReportPaths['JSON'] -PathType Leaf) 'JSON report file missing.'
    Assert-CLMCondition (Test-Path -Path $report.ReportPaths['HTML'] -PathType Leaf) 'HTML report file missing.'
}
finally {
    if (Test-Path -Path $reportDir) {
        Remove-Item -Path $reportDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "CLM Forge compatibility smoke passed on PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))."
