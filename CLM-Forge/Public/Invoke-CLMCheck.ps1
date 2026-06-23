function Invoke-CLMCheck {
    <#
    .SYNOPSIS
        Master orchestrator for CLM Forge. Runs all or selected validation checks.

    .DESCRIPTION
        Comprehensive Constrained Language Mode and WDAC script enforcement validation.
        Detects environment configuration, analyzes scripts for CLM compatibility,
        tests script host execution, checks COM/type restrictions, queries event logs,
        and generates professional reports in multiple formats.

    .PARAMETER ScriptPath
        Path to a PowerShell script to analyze. If omitted, only environment checks run.

    .PARAMETER ConfigPath
        Path to custom configuration JSON. Defaults to module config.

    .PARAMETER Checks
        Which check categories to run. Default is All.

    .PARAMETER OutputFormat
        Output formats to generate. Default is Console.

    .PARAMETER OutputDirectory
        Directory for report files. Default is ./CLM-Forge-Results.

    .PARAMETER RunExecutionTests
        Run script host execution tests (creates/executes temp files). Requires explicit opt-in.

    .PARAMETER IncludeEventLogs
        Include event log analysis.

    .PARAMETER EventLogHours
        Hours of event logs to analyze. Default 24.

    .PARAMETER Quiet
        Suppress console output.

    .PARAMETER PassThru
        Return raw result objects for pipeline use.

    .OUTPUTS
        [PSCustomObject] Report summary with paths and results.

    .EXAMPLE
        Invoke-CLMCheck
        Invoke-CLMCheck -ScriptPath .\Deploy.ps1 -OutputFormat All
        Invoke-CLMCheck -Checks Environment, WDAC -OutputFormat HTML
        Invoke-CLMCheck -ScriptPath .\script.ps1 -RunExecutionTests -IncludeEventLogs -OutputFormat All
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ScriptPath,

        [string]$ConfigPath,

        [ValidateSet('All', 'Environment', 'WDAC', 'AST', 'ScriptHost', 'COM', 'Types', 'Security', 'EventLogs')]
        [string[]]$Checks = @('All'),

        [ValidateSet('Console', 'HTML', 'JSON', 'Log', 'All')]
        [string[]]$OutputFormat = @('Console'),

        [string]$OutputDirectory = (Join-Path $PWD 'CLM-Forge-Results'),

        [switch]$RunExecutionTests,

        [switch]$IncludeEventLogs,

        [int]$EventLogHours = 24,

        [switch]$Quiet,

        [switch]$PassThru
    )

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $runAll = $Checks -contains 'All'

    # Banner
    if (-not $Quiet) {
        Write-Host ''
        Write-Host '  _____ _     __  __       _____ _               _    ' -ForegroundColor Cyan
        Write-Host ' / ____| |   |  \/  |     / ____| |             | |   ' -ForegroundColor Cyan
        Write-Host '| |    | |   | \  / |    | |    | |__   ___  ___| | __' -ForegroundColor Cyan
        Write-Host '| |    | |   | |\/| |    | |    |  _ \ / _ \/ __| |/ /' -ForegroundColor Cyan
        Write-Host '| |____| |___| |  | |    | |____| | | |  __/ (__|   < ' -ForegroundColor Cyan
        Write-Host ' \_____|_____|_|  |_|     \_____|_| |_|\___|\___|_|\_\' -ForegroundColor Cyan
        Write-Host ''
        Write-Host "  CLM Forge v$($script:ModuleVersion) - Script Enforcement Readiness Validator" -ForegroundColor White
        Write-Host "  From script chaos to enforced trust." -ForegroundColor DarkGray
        Write-Host ''
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Environment Checks ---
    if ($runAll -or $Checks -contains 'Environment') {
        if (-not $Quiet) { Write-Host '[*] Running environment checks...' -ForegroundColor Cyan }
        try {
            $envResults = Test-CLMEnvironment -IncludeWinAPI
            foreach ($r in $envResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'Environment' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "Environment check failed: $_"))
        }
    }

    # --- WDAC Policy ---
    if ($runAll -or $Checks -contains 'WDAC') {
        if (-not $Quiet) { Write-Host '[*] Checking WDAC policies...' -ForegroundColor Cyan }
        try {
            $wdacResults = Get-WDACPolicyInfo
            foreach ($r in $wdacResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'WDAC' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "WDAC check failed: $_"))
        }
    }

    # --- Static Analysis ---
    if (($runAll -or $Checks -contains 'AST') -and $ScriptPath) {
        if (-not $Quiet) { Write-Host "[*] Analyzing script: $ScriptPath" -ForegroundColor Cyan }
        try {
            $astResults = Test-ScriptCLMCompatibility -ScriptPath $ScriptPath
            foreach ($r in $astResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "Script analysis failed: $_"))
        }
    }
    elseif (($runAll -or $Checks -contains 'AST') -and -not $ScriptPath) {
        $allResults.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'Skipped' -Status 'Skipped' -Severity 'Info' `
            -Message 'No script path provided. Use -ScriptPath to analyze a specific script.' `
            -Remediation 'Invoke-CLMCheck -ScriptPath <path-to-script.ps1>'))
    }

    # --- WDAC Trust Check (WldpCanExecuteFile) ---
    if (($runAll -or $Checks -contains 'WDAC' -or $Checks -contains 'AST') -and $ScriptPath) {
        if (-not $Quiet) { Write-Host "[*] Querying WDAC trust for: $ScriptPath" -ForegroundColor Cyan }
        try {
            $trustResults = Test-ScriptWDACTrust -ScriptPath $ScriptPath
            foreach ($r in $trustResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'WDACTrust' -TestName 'Error' -Status 'Error' -Severity 'Low' `
                -Message "WDAC trust check failed: $_"))
        }
    }

    # --- Script Host Execution ---
    if (($runAll -or $Checks -contains 'ScriptHost') -and $RunExecutionTests) {
        if (-not $Quiet) { Write-Host '[*] Running script host execution tests...' -ForegroundColor Cyan }
        try {
            $shParams = @{}
            if ($ConfigPath) { $shParams['ConfigPath'] = $ConfigPath }
            $shResults = Test-ScriptHostExecution @shParams
            foreach ($r in $shResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'ScriptHost' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "Script host tests failed: $_"))
        }
    }
    elseif (($runAll -or $Checks -contains 'ScriptHost') -and -not $RunExecutionTests) {
        $allResults.Add((New-CLMResult -Category 'ScriptHost' -TestName 'Skipped' -Status 'Skipped' -Severity 'Info' `
            -Message 'Script host execution tests skipped (use -RunExecutionTests to enable)' `
            -Remediation 'Add -RunExecutionTests flag to test script creation and execution across paths.'))
    }

    # --- COM Restrictions ---
    if ($runAll -or $Checks -contains 'COM') {
        if (-not $Quiet) { Write-Host '[*] Testing COM object restrictions...' -ForegroundColor Cyan }
        try {
            $comResults = Test-CLMCOMRestrictions
            foreach ($r in $comResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'COM' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "COM restriction tests failed: $_"))
        }
    }

    # --- Type Restrictions ---
    if ($runAll -or $Checks -contains 'Types') {
        if (-not $Quiet) { Write-Host '[*] Testing .NET type restrictions...' -ForegroundColor Cyan }
        try {
            $typeResults = Test-CLMTypeRestrictions -TestTypeAccelerators -TestAssemblyLoading
            foreach ($r in $typeResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'TypeRestrictions' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "Type restriction tests failed: $_"))
        }
    }

    # --- Security Features ---
    if ($runAll -or $Checks -contains 'Security') {
        if (-not $Quiet) { Write-Host '[*] Checking security features...' -ForegroundColor Cyan }
        try {
            $secResults = Get-SecurityFeatureStatus
            foreach ($r in $secResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'Error' -Status 'Error' -Severity 'High' `
                -Message "Security feature check failed: $_"))
        }
    }

    # --- Event Logs ---
    if (($runAll -or $Checks -contains 'EventLogs') -and $IncludeEventLogs) {
        if (-not $Quiet) { Write-Host '[*] Querying event logs...' -ForegroundColor Cyan }
        try {
            $elParams = @{ Hours = $EventLogHours }
            if ($ScriptPath) { $elParams['CorrelateScript'] = $ScriptPath }
            $elResults = Get-CLMEventLogs @elParams
            foreach ($r in $elResults) { $allResults.Add($r) }
        }
        catch {
            $allResults.Add((New-CLMResult -Category 'EventLogs' -TestName 'Error' -Status 'Error' -Severity 'Low' `
                -Message "Event log query failed: $_"))
        }
    }
    elseif (($runAll -or $Checks -contains 'EventLogs') -and -not $IncludeEventLogs) {
        $allResults.Add((New-CLMResult -Category 'EventLogs' -TestName 'Skipped' -Status 'Skipped' -Severity 'Info' `
            -Message 'Event log analysis skipped (use -IncludeEventLogs to enable)'))
    }

    $stopwatch.Stop()

    if (-not $Quiet) {
        Write-Host ''
        Write-Host "[*] Checks complete in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s. Generating report..." -ForegroundColor Cyan
    }

    # Generate report
    $report = $allResults.ToArray() | New-CLMReport -Format $OutputFormat -OutputDirectory $OutputDirectory -Quiet:$Quiet

    if ($PassThru) {
        return [PSCustomObject]@{
            Results     = $allResults.ToArray()
            Report      = $report
            Duration    = $stopwatch.Elapsed
        }
    }

    return $report
}
