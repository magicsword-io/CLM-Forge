function Test-ScriptWDACTrust {
    <#
    .SYNOPSIS
        Asks Windows policy APIs whether a script runs trusted, constrained, or blocked.
        Uses WldpCanExecuteFile on supported Windows builds and the legacy
        WldpGetLockdownPolicy per-file path where the newer API is unavailable.

    .DESCRIPTION
        WldpCanExecuteFile evaluates the script file against active App Control policy
        and returns one of three verdicts:

        - Allowed: Script runs in FullLanguage mode (trusted by WDAC)
        - ConstrainedLanguage: Script runs but in CLM (not fully trusted)
        - Blocked: Script is blocked from executing entirely

        The direct blocked/allowed/CLM verdict requires Windows 11 build 22621+ in
        FullLanguage mode. On older Windows builds, the legacy WLDP fallback reports
        whether PowerShell will treat the script as trusted FullLanguage or untrusted
        ConstrainedLanguage. If no WDAC policy is active, scripts return Allowed.

    .PARAMETER ScriptPath
        Path to the script file to evaluate. Can be .ps1, .psm1, .psd1, etc.

    .PARAMETER ScriptPaths
        Array of script paths to evaluate in batch.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Test-ScriptWDACTrust -ScriptPath C:\Scripts\Deploy.ps1
        Test-ScriptWDACTrust -ScriptPaths (Get-ChildItem .\Scripts\*.ps1).FullName
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Single')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ScriptPath,

        [Parameter(ParameterSetName = 'Batch')]
        [string[]]$ScriptPaths
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Combine single and batch paths
    $allPaths = @()
    if ($ScriptPath) { $allPaths += $ScriptPath }
    if ($ScriptPaths) { $allPaths += $ScriptPaths }

    if ($allPaths.Count -eq 0) {
        $results.Add((New-CLMResult -Category 'WDACTrust' -TestName 'NoInput' -Status 'Error' -Severity 'Info' `
            -Message 'No script paths provided.' `
            -Remediation 'Provide -ScriptPath or -ScriptPaths parameter.'))
        return $results.ToArray()
    }

    # Initialize WLDP native methods where possible.
    $null = Get-WldpLockdownPolicy

    foreach ($path in $allPaths) {
        $resolved = $null
        try {
            $resolved = (Resolve-Path $path -ErrorAction Stop).Path
        }
        catch {
            $results.Add((New-CLMResult -Category 'WDACTrust' -TestName "Trust:$([System.IO.Path]::GetFileName($path))" `
                -Status 'Error' -Severity 'Info' `
                -Message "File not found: $path"))
            continue
        }

        $fileName = [System.IO.Path]::GetFileName($resolved)
        $trustResult = Test-WldpCanExecuteFile -FilePath $resolved

        if ($trustResult.Error) {
            $results.Add((New-CLMResult -Category 'WDACTrust' -TestName "Trust:$fileName" `
                -Status 'Skipped' -Severity 'Info' `
                -Message "Could not query WDAC trust for $fileName : $($trustResult.Error)" `
                -Details @{
                    filePath        = $resolved
                    error           = $trustResult.Error
                    detectionMethod = $trustResult.DetectionMethod
                } `
                -Remediation 'Run this check on Windows from a trusted FullLanguage PowerShell host. WldpCanExecuteFile requires Windows 11 build 22621+; older builds use the legacy WLDP fallback.'))
            continue
        }

        $status = switch ($trustResult.ExecutionPolicy) {
            'Allowed'              { 'Pass' }
            'ConstrainedLanguage'  { 'Warning' }
            'Blocked'              { 'Fail' }
            default                { 'Info' }
        }
        $severity = switch ($trustResult.ExecutionPolicy) {
            'Allowed'              { 'Info' }
            'ConstrainedLanguage'  { 'High' }
            'Blocked'              { 'Critical' }
            default                { 'Info' }
        }
        $message = switch ($trustResult.ExecutionPolicy) {
            'Allowed'              { "WDAC TRUSTS $fileName - will run in FullLanguage mode" }
            'ConstrainedLanguage'  { "WDAC CONSTRAINS $fileName - will run in ConstrainedLanguage mode (CLM)" }
            'Blocked'              { "WDAC BLOCKS $fileName - execution denied by policy" }
            default                { "WDAC returned unknown policy for $fileName" }
        }
        $remediation = switch ($trustResult.ExecutionPolicy) {
            'ConstrainedLanguage'  { 'Sign the script with a trusted certificate and add a WDAC signer rule, or add a hash/path rule to your WDAC policy.' }
            'Blocked'              { 'The script is explicitly denied by WDAC policy. Add an allow rule (signer, hash, or path) to permit execution.' }
            default                { '' }
        }

        $results.Add((New-CLMResult -Category 'WDACTrust' -TestName "Trust:$fileName" `
            -Status $status -Severity $severity `
            -Message $message `
            -Details @{
                filePath        = $resolved
                executionPolicy = $trustResult.ExecutionPolicy
                rawResult       = $trustResult.RawResult
                policyMode      = $trustResult.PolicyMode
                detectionMethod = $trustResult.DetectionMethod
                canExecute      = $trustResult.CanExecute
            } `
            -Remediation $remediation))
    }

    return $results.ToArray()
}
