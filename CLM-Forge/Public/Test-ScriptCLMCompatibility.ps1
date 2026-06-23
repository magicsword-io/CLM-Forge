function Test-ScriptCLMCompatibility {
    <#
    .SYNOPSIS
        Performs static analysis on a PowerShell script to detect CLM-incompatible constructs.

    .DESCRIPTION
        Parses the target .ps1 script using the PowerShell AST and checks for 30 known
        CLM-restricted constructs including Add-Type, COM objects, restricted .NET types,
        custom classes, reflection, delegates, XAML, and more. Each finding includes
        line numbers, code snippets, severity, and remediation guidance.

    .PARAMETER ScriptPath
        Path to the .ps1 script to analyze.

    .PARAMETER Recurse
        Also analyze dot-sourced and imported scripts found within the target.

    .PARAMETER MinimumSeverity
        Only report findings at this severity level or above.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects with AST finding details.

    .EXAMPLE
        Test-ScriptCLMCompatibility -ScriptPath C:\Scripts\Deploy.ps1
        Test-ScriptCLMCompatibility -ScriptPath .\MyScript.ps1 -MinimumSeverity High
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ScriptPath,

        [switch]$Recurse,

        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'Info',

        [Parameter(DontShow)]
        [System.Collections.Generic.HashSet[string]]$VisitedScripts
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resolvedPath = Resolve-Path $ScriptPath | Select-Object -ExpandProperty Path
    $resolvedPath = [System.IO.Path]::GetFullPath($resolvedPath)
    $scriptDirectory = Split-Path -Path $resolvedPath -Parent

    if (-not $VisitedScripts) {
        $VisitedScripts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    if (-not $VisitedScripts.Add($resolvedPath)) {
        $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'RecurseCycleGuard' -Status 'Info' -Severity 'Info' `
            -Message "Skipping already analyzed script: $resolvedPath"))
        return $results.ToArray()
    }

    # Parse the script
    $tokens = $null
    $errors = $null
    try {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($resolvedPath, [ref]$tokens, [ref]$errors)
    }
    catch {
        $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'ParseScript' -Status 'Error' -Severity 'Critical' `
            -Message "Failed to parse script: $_" `
            -Details @{ scriptPath = $resolvedPath; error = $_.ToString() } `
            -Remediation 'Ensure the script has valid PowerShell syntax.'))
        return $results.ToArray()
    }

    # Script info
    $lineCount = (Get-Content -Path $resolvedPath -ErrorAction SilentlyContinue | Measure-Object).Count
    $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'ScriptInfo' -Status 'Info' -Severity 'Info' `
        -Message "Analyzing: $resolvedPath ($lineCount lines)" `
        -Details @{ scriptPath = $resolvedPath; lineCount = $lineCount; parseErrors = $(if ($errors) { $errors.Count } else { 0 }) }))

    # Run AST analysis
    $findings = Invoke-ASTAnalysis -AST $ast -Tokens $tokens -Errors $errors -ScriptPath $resolvedPath -MinimumSeverity $MinimumSeverity

    # Convert findings to CLM results
    foreach ($finding in $findings) {
        $status = switch ($finding.Severity) {
            'Critical' { 'Fail' }
            'High'     { 'Fail' }
            'Medium'   { 'Warning' }
            'Low'      { 'Warning' }
            default    { 'Info' }
        }

        $lineInfo = if ($finding.Line -gt 0) { " (Line $($finding.Line))" } else { '' }

        $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName "$($finding.RuleID):$($finding.RuleName)" `
            -Status $status -Severity $finding.Severity `
            -Message "[$($finding.RuleID)] $($finding.RuleName)$lineInfo" `
            -Details @{
                RuleID       = $finding.RuleID
                RuleName     = $finding.RuleName
                Line         = $finding.Line
                Column       = $finding.Column
                EndLine      = $finding.EndLine
                CodeSnippet  = $finding.CodeSnippet
                Description  = $finding.Description
                WDACRuleHint = $finding.WDACRuleHint
                ScriptPath   = $finding.ScriptPath
            } `
            -Remediation $finding.Remediation))
    }

    # Recurse into dot-sourced / imported scripts
    if ($Recurse) {
        $dotSourced = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot
        }, $true)

        foreach ($ds in $dotSourced) {
            if ($ds.CommandElements.Count -ge 1) {
                $targetElement = if ($ds.CommandElements.Count -eq 1) { $ds.CommandElements[0] } else { $ds.CommandElements[1] }
                $targetPath = $targetElement.Extent.Text.Trim("'`"")
                if ($targetPath -notmatch '^\$') {
                    $candidatePath = if ([System.IO.Path]::IsPathRooted($targetPath)) {
                        $targetPath
                    } else {
                        Join-Path $scriptDirectory $targetPath
                    }
                    $resolvedChildPath = $null
                    try {
                        $resolvedChildPath = (Resolve-Path -Path $candidatePath -ErrorAction Stop).Path
                    }
                    catch {
                        continue
                    }

                    $resolvedChildPath = [System.IO.Path]::GetFullPath($resolvedChildPath)
                    if ($VisitedScripts.Contains($resolvedChildPath)) {
                        $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'DotSourced' `
                            -Status 'Info' -Severity 'Info' `
                            -Message "Skipping already analyzed dot-sourced script: $resolvedChildPath" `
                            -Details @{ parentScript = $resolvedPath; childScript = $resolvedChildPath }))
                        continue
                    }

                    $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'DotSourced' `
                        -Status 'Info' -Severity 'Info' `
                        -Message "Recursing into dot-sourced script: $resolvedChildPath" `
                        -Details @{ parentScript = $resolvedPath; childScript = $resolvedChildPath }))

                    $childResults = Test-ScriptCLMCompatibility -ScriptPath $resolvedChildPath -MinimumSeverity $MinimumSeverity -Recurse:$Recurse -VisitedScripts $VisitedScripts
                    foreach ($cr in $childResults) { $results.Add($cr) }
                }
            }
        }
    }

    # WDAC Hash - compute the SHA256 flat file hash that WDAC uses for script allow rules
    $sha256Hash = ''
    $hashError = $null
    $fileSize = $null
    try {
        $hashResult = Get-FileHash -Path $resolvedPath -Algorithm SHA256 -ErrorAction Stop
        $sha256Hash = $hashResult.Hash  # Uppercase hex, 64 chars - exactly what WDAC needs
        try {
            $fileSize = (Get-Item -Path $resolvedPath -ErrorAction Stop).Length
        }
        catch {
            $fileSize = $null
        }
    }
    catch {
        $sha256Hash = ''
        $hashError = $_.Exception.Message
    }

    $hashMessage = if ($hashError) {
        "WDAC SHA256 Hash unavailable: $hashError"
    } else {
        "WDAC SHA256 Hash: $sha256Hash"
    }
    $hashStatus = if ($hashError) { 'Error' } else { 'Info' }
    $hashSeverity = if ($hashError) { 'Low' } else { 'Info' }
    $hashRemediation = if ($hashError) {
        'Verify the script path is readable and rerun hashing to create WDAC hash allow rules.'
    } else {
        "To allow this script via WDAC hash rule, add SHA256: $sha256Hash"
    }

    $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'WDACHash' `
        -Status $hashStatus -Severity $hashSeverity `
        -Message $hashMessage `
        -Details @{
            sha256      = $sha256Hash
            scriptPath  = $resolvedPath
            fileName    = [System.IO.Path]::GetFileName($resolvedPath)
            fileSize    = $fileSize
            error       = $hashError
            instruction = 'Copy this SHA256 hash into your WDAC policy (e.g., MagicSword Policy Editor) to allow this script to run in FullLanguage mode.'
        } `
        -Remediation $hashRemediation))

    # Summary
    $criticalCount = ($findings | Where-Object Severity -eq 'Critical').Count
    $highCount = ($findings | Where-Object Severity -eq 'High').Count
    $mediumCount = ($findings | Where-Object Severity -eq 'Medium').Count
    $lowCount = ($findings | Where-Object Severity -eq 'Low').Count
    $totalFindings = $findings.Count

    $summaryStatus = if ($criticalCount -gt 0) { 'Fail' }
                     elseif ($highCount -gt 0) { 'Fail' }
                     elseif ($mediumCount -gt 0) { 'Warning' }
                     elseif ($lowCount -gt 0) { 'Warning' }
                     else { 'Pass' }
    $summarySeverity = if ($criticalCount -gt 0) { 'Critical' }
                       elseif ($highCount -gt 0) { 'High' }
                       elseif ($mediumCount -gt 0) { 'Medium' }
                       else { 'Info' }

    $summaryMsg = if ($totalFindings -eq 0) {
        "No CLM compatibility issues found in $([System.IO.Path]::GetFileName($resolvedPath))"
    } else {
        "$totalFindings issue(s) found: $criticalCount critical, $highCount high, $mediumCount medium, $lowCount low"
    }

    $results.Add((New-CLMResult -Category 'StaticAnalysis' -TestName 'AnalysisSummary' `
        -Status $summaryStatus -Severity $summarySeverity `
        -Message $summaryMsg `
        -Details @{
            totalFindings = $totalFindings
            critical      = $criticalCount
            high          = $highCount
            medium        = $mediumCount
            low           = $lowCount
            scriptPath    = $resolvedPath
            lineCount     = $lineCount
        } `
        -Remediation $(if ($totalFindings -gt 0) { 'Address the findings above before enabling WDAC script enforcement.' } else { '' })))

    return $results.ToArray()
}
