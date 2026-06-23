function Test-ScriptHostExecution {
    <#
    .SYNOPSIS
        Tests script creation and execution across multiple file types, paths, and execution methods.

    .DESCRIPTION
        Enhanced version of ScriptHostTest. Creates minimal test scripts in each configured path,
        executes them with the appropriate host, and reports success/failure. This reveals which
        script types can execute from which locations under the current WDAC/AppLocker policy.

    .PARAMETER ConfigPath
        Path to configuration JSON. Defaults to module config.

    .PARAMETER FileTypes
        Specific file extensions to test. Default tests all from config.

    .PARAMETER TestPaths
        Specific paths to test. Default tests all from config.

    .PARAMETER TimeoutSeconds
        Timeout per individual test execution. Default 30.

    .PARAMETER Cleanup
        Remove temp files after testing. Default $true.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Test-ScriptHostExecution
        Test-ScriptHostExecution -FileTypes '.ps1', '.vbs' -TimeoutSeconds 10
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param(
        [string]$ConfigPath,

        [ValidateSet('.ps1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsc',
                     '.hta', '.ps1xml', '.psc1', '.mof')]
        [string[]]$FileTypes,

        [string[]]$TestPaths,

        [int]$TimeoutSeconds = 30,

        [bool]$Cleanup = $true
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $createdFiles = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $config = Get-CLMConfig -ConfigPath $ConfigPath
    $isElevated = $false
    try { $isElevated = Test-IsElevated } catch {}

    # Determine file types to test
    $fileTypeConfigs = @()
    if ($config -and $config.scriptHostTests -and $config.scriptHostTests.fileTypes) {
        $fileTypeConfigs = $config.scriptHostTests.fileTypes
    }
    if ($FileTypes) {
        $fileTypeConfigs = $fileTypeConfigs | Where-Object { $FileTypes -contains $_.extension }
    }

    if ($fileTypeConfigs.Count -eq 0) {
        $results.Add((New-CLMResult -Category 'ScriptHost' -TestName 'Configuration' -Status 'Error' -Severity 'Info' `
            -Message 'No file types configured for testing' -Details @{}))
        return $results.ToArray()
    }

    # Determine paths to test
    $testPathConfigs = @()
    if ($config -and $config.scriptHostTests -and $config.scriptHostTests.testPaths) {
        $testPathConfigs = $config.scriptHostTests.testPaths
    }
    if ($TestPaths) {
        $testPathConfigs = $TestPaths | ForEach-Object {
            @{ path = $_; description = $_; requiresAdmin = $false }
        }
    }

    # Filter out admin-only paths if not elevated
    if (-not $isElevated) {
        $testPathConfigs = $testPathConfigs | Where-Object {
            -not $_.requiresAdmin
        }
    }

    $totalTests = $fileTypeConfigs.Count * $testPathConfigs.Count
    $testNum = 0

    foreach ($pathConfig in $testPathConfigs) {
        # Resolve environment variables in path
        $resolvedPath = [System.Environment]::ExpandEnvironmentVariables($pathConfig.path)

        # Check if path exists
        if (-not (Test-Path -Path $resolvedPath -PathType Container)) {
            $results.Add((New-CLMResult -Category 'ScriptHost' -TestName "Path:$($pathConfig.description)" `
                -Status 'Skipped' -Severity 'Info' `
                -Message "Path does not exist: $resolvedPath" `
                -Details @{ path = $resolvedPath; description = $pathConfig.description }))
            continue
        }

        foreach ($ftConfig in $fileTypeConfigs) {
            $testNum++
            $ext = $ftConfig.extension
            $testName = "ScriptExec:$($ext)@$($pathConfig.description)"

            if ($PSCmdlet.ShouldProcess("$ext in $resolvedPath", 'Test script execution')) {
                $testResult = Test-SingleScriptExecution -Extension $ext `
                    -TestPath $resolvedPath `
                    -Host $ftConfig.host `
                    -HostArgs $ftConfig.args `
                    -Content $ftConfig.content `
                    -TimeoutSeconds $TimeoutSeconds `
                    -CreatedFiles $createdFiles

                $status = if ($testResult.Success) { 'Pass' } else { 'Fail' }
                $severity = if ($testResult.Success) { 'Info' } else { 'Medium' }
                $message = if ($testResult.Success) {
                    "$($ftConfig.description) ($ext) executed successfully in $($pathConfig.description)"
                } else {
                    "$($ftConfig.description) ($ext) BLOCKED in $($pathConfig.description): $($testResult.Error)"
                }

                $remediation = ''
                if (-not $testResult.Success) {
                    if ($testResult.Error -match 'language mode|constrained|policy') {
                        $remediation = "Script execution blocked by CLM/WDAC. Add a WDAC allow rule for $ext files in $resolvedPath, or sign the script."
                        $severity = 'High'
                    }
                    elseif ($testResult.Error -match 'access|denied|permission') {
                        $remediation = "Access denied. Check file system permissions for $resolvedPath."
                    }
                    else {
                        $remediation = "Execution failed. Check if the script host ($($ftConfig.host)) is available and allowed by policy."
                    }
                }

                $results.Add((New-CLMResult -Category 'ScriptHost' -TestName $testName -Status $status -Severity $severity `
                    -Message $message `
                    -Details @{
                        extension       = $ext
                        path            = $resolvedPath
                        pathDescription = $pathConfig.description
                        host            = $ftConfig.host
                        exitCode        = $testResult.ExitCode
                        executionTimeMs = $testResult.ExecutionTimeMs
                        stdout          = $testResult.StdOut
                        stderr          = $testResult.StdErr
                        error           = $testResult.Error
                    } `
                    -Remediation $remediation))
            }
        }
    }

    # Cleanup
    if ($Cleanup) {
        foreach ($file in $createdFiles) {
            try {
                if (Test-Path $file) { Remove-Item -Path $file -Force -ErrorAction SilentlyContinue }
            }
            catch {}
        }
    }

    # Summary result
    $passed = ($results | Where-Object { $_.Status -eq 'Pass' -and $_.Category -eq 'ScriptHost' }).Count
    $failed = ($results | Where-Object { $_.Status -eq 'Fail' -and $_.Category -eq 'ScriptHost' }).Count
    $skipped = ($results | Where-Object { $_.Status -eq 'Skipped' -and $_.Category -eq 'ScriptHost' }).Count

    $results.Add((New-CLMResult -Category 'ScriptHost' -TestName 'Summary' `
        -Status $(if ($failed -eq 0) { 'Pass' } elseif ($failed -lt $passed) { 'Warning' } else { 'Fail' }) `
        -Severity 'Info' `
        -Message "Script host tests complete: $passed passed, $failed blocked, $skipped skipped" `
        -Details @{ passed = $passed; failed = $failed; skipped = $skipped; total = $passed + $failed + $skipped }))

    return $results.ToArray()
}

function Test-SingleScriptExecution {
    [CmdletBinding()]
    param(
        [string]$Extension,
        [string]$TestPath,
        [string]$Host,
        [string]$HostArgs,
        [string]$Content,
        [int]$TimeoutSeconds,
        [System.Collections.Concurrent.ConcurrentBag[string]]$CreatedFiles
    )

    $result = @{
        Success        = $false
        ExitCode       = -1
        ExecutionTimeMs = 0
        StdOut         = ''
        StdErr         = ''
        Error          = ''
    }

    $randomName = "CLMChk-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))$Extension"
    $filePath = Join-Path $TestPath $randomName

    try {
        # Create test file
        if (-not $Content -or $Content -eq '') {
            # Skip file types with no content (like .ps1xml which needs special handling)
            $result.Error = 'No test content defined for this extension'
            return $result
        }

        $Content | Out-File -FilePath $filePath -Encoding UTF8 -Force
        $CreatedFiles.Add($filePath)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # Execute based on host
        if ($Extension -eq '.ps1') {
            $output = & powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File $filePath 2>&1
            $result.ExitCode = $LASTEXITCODE
        }
        elseif ($Host -eq 'cmd.exe') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'cmd.exe'
            $psi.Arguments = "/c `"$filePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $result.StdOut = $proc.StandardOutput.ReadToEnd()
            $result.StdErr = $proc.StandardError.ReadToEnd()
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) { $proc.Kill(); $result.Error = 'Timeout'; return $result }
            $result.ExitCode = $proc.ExitCode
        }
        elseif ($Host -eq 'cscript.exe') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'cscript.exe'
            $psi.Arguments = "//nologo `"$filePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $result.StdOut = $proc.StandardOutput.ReadToEnd()
            $result.StdErr = $proc.StandardError.ReadToEnd()
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) { $proc.Kill(); $result.Error = 'Timeout'; return $result }
            $result.ExitCode = $proc.ExitCode
        }
        elseif ($Host -eq 'mshta.exe') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'mshta.exe'
            $psi.Arguments = "`"$filePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) { $proc.Kill(); $result.Error = 'Timeout'; return $result }
            $result.ExitCode = $proc.ExitCode
        }
        elseif ($Host -eq 'mofcomp.exe') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'mofcomp.exe'
            $psi.Arguments = "`"$filePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $result.StdOut = $proc.StandardOutput.ReadToEnd()
            $result.StdErr = $proc.StandardError.ReadToEnd()
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) { $proc.Kill(); $result.Error = 'Timeout'; return $result }
            $result.ExitCode = $proc.ExitCode
        }
        else {
            # Generic execution
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Host
            $psi.Arguments = "$HostArgs `"$filePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $result.StdOut = $proc.StandardOutput.ReadToEnd()
            $result.StdErr = $proc.StandardError.ReadToEnd()
            $completed = $proc.WaitForExit($TimeoutSeconds * 1000)
            if (-not $completed) { $proc.Kill(); $result.Error = 'Timeout'; return $result }
            $result.ExitCode = $proc.ExitCode
        }

        $sw.Stop()
        $result.ExecutionTimeMs = $sw.ElapsedMilliseconds

        if ($result.ExitCode -eq 0) {
            $result.Success = $true
        }
        else {
            $result.Error = "Exit code: $($result.ExitCode)"
            if ($result.StdErr) { $result.Error += " | $($result.StdErr.Substring(0, [Math]::Min(200, $result.StdErr.Length)))" }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        # Always try to clean up
        try {
            if (Test-Path $filePath) {
                Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {}
    }

    return $result
}
