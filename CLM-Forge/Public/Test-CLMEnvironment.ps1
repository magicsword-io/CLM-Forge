function Test-CLMEnvironment {
    <#
    .SYNOPSIS
        Detects the current PowerShell Constrained Language Mode environment and system configuration.

    .DESCRIPTION
        Performs comprehensive environment detection including language mode, PowerShell version,
        OS version, elevation status, WDAC lockdown policy via WinAPI, AppLocker status, and
        session configuration details.

    .PARAMETER IncludeWinAPI
        Attempt WinAPI-based detection (may fail in CLM, will gracefully fall back).

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Test-CLMEnvironment
        Test-CLMEnvironment -IncludeWinAPI
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [switch]$IncludeWinAPI
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Language Mode ---
    $languageMode = $ExecutionContext.SessionState.LanguageMode
    $lmStatus = if ($languageMode -eq 'FullLanguage') { 'Pass' } elseif ($languageMode -eq 'ConstrainedLanguage') { 'Warning' } else { 'Fail' }
    $results.Add((New-CLMResult -Category 'Environment' -TestName 'LanguageMode' -Status $lmStatus -Severity 'Info' `
        -Message "Current language mode: $languageMode" `
        -Details @{ languageMode = $languageMode.ToString() } `
        -Remediation $(if ($languageMode -eq 'ConstrainedLanguage') { 'System is in CLM. Scripts not in WDAC allow list will run with restricted capabilities.' } else { '' })))

    # --- PowerShell Version ---
    $psVersion = $PSVersionTable.PSVersion.ToString()
    $psEdition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
    $results.Add((New-CLMResult -Category 'Environment' -TestName 'PowerShellVersion' -Status 'Info' -Severity 'Info' `
        -Message "PowerShell $psVersion ($psEdition)" `
        -Details @{ version = $psVersion; edition = $psEdition; clrVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { 'N/A' } }))

    # --- OS Version ---
    $osInfo = @{}
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osInfo = @{
            caption     = $os.Caption
            version     = $os.Version
            buildNumber = $os.BuildNumber
            osArch      = $os.OSArchitecture
        }
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'OperatingSystem' -Status 'Info' -Severity 'Info' `
            -Message "$($os.Caption) $($os.Version) Build $($os.BuildNumber)" `
            -Details $osInfo))
    }
    catch {
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'OperatingSystem' -Status 'Info' -Severity 'Info' `
            -Message "OS: $([System.Environment]::OSVersion.VersionString)" `
            -Details @{ versionString = [System.Environment]::OSVersion.VersionString }))
    }

    # --- Elevation Check ---
    $isElevated = $false
    try {
        $isElevated = Test-IsElevated
    }
    catch {
        # Not critical if this fails
    }
    $elevStatus = if ($isElevated) { 'Pass' } else { 'Warning' }
    $results.Add((New-CLMResult -Category 'Environment' -TestName 'Elevation' -Status $elevStatus -Severity 'Low' `
        -Message $(if ($isElevated) { 'Running as Administrator' } else { 'Running as standard user (some checks require elevation)' }) `
        -Details @{ isElevated = $isElevated } `
        -Remediation $(if (-not $isElevated) { 'Run as Administrator to enable WDAC policy enumeration, system path tests, and event log analysis.' } else { '' })))

    # --- Session Type ---
    $sessionType = 'Console'
    if ($host.Name -eq 'Windows PowerShell ISE Host') { $sessionType = 'ISE' }
    elseif ($host.Name -eq 'Visual Studio Code Host') { $sessionType = 'VSCode' }
    elseif ($PSSenderInfo) { $sessionType = 'Remoting' }
    elseif ($host.Name -eq 'ServerRemoteHost') { $sessionType = 'Remoting' }

    $results.Add((New-CLMResult -Category 'Environment' -TestName 'SessionType' -Status 'Info' -Severity 'Info' `
        -Message "Session type: $sessionType (Host: $($host.Name))" `
        -Details @{ sessionType = $sessionType; hostName = $host.Name; hostVersion = $host.Version.ToString() }))

    # --- Execution Policy ---
    try {
        $execPolicies = Get-ExecutionPolicy -List -ErrorAction Stop
        $effectivePolicy = Get-ExecutionPolicy -ErrorAction Stop
        $epDetails = @{}
        foreach ($ep in $execPolicies) {
            $epDetails[$ep.Scope.ToString()] = $ep.ExecutionPolicy.ToString()
        }
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'ExecutionPolicy' -Status 'Info' -Severity 'Info' `
            -Message "Effective execution policy: $effectivePolicy" `
            -Details @{ effective = $effectivePolicy.ToString(); scopes = $epDetails }))
    }
    catch {
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'ExecutionPolicy' -Status 'Error' -Severity 'Low' `
            -Message "Could not determine execution policy: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- .NET CLR Version ---
    $clrVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { 'N/A (PowerShell Core uses .NET Core)' }
    $dotnetVersion = $null
    try {
        $dotnetVersion = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
    }
    catch {
        $dotnetVersion = $clrVersion
    }
    $results.Add((New-CLMResult -Category 'Environment' -TestName 'DotNetVersion' -Status 'Info' -Severity 'Info' `
        -Message ".NET Runtime: $dotnetVersion" `
        -Details @{ clrVersion = $clrVersion; frameworkDescription = $dotnetVersion }))

    # --- WinAPI Detection (if requested) ---
    if ($IncludeWinAPI) {
        try {
            $wldpResults = Get-WldpLockdownPolicy
            if ($wldpResults) {
                $wldpStatus = if ($wldpResults.IsEnforced) { 'Fail' } elseif ($wldpResults.IsAudit) { 'Warning' } else { 'Pass' }
                $wldpSeverity = if ($wldpResults.IsEnforced) { 'Critical' } elseif ($wldpResults.IsAudit) { 'High' } else { 'Info' }
                $wldpMsg = if ($wldpResults.IsEnforced) { 'WDAC UMCI is ENFORCED (scripts will run in CLM)' }
                           elseif ($wldpResults.IsAudit) { 'WDAC UMCI is in AUDIT mode (violations logged, CLM not policy-enforced)' }
                           else { 'No WDAC UMCI lockdown detected for this PowerShell host' }

                $results.Add((New-CLMResult -Category 'Environment' -TestName 'WldpLockdownPolicy' -Status $wldpStatus -Severity $wldpSeverity `
                    -Message "$wldpMsg (via $($wldpResults.DetectionMethod))" `
                    -Details $wldpResults `
                    -Remediation $(if ($wldpResults.IsEnforced) { 'WDAC is enforcing CLM. Ensure scripts are signed and covered by WDAC allow rules before deployment.' } else { '' })))
            }
        }
        catch {
            $results.Add((New-CLMResult -Category 'Environment' -TestName 'WldpLockdownPolicy' -Status 'Skipped' -Severity 'Info' `
                -Message "WinAPI detection unavailable: $_" `
                -Details @{ error = $_.ToString() }))
        }
    }

    # --- PSScriptPolicyTest (how PowerShell detects CLM) ---
    $tempRoot = if ($env:TEMP) { $env:TEMP } elseif ($env:TMP) { $env:TMP } else { [System.IO.Path]::GetTempPath() }
    $policyTestFiles = @()
    if ($tempRoot) {
        $policyTestPath = Join-Path $tempRoot '__PSScriptPolicyTest_*.ps1'
        $policyTestFiles = Get-ChildItem -Path $policyTestPath -ErrorAction SilentlyContinue
    }
    if ($policyTestFiles) {
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'PSScriptPolicyTest' -Status 'Warning' -Severity 'Medium' `
            -Message "Found $($policyTestFiles.Count) PSScriptPolicyTest file(s) in TEMP (indicates CLM detection is active)" `
            -Details @{ count = $policyTestFiles.Count; files = $policyTestFiles.Name }))
    }

    # --- AppLocker Service ---
    try {
        $appIdSvc = Get-Service -Name 'AppIDSvc' -ErrorAction Stop
        $appLockerStatus = if ($appIdSvc.Status -eq 'Running') { 'Warning' } else { 'Info' }
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'AppLockerService' -Status $appLockerStatus -Severity 'Medium' `
            -Message "AppLocker service (AppIDSvc): $($appIdSvc.Status) / StartType: $($appIdSvc.StartType)" `
            -Details @{ status = $appIdSvc.Status.ToString(); startType = $appIdSvc.StartType.ToString() } `
            -Remediation $(if ($appIdSvc.Status -eq 'Running') { 'AppLocker is active. PowerShell scripts not whitelisted by AppLocker rules will run in CLM.' } else { '' })))
    }
    catch {
        $results.Add((New-CLMResult -Category 'Environment' -TestName 'AppLockerService' -Status 'Info' -Severity 'Info' `
            -Message "AppLocker service check: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- Quick CLM Functional Test ---
    # Try something that only works in FullLanguage
    $clmFunctionalTest = $true
    try {
        $null = [System.Collections.Generic.List[string]]::new()
    }
    catch {
        $clmFunctionalTest = $false
    }

    $addTypeWorks = $true
    try {
        $testType = 'public class CLMCheckProbe { public static int Test() { return 42; } }'
        Add-Type -TypeDefinition $testType -ErrorAction Stop
    }
    catch {
        $addTypeWorks = $false
    }

    $results.Add((New-CLMResult -Category 'Environment' -TestName 'FunctionalCLMTest' `
        -Status $(if ($addTypeWorks) { 'Pass' } else { 'Fail' }) `
        -Severity $(if ($addTypeWorks) { 'Info' } else { 'Critical' }) `
        -Message $(if ($addTypeWorks) { 'Add-Type is available (FullLanguage capabilities confirmed)' } else { 'Add-Type is BLOCKED (Constrained Language Mode is active)' }) `
        -Details @{ addTypeAvailable = $addTypeWorks; genericTypeAccess = $clmFunctionalTest } `
        -Remediation $(if (-not $addTypeWorks) { 'CLM is restricting advanced PowerShell features. Scripts using Add-Type, COM objects, or restricted .NET types will fail.' } else { '' })))

    return $results.ToArray()
}
