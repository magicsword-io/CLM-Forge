function Get-SecurityFeatureStatus {
    <#
    .SYNOPSIS
        Detects PowerShell security features and logging configuration.

    .DESCRIPTION
        Checks Script Block Logging, Transcription, Module Logging, AMSI status,
        PowerShell v2 engine availability, execution policy, remoting config,
        Credential Guard, and AppLocker policy configuration.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Get-SecurityFeatureStatus
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Script Block Logging ---
    $sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    try {
        $sblEnabled = (Get-ItemProperty -Path $sblPath -Name 'EnableScriptBlockLogging' -ErrorAction Stop).EnableScriptBlockLogging
        $sblInvocation = $null
        try { $sblInvocation = (Get-ItemProperty -Path $sblPath -Name 'EnableScriptBlockInvocationLogging' -ErrorAction Stop).EnableScriptBlockInvocationLogging } catch {}

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ScriptBlockLogging' `
            -Status $(if ($sblEnabled -eq 1) { 'Pass' } else { 'Warning' }) `
            -Severity $(if ($sblEnabled -eq 1) { 'Info' } else { 'Medium' }) `
            -Message $(if ($sblEnabled -eq 1) { "Script Block Logging is ENABLED$(if ($sblInvocation -eq 1) { ' (with invocation logging)' })" } else { 'Script Block Logging is DISABLED' }) `
            -Details @{ enabled = ($sblEnabled -eq 1); invocationLogging = ($sblInvocation -eq 1); registryPath = $sblPath } `
            -Remediation $(if ($sblEnabled -ne 1) { 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging' } else { '' })))
    }
    catch {
        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ScriptBlockLogging' `
            -Status 'Warning' -Severity 'Medium' `
            -Message 'Script Block Logging policy not configured (registry key not found)' `
            -Details @{ registryPath = $sblPath; error = $_.ToString() } `
            -Remediation 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging'))
    }

    # --- Transcription ---
    $transcriptionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    try {
        $txEnabled = (Get-ItemProperty -Path $transcriptionPath -Name 'EnableTranscripting' -ErrorAction Stop).EnableTranscripting
        $txDir = $null
        try { $txDir = (Get-ItemProperty -Path $transcriptionPath -Name 'OutputDirectory' -ErrorAction Stop).OutputDirectory } catch {}
        $txInvocation = $null
        try { $txInvocation = (Get-ItemProperty -Path $transcriptionPath -Name 'EnableInvocationHeader' -ErrorAction Stop).EnableInvocationHeader } catch {}

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'Transcription' `
            -Status $(if ($txEnabled -eq 1) { 'Pass' } else { 'Warning' }) `
            -Severity $(if ($txEnabled -eq 1) { 'Info' } else { 'Low' }) `
            -Message $(if ($txEnabled -eq 1) { "PowerShell Transcription is ENABLED$(if ($txDir) { " (Output: $txDir)" })" } else { 'PowerShell Transcription is DISABLED' }) `
            -Details @{ enabled = ($txEnabled -eq 1); outputDirectory = $txDir; invocationHeader = ($txInvocation -eq 1) } `
            -Remediation $(if ($txEnabled -ne 1) { 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription' } else { '' })))
    }
    catch {
        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'Transcription' `
            -Status 'Info' -Severity 'Low' `
            -Message 'PowerShell Transcription policy not configured' `
            -Details @{ registryPath = $transcriptionPath }))
    }

    # --- Module Logging ---
    $moduleLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    try {
        $mlEnabled = (Get-ItemProperty -Path $moduleLogPath -Name 'EnableModuleLogging' -ErrorAction Stop).EnableModuleLogging
        $moduleNames = @()
        try {
            $mnPath = Join-Path $moduleLogPath 'ModuleNames'
            if (Test-Path $mnPath) {
                $moduleNames = (Get-ItemProperty -Path $mnPath -ErrorAction Stop).PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } | Select-Object -ExpandProperty Value
            }
        } catch {}

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ModuleLogging' `
            -Status $(if ($mlEnabled -eq 1) { 'Pass' } else { 'Info' }) `
            -Severity 'Info' `
            -Message $(if ($mlEnabled -eq 1) { "Module Logging is ENABLED for: $(if ($moduleNames -contains '*') { 'ALL modules' } else { ($moduleNames -join ', ') })" } else { 'Module Logging is DISABLED' }) `
            -Details @{ enabled = ($mlEnabled -eq 1); modules = $moduleNames }))
    }
    catch {
        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ModuleLogging' `
            -Status 'Info' -Severity 'Info' `
            -Message 'Module Logging policy not configured' `
            -Details @{ registryPath = $moduleLogPath }))
    }

    # --- AMSI Status ---
    $amsiLoaded = $false
    $amsiProviders = @()
    try {
        $amsiDll = Get-Process -Id $PID | Select-Object -ExpandProperty Modules -ErrorAction Stop |
            Where-Object { $_.ModuleName -eq 'amsi.dll' }
        $amsiLoaded = $null -ne $amsiDll
    }
    catch {
        # Try alternative check
        try {
            $amsiLoaded = Test-Path "$env:SystemRoot\System32\amsi.dll"
        }
        catch {}
    }

    # Check registered AMSI providers
    try {
        $amsiProviderPath = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
        if (Test-Path $amsiProviderPath) {
            $amsiProviders = Get-ChildItem -Path $amsiProviderPath -ErrorAction Stop | Select-Object -ExpandProperty PSChildName
        }
    }
    catch {}

    $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'AMSI' `
        -Status $(if ($amsiLoaded) { 'Pass' } else { 'Warning' }) `
        -Severity $(if ($amsiLoaded) { 'Info' } else { 'High' }) `
        -Message $(if ($amsiLoaded) { "AMSI is active ($($amsiProviders.Count) provider(s) registered)" } else { 'AMSI may not be active' }) `
        -Details @{ loaded = $amsiLoaded; providers = $amsiProviders } `
        -Remediation $(if (-not $amsiLoaded) { 'Ensure Windows Defender or another AMSI provider is installed and running.' } else { '' })))

    # --- PowerShell v2 Engine ---
    $psV2Available = $false
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
        $psV2Available = $feature.State -eq 'Enabled'
    }
    catch {
        # Try DISM fallback or registry
        try {
            $psV2Path = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
            if (Test-Path $psV2Path) {
                $runtimeVersion = (Get-ItemProperty -Path $psV2Path -Name 'RuntimeVersion' -ErrorAction Stop).RuntimeVersion
                $psV2Available = $null -ne $runtimeVersion
            }
        }
        catch {}
    }

    $v2Status = if ($psV2Available) { 'Warning' } else { 'Pass' }
    $v2Severity = if ($psV2Available) { 'High' } else { 'Info' }
    $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'PowerShellV2Engine' `
        -Status $v2Status -Severity $v2Severity `
        -Message $(if ($psV2Available) { 'PowerShell v2 engine is AVAILABLE (can bypass CLM!)' } else { 'PowerShell v2 engine is disabled or unavailable' }) `
        -Details @{ available = $psV2Available } `
        -Remediation $(if ($psV2Available) { 'Disable PowerShell v2: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' } else { '' })))

    # --- Execution Policy ---
    try {
        $execPolicy = Get-ExecutionPolicy
        $allPolicies = Get-ExecutionPolicy -List
        $policyDetails = @{}
        foreach ($p in $allPolicies) { $policyDetails[$p.Scope.ToString()] = $p.ExecutionPolicy.ToString() }

        $epStatus = switch ($execPolicy.ToString()) {
            'Restricted'    { 'Pass' }
            'AllSigned'     { 'Pass' }
            'RemoteSigned'  { 'Info' }
            'Unrestricted'  { 'Warning' }
            'Bypass'        { 'Warning' }
            default         { 'Info' }
        }

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ExecutionPolicy' `
            -Status $epStatus -Severity 'Info' `
            -Message "Effective execution policy: $execPolicy" `
            -Details $policyDetails `
            -Remediation $(if ($execPolicy -eq 'Bypass' -or $execPolicy -eq 'Unrestricted') { 'Consider tightening execution policy to RemoteSigned or AllSigned.' } else { '' })))
    }
    catch {
        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'ExecutionPolicy' `
            -Status 'Error' -Severity 'Low' `
            -Message "Could not determine execution policy: $_"))
    }

    # --- PowerShell Remoting ---
    try {
        $wsmanRunning = $false
        $wsmanSvc = Get-Service -Name 'WinRM' -ErrorAction Stop
        $wsmanRunning = $wsmanSvc.Status -eq 'Running'

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'PSRemoting' `
            -Status $(if ($wsmanRunning) { 'Info' } else { 'Info' }) `
            -Severity 'Info' `
            -Message "PowerShell Remoting (WinRM): $($wsmanSvc.Status) / StartType: $($wsmanSvc.StartType)" `
            -Details @{ status = $wsmanSvc.Status.ToString(); startType = $wsmanSvc.StartType.ToString() }))
    }
    catch {
        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'PSRemoting' `
            -Status 'Info' -Severity 'Info' `
            -Message "WinRM service check: $_"))
    }

    # --- JEA Configurations ---
    try {
        $jeaConfigs = Get-PSSessionConfiguration -ErrorAction Stop |
            Where-Object { $_.LanguageMode -or $_.RunAsUser }
        if ($jeaConfigs) {
            foreach ($jea in $jeaConfigs) {
                $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName "JEA:$($jea.Name)" `
                    -Status 'Info' -Severity 'Info' `
                    -Message "PS Session Config: $($jea.Name) | LanguageMode: $($jea.LanguageMode)" `
                    -Details @{ name = $jea.Name; languageMode = $jea.LanguageMode; permission = $jea.Permission }))
            }
        }
    }
    catch {
        # Requires elevation typically
    }

    # --- Credential Guard ---
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $credGuardRunning = $dg.SecurityServicesRunning -contains 1
        $credGuardConfigured = $dg.SecurityServicesConfigured -contains 1

        $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'CredentialGuard' `
            -Status $(if ($credGuardRunning) { 'Pass' } else { 'Info' }) `
            -Severity 'Info' `
            -Message $(if ($credGuardRunning) { 'Credential Guard is running' } elseif ($credGuardConfigured) { 'Credential Guard is configured but not running' } else { 'Credential Guard is not configured' }) `
            -Details @{ running = $credGuardRunning; configured = $credGuardConfigured }))
    }
    catch {}

    # --- AppLocker Policy Summary ---
    try {
        $alPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        if ($alPolicy -and $alPolicy.RuleCollections) {
            $ruleCollections = $alPolicy.RuleCollections
            $scriptRules = $ruleCollections | Where-Object { $_.RuleCollectionType -eq 'Script' }
            $exeRules = $ruleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
            $dllRules = $ruleCollections | Where-Object { $_.RuleCollectionType -eq 'Dll' }

            $alDetails = @{
                scriptRuleCount = if ($scriptRules) { $scriptRules.Count } else { 0 }
                exeRuleCount    = if ($exeRules) { $exeRules.Count } else { 0 }
                dllRuleCount    = if ($dllRules) { $dllRules.Count } else { 0 }
            }

            $results.Add((New-CLMResult -Category 'SecurityFeatures' -TestName 'AppLockerPolicy' `
                -Status $(if ($scriptRules) { 'Warning' } else { 'Info' }) `
                -Severity $(if ($scriptRules) { 'High' } else { 'Info' }) `
                -Message "AppLocker: $($alDetails.scriptRuleCount) script rules, $($alDetails.exeRuleCount) exe rules, $($alDetails.dllRuleCount) DLL rules" `
                -Details $alDetails `
                -Remediation $(if ($scriptRules) { 'AppLocker script rules are active. Non-whitelisted scripts will run in CLM.' } else { '' })))
        }
    }
    catch {
        # AppLocker cmdlet not available or not elevated
    }

    return $results.ToArray()
}
