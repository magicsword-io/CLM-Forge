function Get-WDACPolicyInfo {
    <#
    .SYNOPSIS
        Detects and reports WDAC (Windows Defender Application Control) policy status.

    .DESCRIPTION
        Orchestrates WDAC policy detection using multiple methods: WLDP WinAPI calls with
        3-tier fallback, CIM queries, registry inspection, CiTool enumeration, and deployed
        policy file analysis. Returns structured CLM result objects for reporting.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects with Category 'WDAC'.

    .EXAMPLE
        Get-WDACPolicyInfo
        Get-WDACPolicyInfo | New-CLMReport -Format Console
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- WLDP Lockdown Policy (3-tier fallback) ---
    try {
        $wldp = Get-WldpLockdownPolicy
        if ($wldp) {
            $status   = if ($wldp.IsEnforced) { 'Fail' } elseif ($wldp.IsAudit) { 'Warning' } else { 'Pass' }
            $severity = if ($wldp.IsEnforced) { 'Critical' } elseif ($wldp.IsAudit) { 'High' } else { 'Info' }

            $message = switch ($true) {
                $wldp.IsEnforced { 'WDAC UMCI enforcement detected - scripts run in Constrained Language Mode' }
                $wldp.IsAudit    { 'WDAC UMCI audit mode detected - violations are logged, but CLM is not enforced by policy' }
                default          { 'No WDAC UMCI lockdown for this PowerShell host' }
            }

            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'WldpLockdownPolicy' `
                -Status $status -Severity $severity `
                -Message "$message (detected via $($wldp.DetectionMethod))" `
                -Details @{
                    DetectionMethod          = $wldp.DetectionMethod
                    PolicyFlags              = '0x{0:X8}' -f $wldp.PolicyFlags
                    IsEnforced               = $wldp.IsEnforced
                    IsAudit                  = $wldp.IsAudit
                    ScriptEnforcementEnabled = $wldp.ScriptEnforcementEnabled
                    RawLockdownState         = $wldp.RawLockdownState
                } `
                -Remediation $(if ($wldp.IsEnforced) {
                    'WDAC is enforcing CLM. Ensure all scripts are signed with trusted certificates and covered by WDAC allow rules.'
                } elseif ($wldp.IsAudit) {
                    'WDAC is in audit mode. Review event logs (Microsoft-Windows-CodeIntegrity/Operational) for policy violations before switching to enforce.'
                } else { '' })))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'WldpLockdownPolicy' `
            -Status 'Error' -Severity 'Medium' `
            -Message "WLDP lockdown policy detection failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- CIM-based Device Guard Status ---
    try {
        $cimStatus = Get-WDACStatusViaCIM
        if ($cimStatus.Available) {
            $umciStatus = $cimStatus.UsermodeCodeIntegrityPolicyEnforcementStatus
            $vbsStatus  = $cimStatus.VirtualizationBasedSecurityStatus

            $cimSeverity = switch ($umciStatus) {
                2       { 'Critical' }
                1       { 'High' }
                default { 'Info' }
            }
            $cimResult = switch ($umciStatus) {
                2       { 'Fail' }
                1       { 'Warning' }
                default { 'Pass' }
            }
            $umciDesc = switch ($umciStatus) {
                0       { 'Off' }
                1       { 'Audit' }
                2       { 'Enforced' }
                default { "Unknown ($umciStatus)" }
            }
            $vbsDesc = switch ($vbsStatus) {
                0       { 'Off' }
                1       { 'Configured' }
                2       { 'Running' }
                default { "Unknown ($vbsStatus)" }
            }

            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeviceGuardCIM' `
                -Status $cimResult -Severity $cimSeverity `
                -Message "UMCI: $umciDesc | VBS: $vbsDesc (via CIM)" `
                -Details @{
                    VirtualizationBasedSecurityStatus           = $vbsStatus
                    CodeIntegrityPolicyEnforcementStatus        = $cimStatus.CodeIntegrityPolicyEnforcementStatus
                    UsermodeCodeIntegrityPolicyEnforcementStatus = $umciStatus
                    SecurityServicesConfigured                  = $cimStatus.SecurityServicesConfigured
                    SecurityServicesRunning                     = $cimStatus.SecurityServicesRunning
                } `
                -Remediation $(if ($umciStatus -eq 2) {
                    'UMCI is enforced via Device Guard. All user-mode code including PowerShell scripts must be allowed by policy.'
                } elseif ($umciStatus -eq 1) {
                    'UMCI is in audit mode. Monitor CodeIntegrity event logs to identify scripts that would be blocked in enforcement.'
                } else { '' })))
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeviceGuardCIM' `
                -Status 'Info' -Severity 'Info' `
                -Message "Device Guard CIM class not available: $($cimStatus.Error)" `
                -Details @{ error = $cimStatus.Error }))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeviceGuardCIM' `
            -Status 'Error' -Severity 'Low' `
            -Message "CIM Device Guard query failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- Registry-based WDAC Detection ---
    try {
        $regStatus = Get-WDACStatusViaRegistry

        # Device Guard registry
        if ($regStatus.DeviceGuard) {
            $dg = $regStatus.DeviceGuard
            $vbsEnabled = $dg.EnableVirtualizationBasedSecurity -eq 1
            $hvciEnabled = $dg.HypervisorEnforcedCodeIntegrity -eq 1

            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeviceGuardRegistry' `
                -Status $(if ($vbsEnabled) { 'Warning' } else { 'Pass' }) `
                -Severity $(if ($hvciEnabled) { 'High' } elseif ($vbsEnabled) { 'Medium' } else { 'Info' }) `
                -Message "Device Guard: VBS=$(if ($vbsEnabled) {'Enabled'} else {'Disabled'}), HVCI=$(if ($hvciEnabled) {'Enabled'} else {'Disabled'}) (via Registry)" `
                -Details @{
                    EnableVirtualizationBasedSecurity = $dg.EnableVirtualizationBasedSecurity
                    RequirePlatformSecurityFeatures   = $dg.RequirePlatformSecurityFeatures
                    HypervisorEnforcedCodeIntegrity   = $dg.HypervisorEnforcedCodeIntegrity
                }))
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeviceGuardRegistry' `
                -Status 'Pass' -Severity 'Info' `
                -Message 'Device Guard registry key not found (not configured via policy)'))
        }

        # CI Policy state
        if ($regStatus.CIPolicy) {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'CIPolicyRegistry' `
                -Status 'Info' -Severity 'Info' `
                -Message 'Code Integrity policy configuration found in registry' `
                -Details @{
                    UMCIAuditMode = $regStatus.CIPolicy.UMCIAuditMode
                    UMCIDisabled  = $regStatus.CIPolicy.UMCIDisabled
                }))
        }

        # Deployed policy files
        $policyFiles = @($regStatus.PolicyFiles)
        if ($policyFiles.Count -gt 0) {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeployedPolicyFiles' `
                -Status 'Warning' -Severity 'High' `
                -Message "$($policyFiles.Count) active WDAC policy file(s) deployed in CodeIntegrity\CiPolicies\Active" `
                -Details @{
                    count = $policyFiles.Count
                    files = $policyFiles | ForEach-Object { $_.Name }
                } `
                -Remediation 'Active .p7b policy files indicate WDAC policies are deployed. Use CiTool or Get-CIPolicy to inspect policy rules.'))
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'DeployedPolicyFiles' `
                -Status 'Pass' -Severity 'Info' `
                -Message 'No active .p7b policy files found in CiPolicies\Active'))
        }

        # AppLocker SrpV2 policies
        $appLockerRules = @($regStatus.AppLocker)
        if ($appLockerRules.Count -gt 0) {
            $totalRules = ($appLockerRules | Measure-Object -Property RuleCount -Sum).Sum
            if ($null -eq $totalRules) { $totalRules = 0 }
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'AppLockerPolicies' `
                -Status $(if ($totalRules -gt 0) { 'Warning' } else { 'Pass' }) `
                -Severity $(if ($totalRules -gt 0) { 'Medium' } else { 'Info' }) `
                -Message "AppLocker SrpV2: $($appLockerRules.Count) categories, $totalRules total rules (via Registry)" `
                -Details @{
                    categories = $appLockerRules | ForEach-Object { @{ category = $_.Category; ruleCount = $_.RuleCount } }
                } `
                -Remediation $(if ($totalRules -gt 0) {
                    'AppLocker policies are configured. Script rules can force PowerShell into Constrained Language Mode for scripts not in allow lists.'
                } else { '' })))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'RegistryDetection' `
            -Status 'Error' -Severity 'Low' `
            -Message "Registry-based WDAC detection failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- CiTool Enumeration (Windows 11+ / Server 2022+) ---
    try {
        $ciToolPath = Join-Path $env:SystemRoot 'System32\CiTool.exe'
        if (Test-Path $ciToolPath) {
            $ciToolOutput = & $ciToolPath --list-policies --json 2>$null
            if ($LASTEXITCODE -eq 0 -and $ciToolOutput) {
                $ciPolicies = $ciToolOutput | ConvertFrom-Json -ErrorAction Stop

                $policyList = @($ciPolicies.Policies)
                if ($policyList.Count -eq 0 -and $ciPolicies -is [array]) {
                    $policyList = @($ciPolicies)
                }

                $activePolicies = @($policyList | Where-Object { $_.IsEnforced -or $_.IsOnDisk })
                $enforcedCount  = @($policyList | Where-Object { $_.IsEnforced }).Count

                $results.Add((New-CLMResult -Category 'WDAC' -TestName 'CiToolPolicies' `
                    -Status $(if ($enforcedCount -gt 0) { 'Fail' } elseif ($activePolicies.Count -gt 0) { 'Warning' } else { 'Pass' }) `
                    -Severity $(if ($enforcedCount -gt 0) { 'Critical' } elseif ($activePolicies.Count -gt 0) { 'High' } else { 'Info' }) `
                    -Message "CiTool: $($policyList.Count) policies found, $enforcedCount enforced (enforced does not always imply UMCI script enforcement)" `
                    -Details @{
                        totalPolicies   = $policyList.Count
                        enforcedCount   = $enforcedCount
                        activePolicies  = $activePolicies | ForEach-Object {
                            @{
                                PolicyID   = $_.PolicyID
                                FriendlyName = $_.FriendlyName
                                IsEnforced = $_.IsEnforced
                                IsOnDisk   = $_.IsOnDisk
                            }
                        }
                    } `
                    -Remediation $(if ($enforcedCount -gt 0) {
                        'Enforced WDAC policies detected via CiTool. Review policy options to confirm whether UMCI/script enforcement is enabled for PowerShell workloads.'
                    } else { '' })))
            }
            else {
                $results.Add((New-CLMResult -Category 'WDAC' -TestName 'CiToolPolicies' `
                    -Status 'Info' -Severity 'Info' `
                    -Message "CiTool returned no policy data (exit code: $LASTEXITCODE)"))
            }
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'CiToolPolicies' `
                -Status 'Skipped' -Severity 'Info' `
                -Message 'CiTool.exe not found (requires Windows 11 or Server 2022+)'))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'CiToolPolicies' `
            -Status 'Error' -Severity 'Low' `
            -Message "CiTool enumeration failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- Additional Policy File Locations ---
    try {
        $additionalPaths = @(
            (Join-Path $env:SystemRoot 'System32\CodeIntegrity\SIPolicy.p7b'),
            (Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'),
            'C:\EFI\Microsoft\Boot\CiPolicies\Active'
        )

        $foundFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($path in $additionalPaths) {
            try {
                if (Test-Path $path) {
                    if ((Get-Item $path -ErrorAction SilentlyContinue).PSIsContainer) {
                        $files = Get-ChildItem -Path $path -Filter '*.cip' -ErrorAction SilentlyContinue
                        foreach ($f in $files) {
                            $foundFiles.Add([PSCustomObject]@{
                                Path         = $f.FullName
                                Size         = $f.Length
                                LastModified = $f.LastWriteTime
                            })
                        }
                    }
                    else {
                        $item = Get-Item $path -ErrorAction SilentlyContinue
                        $foundFiles.Add([PSCustomObject]@{
                            Path         = $item.FullName
                            Size         = $item.Length
                            LastModified = $item.LastWriteTime
                        })
                    }
                }
            }
            catch {
                # Skip inaccessible paths
            }
        }

        if ($foundFiles.Count -gt 0) {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'AdditionalPolicyFiles' `
                -Status 'Warning' -Severity 'Medium' `
                -Message "Found $($foundFiles.Count) additional WDAC policy file(s) on disk" `
                -Details @{
                    files = $foundFiles | ForEach-Object { @{ path = $_.Path; size = $_.Size; lastModified = $_.LastModified.ToString('o') } }
                }))
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'AdditionalPolicyFiles' `
                -Status 'Pass' -Severity 'Info' `
                -Message 'No additional WDAC policy files found (SIPolicy.p7b, .cip files)'))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'AdditionalPolicyFiles' `
            -Status 'Error' -Severity 'Low' `
            -Message "Policy file scan failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- HVCI Status ---
    try {
        $hvciEnabled = $false
        $hvciRunning = $false

        # Registry check
        $dgPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        if (Test-Path $dgPath) {
            $dgProps = Get-ItemProperty -Path $dgPath -ErrorAction SilentlyContinue
            $hvciEnabled = $dgProps.HypervisorEnforcedCodeIntegrity -eq 1
        }

        # CIM check for running state
        try {
            $dgCim = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
            $secRunning = @($dgCim.SecurityServicesRunning)
            $hvciRunning = $secRunning -contains 2
        }
        catch {
            Write-Verbose "HVCI CIM check unavailable: $_"
        }

        $hvciStatus   = if ($hvciRunning) { 'Fail' } elseif ($hvciEnabled) { 'Warning' } else { 'Pass' }
        $hvciSeverity = if ($hvciRunning) { 'High' } elseif ($hvciEnabled) { 'Medium' } else { 'Info' }

        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'HVCIStatus' `
            -Status $hvciStatus -Severity $hvciSeverity `
            -Message "HVCI: $(if ($hvciRunning) {'Running'} elseif ($hvciEnabled) {'Configured but not confirmed running'} else {'Not configured'})" `
            -Details @{
                configured = $hvciEnabled
                running    = $hvciRunning
            } `
            -Remediation $(if ($hvciRunning) {
                'Hypervisor-Enforced Code Integrity is active. Kernel-mode drivers must be WHQL-signed and WDAC-compliant.'
            } else { '' })))
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'HVCIStatus' `
            -Status 'Error' -Severity 'Low' `
            -Message "HVCI status check failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    # --- SRP (Software Restriction Policies) ---
    try {
        $srp = Get-SRPPolicy
        if ($srp.Enabled) {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'SoftwareRestrictionPolicies' `
                -Status 'Warning' -Severity 'Medium' `
                -Message "SRP enabled: DefaultLevel=$($srp.DefaultLevel), $($srp.Rules.Count) rule(s)" `
                -Details @{
                    defaultLevel       = $srp.DefaultLevel
                    transparentEnabled = $srp.TransparentEnabled
                    ruleCount          = $srp.Rules.Count
                } `
                -Remediation 'Software Restriction Policies are configured. SRP can restrict script execution independently of WDAC.'))
        }
        else {
            $results.Add((New-CLMResult -Category 'WDAC' -TestName 'SoftwareRestrictionPolicies' `
                -Status 'Pass' -Severity 'Info' `
                -Message "SRP not configured$(if ($srp.Error) {": $($srp.Error)"} else {''})"))
        }
    }
    catch {
        $results.Add((New-CLMResult -Category 'WDAC' -TestName 'SoftwareRestrictionPolicies' `
            -Status 'Error' -Severity 'Low' `
            -Message "SRP detection failed: $_" `
            -Details @{ error = $_.ToString() }))
    }

    return $results.ToArray()
}
