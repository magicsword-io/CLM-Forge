# WLDP Constants
$script:WLDP_HOST_GUID                = [guid]'8E9AAA7C-198B-4879-AE41-A50D47AD6458'
$script:WLDP_HOST_INFORMATION_REVISION = [uint32]0x00000001
$script:WLDP_LOCKDOWN_UNDEFINED        = [uint32]0
$script:WLDP_LOCKDOWN_DEFINED_FLAG     = [uint32]2147483648
$script:WLDP_LOCKDOWN_SECUREBOOT_FLAG  = [uint32]1
$script:WLDP_LOCKDOWN_DEBUGPOLICY_FLAG = [uint32]2
$script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG = [uint32]4
$script:WLDP_LOCKDOWN_UMCIAUDIT_FLAG   = [uint32]8
$script:WLDP_HOST_ID_POWERSHELL        = [uint32]4
$script:WLDP_HOST_ID_GLOBAL            = [uint32]1

function Get-WldpLockdownPolicy {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # Tier 1: direct WLDP P/Invoke (FullLanguage only)
    $tier1Result = Get-WldpViaPInvoke
    if ($tier1Result) { return $tier1Result }

    # Tier 2: Reflection-based delegate invocation
    $tier2Result = Get-WldpViaReflection
    if ($tier2Result) { return $tier2Result }

    # Tier 3: best-effort registry + CIM inference
    return Get-WldpViaRegistryAndCIM
}

function Get-WldpViaPInvoke {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        $languageMode = $ExecutionContext.SessionState.LanguageMode
        if ($languageMode -ne 'FullLanguage') {
            Write-Verbose 'WinAPI Tier 1: Skipped (not in FullLanguage mode)'
            return $null
        }

        $csCode = @'
using System;
using System.Runtime.InteropServices;

public class WldpNativeMethods {
    [StructLayout(LayoutKind.Sequential)]
    public struct WLDP_HOST_INFORMATION {
        public uint dwRevision;
        public uint dwHostId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string szSource;
        public IntPtr hSource;
    }

    [DllImport("wldp.dll", EntryPoint = "WldpGetLockdownPolicy")]
    public static extern int WldpGetLockdownPolicy(
        ref WLDP_HOST_INFORMATION hostInfo,
        ref uint lockdownState,
        uint flags);

    [DllImport("wldp.dll", EntryPoint = "WldpIsClassInApprovedList")]
    public static extern int WldpIsClassInApprovedList(
        ref Guid classId,
        ref WLDP_HOST_INFORMATION hostInfo,
        ref int isApproved,
        uint flags);

    // WldpCanExecuteFile - newer per-file authorization API used by modern PowerShell.
    // Returns WLDP_EXECUTION_POLICY: 0=BLOCKED, 1=ALLOWED, 2=REQUIRE_SANDBOX(=CLM)
    [DllImport("wldp.dll", EntryPoint = "WldpCanExecuteFile")]
    public static extern int WldpCanExecuteFile(
        [MarshalAs(UnmanagedType.LPStruct)] Guid host,
        int options,
        IntPtr fileHandle,
        [MarshalAs(UnmanagedType.LPWStr)] string auditInfo,
        out int result);
}
'@

        if (-not ([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
            Add-Type -TypeDefinition $csCode -ErrorAction Stop
        }

        $hostInfo = New-Object WldpNativeMethods+WLDP_HOST_INFORMATION
        $hostInfo.dwRevision = $script:WLDP_HOST_INFORMATION_REVISION
        $hostInfo.dwHostId   = $script:WLDP_HOST_ID_POWERSHELL
        $hostInfo.szSource   = $null
        $hostInfo.hSource    = [IntPtr]::Zero

        [uint32]$lockdownState = 0
        $hr = [WldpNativeMethods]::WldpGetLockdownPolicy([ref]$hostInfo, [ref]$lockdownState, 0)

        if ($hr -ne 0) {
            Write-Verbose "WinAPI Tier 1: WldpGetLockdownPolicy returned HRESULT 0x$($hr.ToString('X8'))"
            return $null
        }

        Write-Verbose "WinAPI Tier 1: Success (lockdownState=0x$($lockdownState.ToString('X8')))"
        return ConvertTo-WldpResult -PolicyFlags $lockdownState -DetectionMethod 'AddType'
    }
    catch {
        Write-Verbose "WinAPI Tier 1 failed: $_"
        return $null
    }
}

function Get-WldpViaReflection {
    <#
    .SYNOPSIS
        Tier 2: Attempts to detect WDAC lockdown by probing reflection capabilities.
        The inability to perform these operations IS itself diagnostic - if Marshal
        or dynamic assembly creation is blocked, CLM is confirmed active.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # Track what we can and cannot do - each blocked operation confirms CLM
    $probeResults = @{
        MarshalAvailable        = $false
        DynamicAssemblyAvailable = $false
        ProcessModulesAvailable  = $false
        WldpDllLoaded           = $false
    }

    try {
        # Probe 1: Can we access Marshal class at all?
        try {
            $null = [System.Runtime.InteropServices.Marshal]::SizeOf([type][uint32])
            $probeResults.MarshalAvailable = $true
        }
        catch {
            Write-Verbose "WinAPI Tier 2: Marshal access blocked (confirms CLM): $_"
            return ConvertTo-WldpResult -PolicyFlags $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG -DetectionMethod 'Reflection-MarshalBlocked'
        }

        # Probe 2: Can we enumerate process modules to see if wldp.dll is loaded?
        try {
            $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
            $probeResults.ProcessModulesAvailable = $true
            foreach ($mod in $currentProcess.Modules) {
                if ($mod.ModuleName -ieq 'wldp.dll') {
                    $probeResults.WldpDllLoaded = $true
                    break
                }
            }
        }
        catch {
            Write-Verbose "WinAPI Tier 2: Process module enumeration blocked: $_"
        }

        # Probe 3: Can we create dynamic assemblies? (blocked in CLM)
        try {
            $domain = [AppDomain]::CurrentDomain
            $asmName = New-Object System.Reflection.AssemblyName('WldpProbe')
            $asmBuilder = $domain.DefineDynamicAssembly($asmName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $probeResults.DynamicAssemblyAvailable = $true
        }
        catch {
            Write-Verbose "WinAPI Tier 2: Dynamic assembly creation blocked (confirms CLM): $_"
            return ConvertTo-WldpResult -PolicyFlags $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG -DetectionMethod 'Reflection-DynAsmBlocked'
        }

        # wldp.dll presence alone is not a policy verdict.
        if ($probeResults.WldpDllLoaded) {
            Write-Verbose 'WinAPI Tier 2: wldp.dll loaded, but no CLM restriction observed by reflection probes'
            return ConvertTo-WldpResult -PolicyFlags $script:WLDP_LOCKDOWN_UNDEFINED -DetectionMethod 'Reflection-WldpPresentNoRestrictions'
        }

        # All probes passed with no restrictions - likely no WDAC
        Write-Verbose 'WinAPI Tier 2: All reflection probes passed - no CLM restrictions detected'
        return ConvertTo-WldpResult -PolicyFlags $script:WLDP_LOCKDOWN_UNDEFINED -DetectionMethod 'Reflection-NoRestrictions'
    }
    catch {
        Write-Verbose "WinAPI Tier 2 failed: $_ (this may confirm CLM restrictions)"
        return $null
    }
}

function Get-WldpViaRegistryAndCIM {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Verbose 'WinAPI Tier 3: Falling back to registry + CIM detection'

    [uint32]$inferredFlags = $script:WLDP_LOCKDOWN_UNDEFINED
    $detectionMethod = 'Registry'

    # Check Device Guard registry
    try {
        $dgPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        if (Test-Path $dgPath) {
            $dgProps = Get-ItemProperty -Path $dgPath -ErrorAction SilentlyContinue
            if ($dgProps.EnableVirtualizationBasedSecurity -eq 1) {
                $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG
            }
        }
    }
    catch {
        Write-Verbose "Tier 3: Device Guard registry check failed: $_"
    }

    # Check CI policy registry
    try {
        $ciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI'
        if (Test-Path $ciPath) {
            $ciProps = Get-ItemProperty -Path $ciPath -ErrorAction SilentlyContinue
            if ($null -ne $ciProps.UMCIAuditMode) {
                if ($ciProps.UMCIAuditMode -eq 0) {
                    $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG -bor $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG
                }
                else {
                    $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG -bor $script:WLDP_LOCKDOWN_UMCIAUDIT_FLAG
                }
            }
        }
    }
    catch {
        Write-Verbose "Tier 3: CI registry check failed: $_"
    }

    # Try CIM as supplementary source
    try {
        $dgCim = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        if ($dgCim.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) {
            $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG -bor $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG
            $detectionMethod = 'CIM'
        }
        elseif ($dgCim.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 1) {
            $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG -bor $script:WLDP_LOCKDOWN_UMCIAUDIT_FLAG
            $detectionMethod = 'CIM'
        }
    }
    catch {
        Write-Verbose "Tier 3: CIM DeviceGuard query failed: $_"
    }

    # Check current language mode as final signal
    $languageMode = $ExecutionContext.SessionState.LanguageMode
    if ($languageMode -eq 'ConstrainedLanguage') {
        $inferredFlags = $inferredFlags -bor $script:WLDP_LOCKDOWN_DEFINED_FLAG -bor $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG
    }

    return ConvertTo-WldpResult -PolicyFlags $inferredFlags -DetectionMethod $detectionMethod
}

function ConvertTo-WldpResult {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [uint32]$PolicyFlags,

        [Parameter(Mandatory)]
        [string]$DetectionMethod
    )

    $isDefined            = ($PolicyFlags -band $script:WLDP_LOCKDOWN_DEFINED_FLAG) -ne 0
    $isEnforced           = ($PolicyFlags -band $script:WLDP_LOCKDOWN_UMCIENFORCE_FLAG) -ne 0
    $isAudit              = ($PolicyFlags -band $script:WLDP_LOCKDOWN_UMCIAUDIT_FLAG) -ne 0
    $isSecureBoot         = ($PolicyFlags -band $script:WLDP_LOCKDOWN_SECUREBOOT_FLAG) -ne 0
    $isDebugPolicy        = ($PolicyFlags -band $script:WLDP_LOCKDOWN_DEBUGPOLICY_FLAG) -ne 0
    $scriptEnforcement    = $isEnforced -or $isAudit

    [PSCustomObject]@{
        DetectionMethod          = $DetectionMethod
        PolicyFlags              = $PolicyFlags
        IsEnforced               = $isEnforced
        IsAudit                  = $isAudit
        ScriptEnforcementEnabled = $scriptEnforcement
        RawLockdownState         = $PolicyFlags
        IsDefined                = $isDefined
        IsSecureBoot             = $isSecureBoot
        IsDebugPolicy            = $isDebugPolicy
    }
}

function Get-WDACStatusViaRegistry {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $result = @{
        DeviceGuard  = $null
        CIPolicy     = $null
        PolicyFiles  = @()
        AppLocker    = $null
    }

    # Device Guard registry settings
    try {
        $dgPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        if (Test-Path $dgPath) {
            $dgProps = Get-ItemProperty -Path $dgPath -ErrorAction Stop
            $result.DeviceGuard = [PSCustomObject]@{
                EnableVirtualizationBasedSecurity = $dgProps.EnableVirtualizationBasedSecurity
                RequirePlatformSecurityFeatures   = $dgProps.RequirePlatformSecurityFeatures
                HypervisorEnforcedCodeIntegrity   = $dgProps.HypervisorEnforcedCodeIntegrity
                LsaCfgFlags                       = $dgProps.LsaCfgFlags
                ConfigureSystemGuardLaunch        = $dgProps.ConfigureSystemGuardLaunch
            }
        }
    }
    catch {
        Write-Verbose "Registry: Device Guard check failed: $_"
    }

    # CI Policy state
    try {
        $ciPolicyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        $ciBasePath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI'
        $ciResult = @{}

        if (Test-Path $ciBasePath) {
            $ciProps = Get-ItemProperty -Path $ciBasePath -ErrorAction SilentlyContinue
            $ciResult['UMCIAuditMode'] = $ciProps.UMCIAuditMode
            $ciResult['UMCIDisabled']  = $ciProps.UMCIDisabled
        }
        if (Test-Path $ciPolicyPath) {
            $policyProps = Get-ItemProperty -Path $ciPolicyPath -ErrorAction SilentlyContinue
            $ciResult['PolicyState'] = $policyProps
        }

        if ($ciResult.Count -gt 0) {
            $result.CIPolicy = [PSCustomObject]$ciResult
        }
    }
    catch {
        Write-Verbose "Registry: CI Policy check failed: $_"
    }

    # Active policy files
    try {
        $policyDir = Join-Path $env:SystemRoot 'System32\CodeIntegrity\CiPolicies\Active'
        if (Test-Path $policyDir) {
            $policyFiles = Get-ChildItem -Path (Join-Path $policyDir '*.p7b') -ErrorAction SilentlyContinue
            $result.PolicyFiles = foreach ($pf in $policyFiles) {
                [PSCustomObject]@{
                    Name         = $pf.Name
                    FullPath     = $pf.FullName
                    Size         = $pf.Length
                    LastModified = $pf.LastWriteTime
                }
            }
        }
    }
    catch {
        Write-Verbose "Registry: Policy file enumeration failed: $_"
    }

    # AppLocker / SRP V2 policies
    try {
        $srpPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
        if (Test-Path $srpPath) {
            $srpCategories = Get-ChildItem -Path $srpPath -ErrorAction SilentlyContinue
            $result.AppLocker = foreach ($cat in $srpCategories) {
                $rules = Get-ChildItem -Path $cat.PSPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    Category  = $cat.PSChildName
                    RuleCount = @($rules).Count
                }
            }
        }
    }
    catch {
        Write-Verbose "Registry: AppLocker SrpV2 check failed: $_"
    }

    return [PSCustomObject]$result
}

function Get-WDACStatusViaCIM {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        return [PSCustomObject]@{
            Available                                  = $true
            VirtualizationBasedSecurityStatus           = $dg.VirtualizationBasedSecurityStatus
            CodeIntegrityPolicyEnforcementStatus        = $dg.CodeIntegrityPolicyEnforcementStatus
            UsermodeCodeIntegrityPolicyEnforcementStatus = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
            SecurityServicesConfigured                  = $dg.SecurityServicesConfigured
            SecurityServicesRunning                     = $dg.SecurityServicesRunning
            RequiredSecurityProperties                  = $dg.RequiredSecurityProperties
            AvailableSecurityProperties                 = $dg.AvailableSecurityProperties
        }
    }
    catch {
        Write-Verbose "CIM: DeviceGuard query failed: $_"
        return [PSCustomObject]@{
            Available = $false
            Error     = $_.ToString()
        }
    }
}

function Test-IsWindowsPlatform {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) {
        return [bool]$IsWindows
    }

    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-WldpGetLockdownPolicyForFile {
    <#
    .SYNOPSIS
        Legacy per-file WLDP evaluation used when WldpCanExecuteFile is unavailable.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $result = [PSCustomObject]@{
        FilePath        = $FilePath
        CanExecute      = $null
        ExecutionPolicy = $null
        RawResult       = -1
        PolicyMode      = $null
        DetectionMethod = 'None'
        Error           = $null
    }

    if (-not (Test-IsWindowsPlatform)) {
        $result.Error = 'WLDP file evaluation is available only on Windows with wldp.dll.'
        $result.DetectionMethod = 'Unavailable-NonWindows'
        return $result
    }

    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        $result.Error = 'WldpGetLockdownPolicy file evaluation requires FullLanguage mode for P/Invoke.'
        $result.DetectionMethod = 'Unavailable-CLM'
        return $result
    }

    $resolvedPath = $null
    try {
        $resolvedPath = (Resolve-Path $FilePath -ErrorAction Stop).Path
    }
    catch {
        $result.Error = "File not found: $FilePath"
        return $result
    }

    try {
        if (-not ([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
            $null = Get-WldpViaPInvoke
        }

        if (-not ([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
            $result.Error = 'WLDP native methods could not be initialized.'
            $result.DetectionMethod = 'WldpGetLockdownPolicy-InitFailed'
            return $result
        }

        $fileStream = [System.IO.File]::Open($resolvedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $hostInfo = New-Object WldpNativeMethods+WLDP_HOST_INFORMATION
            $hostInfo.dwRevision = $script:WLDP_HOST_INFORMATION_REVISION
            $hostInfo.dwHostId   = $script:WLDP_HOST_ID_POWERSHELL
            $hostInfo.szSource   = $resolvedPath
            $hostInfo.hSource    = $fileStream.SafeFileHandle.DangerousGetHandle()

            [uint32]$lockdownState = 0
            $hr = [WldpNativeMethods]::WldpGetLockdownPolicy([ref]$hostInfo, [ref]$lockdownState, 0)

            if ($hr -ne 0) {
                $result.Error = "WldpGetLockdownPolicy returned HRESULT 0x$($hr.ToString('X8'))"
                $result.DetectionMethod = 'WldpGetLockdownPolicy-FileFailed'
                return $result
            }

            $policy = ConvertTo-WldpResult -PolicyFlags $lockdownState -DetectionMethod 'WldpGetLockdownPolicy-File'
            $result.RawResult = [int64]$lockdownState
            $result.DetectionMethod = 'WldpGetLockdownPolicy-File'

            if ($policy.IsEnforced) {
                $result.CanExecute = $true
                $result.ExecutionPolicy = 'ConstrainedLanguage'
                $result.PolicyMode = 'Enforce'
            }
            elseif ($policy.IsAudit) {
                $result.CanExecute = $true
                $result.ExecutionPolicy = 'Allowed'
                $result.PolicyMode = 'Audit'
            }
            else {
                $result.CanExecute = $true
                $result.ExecutionPolicy = 'Allowed'
                $result.PolicyMode = 'None'
            }

            return $result
        }
        finally {
            if ($fileStream) { $fileStream.Close() }
        }
    }
    catch {
        $exceptionText = $_.Exception.ToString()
        if ($exceptionText -match 'DllNotFoundException|Unable to load DLL .?wldp.dll') {
            $result.Error = 'WLDP APIs are available only on Windows with wldp.dll.'
            $result.DetectionMethod = 'Unavailable-NonWindows'
        }
        else {
            $result.Error = "WldpGetLockdownPolicy file evaluation failed: $_"
            $result.DetectionMethod = 'WldpGetLockdownPolicy-FileException'
        }
        return $result
    }
}

function Test-WldpCanExecuteFile {
    <#
    .SYNOPSIS
        Calls WldpCanExecuteFile to ask WDAC directly how a script file is authorized.
        On unsupported Windows builds, falls back to legacy WldpGetLockdownPolicy
        per-file evaluation, which can distinguish trusted FullLanguage from CLM but
        cannot report the newer hard-block result.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $result = [PSCustomObject]@{
        FilePath        = $FilePath
        CanExecute      = $null    # $true/$false/$null
        ExecutionPolicy = $null    # 'Allowed','Blocked','ConstrainedLanguage'
        RawResult       = -1
        PolicyMode      = $null
        DetectionMethod = 'None'
        Error           = $null
    }

    $resolvedPath = $null
    try {
        $resolvedPath = (Resolve-Path $FilePath -ErrorAction Stop).Path
    }
    catch {
        $result.Error = "File not found: $FilePath"
        return $result
    }

    if (-not (Test-IsWindowsPlatform)) {
        $result.Error = 'WLDP file evaluation is available only on Windows with wldp.dll.'
        $result.DetectionMethod = 'Unavailable-NonWindows'
        return $result
    }

    # Tier 1: P/Invoke via Add-Type
    if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {
        try {
            if (-not ([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
                $null = Get-WldpViaPInvoke
            }

            if (-not ([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
                $result.Error = 'WLDP native methods could not be initialized.'
                $result.DetectionMethod = 'WldpCanExecuteFile-InitFailed'
                return $result
            }

            # Open the file to get a handle
            $fileStream = [System.IO.File]::Open($resolvedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $fileHandle = $fileStream.SafeFileHandle.DangerousGetHandle()
                [int]$executionPolicy = -1

                $hr = [WldpNativeMethods]::WldpCanExecuteFile(
                    $script:WLDP_HOST_GUID,
                    0,   # WLDP_EXECUTION_EVALUATION_OPTION_NONE
                    $fileHandle,
                    $resolvedPath,
                    [ref]$executionPolicy
                )

                if ($hr -eq 0) {
                    $result.RawResult = $executionPolicy
                    $result.DetectionMethod = 'WldpCanExecuteFile'
                    switch ($executionPolicy) {
                        0 {
                            $result.CanExecute = $false
                            $result.ExecutionPolicy = 'Blocked'
                            $result.PolicyMode = 'Blocked'
                        }
                        1 {
                            $result.CanExecute = $true
                            $result.ExecutionPolicy = 'Allowed'
                            $result.PolicyMode = 'Allowed'
                        }
                        2 {
                            $result.CanExecute = $true  # Runs, but in CLM
                            $result.ExecutionPolicy = 'ConstrainedLanguage'
                            $result.PolicyMode = 'RequireSandbox'
                        }
                        default {
                            $result.ExecutionPolicy = "Unknown ($executionPolicy)"
                        }
                    }
                }
                else {
                    $result.Error = "WldpCanExecuteFile returned HRESULT 0x$($hr.ToString('X8'))"
                    $result.DetectionMethod = 'WldpCanExecuteFile-Failed'
                }
            }
            finally {
                $fileStream.Close()
            }

            return $result
        }
        catch {
            $exceptionText = $_.Exception.ToString()
            if ($exceptionText -match 'EntryPointNotFoundException|Unable to find an entry point named .?WldpCanExecuteFile') {
                Write-Verbose 'WldpCanExecuteFile is unavailable on this Windows build; falling back to WldpGetLockdownPolicy file evaluation.'
                return Test-WldpGetLockdownPolicyForFile -FilePath $resolvedPath
            }
            elseif ($exceptionText -match 'DllNotFoundException|Unable to load DLL .?wldp.dll') {
                $result.Error = 'WLDP APIs are available only on Windows with wldp.dll.'
                $result.DetectionMethod = 'Unavailable-NonWindows'
                return $result
            }
            else {
                $result.Error = "WldpCanExecuteFile failed: $_"
                $result.DetectionMethod = 'WldpCanExecuteFile-Exception'
                return $result
            }
        }
    }
    else {
        $result.Error = 'WLDP file evaluation requires FullLanguage mode for P/Invoke. Run this check from a trusted PowerShell host.'
        $result.DetectionMethod = 'Unavailable-CLM'
        return $result
    }
}

function Test-WldpClassApproved {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [guid]$ClassID,

        [string]$ProgID = ''
    )

    $result = [PSCustomObject]@{
        ClassID         = $ClassID
        ProgID          = $ProgID
        IsApproved      = $null
        DetectionMethod = $null
        Error           = $null
    }

    # Tier 1: WldpIsClassInApprovedList via P/Invoke
    try {
        if (([System.Management.Automation.PSTypeName]'WldpNativeMethods').Type) {
            $hostInfo = New-Object WldpNativeMethods+WLDP_HOST_INFORMATION
            $hostInfo.dwRevision = $script:WLDP_HOST_INFORMATION_REVISION
            $hostInfo.dwHostId   = $script:WLDP_HOST_ID_POWERSHELL
            $hostInfo.szSource   = $null
            $hostInfo.hSource    = [IntPtr]::Zero

            [guid]$clsid = $ClassID
            [int]$isApproved = 0
            $hr = [WldpNativeMethods]::WldpIsClassInApprovedList([ref]$clsid, [ref]$hostInfo, [ref]$isApproved, 0)

            if ($hr -eq 0) {
                $result.IsApproved      = ($isApproved -ne 0)
                $result.DetectionMethod = 'AddType'
                return $result
            }
        }
    }
    catch {
        Write-Verbose "WldpIsClassInApprovedList P/Invoke failed: $_"
    }

    # Fallback: Registry-based CLSID check
    try {
        $clsidString = $ClassID.ToString('B').ToUpper()
        $clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsidString"
        $result.DetectionMethod = 'Registry'

        if (Test-Path $clsidPath) {
            # Check if the CLSID has an associated DLL/server
            $serverPath = Join-Path $clsidPath 'InprocServer32'
            if (Test-Path $serverPath) {
                $serverProps = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
                $result.IsApproved = $null  # Cannot definitively determine via registry alone
                $result.Error = 'Registry fallback cannot determine WLDP approval state; CLSID exists but approval status requires WldpIsClassInApprovedList API'
            }
            else {
                $result.IsApproved = $null
                $result.Error = 'CLSID found but no InprocServer32 registered'
            }
        }
        else {
            $result.IsApproved = $false
            $result.Error = 'CLSID not found in registry'
        }
    }
    catch {
        $result.Error = "Registry fallback failed: $_"
    }

    return $result
}

function Get-SRPPolicy {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $result = [PSCustomObject]@{
        Enabled       = $false
        DefaultLevel  = $null
        TransparentEnabled = $null
        Rules         = @()
        Error         = $null
    }

    try {
        $saferPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer'
        if (-not (Test-Path $saferPath)) {
            $result.Error = 'Software Restriction Policies registry key not found'
            return $result
        }

        $codeIdPath = Join-Path $saferPath 'CodeIdentifiers'
        if (Test-Path $codeIdPath) {
            $codeIdProps = Get-ItemProperty -Path $codeIdPath -ErrorAction Stop
            $result.DefaultLevel       = $codeIdProps.DefaultLevel
            $result.TransparentEnabled = $codeIdProps.TransparentEnabled
            $result.Enabled            = ($null -ne $codeIdProps.DefaultLevel)

            # Enumerate security levels and their rules
            $levelPaths = Get-ChildItem -Path $codeIdPath -ErrorAction SilentlyContinue
            foreach ($level in $levelPaths) {
                $rulePaths = Get-ChildItem -Path $level.PSPath -ErrorAction SilentlyContinue
                foreach ($rule in $rulePaths) {
                    try {
                        $ruleProps = Get-ItemProperty -Path $rule.PSPath -ErrorAction SilentlyContinue
                        $result.Rules += [PSCustomObject]@{
                            Level       = $level.PSChildName
                            RuleName    = $rule.PSChildName
                            Description = $ruleProps.Description
                            ItemData    = $ruleProps.ItemData
                        }
                    }
                    catch {
                        # Skip unreadable rules
                    }
                }
            }
        }
    }
    catch {
        $result.Error = "Failed to read SRP policies: $_"
    }

    return $result
}

function Add-Win32Module {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    try {
        foreach ($module in [System.Diagnostics.Process]::GetCurrentProcess().Modules) {
            if ($module.ModuleName -ieq $ModuleName) {
                return $module
            }
        }
        return $null
    }
    catch {
        Write-Verbose "Add-Win32Module: Failed to enumerate process modules: $_"
        return $null
    }
}
