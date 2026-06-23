function Test-COMObjectAccess {
    <#
    .SYNOPSIS
        Tests whether a COM object can be instantiated in the current session.

    .DESCRIPTION
        Attempts to create a COM object by ProgID and distinguishes between CLM restrictions,
        missing COM registrations, and other errors.

    .PARAMETER ProgID
        The programmatic identifier of the COM class to test.

    .OUTPUTS
        [PSCustomObject] with ProgID, Accessible, BlockedByCLM, Error, and ErrorType properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$ProgID
    )

    $result = [PSCustomObject]@{
        ProgID       = $ProgID
        Accessible   = $false
        BlockedByCLM = $false
        Error        = $null
        ErrorType    = 'None'
    }

    try {
        $comObj = New-Object -ComObject $ProgID -ErrorAction Stop

        # Successfully created -- release if it supports disposal
        if ($comObj -and $comObj.PSObject.Methods.Name -contains 'Quit') {
            try { $comObj.Quit() } catch { }
        }
        if ($null -ne $comObj) {
            try {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObj) | Out-Null
            }
            catch {
                # Marshal may not be available in CLM; not critical
            }
        }

        $result.Accessible = $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        $fullError = $_.ToString()

        # CLM blocks COM creation with specific error patterns
        if ($errorMessage -match 'Cannot create type' -or
            $errorMessage -match 'is not allowed in the current language mode' -or
            $errorMessage -match 'Creating instances of the .+ COM component is not allowed' -or
            $fullError -match 'CannotCreateCOMType' -or
            $errorMessage -match 'ConstrainedLanguage') {

            $result.BlockedByCLM = $true
            $result.Error = $errorMessage
            $result.ErrorType = 'CLMRestriction'
        }
        elseif ($errorMessage -match 'Retrieving the COM class factory .+ CLSID' -or
                $errorMessage -match 'Class not registered' -or
                $errorMessage -match 'REGDB_E_CLASSNOTREG' -or
                $errorMessage -match 'is not registered' -or
                $errorMessage -match '80040154' -or
                $errorMessage -match 'Cannot create object') {

            $result.Error = $errorMessage
            $result.ErrorType = 'NotRegistered'
        }
        else {
            $result.Error = $errorMessage
            $result.ErrorType = 'Other'
        }
    }

    return $result
}

function Get-DefaultCOMTestList {
    <#
    .SYNOPSIS
        Returns the default list of COM objects to test from the module configuration.

    .DESCRIPTION
        Reads the comObjects array from DefaultConfig.json and returns it as an array of
        hashtables with progId, risk, and description keys.

    .OUTPUTS
        [hashtable[]] Array of COM object definitions.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    $config = Get-CLMConfig

    if (-not $config -or -not $config.comObjects) {
        Write-Warning 'No COM objects found in configuration. Returning built-in defaults.'
        return @(
            @{ progId = 'WScript.Shell';              risk = 'High';     description = 'Command execution via shell' }
            @{ progId = 'Scripting.FileSystemObject';  risk = 'High';     description = 'File system access' }
            @{ progId = 'Shell.Application';           risk = 'High';     description = 'Explorer and shell operations' }
            @{ progId = 'MSXML2.XMLHTTP';              risk = 'High';     description = 'HTTP requests' }
            @{ progId = 'MMC20.Application';           risk = 'Critical'; description = 'MMC snap-in (lateral movement vector)' }
        )
    }

    $comList = @()
    foreach ($obj in $config.comObjects) {
        $comList += @{
            progId      = $obj.progId
            risk        = $obj.risk
            description = $obj.description
        }
    }

    return $comList
}

function Get-WDACApprovedCOMList {
    <#
    .SYNOPSIS
        Retrieves the list of WDAC-approved COM class GUIDs from the registry and active policies.

    .DESCRIPTION
        Checks HKLM:\SOFTWARE\Microsoft\WDAC\AllowedCOMClasses and enumerates active WDAC
        policies for approved COM object class identifiers.

    .OUTPUTS
        [string[]] Array of approved COM class GUIDs, or $null if unavailable.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $approvedGuids = [System.Collections.Generic.List[string]]::new()

    # Check the WDAC AllowedCOMClasses registry key
    $wdacComPath = 'HKLM:\SOFTWARE\Microsoft\WDAC\AllowedCOMClasses'
    try {
        if (Test-Path -Path $wdacComPath -ErrorAction Stop) {
            $entries = Get-ChildItem -Path $wdacComPath -ErrorAction Stop
            foreach ($entry in $entries) {
                $guid = $entry.PSChildName
                if ($guid -match '^[{(]?[0-9a-fA-F\-]{36}[)}]?$') {
                    $approvedGuids.Add($guid)
                }
            }

            # Also check for values directly on the key
            $properties = Get-ItemProperty -Path $wdacComPath -ErrorAction SilentlyContinue
            if ($properties) {
                $properties.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS' -and $_.Value -match '^[{(]?[0-9a-fA-F\-]{36}[)}]?$'
                } | ForEach-Object {
                    $approvedGuids.Add($_.Value)
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not read WDAC AllowedCOMClasses registry key: $_"
    }

    # Enumerate active WDAC/CI policies for COM allowed entries
    $ciPolicyPaths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
        'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    )

    foreach ($policyPath in $ciPolicyPaths) {
        try {
            if (Test-Path -Path $policyPath -ErrorAction Stop) {
                $subKeys = Get-ChildItem -Path $policyPath -Recurse -ErrorAction SilentlyContinue
                foreach ($key in $subKeys) {
                    if ($key.PSChildName -match 'COM' -or $key.PSChildName -match 'AllowedCOM') {
                        $values = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $values.PSObject.Properties | Where-Object {
                                $_.Name -notmatch '^PS' -and $_.Value -match '[0-9a-fA-F\-]{36}'
                            } | ForEach-Object {
                                $approvedGuids.Add($_.Value)
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not enumerate WDAC policy at ${policyPath}: $_"
        }
    }

    if ($approvedGuids.Count -eq 0) {
        return $null
    }

    # Deduplicate and return
    return @($approvedGuids | Sort-Object -Unique)
}
