function Test-TypeAccess {
    <#
    .SYNOPSIS
        Tests whether a .NET type is accessible in the current session.

    .DESCRIPTION
        Attempts to resolve a .NET type by name and access a property or method on it.
        Distinguishes between CLM restrictions, missing types, and other errors.

    .PARAMETER TypeName
        The fully qualified .NET type name to test (e.g. 'System.Net.WebClient').

    .OUTPUTS
        [PSCustomObject] with TypeName, Accessible, BlockedByCLM, Error, and ErrorType properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$TypeName
    )

    $result = [PSCustomObject]@{
        TypeName     = $TypeName
        Accessible   = $false
        BlockedByCLM = $false
        Error        = $null
        ErrorType    = 'None'
    }

    # Step 1: Attempt to resolve the type
    $resolvedType = $null
    try {
        $resolvedType = [type]::GetType($TypeName, $false, $true)
    }
    catch {
        # GetType itself may be restricted in CLM
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match 'is not allowed in the current language mode' -or
            $errorMessage -match 'ConstrainedLanguage' -or
            $errorMessage -match 'Cannot invoke method') {

            $result.BlockedByCLM = $true
            $result.Error = $errorMessage
            $result.ErrorType = 'CLMRestriction'
            return $result
        }
    }

    # Step 2: If type was not resolved via GetType, try PowerShell type resolution
    if (-not $resolvedType) {
        try {
            # Use the -as operator and scriptblock invocation to resolve types safely
            $resolvedType = $TypeName -as [type]
            if (-not $resolvedType) {
                # Try with full namespace prefix
                $resolvedType = [type]::GetType("System.$TypeName", $false, $true)
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -match 'is not allowed in the current language mode' -or
                $errorMessage -match 'ConstrainedLanguage' -or
                $errorMessage -match 'Cannot create type' -or
                $errorMessage -match 'not allowed') {

                $result.BlockedByCLM = $true
                $result.Error = $errorMessage
                $result.ErrorType = 'CLMRestriction'
                return $result
            }
        }
    }

    # Step 3: If still not resolved, the type is not available
    if (-not $resolvedType) {
        $result.Error = "Type '$TypeName' could not be found or loaded."
        $result.ErrorType = 'TypeNotFound'
        return $result
    }

    # Step 4: Verify functional access by trying to read a member
    try {
        # Attempt to get the type's methods or properties, which CLM may restrict
        $members = $resolvedType.GetMembers()
        $result.Accessible = $true
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match 'is not allowed in the current language mode' -or
            $errorMessage -match 'ConstrainedLanguage' -or
            $errorMessage -match 'Cannot invoke method' -or
            $errorMessage -match 'not allowed') {

            $result.BlockedByCLM = $true
            $result.Error = $errorMessage
            $result.ErrorType = 'CLMRestriction'
        }
        else {
            # Type is resolved but member access produced an unexpected error;
            # the type itself is still reachable, so mark accessible
            $result.Accessible = $true
            $result.Error = $errorMessage
            $result.ErrorType = 'MemberAccessError'
        }
    }

    return $result
}

function Get-DefaultTypeTestList {
    <#
    .SYNOPSIS
        Returns the default list of .NET types to test from the module configuration.

    .DESCRIPTION
        Reads the dotNetTypes array from DefaultConfig.json and returns it.

    .OUTPUTS
        [PSCustomObject[]] Array of type definitions with type, risk, and category properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    $config = Get-CLMConfig

    if (-not $config -or -not $config.dotNetTypes) {
        Write-Warning 'No .NET types found in configuration. Returning built-in defaults.'
        return @(
            [PSCustomObject]@{ type = 'System.Net.WebClient';                          risk = 'Critical'; category = 'Network' }
            [PSCustomObject]@{ type = 'System.Reflection.Assembly';                    risk = 'Critical'; category = 'Reflection' }
            [PSCustomObject]@{ type = 'System.Runtime.InteropServices.Marshal';        risk = 'Critical'; category = 'Interop' }
            [PSCustomObject]@{ type = 'System.Diagnostics.Process';                    risk = 'High';     category = 'Execution' }
            [PSCustomObject]@{ type = 'System.IO.File';                                risk = 'High';     category = 'FileSystem' }
        )
    }

    return $config.dotNetTypes
}

function Test-TypeAccelerator {
    <#
    .SYNOPSIS
        Tests whether a PowerShell type accelerator is accessible in the current session.

    .DESCRIPTION
        Evaluates a type accelerator expression (e.g. '[math]', '[regex]') and determines
        whether it is accessible or blocked by Constrained Language Mode.

    .PARAMETER AcceleratorName
        The type accelerator to test, including brackets (e.g. '[math]', '[regex]').

    .OUTPUTS
        [PSCustomObject] with Accelerator, Accessible, BlockedByCLM, and Error properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$AcceleratorName
    )

    $result = [PSCustomObject]@{
        Accelerator  = $AcceleratorName
        Accessible   = $false
        BlockedByCLM = $false
        Error        = $null
    }

    # Normalize accelerator name and reject non-accelerator expressions.
    $normalized = $AcceleratorName.Trim()
    if ($normalized -match '^\[(?<name>[A-Za-z_][A-Za-z0-9\._]*)\]$') {
        $normalized = $Matches['name']
    }
    elseif ($normalized -notmatch '^[A-Za-z_][A-Za-z0-9\._]*$') {
        $result.Error = "Invalid type accelerator format: '$AcceleratorName'"
        return $result
    }

    try {
        $typeAcceleratorType = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
        if (-not $typeAcceleratorType) {
            $result.Error = 'Could not access TypeAccelerators API.'
            return $result
        }

        # PowerShell 7 exposes TypeAccelerators::Get(); Windows PowerShell 5.1 does not.
        $accelerators = $null
        $getMethod = $typeAcceleratorType.GetMethod(
            'Get',
            [System.Reflection.BindingFlags]'Public,NonPublic,Static'
        )
        if ($getMethod) {
            $accelerators = $getMethod.Invoke($null, @())
        }

        if ($accelerators) {
            if ($accelerators.ContainsKey($normalized)) {
                $result.Accessible = $true
            }
            else {
                $result.Error = "Type accelerator '$AcceleratorName' is not available."
            }
            return $result
        }

        # Fallback for hosts without Get(): evaluate a sanitized type-literal expression.
        $expr = "[{0}]" -f $normalized
        $typeResult = [scriptblock]::Create($expr).InvokeReturnAsIs()
        if ($typeResult -is [type]) {
            $result.Accessible = $true
        }
        else {
            $result.Error = "Type accelerator '$AcceleratorName' is not available."
        }
    }
    catch {
        $errorMessage = $_.Exception.Message

        if ($errorMessage -match 'is not allowed in the current language mode' -or
            $errorMessage -match 'ConstrainedLanguage' -or
            $errorMessage -match 'Cannot create type' -or
            $errorMessage -match 'not allowed' -or
            $errorMessage -match 'type is not allowed') {

            $result.BlockedByCLM = $true
            $result.Error = $errorMessage
        }
        elseif ($errorMessage -match 'Unable to find type' -or
                $errorMessage -match 'TypeNotFound') {
            $result.Error = "Type accelerator '$AcceleratorName' is not available: $errorMessage"
        }
        else {
            $result.Error = $errorMessage
        }
    }

    return $result
}
