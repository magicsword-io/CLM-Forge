function Test-CLMTypeRestrictions {
    <#
    .SYNOPSIS
        Tests .NET type and type accelerator restrictions under Constrained Language Mode.

    .DESCRIPTION
        Iterates over configured .NET types (and optionally type accelerators and assemblies)
        to determine which are accessible, blocked by CLM, or unavailable. Reports results
        with severity aligned to the risk classification in the module configuration.

    .PARAMETER AdditionalTypes
        Extra fully qualified .NET type names to test beyond the default configuration list.

    .PARAMETER TestAssemblyLoading
        Also attempt to load common assemblies (System.DirectoryServices, System.Management,
        System.Web, Microsoft.CSharp) and report the results.

    .PARAMETER TestTypeAccelerators
        Also test all PowerShell type accelerators from the module configuration.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Test-CLMTypeRestrictions
        Test-CLMTypeRestrictions -TestTypeAccelerators -TestAssemblyLoading
        Test-CLMTypeRestrictions -AdditionalTypes 'System.Net.Mail.SmtpClient'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string[]]$AdditionalTypes,

        [switch]$TestAssemblyLoading,

        [switch]$TestTypeAccelerators
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- .NET Type Tests ---
    $typeTestList = @(Get-DefaultTypeTestList)

    # Append additional types with Medium risk
    if ($AdditionalTypes) {
        foreach ($typeName in $AdditionalTypes) {
            $existing = $typeTestList | Where-Object { $_.type -eq $typeName }
            if (-not $existing) {
                $typeTestList += [PSCustomObject]@{
                    type     = $typeName
                    risk     = 'Medium'
                    category = 'UserSpecified'
                }
            }
        }
    }

    Write-Verbose "Testing $($typeTestList.Count) .NET type(s)..."

    foreach ($typeEntry in $typeTestList) {
        $typeName = $typeEntry.type
        $risk = $typeEntry.risk
        $typeCategory = $typeEntry.category

        Write-Verbose "Testing type: $typeName ($risk risk, $typeCategory)"
        $testResult = Test-TypeAccess -TypeName $typeName

        # Map risk to severity
        $severity = switch ($risk) {
            'Critical' { 'Critical' }
            'High'     { 'High' }
            'Medium'   { 'Medium' }
            'Low'      { 'Low' }
            default    { 'Medium' }
        }

        if ($testResult.Accessible) {
            $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Type_$typeName" `
                -Status 'Pass' -Severity $severity `
                -Message "Type '$typeName' is accessible ($typeCategory)" `
                -Details @{
                    typeName    = $typeName
                    risk        = $risk
                    category    = $typeCategory
                    accessible  = $true
                }))
        }
        elseif ($testResult.BlockedByCLM) {
            $remediation = "Type '$typeName' is restricted by CLM. Use approved cmdlets instead of direct .NET type access, or ensure the script is WDAC-signed to run in FullLanguage mode."

            $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Type_$typeName" `
                -Status 'Fail' -Severity $severity `
                -Message "Type '$typeName' is BLOCKED by CLM ($typeCategory)" `
                -Details @{
                    typeName     = $typeName
                    risk         = $risk
                    category     = $typeCategory
                    accessible   = $false
                    blockedByCLM = $true
                    error        = $testResult.Error
                } `
                -Remediation $remediation))
        }
        elseif ($testResult.ErrorType -eq 'TypeNotFound') {
            $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Type_$typeName" `
                -Status 'Info' -Severity 'Info' `
                -Message "Type '$typeName' was not found (assembly may not be loaded)" `
                -Details @{
                    typeName    = $typeName
                    risk        = $risk
                    category    = $typeCategory
                    accessible  = $false
                    typeNotFound = $true
                    error       = $testResult.Error
                }))
        }
        else {
            $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Type_$typeName" `
                -Status 'Error' -Severity 'Low' `
                -Message "Type '$typeName' test produced an error: $($testResult.Error)" `
                -Details @{
                    typeName  = $typeName
                    risk      = $risk
                    category  = $typeCategory
                    accessible = $false
                    errorType = $testResult.ErrorType
                    error     = $testResult.Error
                }))
        }
    }

    # --- Type Accelerator Tests ---
    if ($TestTypeAccelerators) {
        $config = Get-CLMConfig
        $accelerators = @()

        if ($config -and $config.typeAccelerators) {
            $accelerators = @($config.typeAccelerators)
        }
        else {
            # Fallback built-in list
            $accelerators = @(
                '[math]', '[regex]', '[xml]', '[wmi]', '[wmiclass]', '[wmisearcher]',
                '[adsi]', '[adsisearcher]', '[psobject]', '[pscustomobject]',
                '[scriptblock]', '[type]', '[ipaddress]', '[mailaddress]'
            )
        }

        Write-Verbose "Testing $($accelerators.Count) type accelerator(s)..."

        foreach ($accel in $accelerators) {
            $accelResult = Test-TypeAccelerator -AcceleratorName $accel

            if ($accelResult.Accessible) {
                $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Accelerator_$accel" `
                    -Status 'Pass' -Severity 'Low' `
                    -Message "Type accelerator $accel is accessible" `
                    -Details @{
                        accelerator = $accel
                        accessible  = $true
                    }))
            }
            elseif ($accelResult.BlockedByCLM) {
                $remediation = "Type accelerator $accel is restricted by CLM. Sign the script for WDAC trust to regain FullLanguage access."

                $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Accelerator_$accel" `
                    -Status 'Fail' -Severity 'Medium' `
                    -Message "Type accelerator $accel is BLOCKED by CLM" `
                    -Details @{
                        accelerator  = $accel
                        accessible   = $false
                        blockedByCLM = $true
                        error        = $accelResult.Error
                    } `
                    -Remediation $remediation))
            }
            else {
                $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Accelerator_$accel" `
                    -Status 'Info' -Severity 'Info' `
                    -Message "Type accelerator $accel is not available: $($accelResult.Error)" `
                    -Details @{
                        accelerator = $accel
                        accessible  = $false
                        error       = $accelResult.Error
                    }))
            }
        }
    }

    # --- Assembly Loading Tests ---
    if ($TestAssemblyLoading) {
        $assemblies = @(
            @{ name = 'System.DirectoryServices'; description = 'Active Directory and LDAP access' }
            @{ name = 'System.Management';        description = 'WMI management classes' }
            @{ name = 'System.Web';               description = 'Web utilities and HTTP handling' }
            @{ name = 'Microsoft.CSharp';         description = 'C# runtime compiler services' }
        )

        Write-Verbose "Testing $($assemblies.Count) assembly load(s)..."

        foreach ($asm in $assemblies) {
            $asmName = $asm.name
            $asmDesc = $asm.description

            try {
                $loaded = [System.Reflection.Assembly]::LoadWithPartialName($asmName)

                if ($null -ne $loaded) {
                    $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Assembly_$asmName" `
                        -Status 'Pass' -Severity 'Medium' `
                        -Message "Assembly '$asmName' loaded successfully ($asmDesc)" `
                        -Details @{
                            assembly    = $asmName
                            description = $asmDesc
                            loaded      = $true
                            fullName    = $loaded.FullName
                        }))
                }
                else {
                    $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Assembly_$asmName" `
                        -Status 'Info' -Severity 'Info' `
                        -Message "Assembly '$asmName' could not be loaded (not available on this system)" `
                        -Details @{
                            assembly    = $asmName
                            description = $asmDesc
                            loaded      = $false
                        }))
                }
            }
            catch {
                $errorMessage = $_.Exception.Message

                if ($errorMessage -match 'is not allowed in the current language mode' -or
                    $errorMessage -match 'ConstrainedLanguage' -or
                    $errorMessage -match 'Cannot invoke method' -or
                    $errorMessage -match 'not allowed') {

                    $remediation = "Assembly loading for '$asmName' is restricted by CLM. Ensure the script is WDAC-signed to run in FullLanguage mode."

                    $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Assembly_$asmName" `
                        -Status 'Fail' -Severity 'High' `
                        -Message "Assembly '$asmName' loading is BLOCKED by CLM ($asmDesc)" `
                        -Details @{
                            assembly     = $asmName
                            description  = $asmDesc
                            loaded       = $false
                            blockedByCLM = $true
                            error        = $errorMessage
                        } `
                        -Remediation $remediation))
                }
                else {
                    $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName "Assembly_$asmName" `
                        -Status 'Error' -Severity 'Low' `
                        -Message "Assembly '$asmName' load test produced an error: $errorMessage" `
                        -Details @{
                            assembly    = $asmName
                            description = $asmDesc
                            loaded      = $false
                            error       = $errorMessage
                        }))
                }
            }
        }
    }

    # --- Summary ---
    $blockedCount = ($results | Where-Object { $_.Status -eq 'Fail' }).Count
    $passCount = ($results | Where-Object { $_.Status -eq 'Pass' }).Count
    $infoCount = ($results | Where-Object { $_.Status -eq 'Info' }).Count

    $summaryMessage = "Type restriction check complete: $passCount accessible, $blockedCount blocked by CLM, $infoCount informational (out of $($results.Count) tests)"
    $summaryStatus = if ($blockedCount -gt 0) { 'Warning' } else { 'Pass' }

    $results.Add((New-CLMResult -Category 'TypeRestrictions' -TestName 'TypeRestrictions_Summary' `
        -Status $summaryStatus -Severity 'Info' `
        -Message $summaryMessage `
        -Details @{
            totalTests   = $results.Count
            accessible   = $passCount
            blockedByCLM = $blockedCount
            informational = $infoCount
        }))

    return $results.ToArray()
}
