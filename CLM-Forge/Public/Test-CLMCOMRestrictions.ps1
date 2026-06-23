function Test-CLMCOMRestrictions {
    <#
    .SYNOPSIS
        Tests COM object instantiation restrictions under Constrained Language Mode.

    .DESCRIPTION
        Iterates over a default (and optionally extended) list of COM object ProgIDs and
        tests whether each can be created in the current PowerShell session. Reports which
        objects are accessible, blocked by CLM, or not registered on the system.

    .PARAMETER AdditionalProgIDs
        Extra COM ProgIDs to test beyond the default configuration list.

    .PARAMETER SkipDefaults
        Skip the built-in COM test list and only test AdditionalProgIDs.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Test-CLMCOMRestrictions
        Test-CLMCOMRestrictions -AdditionalProgIDs 'MAPI.Session','DAO.DBEngine.36'
        Test-CLMCOMRestrictions -SkipDefaults -AdditionalProgIDs 'MyApp.CustomCOM'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [string[]]$AdditionalProgIDs,

        [switch]$SkipDefaults
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Build the test list
    $comTestList = @()

    if (-not $SkipDefaults) {
        $comTestList = @(Get-DefaultCOMTestList)
    }

    # Append additional ProgIDs as Medium risk with generic description
    if ($AdditionalProgIDs) {
        foreach ($progId in $AdditionalProgIDs) {
            # Skip if already present in the default list
            $existing = $comTestList | Where-Object { $_.progId -eq $progId }
            if (-not $existing) {
                $comTestList += @{
                    progId      = $progId
                    risk        = 'Medium'
                    description = "User-specified COM object: $progId"
                }
            }
        }
    }

    if ($comTestList.Count -eq 0) {
        $results.Add((New-CLMResult -Category 'COM' -TestName 'COMTestList' `
            -Status 'Skipped' -Severity 'Info' `
            -Message 'No COM objects to test. Provide -AdditionalProgIDs or remove -SkipDefaults.'))
        return $results.ToArray()
    }

    Write-Verbose "Testing $($comTestList.Count) COM object(s)..."

    # Attempt to retrieve WDAC-approved COM list for remediation context
    $wdacApproved = $null
    try {
        $wdacApproved = Get-WDACApprovedCOMList
    }
    catch {
        Write-Verbose "Could not retrieve WDAC approved COM list: $_"
    }

    foreach ($comEntry in $comTestList) {
        $progId = $comEntry.progId
        $risk = $comEntry.risk
        $description = $comEntry.description

        Write-Verbose "Testing COM object: $progId ($risk risk)"
        $testResult = Test-COMObjectAccess -ProgID $progId

        # Map risk levels to severity
        $severity = switch ($risk) {
            'Critical' { 'Critical' }
            'High'     { 'High' }
            'Medium'   { 'Medium' }
            'Low'      { 'Low' }
            default    { 'Medium' }
        }

        if ($testResult.Accessible) {
            # COM object was created successfully
            $results.Add((New-CLMResult -Category 'COM' -TestName "COM_$progId" `
                -Status 'Pass' -Severity $severity `
                -Message "COM object '$progId' is accessible ($description)" `
                -Details @{
                    progId      = $progId
                    risk        = $risk
                    description = $description
                    accessible  = $true
                }))
        }
        elseif ($testResult.BlockedByCLM) {
            # Blocked by Constrained Language Mode
            $remediation = "Add COM class GUID for '$progId' to WDAC allow list, or use approved cmdlet alternatives instead of COM automation."

            $results.Add((New-CLMResult -Category 'COM' -TestName "COM_$progId" `
                -Status 'Fail' -Severity $severity `
                -Message "COM object '$progId' is BLOCKED by CLM ($description)" `
                -Details @{
                    progId      = $progId
                    risk        = $risk
                    description = $description
                    accessible  = $false
                    blockedByCLM = $true
                    error       = $testResult.Error
                } `
                -Remediation $remediation))
        }
        elseif ($testResult.ErrorType -eq 'NotRegistered') {
            # COM object is not installed or registered on this system
            $results.Add((New-CLMResult -Category 'COM' -TestName "COM_$progId" `
                -Status 'Info' -Severity 'Info' `
                -Message "COM object '$progId' is not registered on this system ($description)" `
                -Details @{
                    progId      = $progId
                    risk        = $risk
                    description = $description
                    accessible  = $false
                    notInstalled = $true
                    error       = $testResult.Error
                }))
        }
        else {
            # Other error during COM creation
            $results.Add((New-CLMResult -Category 'COM' -TestName "COM_$progId" `
                -Status 'Error' -Severity 'Low' `
                -Message "COM object '$progId' test produced an error: $($testResult.Error)" `
                -Details @{
                    progId      = $progId
                    risk        = $risk
                    description = $description
                    accessible  = $false
                    errorType   = $testResult.ErrorType
                    error       = $testResult.Error
                }))
        }
    }

    # Summary entry
    $blockedCount = ($results | Where-Object { $_.Status -eq 'Fail' }).Count
    $passCount = ($results | Where-Object { $_.Status -eq 'Pass' }).Count
    $notInstalledCount = ($results | Where-Object { $_.Status -eq 'Info' }).Count

    $summaryMessage = "COM restriction check complete: $passCount accessible, $blockedCount blocked by CLM, $notInstalledCount not installed (out of $($comTestList.Count) tested)"
    $summaryStatus = if ($blockedCount -gt 0) { 'Warning' } else { 'Pass' }

    $results.Add((New-CLMResult -Category 'COM' -TestName 'COM_Summary' `
        -Status $summaryStatus -Severity 'Info' `
        -Message $summaryMessage `
        -Details @{
            totalTested  = $comTestList.Count
            accessible   = $passCount
            blockedByCLM = $blockedCount
            notInstalled = $notInstalledCount
            wdacApprovedCOMCount = if ($wdacApproved) { $wdacApproved.Count } else { 0 }
        }))

    return $results.ToArray()
}
