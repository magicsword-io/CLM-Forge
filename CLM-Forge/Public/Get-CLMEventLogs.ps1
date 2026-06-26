function Get-CLMEventLogs {
    <#
    .SYNOPSIS
        Retrieves and analyzes WDAC, AppLocker, and PowerShell security event logs.

    .DESCRIPTION
        Queries Code Integrity, AppLocker, and PowerShell Operational event logs for
        CLM/WDAC-related events. Can filter by time range, event IDs, and correlate
        events with specific script paths.

    .PARAMETER Hours
        Number of hours to look back. Default 24.

    .PARAMETER EventIDs
        Filter to specific event IDs.

    .PARAMETER CorrelateScript
        Filter events related to a specific script file path.

    .PARAMETER MaxEvents
        Maximum events to return per category. Default 100.

    .OUTPUTS
        [PSCustomObject[]] Array of CLM result objects.

    .EXAMPLE
        Get-CLMEventLogs
        Get-CLMEventLogs -Hours 48 -CorrelateScript 'C:\Scripts\Deploy.ps1'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [int]$Hours = 24,

        [int[]]$EventIDs,

        [string]$CorrelateScript,

        [int]$MaxEvents = 100
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $startTime = (Get-Date).AddHours(-$Hours)
    $config = Get-CLMConfig

    $results.Add((New-CLMResult -Category 'EventLogs' -TestName 'EventLogQuery' -Status 'Info' -Severity 'Info' `
        -Message "Querying event logs from the last $Hours hour(s)$(if ($CorrelateScript) { " for $CorrelateScript" })" `
        -Details @{ hours = $Hours; startTime = $startTime.ToString('o'); correlateScript = $CorrelateScript }))

    # --- Code Integrity Events ---
    $ciLogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    $ciEventIds = @(3076, 3077, 3089, 3099)
    if ($EventIDs) { $ciEventIds = $ciEventIds | Where-Object { $EventIDs -contains $_ } }

    try {
        $ciEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $ciLogName
            StartTime = $startTime
            Id        = $ciEventIds
        } -MaxEvents $MaxEvents -ErrorAction Stop

        if ($CorrelateScript) {
            $ciEvents = $ciEvents | Where-Object { $_.Message -match [regex]::Escape($CorrelateScript) }
        }

        $ciGrouped = $ciEvents | Group-Object -Property Id
        foreach ($group in $ciGrouped) {
            $eventDesc = switch ($group.Name) {
                '3076' { 'WDAC Audit Block (would be blocked in enforce mode)' }
                '3077' { 'WDAC Enforce Block (file was blocked)' }
                '3089' { 'Signing information event' }
                '3099' { 'Policy refresh event' }
                default { "Code Integrity event $($group.Name)" }
            }
            $severity = switch ($group.Name) {
                '3076' { 'High' }
                '3077' { 'Critical' }
                default { 'Info' }
            }
            $status = switch ($group.Name) {
                '3076' { 'Warning' }
                '3077' { 'Fail' }
                default { 'Info' }
            }

            $sampleMessages = $group.Group | Select-Object -First 3 | ForEach-Object {
                @{ timeCreated = $_.TimeCreated.ToString('o'); message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }
            }

            $results.Add((New-CLMResult -Category 'EventLogs' -TestName "CI:EventID-$($group.Name)" `
                -Status $status -Severity $severity `
                -Message "$eventDesc - $($group.Count) event(s) in last $Hours hour(s)" `
                -Details @{ eventId = [int]$group.Name; count = $group.Count; samples = $sampleMessages } `
                -Remediation $(switch ($group.Name) {
                    '3076' { 'Review audit events to identify scripts/binaries that will be blocked when switching from audit to enforce mode.' }
                    '3077' { 'These files were blocked by WDAC. Create allow rules or sign the files to resolve.' }
                    default { '' }
                })))
        }

        if ($ciEvents.Count -eq 0) {
            $results.Add((New-CLMResult -Category 'EventLogs' -TestName 'CI:Summary' -Status 'Pass' -Severity 'Info' `
                -Message "No Code Integrity events found in the last $Hours hour(s)" `
                -Details @{ logName = $ciLogName }))
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            $results.Add((New-CLMResult -Category 'EventLogs' -TestName 'CI:Summary' -Status 'Pass' -Severity 'Info' `
                -Message "No Code Integrity events in the last $Hours hour(s)" -Details @{ logName = $ciLogName }))
        }
        else {
            $results.Add((New-CLMResult -Category 'EventLogs' -TestName 'CI:Query' -Status 'Error' -Severity 'Low' `
                -Message "Could not query Code Integrity logs: $_" `
                -Details @{ logName = $ciLogName; error = $_.ToString() } `
                -Remediation 'Run as Administrator to access Code Integrity event logs.'))
        }
    }

    # --- AppLocker Events ---
    $alLogNames = @(
        'Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/Packaged app-Deployment',
        'Microsoft-Windows-AppLocker/Packaged app-Execution'
    )
    $alEventIds = @(8003, 8004, 8005, 8006, 8007, 8020, 8023, 8024, 8025, 8028, 8029, 8036, 8037, 8038)
    if ($EventIDs) { $alEventIds = $alEventIds | Where-Object { $EventIDs -contains $_ } }

    foreach ($alLog in $alLogNames) {
        try {
            $alEvents = Get-WinEvent -FilterHashtable @{
                LogName   = $alLog
                StartTime = $startTime
                Id        = $alEventIds
            } -MaxEvents $MaxEvents -ErrorAction Stop

            if ($CorrelateScript) {
                $alEvents = $alEvents | Where-Object { $_.Message -match [regex]::Escape($CorrelateScript) }
            }

            $alGrouped = $alEvents | Group-Object -Property Id
            foreach ($group in $alGrouped) {
                $eventDesc = switch ($group.Name) {
                    '8003' { 'Exe/DLL allowed' }
                    '8004' { 'Exe/DLL blocked' }
                    '8005' { 'Script/MSI allowed' }
                    '8006' { 'Script/MSI audit block (would be blocked)' }
                    '8007' { 'Script/MSI blocked' }
                    '8020' { 'Packaged app allowed' }
                    '8023' { 'Packaged app blocked' }
                    '8024' { 'Packaged app audit block' }
                    '8025' { 'Packaged app installation blocked' }
                    '8028' { 'App Control script/MSI audit block via WLDP (would be blocked)' }
                    '8029' { 'App Control script/MSI block via WLDP' }
                    '8036' { 'App Control COM object blocked' }
                    '8037' { 'App Control script/MSI allowed via WLDP' }
                    '8038' { 'App Control script/MSI signing information' }
                    default { "AppLocker event $($group.Name)" }
                }
                $severity = if ($group.Name -match '^(8004|8007|8023|8025|8029|8036)$') { 'High' } elseif ($group.Name -match '^(8006|8024|8028)$') { 'Medium' } else { 'Info' }
                $status = if ($group.Name -match '^(8004|8007|8023|8025|8029|8036)$') { 'Fail' } elseif ($group.Name -match '^(8006|8024|8028)$') { 'Warning' } else { 'Pass' }

                $sampleMessages = $group.Group | Select-Object -First 3 | ForEach-Object {
                    @{ timeCreated = $_.TimeCreated.ToString('o'); message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }
                }

                $results.Add((New-CLMResult -Category 'EventLogs' -TestName "AppLocker:$($group.Name)" `
                    -Status $status -Severity $severity `
                    -Message "$eventDesc - $($group.Count) event(s)" `
                    -Details @{ eventId = [int]$group.Name; count = $group.Count; logName = $alLog; samples = $sampleMessages } `
                    -Remediation $(switch ($group.Name) {
                        '8028' { 'Review App Control audit events before enforcing. PowerShell may run the file in Constrained Language Mode instead of hard blocking it.' }
                        '8029' { 'Review App Control script enforcement blocks. For PowerShell, confirm whether the script was blocked outright or forced into Constrained Language Mode.' }
                        '8036' { 'Review COM object policy. App Control COM enforcement is separate from script enforcement and may require explicit COM allow rules.' }
                        default { if ($status -eq 'Fail') { 'Review blocked items and create AppLocker or App Control allow rules as needed.' } else { '' } }
                    })))
            }
        }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                # Only log real errors, not "no events found"
            }
        }
    }

    # --- PowerShell Operational Events ---
    $psLogName = 'Microsoft-Windows-PowerShell/Operational'
    $psEventIds = @(4103, 4104, 4105, 4106)
    if ($EventIDs) { $psEventIds = $psEventIds | Where-Object { $EventIDs -contains $_ } }

    try {
        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName   = $psLogName
            StartTime = $startTime
            Id        = $psEventIds
        } -MaxEvents $MaxEvents -ErrorAction Stop

        if ($CorrelateScript) {
            $psEvents = $psEvents | Where-Object { $_.Message -match [regex]::Escape($CorrelateScript) }
        }

        $psGrouped = $psEvents | Group-Object -Property Id
        foreach ($group in $psGrouped) {
            $eventDesc = switch ($group.Name) {
                '4103' { 'Module logging event' }
                '4104' { 'Script block logging event' }
                '4105' { 'Script block invocation start' }
                '4106' { 'Script block invocation end' }
                default { "PowerShell event $($group.Name)" }
            }

            $results.Add((New-CLMResult -Category 'EventLogs' -TestName "PS:EventID-$($group.Name)" `
                -Status 'Info' -Severity 'Info' `
                -Message "$eventDesc - $($group.Count) event(s) in last $Hours hour(s)" `
                -Details @{ eventId = [int]$group.Name; count = $group.Count; logName = $psLogName }))
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $results.Add((New-CLMResult -Category 'EventLogs' -TestName 'PS:Query' -Status 'Error' -Severity 'Low' `
                -Message "Could not query PowerShell logs: $_" `
                -Details @{ logName = $psLogName; error = $_.ToString() } `
                -Remediation 'Run as Administrator to access PowerShell event logs.'))
        }
    }

    return $results.ToArray()
}
