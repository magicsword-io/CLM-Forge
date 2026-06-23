function Invoke-CLMForge {
    <#
    .SYNOPSIS
        Branded entry point for CLM Forge.

    .DESCRIPTION
        Compatibility wrapper that forwards all parameters to Invoke-CLMCheck.
        Use this command name for CLM Forge branding while preserving existing
        automation that still calls Invoke-CLMCheck.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [string]$ScriptPath,

        [string]$ConfigPath,

        [string[]]$Checks = @('All'),

        [string[]]$OutputFormat = @('Console'),

        [string]$OutputDirectory = (Join-Path $PWD 'CLM-Forge-Results'),

        [switch]$RunExecutionTests,

        [switch]$IncludeEventLogs,

        [int]$EventLogHours = 24,

        [switch]$Quiet,

        [switch]$PassThru
    )

    $params = @{}
    if ($PSBoundParameters.ContainsKey('ScriptPath')) { $params['ScriptPath'] = $ScriptPath }
    if ($PSBoundParameters.ContainsKey('ConfigPath')) { $params['ConfigPath'] = $ConfigPath }
    if ($PSBoundParameters.ContainsKey('Checks')) { $params['Checks'] = $Checks }
    if ($PSBoundParameters.ContainsKey('OutputFormat')) { $params['OutputFormat'] = $OutputFormat }
    if ($PSBoundParameters.ContainsKey('OutputDirectory')) { $params['OutputDirectory'] = $OutputDirectory }
    if ($PSBoundParameters.ContainsKey('RunExecutionTests')) { $params['RunExecutionTests'] = $RunExecutionTests }
    if ($PSBoundParameters.ContainsKey('IncludeEventLogs')) { $params['IncludeEventLogs'] = $IncludeEventLogs }
    if ($PSBoundParameters.ContainsKey('EventLogHours')) { $params['EventLogHours'] = $EventLogHours }
    if ($PSBoundParameters.ContainsKey('Quiet')) { $params['Quiet'] = $Quiet }
    if ($PSBoundParameters.ContainsKey('PassThru')) { $params['PassThru'] = $PassThru }

    Invoke-CLMCheck @params
}
