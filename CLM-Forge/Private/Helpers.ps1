function Test-IsElevated {
    [OutputType([bool])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-CLMLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
        [string]$Level = 'Info',

        [string]$LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$($Level.ToUpper())] $Message"

    if ($LogPath) {
        try {
            $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
        }
        catch {
            Write-Verbose "Failed to write to log file: $_"
        }
    }

    switch ($Level) {
        'Info'    { Write-Verbose $logEntry }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Verbose $logEntry }
        'Debug'   { Write-Debug $logEntry }
        'Verbose' { Write-Verbose $logEntry }
    }
}

function New-CLMResult {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$TestName,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Error', 'Skipped')]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [object]$Details = $null,

        [string]$Remediation = ''
    )

    [PSCustomObject]@{
        Category    = $Category
        TestName    = $TestName
        Status      = $Status
        Severity    = $Severity
        Message     = $Message
        Details     = $Details
        Remediation = $Remediation
        Timestamp   = Get-Date
    }
}

function Get-CLMConfig {
    [OutputType([PSCustomObject])]
    param(
        [string]$ConfigPath
    )

    if (-not $ConfigPath) {
        $ConfigPath = $script:ConfigPath
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "Configuration file not found at $ConfigPath. Using built-in defaults."
        return $null
    }

    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        return $config
    }
    catch {
        Write-Warning "Failed to parse configuration file: $_"
        return $null
    }
}

function Get-SafeTempPath {
    [OutputType([string])]
    param(
        [string]$BasePath
    )

    if (-not $BasePath) {
        $BasePath = [System.IO.Path]::GetTempPath()
    }

    $uniqueDir = Join-Path $BasePath "CLM-Forge-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"

    try {
        $null = New-Item -ItemType Directory -Path $uniqueDir -Force
        return $uniqueDir
    }
    catch {
        Write-Warning "Failed to create temp directory at $uniqueDir : $_"
        return $null
    }
}

function ConvertTo-ColoredConsoleOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [switch]$Quiet
    )

    if ($Quiet) { return }

    $width = 60
    $separator = '=' * $width

    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "  CLM Forge Validation Report" -ForegroundColor White
    Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "  Host: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""

    $categories = $Results | Group-Object -Property Category

    foreach ($cat in $categories) {
        Write-Host "[$($cat.Name.ToUpper())]" -ForegroundColor Yellow
        foreach ($result in $cat.Group) {
            $icon = switch ($result.Status) {
                'Pass'    { '[+]' }
                'Fail'    { '[-]' }
                'Warning' { '[!]' }
                'Info'    { '[*]' }
                'Error'   { '[x]' }
                'Skipped' { '[~]' }
            }
            $color = switch ($result.Status) {
                'Pass'    { 'Green' }
                'Fail'    { 'Red' }
                'Warning' { 'Yellow' }
                'Info'    { 'Cyan' }
                'Error'   { 'Magenta' }
                'Skipped' { 'DarkGray' }
            }

            $severityTag = if ($result.Severity -ne 'Info') { " [$($result.Severity)]" } else { '' }
            Write-Host "  $icon$severityTag $($result.Message)" -ForegroundColor $color

            if ($result.Status -eq 'Fail' -and $result.Remediation) {
                Write-Host "      Fix: $($result.Remediation)" -ForegroundColor DarkYellow
            }

            # Special display for WDAC hash - make it prominent and copyable
            if ($result.TestName -eq 'WDACHash' -and $result.Details.sha256) {
                Write-Host ""
                Write-Host "      +---------------------------------------------------------------------+" -ForegroundColor White
                Write-Host "      | WDAC SHA256 Hash (copy into MagicSword Policy Editor to allow):    |" -ForegroundColor White
                Write-Host "      | $($result.Details.sha256)" -ForegroundColor Green
                Write-Host "      | File: $($result.Details.fileName)" -ForegroundColor Gray
                Write-Host "      +---------------------------------------------------------------------+" -ForegroundColor White
                Write-Host ""
            }

            if ($result.Details -and $result.Details.CodeSnippet) {
                Write-Host "      Code: $($result.Details.CodeSnippet)" -ForegroundColor DarkGray
            }
            if ($result.Details -and $result.Details.Line) {
                Write-Host "      Line: $($result.Details.Line)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }

    # Summary
    $total = $Results.Count
    $pass = ($Results | Where-Object Status -eq 'Pass').Count
    $fail = ($Results | Where-Object Status -eq 'Fail').Count
    $warn = ($Results | Where-Object Status -eq 'Warning').Count
    $critical = ($Results | Where-Object Severity -eq 'Critical').Count
    $high = ($Results | Where-Object Severity -eq 'High').Count
    $medium = ($Results | Where-Object Severity -eq 'Medium').Count

    Write-Host $separator -ForegroundColor Cyan
    Write-Host "[SUMMARY]" -ForegroundColor Yellow
    Write-Host "  Total Checks: $total" -ForegroundColor White
    Write-Host -NoNewline "  Pass: " ; Write-Host -NoNewline "$pass" -ForegroundColor Green
    Write-Host -NoNewline "  |  Fail: " ; Write-Host -NoNewline "$fail" -ForegroundColor Red
    Write-Host -NoNewline "  |  Warning: " ; Write-Host "$warn" -ForegroundColor Yellow
    Write-Host -NoNewline "  Critical: " ; Write-Host -NoNewline "$critical" -ForegroundColor Red
    Write-Host -NoNewline "  |  High: " ; Write-Host -NoNewline "$high" -ForegroundColor DarkRed
    Write-Host -NoNewline "  |  Medium: " ; Write-Host "$medium" -ForegroundColor Yellow
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""
}
