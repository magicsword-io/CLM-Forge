function New-CLMReport {
    <#
    .SYNOPSIS
        Generates CLM Forge validation reports in multiple formats.

    .DESCRIPTION
        Takes collected CLM Forge results and renders them as Console output, HTML report,
        JSON export, and/or log file. The HTML report is self-contained with embedded CSS/JS.

    .PARAMETER Results
        Array of CLM result objects from any CLM Forge test function.

    .PARAMETER Format
        Output formats to generate. Default is Console only.

    .PARAMETER OutputDirectory
        Directory for report output files. Created if it doesn't exist.

    .PARAMETER Title
        Report title for HTML and console output.

    .PARAMETER Quiet
        Suppress console output (useful when only generating files).

    .OUTPUTS
        [PSCustomObject] Report paths and summary.

    .EXAMPLE
        $results = Test-CLMEnvironment
        $results | New-CLMReport -Format Console, HTML, JSON -OutputDirectory ./reports
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Results,

        [ValidateSet('Console', 'HTML', 'JSON', 'Log', 'All')]
        [string[]]$Format = @('Console'),

        [string]$OutputDirectory = (Join-Path $PWD 'CLM-Forge-Results'),

        [string]$Title = 'CLM Forge Validation Report',

        [switch]$Quiet
    )

    begin {
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($r in $Results) {
            $allResults.Add($r)
        }
    }

    end {
        if ($Format -contains 'All') {
            $Format = @('Console', 'HTML', 'JSON', 'Log')
        }

        # Build summary
        $summary = @{
            Total    = $allResults.Count
            Pass     = ($allResults | Where-Object Status -eq 'Pass').Count
            Fail     = ($allResults | Where-Object Status -eq 'Fail').Count
            Warning  = ($allResults | Where-Object Status -eq 'Warning').Count
            Info     = ($allResults | Where-Object Status -eq 'Info').Count
            Error    = ($allResults | Where-Object Status -eq 'Error').Count
            Skipped  = ($allResults | Where-Object Status -eq 'Skipped').Count
            Critical = ($allResults | Where-Object Severity -eq 'Critical').Count
            High     = ($allResults | Where-Object Severity -eq 'High').Count
            Medium   = ($allResults | Where-Object Severity -eq 'Medium').Count
            Low      = ($allResults | Where-Object Severity -eq 'Low').Count
        }

        $reportPaths = @{}
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

        # Ensure output directory exists
        if ($Format -contains 'HTML' -or $Format -contains 'JSON' -or $Format -contains 'Log') {
            if (-not (Test-Path $OutputDirectory)) {
                $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
            }
        }

        # --- Console Output ---
        if ($Format -contains 'Console') {
            ConvertTo-ColoredConsoleOutput -Results $allResults.ToArray() -Quiet:$Quiet
        }

        # --- JSON Export ---
        if ($Format -contains 'JSON') {
            $jsonPath = Join-Path $OutputDirectory "CLM-Forge-$timestamp.json"

            $jsonOutput = [PSCustomObject]@{
                metadata = [PSCustomObject]@{
                    toolVersion       = $script:ModuleVersion
                    generatedAt       = (Get-Date).ToString('o')
                    hostname          = $env:COMPUTERNAME
                    userName          = "$env:USERDOMAIN\$env:USERNAME"
                    powershellVersion = $PSVersionTable.PSVersion.ToString()
                    powershellEdition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
                    osVersion         = [System.Environment]::OSVersion.VersionString
                }
                summary  = $summary
                results  = $allResults.ToArray() | ForEach-Object {
                    [PSCustomObject]@{
                        category    = $_.Category
                        testName    = $_.TestName
                        status      = $_.Status
                        severity    = $_.Severity
                        message     = $_.Message
                        details     = $_.Details
                        remediation = $_.Remediation
                        timestamp   = $_.Timestamp.ToString('o')
                    }
                }
            }

            $jsonOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
            $reportPaths['JSON'] = $jsonPath
            if (-not $Quiet) { Write-Host "[*] JSON report saved: $jsonPath" -ForegroundColor Cyan }
        }

        # --- Log File ---
        if ($Format -contains 'Log') {
            $logPath = Join-Path $OutputDirectory "CLM-Forge-$timestamp.log"

            $logLines = [System.Collections.Generic.List[string]]::new()
            $logLines.Add("[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] CLM Forge v$($script:ModuleVersion) Report Generated")
            $logLines.Add("[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] Host: $env:COMPUTERNAME | User: $env:USERDOMAIN\$env:USERNAME")
            $logLines.Add("[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))] [INFO] Total Checks: $($summary.Total) | Pass: $($summary.Pass) | Fail: $($summary.Fail) | Warning: $($summary.Warning)")
            $logLines.Add("")

            foreach ($result in $allResults) {
                $level = switch ($result.Status) {
                    'Pass'    { 'INFO' }
                    'Fail'    { 'ERROR' }
                    'Warning' { 'WARNING' }
                    'Info'    { 'INFO' }
                    'Error'   { 'ERROR' }
                    'Skipped' { 'INFO' }
                }
                $logLines.Add("[$($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))] [$level] [$($result.Category)] $($result.TestName): $($result.Message)")
                if ($result.Remediation) {
                    $logLines.Add("  -> Remediation: $($result.Remediation)")
                }
            }

            $logLines | Out-File -FilePath $logPath -Encoding UTF8
            $reportPaths['Log'] = $logPath
            if (-not $Quiet) { Write-Host "[*] Log file saved: $logPath" -ForegroundColor Cyan }
        }

        # --- HTML Report ---
        if ($Format -contains 'HTML') {
            $htmlPath = Join-Path $OutputDirectory "CLM-Forge-$timestamp.html"
            $html = Build-HTMLReport -Results $allResults.ToArray() -Summary $summary -Title $Title
            $html | Out-File -FilePath $htmlPath -Encoding UTF8
            $reportPaths['HTML'] = $htmlPath
            if (-not $Quiet) { Write-Host "[*] HTML report saved: $htmlPath" -ForegroundColor Cyan }
        }

        return [PSCustomObject]@{
            ReportPaths = $reportPaths
            Summary     = $summary
            ResultCount = $allResults.Count
        }
    }
}

function ConvertTo-CLMHtmlEncoded {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    try {
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
    catch {
        return [System.Security.SecurityElement]::Escape([string]$Value)
    }
}

function Build-HTMLReport {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Results,
        [hashtable]$Summary,
        [string]$Title
    )

    $resultsJson = ($Results | ForEach-Object {
        [PSCustomObject]@{
            category    = $_.Category
            testName    = $_.TestName
            status      = $_.Status
            severity    = $_.Severity
            message     = $_.Message
            details     = $_.Details
            remediation = $_.Remediation
            timestamp   = $_.Timestamp.ToString('o')
        }
    }) | ConvertTo-Json -Depth 10 -Compress

    $summaryJson = $Summary | ConvertTo-Json -Compress

    # Escape JSON for safe inline <script> embedding while keeping it valid JSON.
    $resultsJson = $resultsJson -replace '<', '\u003c' -replace '>', '\u003e' -replace '&', '\u0026' -replace '\u2028', '\\u2028' -replace '\u2029', '\\u2029'
    $summaryJson = $summaryJson -replace '<', '\u003c' -replace '>', '\u003e' -replace '&', '\u0026' -replace '\u2028', '\\u2028' -replace '\u2029', '\\u2029'

    # Encode values that render in HTML context
    $encodedTitle = ConvertTo-CLMHtmlEncoded $Title
    $encodedHost = ConvertTo-CLMHtmlEncoded $env:COMPUTERNAME
    $encodedUser = ConvertTo-CLMHtmlEncoded "$env:USERDOMAIN\$env:USERNAME"
    $encodedGeneratedAt = ConvertTo-CLMHtmlEncoded ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $encodedModuleVersion = ConvertTo-CLMHtmlEncoded $script:ModuleVersion
    $encodedPSVersion = ConvertTo-CLMHtmlEncoded ($PSVersionTable.PSVersion.ToString())
    $encodedOSVersion = ConvertTo-CLMHtmlEncoded ([System.Environment]::OSVersion.VersionString)

    # Check if template exists, otherwise use embedded
    $templatePath = $script:TemplatePath
    if ($templatePath -and (Test-Path $templatePath)) {
        $html = Get-Content -Path $templatePath -Raw
        $html = $html.Replace('{{TITLE}}', $encodedTitle)
        $html = $html.Replace('{{HOSTNAME}}', $encodedHost)
        $html = $html.Replace('{{USERNAME}}', $encodedUser)
        $html = $html.Replace('{{GENERATED_AT}}', $encodedGeneratedAt)
        $html = $html.Replace('{{MODULE_VERSION}}', $encodedModuleVersion)
        $html = $html.Replace('{{PS_VERSION}}', $encodedPSVersion)
        $html = $html.Replace('{{OS_VERSION}}', $encodedOSVersion)
        $html = $html.Replace('{{RESULTS_JSON}}', $resultsJson)
        $html = $html.Replace('{{SUMMARY_JSON}}', $summaryJson)
        return $html
    }

    # Fallback: embedded minimal HTML report
    $categories = $Results | Group-Object -Property Category

    $categorySections = foreach ($cat in $categories) {
        $rows = foreach ($r in $cat.Group) {
            $statusClass = switch ($r.Status) { 'Pass' { 'pass' } 'Fail' { 'fail' } 'Warning' { 'warn' } default { 'info' } }
            $severityClass = switch ($r.Severity) { 'Critical' { 'critical' } 'High' { 'high' } 'Medium' { 'medium' } default { 'low' } }
            "<tr class=`"$statusClass`"><td><span class=`"badge $statusClass`">$($r.Status)</span></td><td><span class=`"badge $severityClass`">$($r.Severity)</span></td><td>$(ConvertTo-CLMHtmlEncoded $r.TestName)</td><td>$(ConvertTo-CLMHtmlEncoded $r.Message)</td><td>$(ConvertTo-CLMHtmlEncoded $r.Remediation)</td></tr>"
        }
        @"
<div class="category">
<h2 onclick="this.parentElement.classList.toggle('collapsed')">$($cat.Name) <span class="count">($($cat.Count) checks)</span></h2>
<table><thead><tr><th>Status</th><th>Severity</th><th>Test</th><th>Message</th><th>Remediation</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table></div>
"@
    }

    return @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$encodedTitle</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:20px}
header{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:24px}
h1{color:#58a6ff;font-size:24px;margin-bottom:8px}
.meta{color:#8b949e;font-size:13px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:20px 0}
.summary-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.summary-card .num{font-size:28px;font-weight:700}
.summary-card .label{font-size:12px;color:#8b949e;text-transform:uppercase}
.num.pass-num{color:#3fb950}.num.fail-num{color:#f85149}.num.warn-num{color:#d29922}.num.info-num{color:#58a6ff}
.num.crit-num{color:#f85149}.num.high-num{color:#db6d28}.num.med-num{color:#d29922}
.category{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:16px;overflow:hidden}
.category h2{padding:16px;cursor:pointer;background:#1c2128;border-bottom:1px solid #30363d;font-size:16px;color:#c9d1d9;user-select:none}
.category h2:hover{background:#22272e}
.category.collapsed table{display:none}
.count{color:#8b949e;font-weight:400;font-size:13px}
table{width:100%;border-collapse:collapse}
th{background:#1c2128;padding:10px 12px;text-align:left;font-size:12px;text-transform:uppercase;color:#8b949e;border-bottom:1px solid #30363d}
td{padding:10px 12px;border-bottom:1px solid #21262d;font-size:13px;vertical-align:top}
tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase}
.badge.pass{background:#1b4332;color:#3fb950}.badge.fail{background:#490202;color:#f85149}
.badge.warn{background:#4a3000;color:#d29922}.badge.info{background:#0c2d6b;color:#58a6ff}
.badge.critical{background:#490202;color:#f85149}.badge.high{background:#4a2000;color:#db6d28}
.badge.medium{background:#4a3000;color:#d29922}.badge.low{background:#1c2128;color:#8b949e}
footer{text-align:center;padding:20px;color:#484f58;font-size:12px}
</style></head><body>
<div class="container">
<header>
<h1>$encodedTitle</h1>
<div class="meta">Host: $encodedHost | User: $encodedUser | Generated: $encodedGeneratedAt | CLM Forge v$encodedModuleVersion</div>
</header>
<div class="summary">
<div class="summary-card"><div class="num">$($Summary.Total)</div><div class="label">Total</div></div>
<div class="summary-card"><div class="num pass-num">$($Summary.Pass)</div><div class="label">Pass</div></div>
<div class="summary-card"><div class="num fail-num">$($Summary.Fail)</div><div class="label">Fail</div></div>
<div class="summary-card"><div class="num warn-num">$($Summary.Warning)</div><div class="label">Warning</div></div>
<div class="summary-card"><div class="num crit-num">$($Summary.Critical)</div><div class="label">Critical</div></div>
<div class="summary-card"><div class="num high-num">$($Summary.High)</div><div class="label">High</div></div>
<div class="summary-card"><div class="num med-num">$($Summary.Medium)</div><div class="label">Medium</div></div>
</div>
$($categorySections -join "`n")
<footer>Generated by CLM Forge v$encodedModuleVersion | $encodedGeneratedAt</footer>
</div>
<script>const results=$resultsJson;const summary=$summaryJson;</script>
</body></html>
"@
}
