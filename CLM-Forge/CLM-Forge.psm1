# CLM-Forge Root Module
# Dot-source all private and public functions

$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue | Sort-Object Name)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue | Sort-Object Name)

foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import function $($import.FullName): $_"
    }
}

# Module-scoped variables
$script:ModuleRoot    = $PSScriptRoot
$script:ConfigPath    = Join-Path $PSScriptRoot 'Config\DefaultConfig.json'
$script:TemplatePath  = Join-Path $PSScriptRoot 'Templates\ReportTemplate.html'
$script:ModuleVersion = (Import-PowerShellDataFile "$PSScriptRoot\CLM-Forge.psd1").ModuleVersion

New-Alias -Name 'clmforge' -Value 'Invoke-CLMForge' -Force
New-Alias -Name 'clmcheck' -Value 'Invoke-CLMCheck' -Force

# Explicitly export only public functions (private functions stay internal)
$publicFunctions = @(
    'Invoke-CLMForge'
    'Invoke-CLMCheck'
    'Test-CLMEnvironment'
    'Test-ScriptCLMCompatibility'
    'Test-ScriptHostExecution'
    'Test-ScriptWDACTrust'
    'Get-WDACPolicyInfo'
    'Test-CLMCOMRestrictions'
    'Test-CLMTypeRestrictions'
    'Get-SecurityFeatureStatus'
    'Get-CLMEventLogs'
    'New-CLMReport'
)
Export-ModuleMember -Function $publicFunctions -Alias @('clmforge', 'clmcheck')
