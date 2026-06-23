@{
    RootModule        = 'CLM-Forge.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '54ef8200-7680-4e39-b6b6-214930a3273c'
    Author            = 'Magicsword'
    CompanyName       = 'Magicsword'
    Copyright         = '(c) 2025 Magicsword. Apache License 2.0.'
    Description       = 'Comprehensive Constrained Language Mode (CLM) and WDAC script enforcement validation toolkit. Validates scripts before WDAC deployment, detects environment restrictions, performs static analysis, and generates detailed remediation reports.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
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
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @('clmforge', 'clmcheck')
    PrivateData = @{
        PSData = @{
            Tags       = @('WDAC', 'CLM', 'ConstrainedLanguageMode', 'Security', 'AppControl', 'DeviceGuard', 'ScriptEnforcement')
            LicenseUri = 'https://github.com/magicsword-io/clm-forge/blob/main/LICENSE'
            ProjectUri = 'https://github.com/magicsword-io/clm-forge'
        }
    }
}
