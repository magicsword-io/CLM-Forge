BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'CLM-Forge' 'CLM-Forge.psd1'
    Import-Module $modulePath -Force
}

Describe 'CLM-Forge Module' {
    Context 'Module Loading' {
        It 'Should import without errors' {
            Get-Module CLM-Forge | Should -Not -BeNullOrEmpty
        }

        It 'Should export 12 public functions' {
            $exported = (Get-Module CLM-Forge).ExportedFunctions.Keys
            $exported.Count | Should -Be 12
        }

        It 'Should export expected functions' {
            $expected = @(
                'Invoke-CLMForge',
                'Invoke-CLMCheck', 'Test-CLMEnvironment', 'Test-ScriptCLMCompatibility',
                'Test-ScriptHostExecution', 'Test-ScriptWDACTrust', 'Get-WDACPolicyInfo',
                'Test-CLMCOMRestrictions', 'Test-CLMTypeRestrictions', 'Get-SecurityFeatureStatus',
                'Get-CLMEventLogs', 'New-CLMReport'
            )
            $exported = (Get-Module CLM-Forge).ExportedFunctions.Keys
            foreach ($fn in $expected) {
                $exported | Should -Contain $fn
            }
        }

        It 'Should NOT export private functions' {
            $exported = (Get-Module CLM-Forge).ExportedFunctions.Keys
            $exported | Should -Not -Contain 'New-CLMResult'
            $exported | Should -Not -Contain 'Write-CLMLog'
            $exported | Should -Not -Contain 'Get-CLMConfig'
            $exported | Should -Not -Contain 'Get-WldpLockdownPolicy'
            $exported | Should -Not -Contain 'Invoke-ASTAnalysis'
            $exported | Should -Not -Contain 'Test-COMObjectAccess'
            $exported | Should -Not -Contain 'Test-TypeAccess'
        }

        It 'Should define the clmcheck alias' {
            Get-Alias clmcheck -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should define the clmforge alias' {
            Get-Alias clmforge -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }

    Context 'New-CLMResult Helper' {
        It 'Should create a result with all required properties' {
            InModuleScope CLM-Forge {
                $result = New-CLMResult -Category 'Test' -TestName 'TestCheck' `
                    -Status 'Pass' -Severity 'Info' -Message 'Test passed'
                $result.Category | Should -Be 'Test'
                $result.TestName | Should -Be 'TestCheck'
                $result.Status | Should -Be 'Pass'
                $result.Severity | Should -Be 'Info'
                $result.Message | Should -Be 'Test passed'
                $result.Timestamp | Should -Not -BeNullOrEmpty
                $result.Remediation | Should -Be ''
            }
        }

        It 'Should include remediation when provided' {
            InModuleScope CLM-Forge {
                $result = New-CLMResult -Category 'Test' -TestName 'Fail' `
                    -Status 'Fail' -Severity 'High' -Message 'Failed' `
                    -Remediation 'Fix this'
                $result.Remediation | Should -Be 'Fix this'
            }
        }

        It 'Should include Details when provided' {
            InModuleScope CLM-Forge {
                $result = New-CLMResult -Category 'Test' -TestName 'Det' `
                    -Status 'Info' -Severity 'Info' -Message 'With details' `
                    -Details @{ key = 'value' }
                $result.Details.key | Should -Be 'value'
            }
        }
    }

    Context 'Test-CLMEnvironment' {
        It 'Should return results array' {
            $results = Test-CLMEnvironment
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -BeGreaterThan 0
        }

        It 'Should detect current language mode' {
            $results = Test-CLMEnvironment
            $lm = $results | Where-Object TestName -eq 'LanguageMode'
            $lm | Should -Not -BeNullOrEmpty
            $lm.Details.languageMode | Should -BeIn @('FullLanguage', 'ConstrainedLanguage', 'RestrictedLanguage', 'NoLanguage')
        }

        It 'Should return results with Environment category' {
            $results = Test-CLMEnvironment
            $results | ForEach-Object { $_.Category | Should -Be 'Environment' }
        }

        It 'Should detect PowerShell version' {
            $results = Test-CLMEnvironment
            $psVer = $results | Where-Object TestName -eq 'PowerShellVersion'
            $psVer | Should -Not -BeNullOrEmpty
            $psVer.Details.version | Should -Not -BeNullOrEmpty
        }

        It 'Should check elevation status' {
            $results = Test-CLMEnvironment
            $elev = $results | Where-Object TestName -eq 'Elevation'
            $elev | Should -Not -BeNullOrEmpty
            $elev.Details.isElevated | Should -Not -BeNullOrEmpty
        }

        It 'Should check execution policy' {
            $results = Test-CLMEnvironment
            $ep = $results | Where-Object TestName -eq 'ExecutionPolicy'
            $ep | Should -Not -BeNullOrEmpty
        }

        It 'Should run Add-Type functional test' {
            $results = Test-CLMEnvironment
            $ft = $results | Where-Object TestName -eq 'FunctionalCLMTest'
            $ft | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Test-ScriptCLMCompatibility' {
        BeforeAll {
            $script:unsafePath = Join-Path $PSScriptRoot 'fixtures' 'unsafe-script.ps1'
            $script:safePath = Join-Path $PSScriptRoot 'fixtures' 'safe-script.ps1'
            $script:unsafeResults = Test-ScriptCLMCompatibility -ScriptPath $script:unsafePath
            $script:safeResults = Test-ScriptCLMCompatibility -ScriptPath $script:safePath
        }

        It 'Should flag CLM violations in unsafe script' {
            $critical = $script:unsafeResults | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }
            $critical.Count | Should -BeGreaterThan 0
        }

        It 'Should detect Add-Type (CLM001)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM001' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect COM object creation (CLM002)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM002' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect .NET static method calls (CLM003)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM003' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect custom class (CLM004)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM004' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect using assembly (CLM005)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM005' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect Invoke-Expression (CLM006)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM006' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect PS v2 engine (CLM007)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM007' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect reflection (CLM008)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM008' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect Marshal class (CLM009)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM009' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect delegate creation (CLM010)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM010' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect XAML loading (CLM016)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM016' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect type accelerator manipulation (CLM018)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM018' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect DllImport P/Invoke (CLM025)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM025' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect string concat obfuscation (CLM026)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM026' } | Should -Not -BeNullOrEmpty
        }

        It 'Should detect variable-based invocation (CLM029)' {
            $script:unsafeResults | Where-Object { $_.TestName -match 'CLM029' } | Should -Not -BeNullOrEmpty
        }

        It 'Should produce no Critical findings for safe script' {
            $critical = $script:safeResults | Where-Object { $_.Severity -eq 'Critical' -and $_.Status -eq 'Fail' }
            $critical | Should -BeNullOrEmpty
        }

        It 'Should produce no High findings for safe script' {
            $high = $script:safeResults | Where-Object { $_.Severity -eq 'High' -and $_.Status -eq 'Fail' }
            $high | Should -BeNullOrEmpty
        }

        It 'Should include line numbers in findings' {
            $findings = $script:unsafeResults | Where-Object { $_.Details.Line -gt 0 }
            $findings.Count | Should -BeGreaterThan 0
        }

        It 'Should include remediation guidance' {
            $withRemediation = $script:unsafeResults | Where-Object { $_.Remediation -and $_.Remediation -ne '' }
            $withRemediation.Count | Should -BeGreaterThan 0
        }

        It 'Should include WDAC rule hints' {
            $withHints = $script:unsafeResults | Where-Object { $_.Details.WDACRuleHint -and $_.Details.WDACRuleHint -ne '' }
            $withHints.Count | Should -BeGreaterThan 0
        }

        It 'Should respect MinimumSeverity filter' {
            $results = Test-ScriptCLMCompatibility -ScriptPath $script:unsafePath -MinimumSeverity 'Critical'
            $nonCritical = $results | Where-Object {
                $_.Status -eq 'Fail' -and $_.Severity -ne 'Critical' -and $_.TestName -notmatch 'Summary|ScriptInfo'
            }
            $nonCritical | Should -BeNullOrEmpty
        }

        It 'Should include analysis summary' {
            $summary = $script:unsafeResults | Where-Object TestName -eq 'AnalysisSummary'
            $summary | Should -Not -BeNullOrEmpty
            $summary.Details.totalFindings | Should -BeGreaterThan 0
        }
    }

    Context 'Get-WDACPolicyInfo' {
        It 'Should return results without error' {
            { Get-WDACPolicyInfo } | Should -Not -Throw
        }

        It 'Should return results with WDAC category' {
            $results = Get-WDACPolicyInfo
            $results | Should -Not -BeNullOrEmpty
            $wdac = $results | Where-Object { $_.Category -eq 'WDAC' }
            $wdac | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-SecurityFeatureStatus' {
        It 'Should return results without error' {
            { Get-SecurityFeatureStatus } | Should -Not -Throw
        }

        It 'Should return results with SecurityFeatures category' {
            $results = Get-SecurityFeatureStatus
            $results | Should -Not -BeNullOrEmpty
            $sec = $results | Where-Object { $_.Category -eq 'SecurityFeatures' }
            $sec | Should -Not -BeNullOrEmpty
        }

        It 'Should check Script Block Logging' {
            $results = Get-SecurityFeatureStatus
            $sbl = $results | Where-Object TestName -eq 'ScriptBlockLogging'
            $sbl | Should -Not -BeNullOrEmpty
        }

        It 'Should check AMSI status' {
            $results = Get-SecurityFeatureStatus
            $amsi = $results | Where-Object TestName -eq 'AMSI'
            $amsi | Should -Not -BeNullOrEmpty
        }

        It 'Should check PowerShell v2 engine' {
            $results = Get-SecurityFeatureStatus
            $v2 = $results | Where-Object TestName -eq 'PowerShellV2Engine'
            $v2 | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-CLMEventLogs' {
        It 'Should return results without error' {
            { Get-CLMEventLogs -Hours 1 } | Should -Not -Throw
        }

        It 'Should return results with EventLogs category' {
            $results = Get-CLMEventLogs -Hours 1
            $results | Should -Not -BeNullOrEmpty
            $logs = $results | Where-Object { $_.Category -eq 'EventLogs' }
            $logs | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Test-CLMCOMRestrictions' {
        It 'Should return results without error' {
            { Test-CLMCOMRestrictions } | Should -Not -Throw
        }

        It 'Should return results with COM category' {
            $results = Test-CLMCOMRestrictions
            $results | Should -Not -BeNullOrEmpty
            $com = $results | Where-Object { $_.Category -eq 'COM' }
            $com | Should -Not -BeNullOrEmpty
        }

        It 'Should test multiple COM objects' {
            $results = Test-CLMCOMRestrictions
            $comTests = $results | Where-Object { $_.TestName -ne 'Summary' -and $_.Category -eq 'COM' }
            $comTests.Count | Should -BeGreaterThan 5
        }
    }

    Context 'Test-CLMTypeRestrictions' {
        It 'Should return results without error' {
            { Test-CLMTypeRestrictions } | Should -Not -Throw
        }

        It 'Should return results with TypeRestrictions category' {
            $results = Test-CLMTypeRestrictions
            $results | Should -Not -BeNullOrEmpty
            $types = $results | Where-Object { $_.Category -eq 'TypeRestrictions' }
            $types | Should -Not -BeNullOrEmpty
        }

        It 'Should test multiple .NET types' {
            $results = Test-CLMTypeRestrictions
            $typeTests = $results | Where-Object { $_.TestName -ne 'Summary' -and $_.Category -eq 'TypeRestrictions' }
            $typeTests.Count | Should -BeGreaterThan 10
        }
    }

    Context 'Test-ScriptWDACTrust' {
        It 'Should return results without error' {
            $safePath = Join-Path $PSScriptRoot 'fixtures' 'safe-script.ps1'
            { Test-ScriptWDACTrust -ScriptPath $safePath } | Should -Not -Throw
        }

        It 'Should return results with WDACTrust category' {
            $safePath = Join-Path $PSScriptRoot 'fixtures' 'safe-script.ps1'
            $results = Test-ScriptWDACTrust -ScriptPath $safePath
            $results | Should -Not -BeNullOrEmpty
            $trust = $results | Where-Object { $_.Category -eq 'WDACTrust' }
            $trust | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Invoke-CLMCheck Orchestrator' {
        It 'Should run environment checks by default' {
            $report = Invoke-CLMCheck -Checks Environment -OutputFormat Console -Quiet
            $report | Should -Not -BeNullOrEmpty
            $report.Summary.Total | Should -BeGreaterThan 0
        }

        It 'Should accept ScriptPath for AST analysis' {
            $safePath = Join-Path $PSScriptRoot 'fixtures' 'safe-script.ps1'
            $report = Invoke-CLMCheck -ScriptPath $safePath -Checks AST -OutputFormat Console -Quiet
            $report | Should -Not -BeNullOrEmpty
        }

        It 'Should generate all output formats' {
            $outDir = Join-Path $TestDrive 'invoke-all'
            $report = Invoke-CLMCheck -Checks Environment -OutputFormat All -OutputDirectory $outDir -Quiet
            $report.ReportPaths.Keys | Should -Contain 'JSON'
            $report.ReportPaths.Keys | Should -Contain 'HTML'
            $report.ReportPaths.Keys | Should -Contain 'Log'
        }

        It 'Should return results with PassThru' {
            $result = Invoke-CLMCheck -Checks Environment -OutputFormat Console -Quiet -PassThru
            $result.Results | Should -Not -BeNullOrEmpty
            $result.Duration | Should -Not -BeNullOrEmpty
        }
    }

    Context 'New-CLMReport' {
        It 'Should generate JSON report' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports'
            $report = $results | New-CLMReport -Format JSON -OutputDirectory $outDir -Quiet
            $report.ReportPaths['JSON'] | Should -Not -BeNullOrEmpty
            Test-Path $report.ReportPaths['JSON'] | Should -Be $true
        }

        It 'Should produce valid JSON' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports-json'
            $report = $results | New-CLMReport -Format JSON -OutputDirectory $outDir -Quiet
            { Get-Content $report.ReportPaths['JSON'] -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Should generate HTML report' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports-html'
            $report = $results | New-CLMReport -Format HTML -OutputDirectory $outDir -Quiet
            $report.ReportPaths['HTML'] | Should -Not -BeNullOrEmpty
            Test-Path $report.ReportPaths['HTML'] | Should -Be $true
        }

        It 'Should generate log file' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports-log'
            $report = $results | New-CLMReport -Format Log -OutputDirectory $outDir -Quiet
            $report.ReportPaths['Log'] | Should -Not -BeNullOrEmpty
            Test-Path $report.ReportPaths['Log'] | Should -Be $true
        }

        It 'Should include correct summary counts' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports-summary'
            $report = $results | New-CLMReport -Format JSON -OutputDirectory $outDir -Quiet
            $report.Summary.Total | Should -Be $results.Count
        }

        It 'Should handle All format option' {
            $results = Test-CLMEnvironment
            $outDir = Join-Path $TestDrive 'reports-all'
            $report = $results | New-CLMReport -Format All -OutputDirectory $outDir -Quiet
            $report.ReportPaths.Keys.Count | Should -Be 3
        }
    }

    Context 'AST Rule Definitions' {
        It 'Should define 31 rules' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                $rules.Count | Should -Be 31
            }
        }

        It 'Should have unique rule IDs' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                $ids = $rules | ForEach-Object { $_.ID }
                ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
            }
        }

        It 'Should have sequential CLM001-CLM031 IDs' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                for ($i = 1; $i -le 31; $i++) {
                    $expectedId = 'CLM{0:D3}' -f $i
                    $match = $rules | Where-Object { $_.ID -eq $expectedId }
                    $match | Should -Not -BeNullOrEmpty -Because "Rule $expectedId should exist"
                }
            }
        }

        It 'Should have valid severity levels' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                $validSeverities = @('Critical', 'High', 'Medium', 'Low')
                foreach ($rule in $rules) {
                    $validSeverities | Should -Contain $rule.Severity
                }
            }
        }

        It 'Should have predicates that are scriptblocks' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                foreach ($rule in $rules) {
                    $rule.Predicate | Should -BeOfType [scriptblock]
                }
            }
        }

        It 'Should have non-empty descriptions and remediation' {
            InModuleScope CLM-Forge {
                $rules = Get-ASTRuleDefinitions
                foreach ($rule in $rules) {
                    $rule.Description | Should -Not -BeNullOrEmpty -Because "Rule $($rule.ID) needs a description"
                    $rule.Remediation | Should -Not -BeNullOrEmpty -Because "Rule $($rule.ID) needs remediation"
                }
            }
        }
    }

    Context 'DefaultConfig.json' {
        It 'Should parse as valid JSON' {
            $configPath = Join-Path $PSScriptRoot '..' 'CLM-Forge' 'Config' 'DefaultConfig.json'
            { Get-Content $configPath -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'Should define file types for script host tests' {
            $configPath = Join-Path $PSScriptRoot '..' 'CLM-Forge' 'Config' 'DefaultConfig.json'
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.scriptHostTests.fileTypes.Count | Should -BeGreaterThan 10
        }

        It 'Should define COM objects for testing' {
            $configPath = Join-Path $PSScriptRoot '..' 'CLM-Forge' 'Config' 'DefaultConfig.json'
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.comObjects.Count | Should -BeGreaterThan 15
        }

        It 'Should define .NET types for testing' {
            $configPath = Join-Path $PSScriptRoot '..' 'CLM-Forge' 'Config' 'DefaultConfig.json'
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
            $config.dotNetTypes.Count | Should -BeGreaterThan 25
        }
    }
}
