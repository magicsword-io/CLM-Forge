function Get-ASTRuleDefinitions {
    [OutputType([hashtable[]])]
    param()

    $restrictedTypePatterns = @(
        'System\.IO\.File', 'System\.IO\.StreamReader', 'System\.IO\.StreamWriter',
        'System\.Net\.WebClient', 'System\.Net\.Http\.HttpClient',
        'System\.Net\.Sockets\.TcpClient', 'System\.Net\.Sockets\.UdpClient',
        'System\.Reflection\.Assembly', 'System\.Reflection\.MethodInfo',
        'System\.Runtime\.InteropServices\.Marshal',
        'System\.Diagnostics\.Process', 'System\.Diagnostics\.ProcessStartInfo',
        'System\.Security\.Cryptography\.',
        'Microsoft\.Win32\.Registry', 'Microsoft\.Win32\.RegistryKey',
        'System\.DirectoryServices\.',
        'System\.Management\.ManagementObject', 'System\.Management\.ManagementObjectSearcher',
        'System\.Data\.SqlClient\.',
        'System\.Net\.Dns', 'System\.Net\.NetworkInformation\.Ping',
        'System\.Threading\.Thread',
        'System\.Convert', 'System\.Text\.Encoding',
        'System\.Windows\.Forms\.'
    )
    $restrictedTypeRegex = ($restrictedTypePatterns | ForEach-Object { "($_)" }) -join '|'

    @(
        @{
            ID          = 'CLM001'
            Name        = 'Add-Type Usage'
            Severity    = 'Critical'
            Description = 'Add-Type is blocked in Constrained Language Mode. Scripts using Add-Type to compile C#/VB code or load assemblies will fail.'
            Remediation = 'Remove Add-Type usage. Use built-in cmdlets or move custom .NET code to a signed module.'
            WDACRuleHint = 'Sign the script and add a WDAC signer rule, or package the code in a signed assembly.'
            Predicate   = {
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.CommandElements -and
                $node.CommandElements.Count -gt 0 -and
                $node.CommandElements[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $node.CommandElements[0].Value -eq 'Add-Type'
            }
        },
        @{
            ID          = 'CLM002'
            Name        = 'COM Object Creation'
            Severity    = 'High'
            Description = 'New-Object -ComObject is restricted in CLM. Only WDAC-approved COM classes can be instantiated.'
            Remediation = 'Replace with approved cmdlets (e.g., Invoke-WebRequest instead of MSXML2.XMLHTTP, Get-Content instead of Scripting.FileSystemObject).'
            WDACRuleHint = 'Add the COM class GUID to your WDAC policy allowed COM objects list.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmdName = $node.CommandElements[0]
                if ($cmdName -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmdName.Value -ne 'New-Object') { return $false }
                $hasComObject = $false
                foreach ($elem in $node.CommandElements) {
                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elem.ParameterName -match '^(?:ComObject|COM)$') {
                        $hasComObject = $true
                    }
                }
                return $hasComObject
            }
        },
        @{
            ID          = 'CLM003'
            Name        = '.NET Static Method Call on Restricted Type'
            Severity    = 'High'
            Description = 'Direct access to restricted .NET type static methods is blocked in CLM. Only approved types are accessible.'
            Remediation = 'Use equivalent cmdlets (e.g., Get-Content instead of [System.IO.File]::ReadAllText(), Invoke-WebRequest instead of [System.Net.WebClient]).'
            WDACRuleHint = 'Move the .NET code into a signed module that runs in FullLanguage mode.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
                $expr = $node.Expression
                if ($expr -isnot [System.Management.Automation.Language.TypeExpressionAst]) { return $false }
                if (-not $expr.TypeName) { return $false }
                $typeName = $expr.TypeName.FullName
                if (-not $typeName) { return $false }
                if ($typeName -match $restrictedTypeRegex) { return $true }
                return $false
            }
        },
        @{
            ID          = 'CLM004'
            Name        = 'Custom Class Definition'
            Severity    = 'Critical'
            Description = 'PowerShell class definitions are blocked in CLM. The class keyword cannot be used.'
            Remediation = 'Replace class definitions with [PSCustomObject] or hashtables. For complex types, use a signed module.'
            WDACRuleHint = 'Sign the script containing class definitions and add a WDAC signer rule.'
            Predicate   = {
                param($node)
                $node -is [System.Management.Automation.Language.TypeDefinitionAst]
            }
        },
        @{
            ID          = 'CLM005'
            Name        = 'Using Assembly Statement'
            Severity    = 'Critical'
            Description = 'The "using assembly" statement is blocked in CLM. Assembly loading is restricted.'
            Remediation = 'Remove using assembly statements. Use approved cmdlets or signed modules instead.'
            WDACRuleHint = 'Package the required assemblies in a signed module.'
            Predicate   = {
                param($node)
                $node -is [System.Management.Automation.Language.UsingStatementAst] -and
                $node.UsingStatementKind -eq [System.Management.Automation.Language.UsingStatementKind]::Assembly
            }
        },
        @{
            ID          = 'CLM006'
            Name        = 'Invoke-Expression Usage'
            Severity    = 'High'
            Description = 'Invoke-Expression (iex) executes dynamic code which is restricted in CLM and a security risk.'
            Remediation = 'Refactor to avoid dynamic code execution. Use parameterized commands, splatting, or the call operator (&) instead.'
            WDACRuleHint = 'Eliminate Invoke-Expression entirely and use static script constructs.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -eq 0) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                return ($cmd.Value -eq 'Invoke-Expression' -or $cmd.Value -eq 'iex')
            }
        },
        @{
            ID          = 'CLM007'
            Name        = 'PowerShell v2 Engine Invocation'
            Severity    = 'Critical'
            Description = 'PowerShell v2 engine bypasses CLM, AMSI, and Script Block Logging. It should be disabled system-wide.'
            Remediation = 'Remove -Version 2 arguments. Disable PS v2: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root'
            WDACRuleHint = 'Disable the PowerShell v2 engine via Windows Features before deploying WDAC.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -notmatch '^powershell(\.exe)?$') { return $false }
                $text = $node.Extent.Text
                return ($text -match '-[Vv](ersion)?\s+2')
            }
        },
        @{
            ID          = 'CLM008'
            Name        = 'Reflection Usage'
            Severity    = 'High'
            Description = 'System.Reflection types are restricted in CLM. Reflection-based type access, method invocation, and assembly loading are blocked.'
            Remediation = 'Remove reflection usage. Use approved cmdlets and built-in PowerShell features instead.'
            WDACRuleHint = 'Move reflection code to a signed module.'
            Predicate   = {
                param($node)
                if ($node -is [System.Management.Automation.Language.TypeExpressionAst]) {
                    return ($node.TypeName.FullName -match 'System\.Reflection\.')
                }
                if ($node -is [System.Management.Automation.Language.TypeConstraintAst]) {
                    return ($node.TypeName.FullName -match 'System\.Reflection\.')
                }
                return $false
            }
        },
        @{
            ID          = 'CLM009'
            Name        = 'Marshal Class Usage'
            Severity    = 'Critical'
            Description = 'System.Runtime.InteropServices.Marshal is a primary CLM restriction target. Used for P/Invoke and unmanaged memory access.'
            Remediation = 'Remove Marshal usage entirely. This class is used for native API calls which are not permitted in CLM.'
            WDACRuleHint = 'Move interop code to a compiled, signed .NET assembly.'
            Predicate   = {
                param($node)
                if ($node -is [System.Management.Automation.Language.TypeExpressionAst]) {
                    return ($node.TypeName.FullName -match 'System\.Runtime\.InteropServices\.Marshal|Runtime\.InteropServices\.Marshal')
                }
                return $false
            }
        },
        @{
            ID          = 'CLM010'
            Name        = 'Delegate Creation'
            Severity    = 'Critical'
            Description = 'Delegate creation via GetDelegateForFunctionPointer or DynamicInvoke is blocked in CLM.'
            Remediation = 'Remove delegate/P/Invoke patterns. These are used for native API calls not permitted in CLM.'
            WDACRuleHint = 'Move native interop to a compiled, signed .NET assembly.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
                $memberName = $node.Member
                if ($memberName -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    return ($memberName.Value -match '^(GetDelegateForFunctionPointer|DynamicInvoke|CreateDelegate)$')
                }
                return $false
            }
        },
        @{
            ID          = 'CLM011'
            Name        = 'Suspicious Script Block Invocation'
            Severity    = 'Medium'
            Description = 'Script blocks invoked via .Invoke() or .InvokeReturnAsIs() may behave differently in CLM.'
            Remediation = 'Use the call operator (&) or dot-sourcing (.) instead of .Invoke() on script blocks.'
            WDACRuleHint = 'Ensure the calling script is signed and in the WDAC allow list.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
                $memberName = $node.Member
                if ($memberName -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    if ($memberName.Value -match '^(Invoke|InvokeReturnAsIs)$') {
                        $exprText = $node.Expression.Extent.Text
                        return ($exprText -match 'scriptblock|\$sb|\$block|\$script' -or
                                $node.Expression -is [System.Management.Automation.Language.ScriptBlockExpressionAst])
                    }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM012'
            Name        = 'DSC Resource Definition'
            Severity    = 'Medium'
            Description = 'DSC (Desired State Configuration) resources and configurations may not work in CLM.'
            Remediation = 'Move DSC configurations to signed .ps1 files. Ensure DSC modules are WDAC-approved.'
            WDACRuleHint = 'Sign DSC configuration scripts and resource modules.'
            Predicate   = {
                param($node)
                if ($node.GetType().Name -eq 'ConfigurationDefinitionAst') { return $true }
                if ($node.GetType().Name -eq 'DynamicKeywordStatementAst') {
                    $keyword = $node.Keyword
                    if ($keyword) { return $true }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM013'
            Name        = 'Workflow Definition'
            Severity    = 'Low'
            Description = 'PowerShell workflows are deprecated in PS 7+ and restricted in CLM.'
            Remediation = 'Replace workflows with standard functions, ForEach-Object -Parallel (PS 7+), or background jobs.'
            WDACRuleHint = 'N/A - workflows should be replaced entirely.'
            Predicate   = {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.IsWorkflow
            }
        },
        @{
            ID          = 'CLM014'
            Name        = 'Sensitive Cmdlet Usage'
            Severity    = 'Medium'
            Description = 'Certain cmdlets like Invoke-Command with -ScriptBlock, Register-ScheduledTask, and New-Service may behave differently or be restricted under CLM.'
            Remediation = 'Verify these cmdlets work as expected in CLM. Remote Invoke-Command script blocks inherit the remote session language mode.'
            WDACRuleHint = 'Ensure target systems have matching WDAC policies for remote script execution.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -eq 'Invoke-Command') {
                    foreach ($elem in $node.CommandElements) {
                        if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                            $elem.ParameterName -match '^(?:ScriptBlock|Script)$') { return $true }
                    }
                }
                if ($cmd.Value -match '^(Register-ScheduledTask|New-Service|Set-Service)$') { return $true }
                return $false
            }
        },
        @{
            ID          = 'CLM015'
            Name        = 'Encoded Command Usage'
            Severity    = 'High'
            Description = 'EncodedCommand can bypass logging and is often flagged by security tools. It also complicates CLM analysis.'
            Remediation = 'Decode the command and use plain script text. Encoded commands may bypass Script Block Logging on older systems.'
            WDACRuleHint = 'Use plain-text scripts that can be properly evaluated by WDAC.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -notmatch '^powershell(\.exe)?$|^pwsh(\.exe)?$') { return $false }
                foreach ($elem in $node.CommandElements) {
                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elem.ParameterName -match '^(?:EncodedCommand|enc|ec)$') { return $true }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM016'
            Name        = 'XAML Loading'
            Severity    = 'Critical'
            Description = 'System.Windows.Markup.XamlReader is blocked in CLM. XAML-based UI and deserialization will fail.'
            Remediation = 'Remove XAML loading. Use alternative UI approaches or move XAML code to a signed module.'
            WDACRuleHint = 'Package XAML-based UI code in a signed module or compiled assembly.'
            Predicate   = {
                param($node)
                if ($node -is [System.Management.Automation.Language.TypeExpressionAst]) {
                    return ($node.TypeName.FullName -match 'XamlReader|System\.Windows\.Markup')
                }
                if ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
                    $expr = $node.Expression
                    if ($expr -is [System.Management.Automation.Language.TypeExpressionAst]) {
                        return ($expr.TypeName.FullName -match 'XamlReader|System\.Windows\.Markup')
                    }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM017'
            Name        = 'Background Job with Script Block'
            Severity    = 'Medium'
            Description = 'Background jobs (Start-Job) inherit the language mode. Script blocks passed to jobs will run in CLM if the system enforces it.'
            Remediation = 'Verify job script blocks use only CLM-compatible constructs. Consider using signed script files instead of inline script blocks.'
            WDACRuleHint = 'Ensure job script content is in signed .ps1 files referenced by -FilePath.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -notmatch '^(Start-Job|Start-ThreadJob)$') { return $false }
                foreach ($elem in $node.CommandElements) {
                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elem.ParameterName -match '^(?:ScriptBlock|Script)$') { return $true }
                    if ($elem -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { return $true }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM018'
            Name        = 'Type Accelerator Manipulation'
            Severity    = 'Critical'
            Description = 'Accessing or modifying PowerShell type accelerators via reflection is blocked in CLM.'
            Remediation = 'Remove type accelerator manipulation. Use fully qualified type names or built-in accelerators.'
            WDACRuleHint = 'N/A - type accelerator manipulation should not be used in production scripts.'
            Predicate   = {
                param($node)
                if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    return ($node.Value -match 'TypeAccelerators')
                }
                return $false
            }
        },
        @{
            ID          = 'CLM019'
            Name        = 'Dynamic Method Invocation'
            Severity    = 'High'
            Description = 'Calling GetType().GetMethod().Invoke() or similar reflection chains is restricted in CLM.'
            Remediation = 'Remove dynamic method invocation. Use direct cmdlet calls or approved .NET methods.'
            WDACRuleHint = 'Move reflection-based code to a signed module or compiled assembly.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
                $memberName = $node.Member
                if ($memberName -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    if ($memberName.Value -eq 'GetMethod' -or $memberName.Value -eq 'GetField' -or
                        $memberName.Value -eq 'GetProperty' -or $memberName.Value -eq 'GetConstructor') {
                        return $true
                    }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM020'
            Name        = 'Suspicious String Format Pattern'
            Severity    = 'Low'
            Description = 'Complex format strings with -f operator can sometimes be used for obfuscation. Review for safety.'
            Remediation = 'Review format strings to ensure they are not constructing dynamic code for execution.'
            WDACRuleHint = 'N/A - review manually.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.BinaryExpressionAst]) { return $false }
                if ($node.Operator -ne [System.Management.Automation.Language.TokenKind]::Format) { return $false }
                $leftText = $node.Left.Extent.Text
                return ($leftText -match '\{0\}.*\{1\}.*\{2\}' -or $leftText.Length -gt 100)
            }
        },
        @{
            ID          = 'CLM021'
            Name        = '.NET Event Registration'
            Severity    = 'Medium'
            Description = 'Register-ObjectEvent with .NET objects may fail in CLM depending on the source object type.'
            Remediation = 'Verify the source object type is in the CLM approved type list. Use WMI events as an alternative.'
            WDACRuleHint = 'Ensure the .NET types used with Register-ObjectEvent are approved.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -eq 0) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                return ($cmd.Value -eq 'Register-ObjectEvent')
            }
        },
        @{
            ID          = 'CLM022'
            Name        = 'Add-Type with Explicit Language'
            Severity    = 'Critical'
            Description = 'Add-Type with -Language CSharp/JScript/VisualBasic compiles arbitrary code, which is blocked in CLM.'
            Remediation = 'Remove inline code compilation. Pre-compile and sign assemblies, or use cmdlet alternatives.'
            WDACRuleHint = 'Compile the code into a signed .dll and load it from a WDAC-allowed path.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 3) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -ne 'Add-Type') { return $false }
                foreach ($elem in $node.CommandElements) {
                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elem.ParameterName -match '^L') { return $true }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM023'
            Name        = 'Dynamic Module Loading'
            Severity    = 'Medium'
            Description = 'Import-Module with variable/computed paths makes it harder to validate modules against WDAC policy.'
            Remediation = 'Use static, fully-qualified module paths. Ensure all imported modules are signed.'
            WDACRuleHint = 'Sign all modules and place them in WDAC-allowed paths.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }
                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -ne 'Import-Module') { return $false }
                for ($i = 1; $i -lt $node.CommandElements.Count; $i++) {
                    $elem = $node.CommandElements[$i]
                    if ($elem -is [System.Management.Automation.Language.VariableExpressionAst]) { return $true }
                    if ($elem -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { return $true }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM024'
            Name        = 'Restricted Property Access'
            Severity    = 'Medium'
            Description = 'Accessing .PSObject or .PSBase properties may be restricted in CLM for non-approved types.'
            Remediation = 'Use standard property access. Avoid .PSObject and .PSBase on restricted types.'
            WDACRuleHint = 'N/A - use approved access patterns.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.MemberExpressionAst]) { return $false }
                $memberName = $node.Member
                if ($memberName -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    return ($memberName.Value -match '^(PSObject|PSBase|PSAdapted|PSExtended|PSTypeNames)$')
                }
                return $false
            }
        },
        @{
            ID          = 'CLM025'
            Name        = 'Win32 API P/Invoke Pattern'
            Severity    = 'Critical'
            Description = 'DllImport attributes in Add-Type strings indicate Win32 API P/Invoke calls, which are blocked in CLM.'
            Remediation = 'Remove P/Invoke definitions. Use PowerShell cmdlets or move native calls to a signed compiled assembly.'
            WDACRuleHint = 'Compile native interop code into a signed .dll.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $node -isnot [System.Management.Automation.Language.ExpandableStringExpressionAst]) { return $false }
                $text = $node.Value
                if (-not $text) { return $false }
                return ($text -match 'DllImport|DllImportAttribute|EntryPoint\s*=' -and $text.Length -gt 20)
            }
        },

        # --- Obfuscation Detection Rules (CLM026-CLM030) ---

        @{
            ID          = 'CLM026'
            Name        = 'String Concatenation Command Construction'
            Severity    = 'High'
            Description = 'Building command names via string concatenation (e.g., ''Add'' + ''-Type'') is a common obfuscation technique to bypass static analysis. CLM may still block the resulting command at runtime.'
            Remediation = 'Use the command name directly. String-built commands are a red flag for security tools and complicate WDAC evaluation.'
            WDACRuleHint = 'WDAC evaluates the script file, not dynamically constructed strings. Obfuscated scripts are more likely to be blocked by policy.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.BinaryExpressionAst]) { return $false }
                if ($node.Operator -ne [System.Management.Automation.Language.TokenKind]::Plus) { return $false }
                # Look for string concatenation that builds known-sensitive command fragments
                $leftText = ''
                $rightText = ''
                if ($node.Left -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $leftText = $node.Left.Value }
                if ($node.Right -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $rightText = $node.Right.Value }
                $combined = $leftText + $rightText
                if ($combined -match '(?i)(Add-Type|Invoke-Expression|New-Object|Invoke-Command|Start-Process|IEX|Import-Module)') {
                    return $true
                }
                # Detect partial fragments that build suspicious commands
                if ($leftText -match '(?i)^(Add|Invoke|New|Start|Import|Get-Cred|Sys|Reflect)' -and $rightText -match '(?i)(-Type|-Expression|-Object|-Command|-Process|-Module|ion\.|tion\.)') {
                    return $true
                }
                return $false
            }
        },
        @{
            ID          = 'CLM027'
            Name        = 'Char Array / Byte Conversion Obfuscation'
            Severity    = 'High'
            Description = 'Using [char] arrays, [byte] conversions, or ASCII code points to build strings is a common obfuscation technique to hide command names and payloads from static analysis.'
            Remediation = 'Use plain-text commands. Character-level construction is flagged by security tools and AMSI.'
            WDACRuleHint = 'Scripts using heavy character obfuscation will be scrutinized by AMSI even if WDAC allows the file.'
            Predicate   = {
                param($node)
                # Detect [char]<number> patterns - more than 3 in sequence suggests obfuscation
                if ($node -isnot [System.Management.Automation.Language.ArrayExpressionAst] -and
                    $node -isnot [System.Management.Automation.Language.ParenExpressionAst]) { return $false }
                $text = $node.Extent.Text
                if (-not $text) { return $false }
                $charMatches = [regex]::Matches($text, '\[char\]\s*\d+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                return ($charMatches.Count -ge 3)
            }
        },
        @{
            ID          = 'CLM028'
            Name        = 'Base64 Encoded String'
            Severity    = 'Medium'
            Description = 'Large Base64 strings may contain encoded commands or payloads. While CLM blocks [Convert]::FromBase64String(), obfuscated scripts may attempt to decode via other means.'
            Remediation = 'Decode Base64 content and use plain-text equivalents. Base64 in scripts triggers AMSI scrutiny.'
            WDACRuleHint = 'AMSI scans decoded content. Use plain text to avoid unnecessary security friction.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                $text = $node.Value
                if (-not $text -or $text.Length -lt 40) { return $false }
                # Match Base64 pattern: long string of A-Za-z0-9+/= with no spaces
                if ($text -match '^[A-Za-z0-9+/]{40,}={0,2}$') { return $true }
                # Also catch FromBase64String usage
                if ($text -match 'FromBase64String|ToBase64String') { return $true }
                return $false
            }
        },
        @{
            ID          = 'CLM029'
            Name        = 'Variable-Based Command Invocation'
            Severity    = 'High'
            Description = 'Storing a command name in a variable and invoking it via & or . operator hides the actual command from static analysis. CLM still blocks the underlying operation at runtime.'
            Remediation = 'Call commands directly by name. Variable-based invocation bypasses static analysis and is flagged as suspicious.'
            WDACRuleHint = 'WDAC evaluates the script file statically. Variable-based invocation may lead to unexpected CLM behavior.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -eq 0) { return $false }
                # Detect: & $variable or . $variable (invoking a variable as a command)
                $firstElem = $node.CommandElements[0]
                if ($firstElem -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    # Check if the invocation operator is & or .
                    if ($node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -or
                        $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) {
                        return $true
                    }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM030'
            Name        = 'String Reversal / Replace Obfuscation'
            Severity    = 'Medium'
            Description = 'Using string reversal, -replace chains, or -join/-split to construct commands at runtime is an obfuscation technique to evade static detection.'
            Remediation = 'Use plain-text commands. Heavy string manipulation for command construction indicates obfuscation.'
            WDACRuleHint = 'Deobfuscate the script before deploying under WDAC to ensure proper policy evaluation.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
                $memberName = $node.Member
                if ($memberName -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                # Detect suspicious string manipulation chains
                if ($memberName.Value -match '^(Reverse|Replace)$') {
                    # Check if it's on a char array or string in a suspicious context
                    $parentText = $node.Extent.Text
                    if ($parentText -match '\[char\[\]\]|\[array\]::Reverse|\.Replace\(.*\.Replace\(') {
                        return $true
                    }
                }
                return $false
            }
        },
        @{
            ID          = 'CLM031'
            Name        = 'Restricted .NET Object Creation'
            Severity    = 'High'
            Description = 'New-Object for restricted .NET types can fail in CLM because unapproved constructors are blocked.'
            Remediation = 'Use cmdlets or approved types instead of directly constructing restricted .NET objects. Move required .NET code to a signed module.'
            WDACRuleHint = 'Sign the module or script that requires restricted .NET object construction.'
            Predicate   = {
                param($node)
                if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
                if (-not $node.CommandElements -or $node.CommandElements.Count -lt 2) { return $false }

                $cmd = $node.CommandElements[0]
                if ($cmd -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { return $false }
                if ($cmd.Value -ne 'New-Object') { return $false }

                foreach ($elem in $node.CommandElements) {
                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $elem.ParameterName -match '^(?:ComObject|COM)$') {
                        return $false
                    }
                }

                $restrictedObjectPattern = '^(?:System\.)?(?:IO\.(?:FileInfo|DirectoryInfo|FileStream|StreamReader|StreamWriter)|Net\.(?:WebClient|Http\.HttpClient)|Net\.Sockets\.(?:TcpClient|UdpClient)|Diagnostics\.ProcessStartInfo|Management\.(?:ManagementObject|ManagementObjectSearcher)|DirectoryServices\.(?:DirectoryEntry|DirectorySearcher)|Data\.SqlClient\.SqlConnection|Windows\.Forms\..+|Reflection\..+|Runtime\.InteropServices\..+)$'
                $expectTypeName = $false

                for ($i = 1; $i -lt $node.CommandElements.Count; $i++) {
                    $elem = $node.CommandElements[$i]

                    if ($elem -is [System.Management.Automation.Language.CommandParameterAst]) {
                        $expectTypeName = ($elem.ParameterName -match '^(?:TypeName|Type)$')
                        continue
                    }

                    if ($elem -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        if ($expectTypeName -or $i -eq 1) {
                            return ($elem.Value -match $restrictedObjectPattern)
                        }
                    }

                    $expectTypeName = $false
                }

                return $false
            }
        }
    )
}

function Invoke-ASTAnalysis {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$AST,

        [AllowNull()]
        [System.Management.Automation.Language.Token[]]$Tokens,

        [AllowNull()]
        [System.Management.Automation.Language.ParseError[]]$Errors,

        [string]$ScriptPath = 'Unknown',

        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$MinimumSeverity = 'Info'
    )

    $severityRank = @{ 'Info' = 1; 'Low' = 2; 'Medium' = 3; 'High' = 4; 'Critical' = 5 }
    $minRank = $severityRank[$MinimumSeverity]

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Parse errors are themselves findings
    if ($Errors) {
        foreach ($err in $Errors) {
            $findings.Add([PSCustomObject]@{
                RuleID       = 'PARSE'
                RuleName     = 'Parse Error'
                Severity     = 'Critical'
                Line         = $err.Extent.StartLineNumber
                Column       = $err.Extent.StartColumnNumber
                EndLine      = $err.Extent.EndLineNumber
                CodeSnippet  = if ($err.Extent.Text) { $err.Extent.Text.Substring(0, [Math]::Min(200, $err.Extent.Text.Length)) } else { '' }
                Description  = "Parse error: $($err.Message)"
                Remediation  = 'Fix the syntax error before CLM analysis can complete.'
                WDACRuleHint = ''
                ScriptPath   = $ScriptPath
            })
        }
    }

    $rules = Get-ASTRuleDefinitions

    foreach ($rule in $rules) {
        if ($severityRank[$rule.Severity] -lt $minRank) { continue }

        try {
            $predicate = $rule.Predicate
            $matches = $AST.FindAll($predicate, $true)

            foreach ($match in $matches) {
                $snippetText = ''
                if ($match.Extent -and $match.Extent.Text) {
                    $snippetText = $match.Extent.Text
                    if ($snippetText.Length -gt 200) {
                        $snippetText = $snippetText.Substring(0, 200) + '...'
                    }
                }

                $findings.Add([PSCustomObject]@{
                    RuleID       = $rule.ID
                    RuleName     = $rule.Name
                    Severity     = $rule.Severity
                    Line         = if ($match.Extent) { $match.Extent.StartLineNumber } else { 0 }
                    Column       = if ($match.Extent) { $match.Extent.StartColumnNumber } else { 0 }
                    EndLine      = if ($match.Extent) { $match.Extent.EndLineNumber } else { 0 }
                    CodeSnippet  = $snippetText
                    Description  = $rule.Description
                    Remediation  = $rule.Remediation
                    WDACRuleHint = $rule.WDACRuleHint
                    ScriptPath   = $ScriptPath
                })
            }
        }
        catch {
            Write-Verbose "Rule $($rule.ID) ($($rule.Name)) failed: $_"
        }
    }

    return $findings.ToArray()
}

function Get-ASTNodeContext {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$Node,

        [int]$ContextLines = 2
    )

    if (-not $Node.Extent -or -not $Node.Extent.StartScriptPosition) {
        return $Node.Extent.Text
    }

    try {
        $scriptText = $Node.Extent.StartScriptPosition.GetFullScript()
        if (-not $scriptText) { return $Node.Extent.Text }

        $lines = $scriptText -split "`n"
        $startLine = [Math]::Max(0, $Node.Extent.StartLineNumber - 1 - $ContextLines)
        $endLine = [Math]::Min($lines.Count - 1, $Node.Extent.EndLineNumber - 1 + $ContextLines)

        $contextLines = @()
        for ($i = $startLine; $i -le $endLine; $i++) {
            $prefix = if ($i -ge ($Node.Extent.StartLineNumber - 1) -and $i -le ($Node.Extent.EndLineNumber - 1)) { '>>>' } else { '   ' }
            $contextLines += "$prefix $($i + 1): $($lines[$i])"
        }

        return $contextLines -join "`n"
    }
    catch {
        return $Node.Extent.Text
    }
}
