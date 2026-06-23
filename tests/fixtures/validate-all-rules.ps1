<#
.SYNOPSIS
    CLM-Forge Validation Script - Triggers ALL 31 CLM rules.
    Run this through CLM-Forge to verify every detection fires correctly.

.DESCRIPTION
    This script intentionally contains every CLM-restricted construct and
    obfuscation pattern that CLM-Forge detects. Use it to validate the tool
    works end-to-end in both the container (web UI) and on Windows (module).

    DO NOT run this on a production system. It is a test artifact only.

.NOTES
    Expected results: 31+ findings covering CLM001 through CLM031.
#>

# ============================================================
# CLM001: Add-Type (compiling C# inline)
# ============================================================
Add-Type -TypeDefinition @"
using System;
public class ValidationHelper {
    public static string GetInfo() { return "CLM001 test"; }
}
"@

# ============================================================
# CLM002: COM Object Creation
# ============================================================
$shell = New-Object -ComObject WScript.Shell
$fso = New-Object -ComObject Scripting.FileSystemObject

# ============================================================
# CLM003: .NET Static Method on Restricted Type
# ============================================================
$content = [System.IO.File]::ReadAllText("C:\Windows\System32\drivers\etc\hosts")
$b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("test"))

# ============================================================
# CLM004: Custom Class Definition
# ============================================================
class ServerInventory {
    [string]$Name
    [string]$Role
    [bool]$Compliant
    ServerInventory([string]$n, [string]$r) {
        $this.Name = $n
        $this.Role = $r
        $this.Compliant = $false
    }
}

# ============================================================
# CLM005: Using Assembly
# ============================================================
using assembly System.DirectoryServices
using assembly System.Web

# ============================================================
# CLM006: Invoke-Expression
# ============================================================
$dynamicCmd = "Get-Process -Name explorer"
Invoke-Expression $dynamicCmd
$result = iex "Get-Date"

# ============================================================
# CLM007: PowerShell v2 Engine Downgrade
# ============================================================
powershell.exe -version 2 -command "Write-Host 'Running in PS v2'"

# ============================================================
# CLM008: Reflection Usage
# ============================================================
$asm = [System.Reflection.Assembly]::LoadWithPartialName("System.Web")
$methodInfo = [System.Reflection.MethodInfo]

# ============================================================
# CLM009: Marshal Class (Interop)
# ============================================================
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)

# ============================================================
# CLM010: Delegate Creation
# ============================================================
$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [type])

# ============================================================
# CLM011: Script Block .Invoke()
# ============================================================
$scriptblock = { param($x) Write-Output "Processing $x" }
$scriptblock.Invoke("test-data")

# ============================================================
# CLM012: DSC Configuration
# ============================================================
Configuration EnsureFilePresent {
    Node "localhost" {
        File TestFile {
            DestinationPath = "C:\Temp\validation.txt"
            Contents        = "CLM012 validation"
            Ensure          = "Present"
        }
    }
}

# ============================================================
# CLM013: Workflow Definition
# ============================================================
workflow Invoke-ParallelCheck {
    parallel {
        Get-Process
        Get-Service
    }
}

# ============================================================
# CLM014: Sensitive Cmdlets with ScriptBlock
# ============================================================
Invoke-Command -ComputerName DC01 -ScriptBlock { Get-ADUser -Filter * }
Register-ScheduledTask -TaskName "CLM014Test" -Action (New-ScheduledTaskAction -Execute "cmd.exe")
New-Service -Name "CLM014Svc" -BinaryPathName "C:\test.exe"

# ============================================================
# CLM015: Encoded Command
# ============================================================
powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAQwBMAE0AMAAxADUAIgA=
pwsh.exe -enc ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==

# ============================================================
# CLM016: XAML Loading
# ============================================================
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">
    <TextBlock Text="CLM016 Test"/>
</Window>
"@
[System.Windows.Markup.XamlReader]::Parse($xaml)

# ============================================================
# CLM017: Background Job with Script Block
# ============================================================
Start-Job -ScriptBlock { Get-Process | Where-Object { $_.CPU -gt 50 } }
Start-ThreadJob -ScriptBlock { Get-ChildItem C:\ -Recurse }

# ============================================================
# CLM018: Type Accelerator Manipulation
# ============================================================
$typeAccel = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")
$typeAccel::Add("MyCustomType", [System.Collections.Generic.List[string]])

# ============================================================
# CLM019: Dynamic Method Invocation (Reflection chain)
# ============================================================
$targetType = [type]::GetType("System.IO.File")
$readMethod = $targetType.GetMethod("ReadAllText", [type[]]@([string]))
$fieldInfo = $targetType.GetField("InternalBufferSize")
$ctor = $targetType.GetConstructor([type[]]@([string]))

# ============================================================
# CLM020: Suspicious String Format Pattern
# ============================================================
$obfuscated = '{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}' -f 'I','n','v','o','k','e','-','E','x','p','r','e','s','s'

# ============================================================
# CLM021: .NET Event Registration
# ============================================================
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Temp"
Register-ObjectEvent -InputObject $watcher -EventName Created -Action { Write-Host "File created: $($Event.SourceEventArgs.Name)" }

# ============================================================
# CLM022: Add-Type with Explicit Language Parameter
# ============================================================
Add-Type -Language CSharp -TypeDefinition @"
public class CSharpHelper {
    public static int Multiply(int a, int b) { return a * b; }
}
"@

# ============================================================
# CLM023: Dynamic Module Loading (variable path)
# ============================================================
$modulePath = Join-Path $env:USERPROFILE "Documents\CustomModule"
Import-Module $modulePath

# ============================================================
# CLM024: Restricted Property Access
# ============================================================
$proc = Get-Process -Id $PID
$proc.PSObject.Properties | Where-Object { $_.Name -eq 'Id' }
$proc.PSBase.GetType()
$proc.PSTypeNames

# ============================================================
# CLM025: Win32 API P/Invoke via Add-Type
# ============================================================
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class NativeAPI {
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    public static extern uint GetCurrentProcessId();

    [DllImport("user32.dll", EntryPoint = "MessageBoxW")]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
}
"@

# ============================================================
# CLM026: String Concatenation Command Construction
# ============================================================
$builtCmd1 = 'Add' + '-Type'
$builtCmd2 = 'Invoke' + '-Expression'
$builtCmd3 = 'New' + '-Object'

# ============================================================
# CLM027: Char Array / Byte Conversion Obfuscation
# ============================================================
$charBuilt = [char]73 + [char]110 + [char]118 + [char]111 + [char]107 + [char]101
# Spells "Invoke" via ASCII codes

# ============================================================
# CLM028: Base64 Encoded String
# ============================================================
$encodedPayload = "SW52b2tlLUV4cHJlc3Npb24gLUNvbW1hbmQgJ1dyaXRlLUhvc3QgIkhlbGxvIFdvcmxkIic="
$anotherEncoded = "R2V0LVByb2Nlc3MgfCBXaGVyZS1PYmplY3QgeyAkXy5DUFUgLWd0IDEwMCB9"

# ============================================================
# CLM029: Variable-Based Command Invocation
# ============================================================
$cmdName = 'Get-Process'
& $cmdName
$anotherCmd = 'Get-Service'
. $anotherCmd

# ============================================================
# CLM030: String Replace Chain Obfuscation
# ============================================================
$deobfuscated = 'Xdd-Tyqe -TyqeDefinition'.Replace('X','A').Replace('q','p')
$moreReplace = 'ZZZ' -replace 'Z','A' -replace 'AA','Add-' -replace 'A','Type'

# ============================================================
# CLM031: Restricted .NET Object Creation
# ============================================================
$webClient = New-Object System.Net.WebClient
$stream = New-Object -TypeName System.IO.StreamReader -ArgumentList "C:\Temp\input.txt"
