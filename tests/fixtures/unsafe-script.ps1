# Unsafe script - contains ALL CLM-restricted constructs for testing
# Each section triggers one or more CLM rules

# CLM001: Add-Type usage
Add-Type -TypeDefinition @"
using System;
public class MyHelper {
    public static int Add(int a, int b) { return a + b; }
}
"@

# CLM002: COM Object creation
$shell = New-Object -ComObject WScript.Shell
$fso = New-Object -ComObject Scripting.FileSystemObject

# CLM003: .NET static method on restricted types
$fileContent = [System.IO.File]::ReadAllText("C:\test.txt")
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("test"))

# CLM004: Custom class definition
class ServerInfo {
    [string]$Name
    [string]$Status
    ServerInfo([string]$n) { $this.Name = $n; $this.Status = 'Unknown' }
}

# CLM005: Using assembly
using assembly System.DirectoryServices

# CLM006: Invoke-Expression
$cmd = "Get-Process"
Invoke-Expression $cmd
iex "Write-Host 'test'"

# CLM007: PowerShell v2 engine
powershell.exe -version 2 -command "Write-Host 'v2 mode'"

# CLM008: Reflection usage
$assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Web")

# CLM009: Marshal class
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(100)

# CLM010: Delegate creation
$method = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [type])

# CLM011: Script block .Invoke()
$sb = { Write-Output "test" }
$sb.Invoke()

# CLM012: DSC configuration
Configuration TestConfig {
    Node "localhost" {
        File TestFile {
            DestinationPath = "C:\test.txt"
            Contents = "test"
        }
    }
}

# CLM013: Workflow definition
workflow Test-Workflow {
    Get-Process
    Get-Service
}

# CLM014: Sensitive cmdlets
Invoke-Command -ComputerName Server01 -ScriptBlock { Get-Process }
Register-ScheduledTask -TaskName "Test" -Action (New-ScheduledTaskAction -Execute "cmd.exe")

# CLM015: Encoded command
powershell.exe -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==

# CLM016: XAML loading
[System.Windows.Markup.XamlReader]::Parse($xamlString)

# CLM017: Background job with script block
Start-Job -ScriptBlock { Get-Process | Where-Object { $_.CPU -gt 100 } }

# CLM018: Type accelerator manipulation
$accel = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")

# CLM019: Dynamic method invocation
$type = "System.IO.File"
$method = [type]::GetType($type).GetMethod("ReadAllText", [type[]]@([string]))

# CLM020: Suspicious format string
$obfuscated = '{0}{1}{2}{3}{4}' -f 'I','n','v','o','k'

# CLM021: .NET event registration
Register-ObjectEvent -InputObject $watcher -EventName Created -Action { Write-Host "File created" }

# CLM022: Add-Type with explicit language
Add-Type -Language CSharp -TypeDefinition "public class Test { public static int Run() { return 1; } }"

# CLM023: Dynamic module loading
$modulePath = "$env:USERPROFILE\Documents\MyModule"
Import-Module $modulePath

# CLM024: Restricted property access
$obj = Get-Process | Select-Object -First 1
$obj.PSObject.Properties
$obj.PSBase.GetType()

# CLM025: Win32 API P/Invoke via Add-Type
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll", EntryPoint = "MessageBoxW")]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
}
"@

# CLM026: String concatenation command construction
$cmd = 'Add' + '-Type'
$cmd2 = 'Invoke' + '-Expression'

# CLM027: Char array obfuscation
$obfCmd = [char]65 + [char]100 + [char]100 + [char]45 + [char]84

# CLM028: Base64 encoded string
$payload = "SW52b2tlLUV4cHJlc3Npb24gLUNvbW1hbmQgJ1dyaXRlLUhvc3QgIkhlbGxvIFdvcmxkIic="

# CLM029: Variable-based command invocation
$myCmd = 'Get-Process'
& $myCmd

# CLM030: String replace chain obfuscation
$s = 'Xdd-Tyqe'.Replace('X','A').Replace('q','p')

# CLM031: Restricted .NET object creation
$client = New-Object System.Net.WebClient
