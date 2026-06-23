"""
Python-native PowerShell CLM compatibility analyzer.
Uses regex/pattern matching to detect CLM-restricted constructs without requiring PowerShell.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    description: str
    remediation: str
    wdac_hint: str


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    line: int
    column: int
    code_snippet: str
    description: str
    remediation: str
    wdac_rule_hint: str


@dataclass
class AnalysisResult:
    filename: str
    total_lines: int
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    analyzed_at: str = ""
    analysis_method: str = "python_regex"


RULES = [
    Rule(
        id="CLM001", name="Add-Type Usage", severity="Critical",
        pattern=re.compile(r'\bAdd-Type\b', re.IGNORECASE),
        description="Add-Type is blocked in Constrained Language Mode. Scripts using Add-Type to compile C#/VB code or load assemblies will fail.",
        remediation="Remove Add-Type usage. Use built-in cmdlets or move custom .NET code to a signed module.",
        wdac_hint="Sign the script and add a WDAC signer rule.",
    ),
    Rule(
        id="CLM002", name="COM Object Creation", severity="High",
        pattern=re.compile(r'New-Object\s+(?:-ComObject\s+)\S+', re.IGNORECASE),
        description="New-Object -ComObject is restricted in CLM. Only WDAC-approved COM classes can be instantiated.",
        remediation="Replace with approved cmdlets (e.g., Invoke-WebRequest instead of MSXML2.XMLHTTP).",
        wdac_hint="Add the COM class GUID to your WDAC policy.",
    ),
    Rule(
        id="CLM003", name=".NET Static Method Call", severity="High",
        pattern=re.compile(
            r'\[(?:System\.)?(?:IO\.File|IO\.StreamReader|IO\.StreamWriter|Net\.WebClient|'
            r'Net\.Http\.HttpClient|Net\.Sockets\.(?:Tcp|Udp)Client|Reflection\.Assembly|'
            r'Runtime\.InteropServices\.Marshal|Diagnostics\.Process|'
            r'Security\.Cryptography\.\w+|DirectoryServices\.\w+|'
            r'Data\.SqlClient\.\w+|Management\.ManagementObject\w*|'
            r'Convert|Text\.Encoding)\]::',
            re.IGNORECASE
        ),
        description="Direct access to restricted .NET type static methods is blocked in CLM.",
        remediation="Use equivalent cmdlets (e.g., Get-Content instead of [System.IO.File]::ReadAllText()).",
        wdac_hint="Move .NET code into a signed module.",
    ),
    Rule(
        id="CLM004", name="Custom Class Definition", severity="Critical",
        pattern=re.compile(r'^\s*class\s+\w+\s*(?:\{|:)', re.IGNORECASE | re.MULTILINE),
        description="PowerShell class definitions are blocked in CLM.",
        remediation="Replace with [PSCustomObject] or hashtables. For complex types, use a signed module.",
        wdac_hint="Sign the script containing class definitions.",
    ),
    Rule(
        id="CLM005", name="Using Assembly Statement", severity="Critical",
        pattern=re.compile(r'^\s*using\s+assembly\b', re.IGNORECASE | re.MULTILINE),
        description="The 'using assembly' statement is blocked in CLM.",
        remediation="Remove using assembly statements. Use approved cmdlets or signed modules.",
        wdac_hint="Package required assemblies in a signed module.",
    ),
    Rule(
        id="CLM006", name="Invoke-Expression Usage", severity="High",
        pattern=re.compile(r'\b(?:Invoke-Expression|iex)\b', re.IGNORECASE),
        description="Invoke-Expression executes dynamic code which is restricted in CLM.",
        remediation="Refactor to avoid dynamic code execution. Use parameterized commands or the call operator (&).",
        wdac_hint="Eliminate Invoke-Expression and use static constructs.",
    ),
    Rule(
        id="CLM007", name="PowerShell v2 Engine", severity="Critical",
        pattern=re.compile(r'powershell(?:\.exe)?\s+.*-(?:v(?:ersion)?)\s+2', re.IGNORECASE),
        description="PowerShell v2 bypasses CLM, AMSI, and Script Block Logging.",
        remediation="Remove -Version 2 arguments. Disable PS v2 engine system-wide.",
        wdac_hint="Disable PowerShell v2 via Windows Features before deploying WDAC.",
    ),
    Rule(
        id="CLM008", name="Reflection Usage", severity="High",
        pattern=re.compile(r'\[System\.Reflection\.\w+\]', re.IGNORECASE),
        description="System.Reflection types are restricted in CLM.",
        remediation="Remove reflection usage. Use approved cmdlets.",
        wdac_hint="Move reflection code to a signed module.",
    ),
    Rule(
        id="CLM009", name="Marshal Class Usage", severity="Critical",
        pattern=re.compile(r'\[(?:System\.)?Runtime\.InteropServices\.Marshal\]', re.IGNORECASE),
        description="System.Runtime.InteropServices.Marshal is a primary CLM restriction target.",
        remediation="Remove Marshal usage. Move interop code to a compiled, signed .NET assembly.",
        wdac_hint="Compile interop code into a signed .dll.",
    ),
    Rule(
        id="CLM010", name="Delegate Creation", severity="Critical",
        pattern=re.compile(r'\b(?:GetDelegateForFunctionPointer|DynamicInvoke|CreateDelegate)\b', re.IGNORECASE),
        description="Delegate creation and invocation is blocked in CLM.",
        remediation="Remove delegate/P/Invoke patterns.",
        wdac_hint="Move native interop to a compiled, signed .NET assembly.",
    ),
    Rule(
        id="CLM011", name="Script Block Invocation", severity="Medium",
        pattern=re.compile(r'\.\s*Invoke\s*\(', re.IGNORECASE),
        description="Script blocks invoked via .Invoke() may behave differently in CLM.",
        remediation="Use the call operator (&) instead of .Invoke().",
        wdac_hint="Ensure the calling script is signed.",
    ),
    Rule(
        id="CLM012", name="DSC Configuration", severity="Medium",
        pattern=re.compile(r'^\s*(?:Configuration|DscResource)\s+\w+', re.IGNORECASE | re.MULTILINE),
        description="DSC resources and configurations may not work in CLM.",
        remediation="Move DSC configurations to signed .ps1 files.",
        wdac_hint="Sign DSC configuration scripts and resource modules.",
    ),
    Rule(
        id="CLM013", name="Workflow Definition", severity="Low",
        pattern=re.compile(r'^\s*workflow\s+\w+', re.IGNORECASE | re.MULTILINE),
        description="PowerShell workflows are deprecated in PS 7+ and restricted in CLM.",
        remediation="Replace workflows with standard functions or ForEach-Object -Parallel.",
        wdac_hint="N/A - workflows should be replaced.",
    ),
    Rule(
        id="CLM014", name="Sensitive Cmdlet Usage", severity="Medium",
        pattern=re.compile(r'\b(?:Invoke-Command\s+.*-ScriptBlock|Register-ScheduledTask|New-Service)\b', re.IGNORECASE),
        description="Certain cmdlets may behave differently under CLM.",
        remediation="Verify these cmdlets work as expected in CLM.",
        wdac_hint="Ensure target systems have matching WDAC policies.",
    ),
    Rule(
        id="CLM015", name="Encoded Command", severity="High",
        pattern=re.compile(r'(?:powershell|pwsh)(?:\.exe)?\s+.*-(?:EncodedCommand|enc|e|ec)\b', re.IGNORECASE),
        description="EncodedCommand can bypass logging and complicates CLM analysis.",
        remediation="Decode and use plain script text.",
        wdac_hint="Use plain-text scripts that WDAC can evaluate.",
    ),
    Rule(
        id="CLM016", name="XAML Loading", severity="Critical",
        pattern=re.compile(r'\[(?:System\.Windows\.Markup\.)?XamlReader\]', re.IGNORECASE),
        description="XamlReader is blocked in CLM.",
        remediation="Remove XAML loading. Use alternative UI approaches or a signed module.",
        wdac_hint="Package XAML code in a signed module or compiled assembly.",
    ),
    Rule(
        id="CLM017", name="Background Job with Script Block", severity="Medium",
        pattern=re.compile(r'\b(?:Start-Job|Start-ThreadJob)\s+.*-ScriptBlock\b', re.IGNORECASE),
        description="Background jobs inherit language mode. Script blocks will run in CLM.",
        remediation="Use -FilePath with signed script files instead of inline script blocks.",
        wdac_hint="Ensure job scripts are signed.",
    ),
    Rule(
        id="CLM018", name="Type Accelerator Manipulation", severity="Critical",
        pattern=re.compile(r'TypeAccelerators', re.IGNORECASE),
        description="Accessing or modifying PowerShell type accelerators is blocked in CLM.",
        remediation="Remove type accelerator manipulation.",
        wdac_hint="N/A - should not be used in production.",
    ),
    Rule(
        id="CLM019", name="Dynamic Method Invocation", severity="High",
        pattern=re.compile(r'\.(?:GetMethod|GetField|GetProperty|GetConstructor)\s*\(', re.IGNORECASE),
        description="Reflection-based method invocation is restricted in CLM.",
        remediation="Remove dynamic method invocation. Use direct cmdlet calls.",
        wdac_hint="Move reflection code to a signed assembly.",
    ),
    Rule(
        id="CLM020", name="Suspicious String Format", severity="Low",
        pattern=re.compile(r"'[^']*\{0\}[^']*\{1\}[^']*\{2\}[^']*'\s*-f\s", re.IGNORECASE),
        description="Complex format strings can be used for obfuscation.",
        remediation="Review format strings for safety.",
        wdac_hint="N/A - review manually.",
    ),
    Rule(
        id="CLM021", name=".NET Event Registration", severity="Medium",
        pattern=re.compile(r'\bRegister-ObjectEvent\b', re.IGNORECASE),
        description="Register-ObjectEvent with .NET objects may fail in CLM.",
        remediation="Verify the source object type is CLM-approved. Use WMI events as alternative.",
        wdac_hint="Ensure .NET types used are approved.",
    ),
    Rule(
        id="CLM022", name="Add-Type with Language", severity="Critical",
        pattern=re.compile(r'Add-Type\s+.*-Language\s+(?:CSharp|JScript|VisualBasic)', re.IGNORECASE),
        description="Add-Type with -Language compiles arbitrary code, blocked in CLM.",
        remediation="Pre-compile and sign assemblies.",
        wdac_hint="Compile code into a signed .dll.",
    ),
    Rule(
        id="CLM023", name="Dynamic Module Loading", severity="Medium",
        pattern=re.compile(r'Import-Module\s+\$', re.IGNORECASE),
        description="Import-Module with variable paths makes WDAC validation harder.",
        remediation="Use static, fully-qualified module paths. Sign all modules.",
        wdac_hint="Sign modules and place in WDAC-allowed paths.",
    ),
    Rule(
        id="CLM024", name="Restricted Property Access", severity="Medium",
        pattern=re.compile(r'\.(?:PSObject|PSBase|PSAdapted|PSExtended|PSTypeNames)\b'),
        description="Accessing .PSObject or .PSBase may be restricted in CLM.",
        remediation="Use standard property access patterns.",
        wdac_hint="N/A - use approved access patterns.",
    ),
    Rule(
        id="CLM025", name="Win32 API P/Invoke", severity="Critical",
        pattern=re.compile(r'DllImport(?:Attribute)?\s*\(', re.IGNORECASE),
        description="DllImport attributes indicate Win32 API P/Invoke, blocked in CLM.",
        remediation="Remove P/Invoke. Use PowerShell cmdlets or a signed compiled assembly.",
        wdac_hint="Compile native interop into a signed .dll.",
    ),
    # --- Obfuscation Detection Rules ---
    Rule(
        id="CLM026", name="String Concatenation Command Construction", severity="High",
        pattern=re.compile(
            r"""(?:['"](?:Add|Invoke|New|Start|Import|Get-Cred|Sys|Reflect)\w*['"])\s*\+\s*(?:['"][-.](?:Type|Expression|Object|Command|Process|Module|ion|tion)\w*['"])""",
            re.IGNORECASE
        ),
        description="Building command names via string concatenation is an obfuscation technique to bypass static analysis.",
        remediation="Use the command name directly. String-built commands are a red flag for security tools.",
        wdac_hint="WDAC evaluates the script file, not dynamically constructed strings.",
    ),
    Rule(
        id="CLM027", name="Char Array / Byte Conversion Obfuscation", severity="High",
        pattern=re.compile(r'(?:\[char\]\s*\d+\s*[,+]\s*){2,}', re.IGNORECASE),
        description="Using [char] arrays or ASCII code points to build strings hides commands from static analysis.",
        remediation="Use plain-text commands. Character-level construction is flagged by AMSI.",
        wdac_hint="Scripts with heavy character obfuscation trigger additional AMSI scrutiny.",
    ),
    Rule(
        id="CLM028", name="Base64 Encoded String", severity="Medium",
        pattern=re.compile(r'[A-Za-z0-9+/]{60,}={0,2}'),
        description="Large Base64 strings may contain encoded commands or payloads.",
        remediation="Decode Base64 content and use plain-text equivalents.",
        wdac_hint="AMSI scans decoded content. Use plain text to avoid security friction.",
    ),
    Rule(
        id="CLM029", name="Variable-Based Command Invocation", severity="High",
        pattern=re.compile(r'[&.]\s*\$\w+', re.IGNORECASE),
        description="Invoking commands via & $variable or . $variable hides the actual command from static analysis.",
        remediation="Call commands directly by name instead of through variables.",
        wdac_hint="Variable-based invocation complicates WDAC static evaluation.",
    ),
    Rule(
        id="CLM030", name="String Replace Chain Obfuscation", severity="Medium",
        pattern=re.compile(r'(?:\.Replace\([^)]+\)\s*){2,}|-(?:replace\s+\S+\s*){2,}', re.IGNORECASE),
        description="Chained .Replace() or -replace operations on strings can construct commands at runtime.",
        remediation="Use plain-text commands. Heavy string manipulation indicates obfuscation.",
        wdac_hint="Deobfuscate scripts before deploying under WDAC.",
    ),
    Rule(
        id="CLM031", name="Restricted .NET Object Creation", severity="High",
        pattern=re.compile(
            r'\bNew-Object\s+(?:-TypeName\s+)?["\']?(?:System\.)?'
            r'(?:IO\.(?:FileInfo|DirectoryInfo|FileStream|StreamReader|StreamWriter)|'
            r'Net\.(?:WebClient|Http\.HttpClient)|Net\.Sockets\.(?:TcpClient|UdpClient)|'
            r'Diagnostics\.ProcessStartInfo|Management\.(?:ManagementObject|ManagementObjectSearcher)|'
            r'DirectoryServices\.(?:DirectoryEntry|DirectorySearcher)|Data\.SqlClient\.SqlConnection|'
            r'Windows\.Forms\.[\w.]+|Reflection\.[\w.]+|Runtime\.InteropServices\.[\w.]+)',
            re.IGNORECASE,
        ),
        description="New-Object for restricted .NET types can fail in CLM because unapproved constructors are blocked.",
        remediation="Use cmdlets or approved types instead of directly constructing restricted .NET objects. Move required .NET code to a signed module.",
        wdac_hint="Sign the module or script that requires restricted .NET object construction.",
    ),
]


def _strip_comments(line: str, in_block: bool) -> tuple[str, bool]:
    """Strip comments from a line, returning (code_portion, still_in_block_comment)."""
    result = []
    i = 0
    while i < len(line):
        if in_block:
            # Look for block comment end
            if i < len(line) - 1 and line[i] == '#' and line[i + 1] == '>':
                in_block = False
                i += 2
                continue
            i += 1
            continue

        # Check for block comment start
        if i < len(line) - 1 and line[i] == '<' and line[i + 1] == '#':
            in_block = True
            i += 2
            continue

        # Check for line comment
        if line[i] == '#':
            break

        result.append(line[i])
        i += 1

    return ''.join(result), in_block


def analyze_script(content: str, filename: str = "script.ps1") -> dict:
    """Analyze PowerShell script content against all CLM rules."""
    lines = content.splitlines()
    findings: list[dict] = []
    in_block_comment = False

    for line_num, line in enumerate(lines, 1):
        # Strip comments properly (handles inline, block, and nested)
        code_portion, in_block_comment = _strip_comments(line, in_block_comment)

        if not code_portion.strip():
            continue

        for rule in RULES:
            for match in rule.pattern.finditer(code_portion):
                findings.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "line": line_num,
                    "column": match.start() + 1,
                    "code_snippet": line.strip()[:200],
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "wdac_rule_hint": rule.wdac_hint,
                })

    # Deduplicate: CLM022 is a subset of CLM001
    seen_lines: dict[str, set[int]] = {}
    deduped: list[dict] = []
    for f in findings:
        key = f"{f['rule_id']}:{f['line']}"
        if key not in seen_lines:
            seen_lines[key] = set()
        if f["column"] not in seen_lines[key]:
            seen_lines[key].add(f["column"])
            deduped.append(f)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in deduped:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    # Compute WDAC SHA256 flat file hash (same as Get-FileHash on Windows)
    # WDAC uses the raw file bytes hash, uppercase hex
    sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest().upper()

    return {
        "filename": filename,
        "total_lines": len(lines),
        "findings": deduped,
        "summary": {
            "total_findings": len(deduped),
            **severity_counts,
        },
        "wdac_hash": {
            "sha256": sha256_hash,
            "instruction": "Copy this SHA256 hash into your WDAC policy (e.g., MagicSword Policy Editor) to allow this script to run in FullLanguage mode.",
        },
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "analysis_method": "python_regex",
    }


def get_rules() -> list[dict]:
    """Return all rules with descriptions."""
    return [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "description": r.description,
            "remediation": r.remediation,
            "wdac_hint": r.wdac_hint,
        }
        for r in RULES
    ]
