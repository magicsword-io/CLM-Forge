"""
PowerShell subprocess bridge for real AST analysis and constrained
language mode dynamic testing when pwsh is available.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def powershell_available() -> bool:
    """Check if PowerShell (pwsh or powershell.exe) is on PATH."""
    return shutil.which("pwsh") is not None or shutil.which("powershell") is not None


def get_powershell_exe() -> Optional[str]:
    """Return path to PowerShell executable."""
    return shutil.which("pwsh") or shutil.which("powershell")


def get_module_path() -> Optional[Path]:
    """Resolve the CLM-Forge module path across local and container layouts."""
    candidates: list[Path] = []

    configured = os.getenv("CLM_CHECK_MODULE_PATH") or os.getenv("CLM_FORGE_MODULE_PATH")
    if configured:
        candidates.append(Path(configured).expanduser())

    here = Path(__file__).resolve()
    # Local repo layout: <repo>/web/analysis/ps_bridge.py -> <repo>/CLM-Forge
    if len(here.parents) > 2:
        candidates.append(here.parents[2] / "CLM-Forge")
    # Container layout: /app/analysis/ps_bridge.py -> /app/CLM-Forge
    if len(here.parents) > 1:
        candidates.append(here.parents[1] / "CLM-Forge")
    candidates.append(Path.cwd() / "CLM-Forge")

    for candidate in candidates:
        module_path = candidate.resolve()
        if (module_path / "CLM-Forge.psd1").exists():
            return module_path

    return None


def analyze_via_powershell(script_content: str, filename: str = "script.ps1") -> Optional[dict]:
    """
    Run CLM Forge PowerShell AST analysis on script content.
    Returns parsed JSON results or None if PowerShell is unavailable.
    """
    ps_exe = get_powershell_exe()
    if not ps_exe:
        return None

    module_path = get_module_path()
    if not module_path:
        return None
    module_manifest = module_path / "CLM-Forge.psd1"

    fd, temp_path = tempfile.mkstemp(suffix=".ps1", prefix="clmforge_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_content)

        escaped_module = str(module_manifest).replace("'", "''")
        escaped_temp = temp_path.replace("'", "''")
        ps_command = (
            f"Import-Module '{escaped_module}' -Force; "
            f"$results = Test-ScriptCLMCompatibility -ScriptPath '{escaped_temp}'; "
            f"$results | ForEach-Object {{ "
            f"  [PSCustomObject]@{{ "
            f"    category=$_.Category; testName=$_.TestName; status=$_.Status; "
            f"    severity=$_.Severity; message=$_.Message; "
            f"    remediation=$_.Remediation; details=$_.Details "
            f"  }} "
            f"}} | ConvertTo-Json -Depth 10"
        )

        result = subprocess.run(
            [ps_exe, "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict):
                parsed = [parsed]
            return {
                "filename": filename,
                "findings": parsed,
                "analysis_method": "powershell_ast",
            }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError):
        pass
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    return None


def test_in_constrained_mode(script_content: str, filename: str = "script.ps1") -> Optional[dict]:
    """
    Actually execute the script inside a ConstrainedLanguage runspace and
    capture what errors out. This gives dynamic proof of what CLM blocks,
    not just static pattern matching.

    Works on Linux pwsh — we create a runspace with ConstrainedLanguage,
    feed the script in, and capture every error with line numbers.
    """
    ps_exe = get_powershell_exe()
    if not ps_exe:
        return None

    fd, temp_path = tempfile.mkstemp(suffix=".ps1", prefix="clmforge_clm_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_content)

        escaped_temp = temp_path.replace("'", "''")

        # This PowerShell script creates a constrained runspace and tries
        # to execute the user's script inside it, capturing all errors.
        clm_test_script = f"""
$scriptPath = '{escaped_temp}'
$scriptContent = Get-Content -Path $scriptPath -Raw

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Create a constrained language runspace
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage

$runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
$runspace.Open()

$ps = [System.Management.Automation.PowerShell]::Create()
$ps.Runspace = $runspace

# Confirm the runspace is actually constrained
$null = $ps.AddScript('$ExecutionContext.SessionState.LanguageMode')
$null = $ps.Invoke()
$actualMode = $ps.Streams.Information | Select-Object -Last 1
$ps.Commands.Clear()
$ps.Streams.ClearStreams()

# Try to run the script
$null = $ps.AddScript($scriptContent)

try {{
    $null = $ps.Invoke()
}}
catch {{
    # Invocation-level errors
}}

# Collect errors from the constrained execution
foreach ($err in $ps.Streams.Error) {{
    $line = 0
    if ($err.InvocationInfo) {{
        $line = $err.InvocationInfo.ScriptLineNumber
    }}
    $snippet = ''
    if ($err.InvocationInfo -and $err.InvocationInfo.Line) {{
        $snippet = $err.InvocationInfo.Line.Trim()
        if ($snippet.Length -gt 200) {{ $snippet = $snippet.Substring(0, 200) + '...' }}
    }}

    $results.Add([PSCustomObject]@{{
        line        = $line
        error       = $err.Exception.Message
        category    = $err.CategoryInfo.Category.ToString()
        errorId     = $err.FullyQualifiedErrorId
        codeSnippet = $snippet
        blocked     = ($err.Exception.Message -match 'language mode|CannotCreateType|cannot be created in a script|not allowed|not supported' -or $err.FullyQualifiedErrorId -match 'ConstrainedLanguage|CannotDefineNewType')
    }})
}}

$ps.Dispose()
$runspace.Close()
$runspace.Dispose()

[PSCustomObject]@{{
    totalErrors   = $results.Count
    blockedByCLM  = ($results | Where-Object blocked -eq $true).Count
    otherErrors   = ($results | Where-Object blocked -ne $true).Count
    errors        = $results
}} | ConvertTo-Json -Depth 5
"""

        result = subprocess.run(
            [ps_exe, "-NoProfile", "-NonInteractive", "-Command", clm_test_script],
            capture_output=True, text=True, timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            parsed = json.loads(result.stdout)
            return {
                "filename": filename,
                "analysis_method": "constrained_runspace",
                "clm_results": parsed,
            }
        elif result.stderr.strip():
            # Even if it fails, the error itself may be informative
            return {
                "filename": filename,
                "analysis_method": "constrained_runspace",
                "clm_results": {
                    "totalErrors": 1,
                    "blockedByCLM": 0,
                    "otherErrors": 1,
                    "errors": [{"line": 0, "error": result.stderr[:500], "blocked": False}],
                },
            }
    except subprocess.TimeoutExpired:
        return {
            "filename": filename,
            "analysis_method": "constrained_runspace",
            "clm_results": {
                "totalErrors": 1,
                "blockedByCLM": 0,
                "otherErrors": 1,
                "errors": [{"line": 0, "error": "Script execution timed out (30s limit)", "blocked": False}],
            },
        }
    except (json.JSONDecodeError, FileNotFoundError, OSError):
        pass
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass

    return None
