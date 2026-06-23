"""CLM Forge Web UI - FastAPI application for PowerShell CLM compatibility analysis."""

import csv
import io
import json
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel, Field

from analysis.ast_analyzer import analyze_script, get_rules
from analysis.ps_bridge import (
    powershell_available,
    analyze_via_powershell,
    test_in_constrained_mode,
)

# ---------------------------------------------------------------------------
# OpenAPI metadata
# ---------------------------------------------------------------------------

API_DESCRIPTION = """
**CLM Forge** is a PowerShell Constrained Language Mode (CLM) compatibility
analyzer. It combines:

* **Static analysis** — 30+ regex + AST rules covering `Add-Type`,
  `New-Object -ComObject`, reflection, `Invoke-Expression`, type accelerators,
  obfuscation, and other WDAC-blocked constructs.
* **Dynamic analysis** (when `pwsh` is available) — runs the script in a
  real `ConstrainedLanguage` runspace and captures the actual errors.
* **WDAC SHA256 hashing** — ready to paste into a WDAC policy.

### Typical flows

| Goal | Endpoint |
|------|----------|
| Analyze one script pasted from the editor | `POST /api/analyze-text` |
| Analyze one uploaded `.ps1` file | `POST /api/analyze` |
| Audit many scripts in one call (CI / bulk) | `POST /api/analyze-batch` |
| Upload many files via `multipart/form-data` | `POST /api/analyze-batch-upload` |
| Self-contained HTML report (single or batch) | `POST /api/report/html` or `/api/report/html-batch` |
| GitHub code-scanning / SIEM ingest | `POST /api/export/sarif` |
| Flat audit CSV | `POST /api/export/csv` |

### CI integration

Pass `fail_on: "High"` to `/api/analyze-batch`. The response's
`aggregate.ci_pass` flag flips to `false` as soon as a finding at or above
that severity exists, which you can trivially convert into a non-zero exit
code in any pipeline step.

### Baseline suppression

Pass `baseline: ["CLM001", "CLM014"]` to mark those rule IDs as
`suppressed: true` in every script's findings. They stay in the payload for
audit purposes but are excluded from `summary` counts and the CI threshold.
"""

TAGS_METADATA = [
    {"name": "Analyze",  "description": "Run CLM compatibility analysis against one or many PowerShell scripts."},
    {"name": "Reports",  "description": "Render self-contained HTML reports (single-script or portfolio)."},
    {"name": "Exports",  "description": "Export findings as SARIF 2.1.0 (code scanning / SIEM) or CSV (audit)."},
    {"name": "Meta",     "description": "Rule catalog, engine availability, health check."},
    {"name": "UI",       "description": "HTML pages served for humans."},
]

app = FastAPI(
    title="CLM Forge API",
    description=API_DESCRIPTION,
    version="1.1.0",
    openapi_tags=TAGS_METADATA,
    contact={
        "name": "CLM Forge on GitHub",
        "url": "https://github.com/magicsword-io/clm-forge",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
    swagger_ui_parameters={
        "defaultModelsExpandDepth": 0,
        "docExpansion": "list",
        "tryItOutEnabled": True,
        "persistAuthorization": True,
    },
)

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB per file
MAX_BATCH_FILES = 50             # hard cap per batch request
SEVERITY_WEIGHT = {"Critical": 15, "High": 8, "Medium": 3, "Low": 1}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AnalyzeTextRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_FILE_SIZE, description="Raw PowerShell script contents.")
    filename: str = Field(default="script.ps1", max_length=255, description="Logical filename (used in the response and WDAC hash label).")

    model_config = {
        "json_schema_extra": {
            "example": {
                "filename": "login-check.ps1",
                "content": "Add-Type -TypeDefinition 'public class A{}'\nInvoke-Expression 'Get-Process'",
            }
        }
    }


class ScriptInput(BaseModel):
    filename: str = Field(..., max_length=255)
    content: str = Field(..., min_length=1, max_length=MAX_FILE_SIZE)


class BatchAnalyzeRequest(BaseModel):
    scripts: List[ScriptInput] = Field(..., max_length=MAX_BATCH_FILES, description=f"Up to {MAX_BATCH_FILES} scripts per request.")
    baseline: Optional[List[str]] = Field(
        default=None,
        description="Rule IDs to suppress (e.g. accepted risks). Suppressed findings are kept in the payload but excluded from summary counts and CI threshold evaluation.",
        examples=[["CLM001", "CLM014"]],
    )
    fail_on: Optional[str] = Field(
        default=None,
        description="Lowest severity that causes `aggregate.ci_pass=false`. One of: Critical, High, Medium, Low.",
        examples=["High"],
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "scripts": [
                    {"filename": "bootstrap.ps1", "content": "Add-Type 'public class X{}'"},
                    {"filename": "cleanup.ps1",   "content": "Write-Host done"},
                ],
                "baseline": ["CLM014"],
                "fail_on": "High",
            }
        }
    }


class BatchReportRequest(BaseModel):
    scripts: List[Dict[str, Any]] = Field(..., max_length=MAX_BATCH_FILES, description="Per-script result objects (as returned by /api/analyze-batch).")
    generated_at: Optional[str] = Field(default=None, description="ISO8601 timestamp to stamp on the report. Defaults to now.")


class Finding(BaseModel):
    rule_id: str = Field(..., examples=["CLM001"])
    rule_name: str = Field(..., examples=["Add-Type Usage"])
    severity: str = Field(..., examples=["Critical"])
    line: int = Field(..., examples=[3])
    column: int = Field(..., examples=[1])
    code_snippet: str = Field(..., examples=["Add-Type -TypeDefinition 'public class A{}'"])
    description: str
    remediation: str
    wdac_rule_hint: Optional[str] = None
    suppressed: Optional[bool] = None


class SeveritySummary(BaseModel):
    total_findings: int
    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0


class WdacHash(BaseModel):
    sha256: str
    instruction: str


class AnalysisResult(BaseModel):
    filename: str
    total_lines: int
    findings: List[Finding]
    summary: SeveritySummary
    wdac_hash: WdacHash
    analyzed_at: str
    analysis_method: str
    score: Optional[int] = Field(default=None, description="0-100 risk score (100 = clean).")
    suppressed_count: Optional[int] = None
    ps_ast_results: Optional[Dict[str, Any]] = None
    clm_dynamic_results: Optional[Dict[str, Any]] = None


class BatchAggregate(BaseModel):
    total_scripts: int
    total_findings: int
    severity_counts: Dict[str, int]
    scripts_with_issues: int
    scripts_clean: int
    average_score: int
    clm_blocked_total: int
    clm_dynamic_failures: int
    fail_on: Optional[str]
    ci_pass: bool
    generated_at: str


class BatchAnalyzeResponse(BaseModel):
    scripts: List[AnalysisResult]
    aggregate: BatchAggregate


class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    powershell_available: bool
    version: str


class Rule(BaseModel):
    id: str
    name: str
    severity: str
    description: str
    remediation: str
    wdac_hint: Optional[str] = None


class RulesResponse(BaseModel):
    rules: List[Rule]
    total: int


# ---------------------------------------------------------------------------
# Core analysis helpers
# ---------------------------------------------------------------------------


def _run_analysis(script_text: str, filename: str) -> dict:
    """Run all available analysis methods on a single script."""
    result = analyze_script(script_text, filename)
    methods = ["python_regex"]

    if powershell_available():
        ps_result = analyze_via_powershell(script_text, filename)
        if ps_result:
            result["ps_ast_results"] = ps_result
            methods.append("powershell_ast")

        clm_result = test_in_constrained_mode(script_text, filename)
        if clm_result:
            result["clm_dynamic_results"] = clm_result.get("clm_results", {})
            methods.append("constrained_runspace")

    result["analysis_method"] = " + ".join(methods)
    return result


def _compute_score(findings: list) -> int:
    deductions = sum(SEVERITY_WEIGHT.get(f.get("severity"), 0) for f in findings)
    return max(0, 100 - deductions)


def _apply_baseline(result: dict, baseline: Optional[List[str]]) -> dict:
    if not baseline:
        return result
    suppressed = set(baseline)
    active = []
    for f in result.get("findings", []):
        if f.get("rule_id") in suppressed:
            f["suppressed"] = True
        else:
            active.append(f)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in active:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    result["summary"] = {"total_findings": len(active), **counts}
    result["suppressed_count"] = len(result.get("findings", [])) - len(active)
    return result


def _aggregate(scripts: List[dict], fail_on: Optional[str] = None) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_findings = 0
    scripts_with_issues = 0
    total_score = 0
    total_blocked = 0
    clm_dynamic_failures = 0

    for s in scripts:
        summary = s.get("summary") or {}
        total_findings += summary.get("total_findings", 0)
        for sev in counts:
            counts[sev] += summary.get(sev, 0)
        if summary.get("total_findings", 0) > 0:
            scripts_with_issues += 1
        total_score += s.get("score", _compute_score(s.get("findings", [])))
        clm = s.get("clm_dynamic_results") or {}
        total_blocked += clm.get("blockedByCLM", 0) or 0
        if (clm.get("totalErrors") or 0) > 0:
            clm_dynamic_failures += 1

    n = max(1, len(scripts))
    avg = total_score // n

    severity_order = ["Low", "Medium", "High", "Critical"]
    ci_pass = True
    if fail_on and fail_on in severity_order:
        threshold_idx = severity_order.index(fail_on)
        for sev in severity_order[threshold_idx:]:
            if counts.get(sev, 0) > 0:
                ci_pass = False
                break

    return {
        "total_scripts": len(scripts),
        "total_findings": total_findings,
        "severity_counts": counts,
        "scripts_with_issues": scripts_with_issues,
        "scripts_clean": len(scripts) - scripts_with_issues,
        "average_score": avg,
        "clm_blocked_total": total_blocked,
        "clm_dynamic_failures": clm_dynamic_failures,
        "fail_on": fail_on,
        "ci_pass": ci_pass,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _decode_upload(content: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    raise HTTPException(400, "Could not decode file. Ensure it is a valid text file.")


def _json_for_script_tag(payload: Any) -> str:
    """Serialize JSON safely for inline <script> assignment."""
    return (
        json.dumps(payload)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------


@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["UI"],
    summary="Web UI",
    description="Serves the CLM Forge single-page web app (editor + batch analyzer).",
    include_in_schema=False,
)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "ps_available": powershell_available(),
    })


# ---------------------------------------------------------------------------
# Analysis endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/api/analyze",
    tags=["Analyze"],
    summary="Analyze one uploaded .ps1 file",
    description="Accepts a single `multipart/form-data` file upload and returns the analysis result. Use `/api/analyze-text` to submit raw content without a file.",
    response_model=AnalysisResult,
)
async def analyze_upload(file: UploadFile = File(..., description="A .ps1, .psm1, or .psd1 file (5 MB max).")):
    if not file.filename or not file.filename.lower().endswith((".ps1", ".psm1", ".psd1")):
        raise HTTPException(400, "Only PowerShell files (.ps1, .psm1, .psd1) are supported.")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum size is {MAX_FILE_SIZE // 1024 // 1024}MB.")

    script_text = _decode_upload(content)
    return JSONResponse(_run_analysis(script_text, file.filename))


@app.post(
    "/api/analyze-text",
    tags=["Analyze"],
    summary="Analyze a pasted PowerShell script",
    description="Accepts raw script text in a JSON body. Useful for editors and inline tooling.",
    response_model=AnalysisResult,
)
async def analyze_text(body: AnalyzeTextRequest):
    if not body.content.strip():
        raise HTTPException(400, "No script content provided.")
    return JSONResponse(_run_analysis(body.content, body.filename))


@app.post(
    "/api/analyze-batch",
    tags=["Analyze"],
    summary="Analyze many scripts in one request",
    description=(
        "Runs the full static + dynamic analysis on up to "
        f"{MAX_BATCH_FILES} scripts and returns per-script results plus a "
        "portfolio aggregate. Supports `baseline` rule-ID suppression and a "
        "`fail_on` severity threshold that sets `aggregate.ci_pass` for CI."
    ),
    response_model=BatchAnalyzeResponse,
)
async def analyze_batch(body: BatchAnalyzeRequest):
    if not body.scripts:
        raise HTTPException(400, "No scripts provided.")

    seen: Dict[str, int] = {}
    results = []
    for s in body.scripts:
        name = s.filename or "script.ps1"
        if name in seen:
            seen[name] += 1
            base, _, ext = name.rpartition(".")
            name = f"{base}_{seen[name]}.{ext}" if ext else f"{name}_{seen[name]}"
        else:
            seen[name] = 0

        result = _run_analysis(s.content, name)
        result = _apply_baseline(result, body.baseline)
        result["score"] = _compute_score(
            [f for f in result.get("findings", []) if not f.get("suppressed")]
        )
        results.append(result)

    aggregate = _aggregate(results, body.fail_on)
    return JSONResponse({"scripts": results, "aggregate": aggregate})


@app.post(
    "/api/analyze-batch-upload",
    tags=["Analyze"],
    summary="Analyze many uploaded files (multipart)",
    description=f"Upload up to {MAX_BATCH_FILES} `.ps1`/`.psm1`/`.psd1` files via `multipart/form-data` and receive the same payload as `/api/analyze-batch`.",
    response_model=BatchAnalyzeResponse,
)
async def analyze_batch_upload(files: List[UploadFile] = File(..., description="Multiple PowerShell files in one multipart request.")):
    if not files:
        raise HTTPException(400, "No files provided.")
    if len(files) > MAX_BATCH_FILES:
        raise HTTPException(400, f"Batch size exceeds limit of {MAX_BATCH_FILES} files.")

    scripts = []
    for f in files:
        if not f.filename or not f.filename.lower().endswith((".ps1", ".psm1", ".psd1")):
            raise HTTPException(400, f"Unsupported file type: {f.filename}. Only .ps1/.psm1/.psd1 accepted.")
        content = await f.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(400, f"File '{f.filename}' exceeds {MAX_FILE_SIZE // 1024 // 1024}MB limit.")
        scripts.append(ScriptInput(filename=f.filename, content=_decode_upload(content)))

    return await analyze_batch(BatchAnalyzeRequest(scripts=scripts))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.post(
    "/api/report/html",
    response_class=HTMLResponse,
    tags=["Reports"],
    summary="Single-script HTML report",
    description="Renders a self-contained, print-friendly HTML report for one script. The returned document embeds its JSON payload — no external network calls required to view it.",
    responses={200: {"content": {"text/html": {}}, "description": "Self-contained HTML document."}},
)
async def generate_html_report(body: AnalyzeTextRequest):
    if not body.content.strip():
        raise HTTPException(400, "No script content provided.")

    result = _run_analysis(body.content, body.filename)
    result["_source"] = body.content

    report_template = (BASE_DIR / "templates" / "report.html").read_text(encoding="utf-8")
    html = report_template.replace("{{REPORT_JSON}}", _json_for_script_tag(result))
    html = html.replace("{{filename}}", html_escape(body.filename))
    return HTMLResponse(html)


@app.post(
    "/api/report/html-batch",
    response_class=HTMLResponse,
    tags=["Reports"],
    summary="Portfolio HTML report",
    description="Consolidated self-contained HTML report covering many scripts: portfolio score ring, script table with jump links, top-rule-violations roll-up, and per-script detail sections.",
    responses={200: {"content": {"text/html": {}}, "description": "Self-contained HTML document."}},
)
async def generate_batch_html_report(body: BatchReportRequest):
    if not body.scripts:
        raise HTTPException(400, "No scripts provided.")

    aggregate = _aggregate(body.scripts)
    payload = {
        "scripts": body.scripts,
        "aggregate": aggregate,
        "generated_at": body.generated_at or datetime.now(timezone.utc).isoformat(),
    }

    report_template = (BASE_DIR / "templates" / "batch_report.html").read_text(encoding="utf-8")
    html = report_template.replace("{{REPORT_JSON}}", _json_for_script_tag(payload))
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


@app.post(
    "/api/export/sarif",
    tags=["Exports"],
    summary="SARIF 2.1.0 export",
    description="Emits a SARIF 2.1.0 document suitable for GitHub code-scanning, Azure DevOps, or SIEM ingest. Each finding becomes a SARIF `result` and each rule fires once per run under `tool.driver.rules`.",
    responses={200: {"content": {"application/sarif+json": {}, "application/json": {}}, "description": "SARIF 2.1.0 document."}},
)
async def export_sarif(body: BatchReportRequest):
    if not body.scripts:
        raise HTTPException(400, "No scripts provided.")

    level_map = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
    rules_index = {r["id"]: r for r in get_rules()}
    rules_used: Dict[str, Dict[str, Any]] = {}
    results_out = []

    for s in body.scripts:
        uri = s.get("filename") or "script.ps1"
        for f in s.get("findings", []):
            if f.get("suppressed"):
                continue
            rid = f.get("rule_id")
            if rid and rid not in rules_used:
                r = rules_index.get(rid, {})
                rules_used[rid] = {
                    "id": rid,
                    "name": f.get("rule_name") or r.get("name") or rid,
                    "shortDescription": {"text": f.get("rule_name") or r.get("name") or rid},
                    "fullDescription": {"text": r.get("description") or f.get("description") or ""},
                    "defaultConfiguration": {"level": level_map.get(f.get("severity"), "warning")},
                    "properties": {"severity": f.get("severity"), "tags": ["clm", "powershell", "wdac"]},
                }
            results_out.append({
                "ruleId": rid,
                "level": level_map.get(f.get("severity"), "warning"),
                "message": {"text": f.get("description") or ""},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, f.get("line") or 1),
                            "startColumn": max(1, f.get("column") or 1),
                            "snippet": {"text": f.get("code_snippet") or ""},
                        },
                    },
                }],
                "properties": {
                    "severity": f.get("severity"),
                    "remediation": f.get("remediation") or "",
                    "wdac_rule_hint": f.get("wdac_rule_hint") or "",
                },
            })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CLM Forge",
                    "informationUri": "https://github.com/magicsword-io/clm-forge",
                    "version": "1.1.0",
                    "rules": list(rules_used.values()),
                }
            },
            "results": results_out,
        }],
    }
    return Response(
        content=json.dumps(sarif),
        media_type="application/sarif+json",
        headers={"Content-Disposition": 'attachment; filename="clm-forge.sarif"'},
    )


@app.post(
    "/api/export/csv",
    response_class=PlainTextResponse,
    tags=["Exports"],
    summary="Flat CSV of all findings",
    description="One row per finding across all scripts. Header: `filename,rule_id,rule_name,severity,line,column,description,remediation,wdac_rule_hint,code_snippet,suppressed,analysis_method`.",
    responses={200: {"content": {"text/csv": {}}, "description": "UTF-8 encoded CSV."}},
)
async def export_csv(body: BatchReportRequest):
    if not body.scripts:
        raise HTTPException(400, "No scripts provided.")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "filename", "rule_id", "rule_name", "severity", "line", "column",
        "description", "remediation", "wdac_rule_hint", "code_snippet",
        "suppressed", "analysis_method",
    ])
    for s in body.scripts:
        fn = s.get("filename") or "script.ps1"
        method = s.get("analysis_method") or ""
        for f in s.get("findings", []):
            writer.writerow([
                fn, f.get("rule_id", ""), f.get("rule_name", ""),
                f.get("severity", ""), f.get("line", ""), f.get("column", ""),
                (f.get("description") or "").replace("\n", " "),
                (f.get("remediation") or "").replace("\n", " "),
                f.get("wdac_rule_hint", ""),
                (f.get("code_snippet") or "").replace("\n", " ")[:500],
                "true" if f.get("suppressed") else "false",
                method,
            ])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="clm-forge-findings.csv"'},
    )


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


@app.get(
    "/api/rules",
    tags=["Meta"],
    summary="List all CLM rules",
    description="Returns the full catalog of rules enforced by this build, including severity, description, remediation, and WDAC hint text.",
    response_model=RulesResponse,
)
async def list_rules():
    rules = get_rules()
    return JSONResponse({"rules": rules, "total": len(rules)})


@app.get(
    "/api/health",
    tags=["Meta"],
    summary="Health check",
    description="Liveness probe. `powershell_available` indicates whether dynamic CLM testing is enabled (requires `pwsh` on PATH).",
    response_model=HealthResponse,
)
async def health():
    return {
        "status": "ok",
        "powershell_available": powershell_available(),
        "version": "1.1.0",
    }
