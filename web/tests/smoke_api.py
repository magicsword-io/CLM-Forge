"""Runtime smoke test for the CLM Forge web API.

Uses only the app runtime dependencies plus Python stdlib. It starts uvicorn
on a local ephemeral port and verifies the user-facing API paths that matter
for production readiness.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


WEB_DIR = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(base_url: str, path: str, payload: dict | None = None) -> tuple[int, str, bytes]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(base_url + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def multipart_request(
    base_url: str,
    path: str,
    files: list[tuple[str, str, bytes, str]],
) -> tuple[int, str, bytes]:
    boundary = f"----clmforge{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for field_name, filename, content, content_type in files:
        chunks.extend([
            f"--{boundary}\r\n".encode("utf-8"),
            (
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{filename}"\r\n'
            ).encode("utf-8"),
            f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"),
            content,
            b"\r\n",
        ])
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    data = b"".join(chunks)
    req = urllib.request.Request(
        base_url + path,
        data=data,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def wait_for_health(base_url: str) -> None:
    deadline = time.time() + 20
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            status, _, body = request(base_url, "/api/health")
            if status == 200 and json.loads(body)["status"] == "ok":
                return
        except Exception as exc:  # noqa: BLE001 - preserve last startup failure
            last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"API did not become healthy: {last_error}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]

    proc = subprocess.Popen(cmd, cwd=str(WEB_DIR))
    try:
        wait_for_health(base_url)

        status, content_type, body = request(base_url, "/")
        assert_true(status == 200, "UI route did not return 200")
        assert_true("text/html" in content_type, "UI route did not return HTML")
        assert_true(b"CLM Forge" in body, "UI route did not include CLM Forge branding")

        status, _, body = request(base_url, "/api/rules")
        assert_true(status == 200, "Rules route did not return 200")
        rules = json.loads(body)
        assert_true(rules["total"] == 31, "Rules route did not return 31 rules")

        status, _, body = request(
            base_url,
            "/api/analyze-text",
            {
                "filename": "new-object.ps1",
                "content": "$client = New-Object System.Net.WebClient",
            },
        )
        assert_true(status == 200, "Analyze-text route did not return 200")
        single = json.loads(body)
        single_rule_ids = {f["rule_id"] for f in single["findings"]}
        assert_true("CLM031" in single_rule_ids, "Analyze-text did not detect CLM031")

        status, _, body = multipart_request(
            base_url,
            "/api/analyze",
            [("file", "upload.ps1", b"Invoke-Expression 'Get-Process'", "text/plain")],
        )
        assert_true(status == 200, "Upload analysis route did not return 200")
        upload = json.loads(body)
        assert_true(upload["filename"] == "upload.ps1", "Upload analysis filename mismatch")

        status, _, body = request(
            base_url,
            "/api/analyze-batch",
            {
                "scripts": [
                    {"filename": "safe.ps1", "content": "Write-Host ok"},
                    {"filename": "unsafe.ps1", "content": "Invoke-Expression 'Get-Process'"},
                ],
                "fail_on": "High",
            },
        )
        assert_true(status == 200, "Batch analysis route did not return 200")
        batch = json.loads(body)
        assert_true(batch["aggregate"]["total_scripts"] == 2, "Batch analysis script count mismatch")
        assert_true(batch["aggregate"]["ci_pass"] is False, "Batch fail_on=High should fail CI")

        status, _, body = request(
            base_url,
            "/api/analyze-batch",
            {
                "scripts": [
                    {"filename": "baseline.ps1", "content": "Invoke-Expression 'Get-Process'"},
                ],
                "baseline": ["CLM006"],
                "fail_on": "High",
            },
        )
        assert_true(status == 200, "Baseline batch route did not return 200")
        baseline_batch = json.loads(body)
        assert_true(
            baseline_batch["scripts"][0]["suppressed_count"] >= 1,
            "Baseline did not suppress CLM006",
        )
        assert_true(
            baseline_batch["aggregate"]["ci_pass"] is True,
            "Baseline suppression should pass fail_on=High",
        )

        status, _, body = multipart_request(
            base_url,
            "/api/analyze-batch-upload",
            [
                ("files", "one.ps1", b"Write-Host ok", "text/plain"),
                ("files", "two.ps1", b"New-Object System.Net.WebClient", "text/plain"),
            ],
        )
        assert_true(status == 200, "Batch upload route did not return 200")
        upload_batch = json.loads(body)
        assert_true(upload_batch["aggregate"]["total_scripts"] == 2, "Batch upload count mismatch")

        status, content_type, _ = request(
            base_url,
            "/api/export/sarif",
            {
                "scripts": [
                    {
                        "filename": "unsafe.ps1",
                        "analysis_method": "python_regex",
                        "findings": [
                            {
                                "rule_id": "CLM006",
                                "rule_name": "Invoke-Expression Usage",
                                "severity": "High",
                                "line": 1,
                                "column": 1,
                                "description": "desc",
                                "remediation": "fix",
                                "wdac_rule_hint": "hint",
                                "code_snippet": "Invoke-Expression 'x'",
                            }
                        ],
                    }
                ]
            },
        )
        assert_true(status == 200, "SARIF export route did not return 200")
        assert_true("application/sarif+json" in content_type, "SARIF response has wrong media type")

        export_payload = {
            "scripts": [
                {
                    "filename": "unsafe.ps1",
                    "analysis_method": "python_regex",
                    "findings": [
                        {
                            "rule_id": "CLM006",
                            "rule_name": "Invoke-Expression Usage",
                            "severity": "High",
                            "line": 1,
                            "column": 1,
                            "description": "desc",
                            "remediation": "fix",
                            "wdac_rule_hint": "hint",
                            "code_snippet": "Invoke-Expression 'x'",
                        }
                    ],
                }
            ]
        }

        status, content_type, body = request(base_url, "/api/export/csv", export_payload)
        assert_true(status == 200, "CSV export route did not return 200")
        assert_true("text/csv" in content_type, "CSV response has wrong media type")
        csv_text = body.decode("utf-8")
        assert_true("filename,rule_id,rule_name" in csv_text, "CSV header missing")
        assert_true("unsafe.ps1,CLM006" in csv_text, "CSV finding row missing")

        status, _, body = request(
            base_url,
            "/api/report/html",
            {
                "filename": "</title><script>alert(1)</script>.ps1",
                "content": "Write-Host '</script><!--'",
            },
        )
        assert_true(status == 200, "HTML report route did not return 200")
        html = body.decode("utf-8")
        assert_true("</script><!--" not in html, "HTML report contains an unescaped script terminator")
        assert_true("</title><script>" not in html, "HTML report title contains unescaped filename HTML")

        status, content_type, body = request(base_url, "/api/report/html-batch", export_payload)
        assert_true(status == 200, "Batch HTML report route did not return 200")
        assert_true("text/html" in content_type, "Batch HTML route did not return HTML")
        assert_true(b"CLM Forge Batch Audit" in body, "Batch HTML report missing title")

        status, _, body = request(base_url, "/openapi.json")
        assert_true(status == 200, "OpenAPI route did not return 200")
        openapi = json.loads(body)
        contact = openapi["info"]["contact"]["url"]
        assert_true(
            contact == "https://github.com/magicsword-io/clm-forge",
            "OpenAPI contact URL is not production repo",
        )
        old_owner = b"MH" + b"aggis"
        assert_true(old_owner not in body, "OpenAPI still references old repo owner")

        print("CLM Forge web API smoke passed.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
