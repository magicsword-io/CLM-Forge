#!/usr/bin/env bash
set -euo pipefail

SKIP_DOCKER=0
SKIP_POWERSHELL=0

for arg in "$@"; do
  case "$arg" in
    --skip-docker) SKIP_DOCKER=1 ;;
    --skip-powershell) SKIP_POWERSHELL=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--skip-docker] [--skip-powershell]" >&2
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$ROOT_DIR/web"

if [[ -x "$WEB_DIR/.venv/bin/python" ]]; then
  PYTHON="$WEB_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON="python"
else
  echo "Python is required for production verification." >&2
  exit 1
fi

run_step() {
  echo
  echo "==> $*"
  "$@"
}

echo "Production verification for CLM Forge"
echo "Repo: $ROOT_DIR"

run_step git -C "$ROOT_DIR" diff --check
run_step "$PYTHON" -m compileall "$WEB_DIR/app.py" "$WEB_DIR/analysis" "$WEB_DIR/tests"
run_step "$PYTHON" "$WEB_DIR/tests/smoke_api.py"

if command -v docker >/dev/null 2>&1; then
  run_step docker compose -f "$ROOT_DIR/web/docker-compose.yml" config
else
  echo "Docker CLI not found; compose config check skipped." >&2
  if [[ "$SKIP_DOCKER" -eq 0 ]]; then
    exit 1
  fi
fi

if [[ "$SKIP_DOCKER" -eq 0 ]]; then
  if ! docker version >/dev/null 2>&1; then
    echo "Docker daemon is not reachable. Re-run with --skip-docker to run non-container checks only." >&2
    exit 1
  fi

  cleanup_container() {
    docker compose -f "$ROOT_DIR/web/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
  }
  trap cleanup_container EXIT

  run_step docker compose -f "$ROOT_DIR/web/docker-compose.yml" up -d --build

  echo
  echo "==> Waiting for container health"
  for _ in $(seq 1 30); do
    if health="$(curl -fsS http://127.0.0.1:8080/api/health 2>/dev/null)"; then
      echo "$health"
      "$PYTHON" -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("powershell_available") is True else 1)' <<<"$health"
      break
    fi
    sleep 2
  done

  if [[ -z "${health:-}" ]]; then
    docker compose -f "$ROOT_DIR/web/docker-compose.yml" ps
    docker compose -f "$ROOT_DIR/web/docker-compose.yml" logs
    echo "Container health endpoint did not become available." >&2
    exit 1
  fi

  echo
  echo "==> Verifying container PowerShell bridge"
  "$PYTHON" - <<'PY'
import json
import urllib.request

payload = {
    "filename": "unsafe.ps1",
    "content": "Add-Type -TypeDefinition 'public class A{}'",
}
req = urllib.request.Request(
    "http://127.0.0.1:8080/api/analyze-text",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=30) as resp:
    result = json.loads(resp.read())
print(json.dumps(result, indent=2))
method = result.get("analysis_method", "")
if "powershell_ast" not in method:
    raise SystemExit("container analysis did not include powershell_ast")
if "constrained_runspace" not in method:
    raise SystemExit("container analysis did not include constrained_runspace")
PY
else
  echo
  echo "==> Docker runtime checks skipped by --skip-docker"
fi

if [[ "$SKIP_POWERSHELL" -eq 0 ]]; then
  if command -v powershell.exe >/dev/null 2>&1; then
    PS51="powershell.exe"
  elif command -v powershell >/dev/null 2>&1; then
    PS51="powershell"
  else
    echo "Windows PowerShell 5.1 is required for full compatibility verification." >&2
    echo "Re-run with --skip-powershell to run non-PowerShell checks only." >&2
    exit 1
  fi

  if ! command -v pwsh >/dev/null 2>&1; then
    echo "PowerShell 7 (pwsh) is required for full compatibility verification." >&2
    echo "Re-run with --skip-powershell to run non-PowerShell checks only." >&2
    exit 1
  fi

  run_step "$PS51" -NoProfile -ExecutionPolicy Bypass -File "$ROOT_DIR/tests/run-compatibility.ps1"
  run_step pwsh -NoProfile -File "$ROOT_DIR/tests/run-compatibility.ps1"
else
  echo
  echo "==> PowerShell compatibility checks skipped by --skip-powershell"
fi

echo
if [[ "$SKIP_DOCKER" -eq 0 && "$SKIP_POWERSHELL" -eq 0 ]]; then
  echo "Production verification passed."
else
  echo "Selected production checks passed. Skipped checks must pass before release."
fi
