FROM python:3.11-slim-bookworm

ARG POWERSHELL_VERSION=7.6.1

WORKDIR /app

# Install dependencies first for better layer caching
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install PowerShell directly from GitHub releases (supports amd64 and arm64)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates libicu72 && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then PS_ARCH="arm64"; else PS_ARCH="x64"; fi && \
    curl -fsSL -o /tmp/powershell.tar.gz "https://github.com/PowerShell/PowerShell/releases/download/v${POWERSHELL_VERSION}/powershell-${POWERSHELL_VERSION}-linux-${PS_ARCH}.tar.gz" && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar -xzf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    rm /tmp/powershell.tar.gz && \
    rm -rf /var/lib/apt/lists/*

# Copy application code and the PowerShell module used by AST analysis
COPY web/ .
COPY CLM-Forge ./CLM-Forge

# Create non-root user and set ownership
RUN useradd --create-home appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/api/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
