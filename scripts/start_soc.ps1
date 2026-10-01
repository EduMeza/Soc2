# SOC Command Center - Start SOC
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot

try {
    Write-Host "=== SOC 24x7 Command Center - Inicio ===" -ForegroundColor Cyan
    Write-Host "Directorio: $ProjectRoot" -ForegroundColor Gray

    # En entornos normales se requiere un archivo .env local.
    if (
        $env:APP_ENV -ne 'test' -and
        -not (Test-Path (Join-Path $ProjectRoot '.env'))
    ) {
        throw 'Configure .env usando .env.example antes de iniciar el SOC'
    }

    Write-Host "`n[1/2] Iniciando Backend (FastAPI)..." -ForegroundColor Yellow

    & powershell.exe -NoProfile -File (
        Join-Path $PSScriptRoot 'start_backend.ps1'
    )

    if ($LASTEXITCODE -ne 0) {
        throw 'Backend no disponible'
    }

    Write-Host "`n[2/2] Iniciando Frontend (React + Vite)..." -ForegroundColor Yellow

    & powershell.exe -NoProfile -File (
        Join-Path $PSScriptRoot 'start_frontend.ps1'
    )

    if ($LASTEXITCODE -ne 0) {
        throw 'Frontend no disponible'
    }

    $BackendPort = if ($env:SOC_BACKEND_PORT) {
        $env:SOC_BACKEND_PORT
    } else {
        '8000'
    }

    $FrontendPort = if ($env:SOC_FRONTEND_PORT) {
        $env:SOC_FRONTEND_PORT
    } else {
        '5173'
    }

    Write-Host "`n=== SOC 24x7 INICIADO ===" -ForegroundColor Green
    Write-Host "Frontend: http://localhost:$FrontendPort" -ForegroundColor Cyan
    Write-Host "Backend: http://127.0.0.1:$BackendPort" -ForegroundColor Cyan
    Write-Host "Swagger (development): http://127.0.0.1:$BackendPort/docs" -ForegroundColor Cyan

    Write-Host (
        "`nCredenciales iniciales: configurables mediante " +
        "INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_PASSWORD."
    ) -ForegroundColor Gray

    Write-Host (
        "JWT_SECRET: requerido mediante .env. " +
        "Los secretos no se muestran por seguridad."
    ) -ForegroundColor Gray

    Write-Host "`nPara detener: .\scripts\stop_soc.ps1" -ForegroundColor Gray
}
catch {
    Write-Error $_
    exit 1
}