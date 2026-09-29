# SOC Command Center - Start Backend (PowerShell 5.1 compatible)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Join-Path $ScriptDir ".."
$BackendDir = Join-Path $ProjectRoot "backend"

Write-Host "=== Iniciando Backend SOC ===" -ForegroundColor Cyan

# Verificar entorno virtual
$VenvPath = Join-Path $BackendDir "venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $PythonExe)) {
    Write-Error "Entorno virtual no encontrado. Ejecute .\scripts\setup.ps1 primero"
    exit 1
}

# Iniciar uvicorn con la app reutilizada
$AppDir = Join-Path $BackendDir "app"
Write-Host "Iniciando Uvicorn en http://localhost:8000" -ForegroundColor Green

Start-Process -FilePath "$PythonExe" -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload" -WorkingDirectory $BackendDir -WindowStyle Hidden

Start-Sleep -Seconds 3

Write-Host "Backend iniciado en http://localhost:8000" -ForegroundColor Green
Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor Cyan