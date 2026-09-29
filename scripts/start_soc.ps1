# SOC Command Center - Start SOC (PowerShell 5.1 compatible)
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Join-Path $ScriptDir ".."

Write-Host "=== SOC 24x7 Command Center - Inicio ===" -ForegroundColor Cyan
Write-Host "Directorio: $ProjectRoot" -ForegroundColor Gray

# Iniciar Backend
Write-Host "`n[1/2] Iniciando Backend (FastAPI)..." -ForegroundColor Yellow
Start-Process -FilePath "powershell" -ArgumentList "-File", (Join-Path $ProjectRoot "scripts\start_backend.ps1") -WorkingDirectory $ProjectRoot -WindowStyle Normal

Start-Sleep -Seconds 3

# Iniciar Frontend
Write-Host "`n[2/2] Iniciando Frontend (React + Vite)..." -ForegroundColor Yellow
Start-Process -FilePath "powershell" -ArgumentList "-File", (Join-Path $ProjectRoot "scripts\start_frontend.ps1") -WorkingDirectory $ProjectRoot -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host "`n=== SOC 24x7 INICIADO ===" -ForegroundColor Green
Write-Host "Dashboard:     http://localhost:5173" -ForegroundColor Cyan
Write-Host "API Backend:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "API Docs:      http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Usuario:       5205342" -ForegroundColor Gray
Write-Host "Contraseña:    5205342" -ForegroundColor Gray
Write-Host "`nPara detener: .\scripts\stop_soc.ps1" -ForegroundColor Gray