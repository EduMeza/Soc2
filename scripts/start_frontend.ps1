# SOC Command Center - Start Frontend (PowerShell 5.1 compatible)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Join-Path $ScriptDir ".."
$FrontendDir = Join-Path $ProjectRoot "frontend"

Write-Host "=== Iniciando Frontend SOC ===" -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath (Join-Path $FrontendDir "node_modules"))) {
    Write-Host "Instalando dependencias..." -ForegroundColor Yellow
    npm install
}

Write-Host "Iniciando Vite dev server en http://localhost:5173" -ForegroundColor Green
Start-Process -FilePath "npm" -ArgumentList "run", "dev" -WorkingDirectory $FrontendDir -WindowStyle Normal