# SOC Command Center - Setup Script (PowerShell 5.1 compatible)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Join-Path $ScriptDir ".."

Write-Host "=== SOC Command Center Setup ===" -ForegroundColor Cyan

# Verificar Python
$PythonPath = "python"
if (-not (Get-Command $PythonPath -ErrorAction SilentlyContinue)) {
    Write-Error "Python no encontrado en PATH. Instale Python 3.11+"
    exit 1
}

# Verificar Node.js
$NodePath = "node"
if (-not (Get-Command $NodePath -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js no encontrado en PATH. Instale Node.js 18+"
    exit 1
}

Write-Host "Python: $($PythonPath --version)" -ForegroundColor Green
Write-Host "Node: $($NodePath --version)" -ForegroundColor Green

# Crear entorno virtual si no existe
$VenvPath = Join-Path $ProjectRoot "backend\venv"
if (-not (Test-Path -LiteralPath $VenvPath)) {
    Write-Host "Creando entorno virtual Python..." -ForegroundColor Yellow
    & $PythonPath -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Error creando entorno virtual"
        exit 1
    }
}

$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
$PipExe = Join-Path $VenvPath "Scripts\pip.exe"

Write-Host "Actualizando pip..." -ForegroundColor Yellow
& $PipExe install --quiet --upgrade pip

Write-Host "Instalando dependencias del backend..." -ForegroundColor Yellow
& $PipExe install --quiet fastapi uvicorn sqlalchemy pydantic python-dotenv bcrypt python-multipart python-jose[cryptography] jwt pydantic-settings reportlab matplotlib requests pandas numpy

Write-Host "Instalando dependencias del frontend..." -ForegroundColor Yellow
Set-Location "$ProjectRoot\frontend"
npm install

Write-Host "=== Setup completado ===" -ForegroundColor Green
Write-Host "Para iniciar: .\scripts\start_soc.ps1" -ForegroundColor Cyan