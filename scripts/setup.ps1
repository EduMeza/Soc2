$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $ProjectRoot 'backend\requirements.txt'))) { throw 'PROJECT ROOT incorrecto' }
$Venv = Join-Path $ProjectRoot 'backend\venv'
if (-not (Test-Path $Venv)) {
    & python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear venv' }
}
$Python = Join-Path $Venv 'Scripts\python.exe'
& $Python -m pip install -r (Join-Path $ProjectRoot 'backend\requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Instalación Python fallida' }
& npm.cmd --prefix (Join-Path $ProjectRoot 'frontend') ci
if ($LASTEXITCODE -ne 0) { throw 'Instalación frontend fallida' }

Write-Host 'Setup completo.' -ForegroundColor Green
Write-Host 'Pasos siguientes:' -ForegroundColor Cyan
Write-Host '  1. Configure .env usando .env.example (JWT_SECRET obligatorio, INITIAL_ADMIN_USERNAME/PASSWORD opcionales)' -ForegroundColor Gray
Write-Host '  2. La migración de datos legacy NO se ejecuta automáticamente.' -ForegroundColor Yellow
Write-Host '  3. Si necesita migrar una instalación legacy existente, detenga el backend y ejecute:' -ForegroundColor Gray
Write-Host '       .\backend\venv\Scripts\python.exe .\backend\migrate.py' -ForegroundColor Gray
Write-Host '     La migración genera backup en _backup/ antes de modificar data/soc.db.' -ForegroundColor Gray
Write-Host '  4. Para iniciar el SOC: .\scripts\start_soc.ps1' -ForegroundColor Gray
