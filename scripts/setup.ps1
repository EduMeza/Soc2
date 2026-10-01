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
& $Python (Join-Path $ProjectRoot 'backend\migrate.py')
if ($LASTEXITCODE -ne 0) { throw 'Migración fallida' }
Write-Host 'Setup completo. Configure .env antes de iniciar.'
