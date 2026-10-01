. (Join-Path $PSScriptRoot 'runtime.ps1')
try {
    $Python = Join-Path $ProjectRoot 'backend\venv\Scripts\python.exe'
    if (-not (Test-Path $Python)) { throw 'Ejecute setup.ps1' }
    Start-SocProcess 'backend' $BackendPort $Python @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port',"$BackendPort") (Join-Path $ProjectRoot 'backend') "http://127.0.0.1:$BackendPort/api/health"
} catch { Write-Error $_; exit 1 }
