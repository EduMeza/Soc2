. (Join-Path $PSScriptRoot 'runtime.ps1')
try {
    $Frontend = Join-Path $ProjectRoot 'frontend'
    $Vite = Join-Path $Frontend 'node_modules\vite\bin\vite.js'
    if (-not (Test-Path $Vite)) { throw 'Ejecute setup.ps1' }
    Start-SocProcess 'frontend' $FrontendPort (Get-Command node).Source @(('"' + $Vite + '"'),'--host','localhost','--port',"$FrontendPort",'--strictPort') $Frontend "http://localhost:$FrontendPort"
} catch { Write-Error $_; exit 1 }
