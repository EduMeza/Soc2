. (Join-Path $PSScriptRoot 'runtime.ps1')
try {
    foreach ($Name in @('backend','frontend')) {
        $PidFile = Join-Path $Runtime "$Name.pid"
        $StartedFile = Join-Path $Runtime "$Name.started"
        if (Test-Path $PidFile) {
            $ProcessId = [int](Get-Content $PidFile)
            $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
            if ($Process) {
                if (-not (Test-Path $StartedFile)) { throw "No se puede verificar propiedad de PID $ProcessId" }
                if ($Process.StartTime.ToUniversalTime().Ticks -ne [long](Get-Content $StartedFile)) { throw "PID $ProcessId reutilizado; no se detendrá" }
                & taskkill.exe /PID $ProcessId /T /F | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "No se pudo detener PID $ProcessId" }
                $Process.WaitForExit(10000) | Out-Null
            }
            Remove-Item $PidFile
            if (Test-Path $StartedFile) { Remove-Item $StartedFile }
        }
    }
    foreach ($Port in @($BackendPort,$FrontendPort)) {
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "Puerto $Port sigue abierto; proceso ajeno no detenido" }
    }
    Write-Host "SOC detenido; puertos $BackendPort y $FrontendPort cerrados."
} catch { Write-Error $_; exit 1 }
