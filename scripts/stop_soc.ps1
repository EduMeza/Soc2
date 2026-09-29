# SOC Command Center - Stop SOC (PowerShell 5.1 compatible)
$ErrorActionPreference = "Continue"

Write-Host "=== Deteniendo SOC 24x7 ===" -ForegroundColor Yellow

# Detener procesos de uvicorn/python en puerto 8000
$backendProcs = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($backendProcs) {
    foreach ($pid in $backendProcs) {
        try {
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($proc -and $proc.Path -like "*python*" -or $proc.Path -like "*uvicorn*") {
                Write-Host "Deteniendo proceso $pid ($($proc.ProcessName))..." -ForegroundColor Yellow
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

# Detener procesos de node/Vite en puerto 5173
$frontendProcs = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($frontendProcs) {
    foreach ($pid in $frontendProcs) {
        try {
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($proc -and ($proc.ProcessName -like "*node*" -or $proc.Path -like "*vite*")) {
                Write-Host "Deteniendo proceso $pid ($($proc.ProcessName))..." -ForegroundColor Yellow
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

# Fallback: matar todos los python del proyecto
Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Soc2*backend*venv*" } | ForEach-Object {
    Write-Host "Deteniendo proceso python residual $($_.Id)..." -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

# Fallback: matar node/Vite residuales
Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Soc2*frontend*" -or $_.CommandLine -like "*vite*" } | ForEach-Object {
    Write-Host "Deteniendo proceso node residual $($_.Id)..." -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== SOC detenido ===" -ForegroundColor Green