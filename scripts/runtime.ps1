$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Runtime = Join-Path $ProjectRoot '.runtime'
if ($env:APP_ENV -eq 'test' -and $env:SOC_TEST_RUNTIME_DIR) { $Runtime = $env:SOC_TEST_RUNTIME_DIR }
$BackendPort = if ($env:SOC_BACKEND_PORT) { [int]$env:SOC_BACKEND_PORT } else { 8000 }
$FrontendPort = if ($env:SOC_FRONTEND_PORT) { [int]$env:SOC_FRONTEND_PORT } else { 5173 }
if (-not (Test-Path (Join-Path $ProjectRoot 'backend\app\main.py'))) { throw 'PROJECT ROOT incorrecto' }
if (-not (Test-Path $Runtime)) { New-Item -ItemType Directory -Path $Runtime | Out-Null }

function Wait-Http([string]$Url, [int]$Timeout = 45) {
    $Deadline = (Get-Date).AddSeconds($Timeout)
    do {
        try {
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($Response.StatusCode -eq 200) {
                if ($Url -like '*/api/health' -and ($Response.Content | ConvertFrom-Json).status -ne 'ok') { throw 'Health inválido' }
                return
            }
        } catch { }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $Deadline)
    throw "ERROR: sin respuesta válida en $Url"
}

function Start-SocProcess([string]$Name, [int]$Port, [string]$Exe, [string[]]$Arguments, [string]$Directory, [string]$Url) {
    if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "Puerto $Port ocupado; no se iniciará otro proceso" }
    $Process = Start-Process -FilePath $Exe -ArgumentList $Arguments -WorkingDirectory $Directory -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $Runtime "$Name.log") -RedirectStandardError (Join-Path $Runtime "$Name.error.log")
    $Process.Id | Set-Content (Join-Path $Runtime "$Name.pid")
    $Process.StartTime.ToUniversalTime().Ticks | Set-Content (Join-Path $Runtime "$Name.started")
    Wait-Http $Url
    Write-Host "$Name PID=$($Process.Id) OK $Url"
}
