# Stops the backend and tunnel started by start.ps1. Also sweeps for any
# stray python.exe/cloudflared.exe processes tied to this project, in case
# a .run/*.pid file is stale (e.g. the machine was rebooted).

$root = $PSScriptRoot

foreach ($name in @("backend", "tunnel")) {
    $pidFile = "$root\.run\$name.pid"
    if (Test-Path $pidFile) {
        $trackedId = Get-Content $pidFile
        Stop-Process -Id $trackedId -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile -ErrorAction SilentlyContinue
        Write-Host "Stopped $name (PID $trackedId)"
    }
}

Get-CimInstance Win32_Process -Filter "Name = 'python.exe' or Name = 'cloudflared.exe'" |
    Where-Object { $_.CommandLine -like "*$root*" } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host "Stopped stray $($_.Name) (PID $($_.ProcessId))"
    }

Write-Host "Done. Nothing from this project should be running or exposed now."
