# Builds the frontend, launches the backend + a Cloudflare quick tunnel,
# and prints the public URL. Run stop.ps1 to shut everything down.
#
# Always stops any leftover instances of itself first — this project's
# waitress/cloudflared processes have a habit of outliving a closed terminal
# on Windows, and a stale backend silently serving old code is worse than
# a clean restart.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

Write-Host "Stopping any stale instances..."
Get-CimInstance Win32_Process -Filter "Name = 'python.exe' or Name = 'cloudflared.exe'" |
    Where-Object { $_.CommandLine -like "*$root*" } |
    ForEach-Object {
        Write-Host "  stopping PID $($_.ProcessId) ($($_.Name))"
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Force -Path "$root\.run" | Out-Null

Write-Host "Building frontend..."
Push-Location "$root\frontend"
npm run build
Pop-Location

Write-Host "Starting backend..."
$backend = Start-Process -FilePath "$root\.venv\Scripts\python.exe" -ArgumentList "run.py" `
    -PassThru -RedirectStandardOutput "$root\.run\backend.log" -RedirectStandardError "$root\.run\backend.err.log" `
    -WindowStyle Hidden
$backend.Id | Out-File "$root\.run\backend.pid" -Encoding ascii
Start-Sleep -Seconds 2
Get-Content "$root\.run\backend.log" -ErrorAction SilentlyContinue

$cloudflaredPath = "$root\bin\cloudflared.exe"
if (-not (Test-Path $cloudflaredPath)) {
    Write-Host ""
    Write-Host "bin\cloudflared.exe not found - backend is running on http://127.0.0.1:5000 only."
    Write-Host "See README > 'Exposing this beyond localhost' to add a public tunnel."
    exit 0
}

Write-Host "Starting Cloudflare tunnel..."
$tunnel = Start-Process -FilePath $cloudflaredPath -ArgumentList "tunnel", "--url", "http://127.0.0.1:5000" `
    -PassThru -RedirectStandardOutput "$root\.run\tunnel.log" -RedirectStandardError "$root\.run\tunnel.err.log" `
    -WindowStyle Hidden
$tunnel.Id | Out-File "$root\.run\tunnel.pid" -Encoding ascii

$publicUrl = $null
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    $match = Select-String -Path "$root\.run\tunnel.err.log" -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($match) {
        $publicUrl = $match.Matches[0].Value
        break
    }
}

Write-Host ""
Write-Host "Local:  http://127.0.0.1:5000"
if ($publicUrl) {
    Write-Host "Public: $publicUrl"
} else {
    Write-Host "Tunnel did not report a URL within 20s - check .run\tunnel.err.log"
}
Write-Host ""
Write-Host "Run .\stop.ps1 to shut everything down."
