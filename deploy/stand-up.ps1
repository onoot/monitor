# Bring up the monitoring stand in one command: build the monitoring image
# (unless told not to), start the monitoring project, and wait until the gateway
# is healthy before reporting.
#
# The watched services are NOT started here. They run isolated from their own
# compose files, and this script only joins the monitoring container to the
# networks they created, so the services must already be up.
#
#   .\deploy\stand-up.ps1            # build + up
#   .\deploy\stand-up.ps1 -SkipBuild # up only, image already built
#
# NOTE: this file must stay ASCII-only: Windows PowerShell 5.1 misreads UTF-8
# without a BOM, so any non-ASCII byte in a string becomes a parse error.
#
param(
  [switch]$SkipBuild,
  [int]$WaitSeconds = 120
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $SkipBuild) {
  docker compose build monitoring
  if ($LASTEXITCODE -ne 0) { Write-Error 'build failed'; exit 1 }
}

docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Error 'up failed'; exit 1 }

$deadline = (Get-Date).AddSeconds($WaitSeconds)
$health = 'starting'
do {
  $health = docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}starting{{end}}' ad-monitoring 2>$null
  if ($health -eq 'healthy') { break }
  Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

if ($health -ne 'healthy') {
  Write-Host 'ad-monitoring is not healthy:' -ForegroundColor Red
  docker compose ps
  exit 1
}

Write-Host ''
Write-Host 'stand is up:' -ForegroundColor Green
Write-Host "  ingress   http://127.0.0.1:9090   (participants / checker)"
Write-Host "  operator  http://127.0.0.1:8787/  (UI, login: ops)"
Write-Host "  data      $root\services\monitoring\data\"
Write-Host ''
Write-Host 'preflight: .\deploy\stand-verify.ps1'