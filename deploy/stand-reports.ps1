# Regenerate the static analysis reports for every service from the stand's own
# live capture, so `reports/<service>/` always reflects the traffic the monitor
# actually saw. Run this after a run; the dashboard's Reports tab reads what it
# writes.
#
#   .\deploy\stand-reports.ps1
#
# Each service report merges:
#   * the source scan (SAST) of services/<service>
#   * services/monitoring/data/<service>/<date>.jsonl, the stand capture for that
#     service (team and operator traffic, classified by the gateway)
#
# The checker's cross-cutting traffic lives in data/checker and is NOT folded
# into each service report: a checker record carries no service field, so mixing
# it in would attribute every service's routes to every other. The stand-wide
# view of checker traffic is the dashboard's digest (/api/digest).
#
# NOTE: this file must stay ASCII-only (see stand-up.ps1).

param(
  [string]$ConfigDir = 'configs',
  [string]$DataDir = 'services\monitoring\data',
  [string[]]$Services = @('curs', 'magiclib', 'AltayCoin', 'Omnyhub')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$fail = 0
foreach ($service in $Services) {
  $config = Join-Path $ConfigDir "$service.json"
  $monitor = Join-Path $DataDir $service
  if (-not (Test-Path $config)) {
    Write-Host "  skip $service (no $config)"
    continue
  }
  $scanArgs = @('-m', 'ad', 'scan', '--config', $config)
  if (Test-Path $monitor) {
    $scanArgs += @('--monitor', $monitor)
  }
  Write-Host "  report $service"
  & python @scanArgs
  if ($LASTEXITCODE -ne 0) { $script:fail += 1 }
}

if ($fail -eq 0) {
  Write-Host ''
  Write-Host 'REPORTS: OK' -ForegroundColor Green
} else {
  Write-Host ''
  Write-Host "REPORTS: $fail failures" -ForegroundColor Red
  exit 1
}
