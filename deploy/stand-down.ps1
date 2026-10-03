# Tear the stand down. Named volumes (databases) and the capture bind mount
# under services/monitoring/data are kept; -Clean removes the volumes too.
#
#   .\deploy\stand-down.ps1
#   .\deploy\stand-down.ps1 -Clean
#
param([switch]$Clean)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
docker compose down $(if ($Clean) { '-v' })