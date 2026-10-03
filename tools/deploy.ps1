param(
  [string]$LogDir = "",
  [string[]]$Only = @()
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
$Root = Join-Path $repo 'services'
if ($LogDir -eq "") { $LogDir = Join-Path $env:TEMP 'opencode\altay\logs' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Write-Output "repo = $repo"
Write-Output "root = $Root"

$all = @('curs', 'magiclib', 'AltayCoin', 'Omnyhub')
if ($Only.Count -gt 0) { $all = $Only }

$failures = @()
foreach ($s in $all) {
    $compose = Join-Path $Root (Join-Path $s 'docker-compose.yml')
    $log = Join-Path $LogDir "$s.log"
    # Buffer the whole run and write once: repeated Out-File -Append calls fail
    # with IOException while a previous handle is still closing, which reported
    # a healthy service as failed.
    $output = docker compose -f $compose up -d --build 2>&1 | Out-String
    $code = $LASTEXITCODE
    $payload = @("=== $s : $(Get-Date -Format o) ===", $output, "exit=$code") -join [Environment]::NewLine
    try {
        [System.IO.File]::WriteAllText($log, $payload, [System.Text.UTF8Encoding]::new($false))
    } catch {
        Write-Output ("[{0}] log write failed: {1}" -f $s, $_.Exception.Message)
    }
    if ($code -ne 0) { $failures += $s }
    Write-Output ("[{0}] exit={1} log={2}" -f $s, $code, $log)
}

Write-Output "--- containers ---"
docker ps -a --format '{{.Names}}|{{.Status}}|{{.Ports}}'
if ($failures.Count -gt 0) { Write-Output ("FAILED: " + ($failures -join ', ')) } else { Write-Output "ALL OK" }