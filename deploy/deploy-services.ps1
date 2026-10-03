# deploy-services.ps1
#
# Bring up every service project under -Dir with its published (host) ports
# stripped, so the only way into a service from outside Docker is the gateway.
# This is the deploy step the operator runs before a game: services publish
# nothing to the host, and the monitoring UI then discovers each service's name
# and port from its compose file and occupies the same port on the gateway.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File deploy\deploy-services.ps1 -Dir ".\services из wm - запустить"
#   powershell -ExecutionPolicy Bypass -File deploy\deploy-services.ps1 -Dir ".\services из wm - запустить" -WhatIf
#
# For every docker-compose.yml / compose.yaml found one level below -Dir the
# script writes a sibling override declaring `ports: !override []` for each
# service, validates the merged file with `docker compose config`, and runs
# `up -d`. The override is left on disk (it is harmless and documents what was
# applied); deleting it and re-running `up` restores the published ports.
#
# Networks are intentionally untouched: the compose files themselves declare the
# isolated networks (cursnet, magicnet, omninet, app-network) that the gateway
# joins later, so stripping ports does not change how the services are found.

param(
    [string]$Dir,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = '.'
}
if (-not (Test-Path -LiteralPath $Dir -PathType Container)) {
    Write-Error "directory does not exist: $Dir"
    exit 2
}
$root = (Resolve-Path -LiteralPath $Dir).Path

function Invoke-Docker {
    param([string[]]$Arguments)
    # PowerShell 5.1 turns a native command's stderr lines into error records,
    # and with $ErrorActionPreference='Stop' that aborts on any compose
    # progress line (compose v5 writes even "Creating ..." to stderr). Scope the
    # preference to Continue while the child runs and judge success by the exit
    # code, so a warning can never abort a deployment.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $errFile = Join-Path $env:TEMP ("dc.err." + [guid]::NewGuid().ToString('N') + '.txt')
        $output = @(& docker @Arguments 2> $errFile)
        $code = $LASTEXITCODE
        $stderr = @()
        if (Test-Path -LiteralPath $errFile) {
            $stderr = @(Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue)
            Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
        }
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        $text = (($output) -join "`n")
        if ($stderr.Count -gt 0) { $text = $text + "`n" + (($stderr) -join "`n") }
        Write-Error "docker failed (exit $code):`n$text"
        exit 1
    }
    return $output
}

function Get-ComposeProjects {
    param([string]$Base)
    $found = @()
    foreach ($proj in Get-ChildItem -LiteralPath $Base -Directory) {
        $compose = Get-ChildItem -LiteralPath $proj.FullName -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'docker-compose.yml' -or $_.Name -eq 'compose.yaml' -or $_.Name -eq 'compose.yml' } |
            Select-Object -First 1
        if ($null -ne $compose) {
            $found += , $compose
        }
    }
    return $found
}

function Get-ServiceNames {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    $inServices = $false
    foreach ($raw in ($Text -split "\r?\n")) {
        $line = $raw.TrimEnd()
        if ($line.Trim() -eq '' -or $line.Trim().StartsWith('#')) { continue }
        $match = [regex]::Match($line, '^(\s*)')
        $indent = $match.Groups[1].Value.Length
        $trimmed = $line.Trim()
        if (-not $inServices) {
            if ($indent -eq 0 -and $trimmed -eq 'services:') { $inServices = $true }
            continue
        }
        if ($indent -eq 0) { $inServices = $false; continue }
        if ($indent -eq 2 -and $trimmed -match '^[A-Za-z0-9_.-]+:$') {
            $names.Add($trimmed.Substring(0, $trimmed.Length - 1))
        }
    }
    return , @($names)
}

$projects = @(Get-ComposeProjects -Base $root)
if ($projects.Count -eq 0) {
    Write-Host "no docker-compose.yml / compose.yaml found one level below: $root"
    exit 0
}

Write-Host "deploying $($projects.Count) project(s) from $root"
$done = 0
foreach ($compose in $projects) {
    $dir = $compose.Directory.FullName
    $projectName = $compose.Directory.Name
    $content = [System.IO.File]::ReadAllText($compose.FullName)
    $names = Get-ServiceNames -Text $content
    if ($names.Count -eq 0) {
        Write-Host "[$projectName] skipped: no services: block in $($compose.Name)"
        continue
    }

    $overridePath = Join-Path $dir "_strip.$($compose.BaseName).override.yml"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('services:')
    foreach ($n in $names) {
        [void]$sb.AppendLine("  ${n}:")
        [void]$sb.AppendLine('    ports: !override []')
    }
    [System.IO.File]::WriteAllText($overridePath, $sb.ToString(), [System.Text.Encoding]::ASCII)

    $baseArgs = @('-f', $compose.FullName, '-f', $overridePath)
    Write-Host "[$projectName] services: $($names -join ', '); host ports stripped"
    if ($WhatIf) {
        Write-Host "  (WhatIf) docker compose $($baseArgs -join ' ') up -d"
        continue
    }

    Invoke-Docker -Arguments (@('compose') + $baseArgs + @('config', '-q')) | Out-Null
    Invoke-Docker -Arguments (@('compose') + $baseArgs + @('up', '-d', '--quiet-pull')) | Out-Null
    $done++
    Write-Host "  OK: $($names.Count) service(s) up, nothing published to the host"
}

Write-Host "done: $done project(s) up"
Write-Host 'next: connect to the monitoring UI (http://127.0.0.1:8787, login ops), open Services,'
Write-Host 'rescan and click "add" on each candidate to occupy its port on the gateway.'