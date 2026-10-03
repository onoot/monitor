# Automated preflight for the docker stand, duplicating MONITORING.md as a
# script with a non-zero exit, so it can gate a deployment.
#
#   .\deploy\stand-verify.ps1                      # without admin-API checks
#   .\deploy\stand-verify.ps1 -Password ops@1234   # also checks /api/flags & /api/checker
#
# Truth is asserted from the capture files, not from a single HTTP status: the
# gateway logs an attempt the moment it accepts the connection, so "did this
# request reach the gateway and what did it decide" is read back from the JSONL
# the file store wrote. Every probe carries a unique marker, and the marker must
# appear in exactly one expected file with the expected outcome.
#
# NOTE: this file must stay ASCII-only (see stand-up.ps1).
#
param([string]$Password = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$GW = '10.77.0.254'
$NET = 'ad-stand'
# Capture files are named by the UTC date of the event (the gateway stamps each
# attempt with `new Date().toISOString()`), while the host clock can be a day
# ahead -- after local midnight a host-local date would look in tomorrow's file
# and every marker check would "fail". Read the same clock the gateway wrote.
$today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
$fail = 0

function Ok($name) { Write-Host "  ok   $name" }
function F($name)  { Write-Host "  FAIL $name" -ForegroundColor Red; $script:fail += 1 }

function Probe([string]$ip, [string]$hostHeader, [string]$url, [string]$method = 'GET', [string]$body = '') {
  $a = @('run', '--rm', '--network', "$NET", '--ip', $ip, 'curlimages/curl:latest', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-X', $method, '-H', "Host: $hostHeader")
  if ($body) { $a += @('-d', $body) }
  # NB: `${GW}` -- a bare `$GW:` would parse as a scope-qualified variable and
  # silently empty the address, and every probe would "succeed" with a DNS error.
  $a += "http://${GW}:9090$url"
  return (& docker @a)
}

function LineWith([string]$file, [string]$marker) {
  if (-not (Test-Path $file)) { return $null }
  return Get-Content $file -ErrorAction SilentlyContinue | Where-Object { $_.Contains($marker) } | Select-Object -First 1
}

$checkerFile = "$root\services\monitoring\data\checker\$today.jsonl"
$cursFile = "$root\services\monitoring\data\curs\$today.jsonl"
$stamp = Get-Date -Format 'HHmmssfff'

Write-Host '1. live endpoints'
$ui = (Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8787/').StatusCode
if ($ui -eq 200) { Ok 'UI on :8787' } else { F "UI: $ui" }
$h = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/health'
if ($h.ok) { Ok 'health' } else { F 'health' }

Write-Host '2. route reaches the service (host, as operator)'
$r = (Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:9090/' -Headers @{Host='curs.local'}).StatusCode
if ($r -gt 0 -and $r -ne 502) { Ok "curs.local -> $r" } else { F "curs.local -> $r" }

Write-Host '3. team subnet is policed'
$mkA = "vk$stamp" + 'a'
$bcode = Probe '10.77.0.20' 'curs.local' "/.git/config?x=$mkA"
$line = LineWith $cursFile $mkA
if ($line -and (($line | ConvertFrom-Json).outcome) -eq 'blocked') { Ok "team .git blocked (code $bcode)" } else { F "team .git not captured as blocked (code $bcode)" }

Write-Host '4. checker and stranger are forwarded'
$mkB = "vk$stamp" + 'b'
$ccode = Probe '10.77.0.250' 'curs.local' "/probe?x=$mkB"
$line = LineWith $checkerFile $mkB
if ($line -and (($line | ConvertFrom-Json).outcome) -eq 'forwarded') { Ok "checker forwarded (code $ccode)" } else { F "checker not captured as forwarded (code $ccode)" }
$mkC = "vk$stamp" + 'c'
$ucode = Probe '10.77.0.130' 'curs.local' "/user/login?x=$mkC&u=a" 'POST' "login=admin' or '1'='1"
$line = LineWith $cursFile $mkC
if ($line -and (($line | ConvertFrom-Json).outcome) -eq 'forwarded') { Ok "unlisted forwarded (code $ucode)" } else { F "unlisted not captured as forwarded (code $ucode)" }

Write-Host '5. flags and artifacts land in files'
$flag = 'flag{verify_' + $stamp + '}'
$md5 = [guid]::NewGuid().ToString('N')
$mkD = "vk$stamp" + 'd'
Probe '10.77.0.250' 'magiclib.local' "/pay?x=$mkD&token=$md5" 'POST' $flag | Out-Null
$line = LineWith $checkerFile $mkD
if ($line -and $line.Contains($flag) -and $line.Contains($md5)) { Ok 'checker file has flag + md5 artifact' } else { F 'flag/md5 not captured via checker' }
$mkE = "vk$stamp" + 'e'
$flag2 = 'flag{team_' + $stamp + '}'
Probe '10.77.0.20' 'curs.local' "/api/ping?x=$mkE" 'POST' $flag2 | Out-Null
$line = LineWith $cursFile $mkE
if ($line -and $line.Contains($flag2)) { Ok 'team file has flag' } else { F 'team flag not captured' }

if ($Password) {
  Write-Host '6. admin session and checker section'
  $login = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/login' -Method Post -ContentType 'application/json' -Body (@{login='ops';password=$Password} | ConvertTo-Json)
  $auth = @{Authorization = "Bearer $($login.token)"}
  $flags = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/flags' -Headers $auth
  if ($flags.flags.Count -gt 0) { Ok '/api/flags sees flags' } else { F '/api/flags empty' }
  $chk = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/checker' -Headers $auth
  if ($chk.attempts.Count -gt 0) { Ok '/api/checker sees checker' } else { F '/api/checker empty' }
}

if ($fail -eq 0) {
  Write-Host ''
  Write-Host 'VERIFY: PASS' -ForegroundColor Green
} else {
  Write-Host ''
  Write-Host "VERIFY: $fail failures" -ForegroundColor Red
  exit 1
}