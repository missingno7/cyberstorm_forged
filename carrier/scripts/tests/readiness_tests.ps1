$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'Readiness.ps1')
$file = Join-Path ([IO.Path]::GetTempPath()) ("cs-ready-" + [guid]::NewGuid().ToString('N') + '.log')
try {
    New-Item -ItemType File -Path $file | Out-Null
    if (Test-CyberStormObserverReady $file 4242) { throw 'empty observer log passed readiness' }
    Set-Content -LiteralPath $file -Value 'observer=ready pid=9999 inventory=complete'
    if (Test-CyberStormObserverReady $file 4242) { throw 'wrong PID passed readiness' }
    Set-Content -LiteralPath $file -Value 'observer=attached pid=4242 tid=1'
    if (Test-CyberStormObserverReady $file 4242) { throw 'attached-only log passed readiness' }
    Set-Content -LiteralPath $file -Value @('observer=attached pid=4242 tid=1', 'observer=ready pid=4242 inventory=complete hooks_installed=1')
    if (-not (Test-CyberStormObserverReady $file 4242)) { throw 'correct ready marker did not pass readiness' }
    Write-Host 'observer readiness fixtures: PASS'
} finally {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}
