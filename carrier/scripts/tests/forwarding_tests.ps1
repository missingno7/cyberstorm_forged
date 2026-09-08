$ErrorActionPreference = 'Stop'
$carrier = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
. (Join-Path $carrier '../port_forge/scripts/win32/native_process.ps1')
$fixtureDir = Join-Path $env:TEMP ('cyberstorm-forward-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $fixtureDir | Out-Null
$oldLog = $env:CS_OBSERVER_LOG
try {
    $env:CS_OBSERVER_LOG = Join-Path $fixtureDir 'observer.log'
    $resultPath = Join-Path $fixtureDir 'result.txt'
    $exitCode = Invoke-NativeToLog (Join-Path $carrier 'build/cs_observer_forwarding_fixture.exe') @(
        (Join-Path $carrier 'build/cs_observer.dll'),
        (Join-Path $carrier 'build/cs_observer_fixture_provider.dll'),
        $resultPath
    ) (Join-Path $fixtureDir 'process.log') 10 'synthetic observer forwarding'
    if ($exitCode -ne 0) { throw "fixture failed ($exitCode): $fixtureDir" }
    $log = Get-Content -Raw $env:CS_OBSERVER_LOG
    foreach ($required in @('hook_install name=LoadLibraryA', 'hook_install name=GetProcAddress', 'name=cs_fixture_named result=', 'name=#7 result=')) {
        if (-not $log.Contains($required)) { throw "missing actual hook evidence: $required" }
    }
    if (-not (Get-Content -Raw $resultPath).Contains('forwarding_equivalent=true')) { throw 'missing equivalence result' }
    Get-Content $resultPath
    "PASS synthetic forwarding; evidence: $fixtureDir"
} finally {
    if ($null -eq $oldLog) { Remove-Item Env:CS_OBSERVER_LOG -ErrorAction SilentlyContinue } else { $env:CS_OBSERVER_LOG = $oldLog }
}
