Set-StrictMode -Version Latest

function Test-CyberStormObserverReady([string] $Path, [int] $ExpectedPid) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $Path).Length -le 0) { return $false }
    # The observer writes this only after its initialization/inventory work.
    # A prior "attached" line says only that DllMain started a thread.
    return [bool](Select-String -LiteralPath $Path -SimpleMatch -Quiet -Pattern "observer=ready pid=$ExpectedPid ")
}
