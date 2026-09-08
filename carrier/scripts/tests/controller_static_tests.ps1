$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Get-Content -Raw (Join-Path $root 'Invoke-CyberStormBounded.ps1')
$readiness = Get-Content -Raw (Join-Path $root 'Readiness.ps1')
$mustContain = @(
  '[ValidateRange(1, 45)] [int] $DurationSeconds = 25',
  'b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181',
  '"$quotedExe /Q /R:1"',
  '$job.Contains($candidate.Handle)',
  '[CarrierPassiveInspector]::DisplayModes()',
  'GetWindowLongCompat',
  'DISPLAY_OR_PRINTER_UNION',
  'dmDisplayOrientation',
  'TH32CS_SNAPMODULE32',
  'CreateToolhelp32Snapshot',
  'Module32First',
  'Module32Next',
  '[CarrierPassiveInspector]::ModulePaths($gamePid)',
  "[CarrierPassiveInspector]::HasModule(`$modulePaths, 'dxwnd.dll')",
  'module_paths_discovery',
  'module_paths_timeout',
  'Test-CyberStormObserverReady',
  '''--attach'', "$gamePid", ''--dll'', $observer, ''--expected-image'', $target, ''--report'', $report.attach_log',
  '$job.Terminate()'
)
foreach ($needle in $mustContain) { if (-not $source.Contains($needle)) { throw "missing required controller guard: $needle" } }
if (-not $readiness.Contains('observer=ready pid=$ExpectedPid ')) { throw 'readiness check does not require the exact ready PID token' }
if ($source -match 'ChangeDisplaySettings|SetDisplayConfig|SetCursorPos|SetForegroundWindow|SendInput|PrintWindow') { throw 'controller contains forbidden display/input/window-control API' }
if ($source -match "GetField\('_handle'|BindingFlags.*NonPublic") { throw 'controller must use the reviewed public Job Object API, not private-handle reflection' }
if ($source -match 'process\.Modules') { throw 'controller must use Toolhelp module enumeration so a 64-bit controller sees WOW64 modules' }
Write-Host 'controller static guards: PASS'
