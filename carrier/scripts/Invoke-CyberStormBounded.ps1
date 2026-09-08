[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PrivateDxWndDir,
    [Parameter(Mandatory)] [string] $PrivateConfigPath,
    [Parameter(Mandatory)] [string] $PrivateAssetsDir,
    [Parameter(Mandatory)] [string] $ObserverDll,
    [Parameter(Mandatory)] [string] $AttachHelper,
    [Parameter(Mandatory)] [string] $ReportPath,
    [Parameter(Mandatory)] [string] $LogDir,
    [ValidateRange(1, 45)] [int] $DurationSeconds = 25,
    [string] $NativeProcessHelper,
    [string] $ObserverLogPath,
    [switch] $PreflightOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $NativeProcessHelper) { $NativeProcessHelper = Join-Path $PSScriptRoot '../../port_forge/scripts/win32/native_process.ps1' }
. (Join-Path $PSScriptRoot 'Readiness.ps1')

# This controller owns the bounded bootstrap lifecycle. It never starts the
# game directly, sends input, activates windows, or changes a display mode.
# DxWnd receives the documented /Q /R:1 command from its private working dir.

$ExpectedSha256 = 'b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181'
$ControllerVersion = '2026-09-08.2'

function Resolve-ExistingFile([string] $Path, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label does not exist or is not a file: $Path" }
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
}
function Resolve-ExistingDirectory([string] $Path, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Label does not exist or is not a directory: $Path" }
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path).TrimEnd('\\')
}
function Require-FreshFile([string] $Path, [string] $Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "$Label parent does not exist: $parent" }
    if (Test-Path -LiteralPath $full) { throw "$Label must be a fresh path: $full" }
    return $full
}
function Require-FreshDirectory([string] $Path, [string] $Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "$Label parent does not exist: $parent" }
    if (Test-Path -LiteralPath $full) { throw "$Label must be a fresh path: $full" }
    return $full
}
function Same-Path([string] $Left, [string] $Right) {
    return [String]::Equals([IO.Path]::GetFullPath($Left).TrimEnd('\\'), [IO.Path]::GetFullPath($Right).TrimEnd('\\'), [StringComparison]::OrdinalIgnoreCase)
}
function Get-RemainingMilliseconds([datetime] $Deadline) {
    return [Math]::Max(0, [int][Math]::Floor(($Deadline - [datetime]::UtcNow).TotalMilliseconds))
}
function Get-ExistingNamedProcesses([string[]] $Names) {
    $wanted = @{}; foreach ($name in $Names) { $wanted[$name.ToLowerInvariant()] = $true }
    @(Get-CimInstance Win32_Process | Where-Object { $wanted.ContainsKey(([IO.Path]::GetFileNameWithoutExtension($_.Name)).ToLowerInvariant()) })
}
function Write-Event([string] $Name, [System.Collections.IDictionary] $Fields = @{}) {
    $record = [ordered]@{ utc = [datetime]::UtcNow.ToString('o'); event = $Name }
    foreach ($key in $Fields.Keys) { $record[$key] = $Fields[$key] }
    ($record | ConvertTo-Json -Compress -Depth 6) | Add-Content -LiteralPath $script:EventLogPath -Encoding UTF8
}
function Get-ProcessPath([int] $Id) {
    try { return [IO.Path]::GetFullPath((Get-Process -Id $Id -ErrorAction Stop).Path) } catch { return $null }
}
function Get-ProcessSample([int] $Id) {
    try {
        $p = Get-Process -Id $Id -ErrorAction Stop
        return [ordered]@{ pid=$Id; priority=$p.BasePriority; start_utc=$p.StartTime.ToUniversalTime().ToString('o'); cpu_seconds=[Math]::Round($p.TotalProcessorTime.TotalSeconds,3); responding=$p.Responding }
    } catch { return $null }
}

if ($null -eq ('CarrierPassiveInspector' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public sealed class CarrierWindowSample {
    public long hwnd;
    public string title;
    public long style;
    public long exstyle;
    public int client_width;
    public int client_height;
    public bool visible;
}

public static class CarrierPassiveInspector {
    private const int ENUM_CURRENT_SETTINGS = -1;
    private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x00000001;
    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceKey;
    }
    [StructLayout(LayoutKind.Explicit)] private struct DISPLAY_OR_PRINTER_UNION {
        // The 16-byte union is DISPLAY_POSITION / orientation fields for a
        // display DEVMODE.  Treating it as printer shorts reads positionX as
        // orientation on multi-monitor desktops.
        [FieldOffset(0)] public int dmPositionX;
        [FieldOffset(4)] public int dmPositionY;
        [FieldOffset(8)] public int dmDisplayOrientation;
        [FieldOffset(12)] public int dmDisplayFixedOutput;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmDeviceName;
        public short dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
        public int dmFields;
        public DISPLAY_OR_PRINTER_UNION dmUnion;
        public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency, dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2, dmPanningWidth, dmPanningHeight;
    }
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] private struct MODULEENTRY32 {
        public int dwSize;
        public int th32ModuleID;
        public int th32ProcessID;
        public int GlblcntUsage;
        public int ProccntUsage;
        public IntPtr modBaseAddr;
        public int modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string szExePath;
    }
    private const uint TH32CS_SNAPMODULE = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool EnumDisplayDevices(string device, int index, ref DISPLAY_DEVICE displayDevice, int flags);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr data);
    [DllImport("user32.dll", SetLastError=true)] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll", SetLastError=true)] private static extern bool GetClientRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW", SetLastError=true)] private static extern IntPtr GetWindowLongPtr64(IntPtr hwnd, int index);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW", SetLastError=true)] private static extern int GetWindowLong32(IntPtr hwnd, int index);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Module32First(IntPtr snapshot, ref MODULEENTRY32 module);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Module32Next(IntPtr snapshot, ref MODULEENTRY32 module);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);

    private static IntPtr GetWindowLongCompat(IntPtr hwnd, int index) {
        return IntPtr.Size == 4 ? new IntPtr(GetWindowLong32(hwnd, index)) : GetWindowLongPtr64(hwnd, index);
    }

    public static string[] DisplayModes() {
        List<string> result = new List<string>();
        for (int i=0; ; ++i) {
            DISPLAY_DEVICE device = new DISPLAY_DEVICE(); device.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
            if (!EnumDisplayDevices(null, i, ref device, 0)) break;
            if ((device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0) continue;
            DEVMODE mode = new DEVMODE(); mode.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));
            if (!EnumDisplaySettings(device.DeviceName, ENUM_CURRENT_SETTINGS, ref mode)) throw new Win32Exception(Marshal.GetLastWin32Error(), "EnumDisplaySettings failed for " + device.DeviceName);
            result.Add(device.DeviceName + "|" + mode.dmPelsWidth + "x" + mode.dmPelsHeight + "|" + mode.dmBitsPerPel + "|" + mode.dmDisplayFrequency + "|" + mode.dmUnion.dmDisplayOrientation);
        }
        if (result.Count == 0) throw new InvalidOperationException("no attached desktop display modes were enumerated");
        result.Sort(StringComparer.Ordinal);
        return result.ToArray();
    }
    public static string[] ModulePaths(int pid) {
        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
        if (snapshot == INVALID_HANDLE_VALUE) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot failed for PID " + pid);
        try {
            List<string> modules = new List<string>();
            MODULEENTRY32 module = new MODULEENTRY32(); module.dwSize = Marshal.SizeOf(typeof(MODULEENTRY32));
            if (!Module32First(snapshot, ref module)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Module32First failed for PID " + pid);
            do {
                modules.Add(module.szExePath);
                module.dwSize = Marshal.SizeOf(typeof(MODULEENTRY32));
            } while (Module32Next(snapshot, ref module));
            int lastError = Marshal.GetLastWin32Error();
            if (lastError != 18) throw new Win32Exception(lastError, "Module32Next failed for PID " + pid);
            modules.Sort(StringComparer.OrdinalIgnoreCase);
            return modules.ToArray();
        } finally { CloseHandle(snapshot); }
    }
    public static bool HasModule(string[] modulePaths, string leafName) {
        foreach (string modulePath in modulePaths) {
            if (String.Equals(System.IO.Path.GetFileName(modulePath), leafName, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
    public static CarrierWindowSample[] WindowsForProcess(int expectedPid) {
        List<CarrierWindowSample> samples = new List<CarrierWindowSample>();
        EnumWindows(delegate(IntPtr hwnd, IntPtr ignored) {
            uint pid; GetWindowThreadProcessId(hwnd, out pid);
            if (pid != (uint)expectedPid) return true;
            StringBuilder title = new StringBuilder(1024); GetWindowText(hwnd, title, title.Capacity);
            RECT rect = new RECT(); GetClientRect(hwnd, out rect);
            samples.Add(new CarrierWindowSample { hwnd=hwnd.ToInt64(), title=title.ToString(), style=GetWindowLongCompat(hwnd, -16).ToInt64(), exstyle=GetWindowLongCompat(hwnd, -20).ToInt64(), client_width=rect.Right-rect.Left, client_height=rect.Bottom-rect.Top, visible=IsWindowVisible(hwnd) });
            return true;
        }, IntPtr.Zero);
        return samples.ToArray();
    }
}
'@
}

$started = [datetime]::UtcNow
$deadline = $started.AddSeconds($DurationSeconds)
$report = [ordered]@{
    controller_version = $ControllerVersion; started_utc = $started.ToString('o'); duration_seconds = $DurationSeconds
    expected_target_sha256 = $ExpectedSha256; result = 'not_started'; termination = 'none'; observer_ready = $false; events = @()
}
$job = $null; $launched = $null; $originalObserverLog = $env:CS_OBSERVER_LOG; $envChanged = $false
$terminationRequested = $false; $failure = $null; $gamePid = $null; $helperExit = $null
$freshReport = $null; $script:EventLogPath = $null
$attachJob = $null; $attachProcess = $null; $attachDeadline = [datetime]::MinValue
$attachStarted = $false; $attachFinished = $false
$freshLogDir = $null; $observerReadyDeadline = [datetime]::MinValue

try {
    $privateDxWnd = Resolve-ExistingDirectory $PrivateDxWndDir 'PrivateDxWndDir'
    $privateConfig = Resolve-ExistingFile $PrivateConfigPath 'PrivateConfigPath'
    $assets = Resolve-ExistingDirectory $PrivateAssetsDir 'PrivateAssetsDir'
    $observer = Resolve-ExistingFile $ObserverDll 'ObserverDll'
    $attach = Resolve-ExistingFile $AttachHelper 'AttachHelper'
    $nativeHelper = Resolve-ExistingFile $NativeProcessHelper 'NativeProcessHelper'
    $dxwndExe = Resolve-ExistingFile (Join-Path $privateDxWnd 'dxwnd.exe') 'private dxwnd.exe'
    $target = Resolve-ExistingFile (Join-Path $assets 'CSTORM.EXE') 'private CSTORM.EXE'
    $expectedConfig = Join-Path $privateDxWnd 'dxwnd.ini'
    if (-not (Same-Path $privateConfig $expectedConfig)) { throw "PrivateConfigPath must be the private DxWnd working-directory config: $expectedConfig" }
    if (-not (Same-Path (Split-Path -Parent $target) $assets)) { throw 'target path escaped PrivateAssetsDir' }
    $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($targetHash -ne $ExpectedSha256) { throw "target SHA-256 mismatch: expected $ExpectedSha256, got $targetHash" }
    $configuredPath = Select-String -LiteralPath $privateConfig -Pattern '^\s*path0\s*=\s*(.*)$' | Select-Object -First 1
    if ($null -eq $configuredPath) { throw 'private dxwnd.ini has no path0 entry' }
    if (-not (Same-Path $configuredPath.Matches[0].Groups[1].Value.Trim() $target)) { throw "private dxwnd.ini path0 is not the exact private target: $($configuredPath.Matches[0].Groups[1].Value.Trim())" }
    $freshReport = Require-FreshFile $ReportPath 'ReportPath'
    $freshLogDir = Require-FreshDirectory $LogDir 'LogDir'
    New-Item -ItemType Directory -Path $freshLogDir | Out-Null
    $script:EventLogPath = Join-Path $freshLogDir 'controller.events.jsonl'
    $report.inputs = [ordered]@{ private_dxwnd=$privateDxWnd; private_config=$privateConfig; private_assets=$assets; target=$target; target_sha256=$targetHash; observer_dll=$observer; observer_dll_sha256=(Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash.ToLowerInvariant(); attach_helper=$attach; attach_helper_sha256=(Get-FileHash -LiteralPath $attach -Algorithm SHA256).Hash.ToLowerInvariant(); native_process_helper=$nativeHelper; log_dir=$freshLogDir }
    $report.event_log = $script:EventLogPath
    $report.launcher_log = Join-Path $freshLogDir 'dxwnd.launcher.log'
    $report.attach_log = Join-Path $freshLogDir 'attach.txt'
    $requestedObserverLog = if ($ObserverLogPath) { [IO.Path]::GetFullPath($ObserverLogPath) } else { Join-Path $freshLogDir 'cs_observer.log' }
    $report.observer_log = Require-FreshFile $requestedObserverLog 'ObserverLogPath'
    $report.prior_cs_observer_log = $originalObserverLog
    Write-Event 'preflight_ok' @{ target_sha256=$targetHash; deadline_utc=$deadline.ToString('o') }
    if ($PreflightOnly) { $report.result = 'preflight_ok'; return }

    $existing = @(Get-ExistingNamedProcesses @('dxwnd', 'CSTORM'))
    if ($existing.Count -ne 0) {
        $found = @($existing | ForEach-Object { "$($_.Name):$($_.ProcessId)" }) -join ', '
        throw "exclusive DxWnd presentation lease is unavailable; existing dxwnd/CSTORM process(es): $found"
    }
    $report.baseline_display_modes = [CarrierPassiveInspector]::DisplayModes()
    Write-Event 'display_baseline' @{ modes=@($report.baseline_display_modes) }

    . $nativeHelper
    # The observer reads CS_OBSERVER_LOG during DLL initialization.  Set it before
    # DxWnd starts so DxWnd and its OS-created target inherit the same value.
    $env:CS_OBSERVER_LOG = $report.observer_log; $envChanged = $true
    $quotedExe = [GateProcessJob]::QuoteArgument($dxwndExe)
    $launched = [GateLaunchedProcess]::Launch($dxwndExe, "$quotedExe /Q /R:1", $report.launcher_log, $privateDxWnd)
    $job = New-Object GateProcessJob
    try { $job.Assign($launched.Handle) } catch { $launched.Terminate(); throw }
    $launched.Resume()
    $report.dxwnd_pid = $launched.Id
    Write-Event 'dxwnd_resumed' @{ pid=$launched.Id; command='/Q /R:1'; working_directory=$privateDxWnd }

    $attached = $false; $lastDisplaySample = [datetime]::MinValue; $lastProcessSample = [datetime]::MinValue; $firstWindowObserved = $false; $moduleSummaryRecorded = $false
    while ($true) {
        if ([datetime]::UtcNow -ge $deadline) {
            if ($null -ne $gamePid) {
                try { $report.game_modules_at_timeout=[CarrierPassiveInspector]::ModulePaths($gamePid); Write-Event 'module_paths_timeout' @{ modules=@($report.game_modules_at_timeout) } }
                catch { $report.module_enumeration_timeout_error=$_.Exception.Message; Write-Event 'module_enumeration_timeout_error' @{ message=$_.Exception.Message } }
            }
            $report.result='deadline_expired'; $report.termination='bounded_termination'; $terminationRequested=$true; Write-Event 'deadline_expired'; break
        }
        $report.dxwnd_host_exited = $launched.HasExited()
        if ($job.ActiveProcesses() -eq 0) {
            if ($null -eq $gamePid) { $report.result='launcher_exited_without_verified_target' }
            elseif (-not $attachFinished -or -not $report.observer_ready) { $report.result='owned_tree_exited_before_observer_ready' }
            else { $report.result='owned_tree_exited' }
            $report.termination='natural_exit'; Write-Event 'owned_tree_empty' @{ result=$report.result }; break
        }
        if (([datetime]::UtcNow - $lastDisplaySample).TotalMilliseconds -ge 1000) {
            $currentModes = [CarrierPassiveInspector]::DisplayModes(); $lastDisplaySample=[datetime]::UtcNow
            $report.last_display_modes = $currentModes
            if ((@($currentModes) -join "`n") -ne (@($report.baseline_display_modes) -join "`n")) { $report.result='display_mode_changed'; $report.termination='bounded_termination'; $terminationRequested=$true; Write-Event 'display_mode_changed' @{ current=@($currentModes) }; break }
        }
        if ($null -eq $gamePid) {
            $candidates = @()
            foreach ($candidate in (Get-Process -Name CSTORM -ErrorAction SilentlyContinue)) {
                $candidatePath = Get-ProcessPath $candidate.Id
                if ($candidatePath -and (Same-Path $candidatePath $target) -and $job.Contains($candidate.Handle)) { $candidates += $candidate }
            }
            if ($candidates.Count -gt 1) { $report.result='ambiguous_owned_target'; $report.termination='bounded_termination'; $terminationRequested=$true; Write-Event 'ambiguous_target' @{ pids=@($candidates.Id) }; break }
            if ($candidates.Count -eq 1) { $gamePid=$candidates[0].Id; $report.game_pid=$gamePid; $report.game_path=$target; Write-Event 'verified_owned_target' @{ pid=$gamePid; path=$target } }
        }
        if ($null -ne $gamePid) {
            if (([datetime]::UtcNow - $lastProcessSample).TotalMilliseconds -ge 1000) {
                $sample=Get-ProcessSample $gamePid; if ($sample) { $report.game_last_sample=$sample; Write-Event 'game_sample' $sample }; $lastProcessSample=[datetime]::UtcNow
            }
            $windows = [CarrierPassiveInspector]::WindowsForProcess($gamePid)
            if ($windows.Count -gt 0) { $report.game_windows=@($windows); if (-not $firstWindowObserved) { $firstWindowObserved=$true; Write-Event 'first_observed_window' @{ count=$windows.Count } } }
            $modulePaths = $null
            try { $modulePaths = [CarrierPassiveInspector]::ModulePaths($gamePid) }
            catch {
                $report.module_enumeration_error=$_.Exception.Message; $report.result='module_enumeration_failed'; $report.termination='bounded_termination'; $terminationRequested=$true
                Write-Event 'module_enumeration_failed' @{ pid=$gamePid; message=$_.Exception.Message }; break
            }
            if (-not $moduleSummaryRecorded) {
                $report.game_modules_on_discovery=$modulePaths; $moduleSummaryRecorded=$true
                Write-Event 'module_paths_discovery' @{ pid=$gamePid; modules=@($modulePaths) }
            }
            if (-not $attached -and [CarrierPassiveInspector]::HasModule($modulePaths, 'dxwnd.dll')) {
                $remaining = Get-RemainingMilliseconds $deadline
                if ($remaining -le 0) { continue }
                $helperSeconds = [Math]::Max(1, [Math]::Min(30, [int][Math]::Ceiling($remaining / 1000.0)))
                Write-Event 'attach_begin' @{ pid=$gamePid; timeout_seconds=$helperSeconds }
                $attachArgs = @('--attach', "$gamePid", '--dll', $observer, '--expected-image', $target, '--report', $report.attach_log)
                $attachCommand = ((@($attach) + @($attachArgs) | ForEach-Object { [GateProcessJob]::QuoteArgument($_) }) -join ' ')
                $attachProcess = [GateLaunchedProcess]::Launch($attach, $attachCommand, (Join-Path $freshLogDir 'attach.launcher.log'), $privateDxWnd)
                $attachJob = New-Object GateProcessJob
                try { $attachJob.Assign($attachProcess.Handle) } catch { $attachProcess.Terminate(); throw }
                $attachProcess.Resume(); $attachDeadline=[datetime]::UtcNow.AddSeconds($helperSeconds); $attachStarted=$true; $attached=$true
            }
        }
        if ($attachStarted -and -not $attachFinished) {
            if ([datetime]::UtcNow -ge $attachDeadline) {
                $attachJob.Terminate(); $report.result='observer_attach_timeout'; $report.termination='bounded_termination'; $terminationRequested=$true; Write-Event 'attach_timeout'; break
            }
            if ($attachJob.ActiveProcesses() -eq 0) {
                $helperExit=$attachProcess.ExitCode(); $report.attach_exit_code=$helperExit; $attachFinished=$true
                $report.observer_ready = Test-CyberStormObserverReady $report.observer_log $gamePid
                $observerReadyDeadline = [datetime]::UtcNow.AddSeconds(2)
                Write-Event 'attach_complete' @{ exit_code=$helperExit; observer_log_ready=$report.observer_ready }
                if ($helperExit -ne 0) { $report.result='observer_attach_failed'; $report.termination='bounded_termination'; $terminationRequested=$true; break }
            }
        }
        if ($attachFinished -and -not $report.observer_ready) {
            $report.observer_ready = Test-CyberStormObserverReady $report.observer_log $gamePid
            if ($report.observer_ready) { Write-Event 'observer_ready' @{ pid=$gamePid; log=$report.observer_log } }
            elseif ([datetime]::UtcNow -ge $observerReadyDeadline) { $report.result='observer_not_ready'; $report.termination='bounded_termination'; $terminationRequested=$true; Write-Event 'observer_not_ready' @{ log=$report.observer_log }; break }
        }
        Start-Sleep -Milliseconds 250
    }
} catch {
    $failure = $_.Exception.Message
    if ($report.result -eq 'not_started') { $report.result='failure' }
    if ($null -ne $job) { $report.termination='bounded_termination'; $terminationRequested=$true }
    $report.failure = $failure
    if ($null -ne $script:EventLogPath) { Write-Event 'failure' @{ message=$failure } }
} finally {
    if ($null -ne $launched -and $null -eq $job) { $launched.Terminate() }
    if ($null -ne $attachProcess -and $null -eq $attachJob) { $attachProcess.Terminate() }
    if ($envChanged) { if ($null -eq $originalObserverLog) { Remove-Item Env:CS_OBSERVER_LOG -ErrorAction SilentlyContinue } else { $env:CS_OBSERVER_LOG=$originalObserverLog } }
    if ($terminationRequested -and $null -ne $job) {
        try { $job.Terminate(); Write-Event 'owned_job_terminated' } catch { $report.cleanup_error=$_.Exception.Message }
    }
    if ($null -ne $attachJob) {
        try { if ($attachJob.ActiveProcesses() -gt 0) { $attachJob.Terminate(); Write-Event 'attach_job_terminated' } } catch { $report.attach_cleanup_error=$_.Exception.Message }
        $attachCleanupDeadline=[datetime]::UtcNow.AddSeconds(5)
        try {
            while ($attachJob.ActiveProcesses() -gt 0 -and [datetime]::UtcNow -lt $attachCleanupDeadline) { Start-Sleep -Milliseconds 50 }
            $report.attach_job_active_after_cleanup=$attachJob.ActiveProcesses()
        } catch { $report.attach_cleanup_error=$_.Exception.Message }
    }
    if ($null -ne $job) {
        $cleanupDeadline=[datetime]::UtcNow.AddSeconds(5)
        try { while ($job.ActiveProcesses() -gt 0 -and [datetime]::UtcNow -lt $cleanupDeadline) { Start-Sleep -Milliseconds 50 }; $report.owned_job_active_after_cleanup=$job.ActiveProcesses() } catch { $report.cleanup_error=$_.Exception.Message }
    }
    if ($null -ne $launched) { try { $report.dxwnd_exit_code=$launched.ExitCode() } catch { $report.dxwnd_exit_code='unavailable' } }
    if ($report.Contains('baseline_display_modes')) {
        try {
            $report.final_display_modes=[CarrierPassiveInspector]::DisplayModes()
            $report.display_modes_restated_unchanged=((@($report.final_display_modes) -join "`n") -eq (@($report.baseline_display_modes) -join "`n"))
        } catch { $report.final_display_error=$_.Exception.Message }
    }
    $report.ended_utc=[datetime]::UtcNow.ToString('o'); $report.elapsed_seconds=[Math]::Round(([datetime]::UtcNow-$started).TotalSeconds,3)
    $report.game_discovered=($null -ne $gamePid); $report.observer_attached=($null -ne $helperExit -and $helperExit -eq 0)
    if ($null -ne $attachJob) { $attachJob.Dispose() }; if ($null -ne $attachProcess) { $attachProcess.Dispose() }
    if ($null -ne $job) { $job.Dispose() }; if ($null -ne $launched) { $launched.Dispose() }
    if ($null -ne $freshReport) { $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $freshReport -Encoding UTF8 }
}

if ($failure) { throw $failure }
if ($report.result -eq 'preflight_ok') { exit 0 }
if ($report.result -ne 'owned_tree_exited') { exit 1 }
# An idle DxWnd exit code 0 is only a lifecycle observation.  This controller
# never reports menu reachability or game success; inspect the observer output.
exit 0
