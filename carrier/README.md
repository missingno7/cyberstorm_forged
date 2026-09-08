# Windowed native bootstrap

This is the first CyberStorm carrier bootstrap: Windows loads the original
GOG executable, the operator's DxWnd profile provides windowed presentation,
and an x86 observer DLL inspects that running image. It does not yet record
gameplay, replay deterministically, restore snapshots or replace game functions.

The controller uses PortForge's shared suspended-process / Job Object helper.
It verifies the GOG SHA-256 and exact private target path, refuses an existing
DxWnd/CSTORM session, monitors host display modes without changing them, and
terminates only its owned process trees at the deadline. No simulated input,
window activation or screenshots are used. An ordinary bounded run returns 1
with `result=deadline_expired`; inspect readiness and cleanup separately.

## Build and checks

Run `carrier\build.cmd` from a checkout with Visual Studio 2022 C++ x86 tools.
Build products stay under ignored `carrier/build/`. Then run:

```powershell
& ./carrier/build/cs_contract_test.exe
& ./carrier/build/cs_preflight.exe ./assets/CSTORM.EXE
powershell -NoProfile -ExecutionPolicy Bypass -File carrier/scripts/tests/controller_static_tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File carrier/scripts/tests/readiness_tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File carrier/scripts/tests/forwarding_tests.ps1
```

## Operator profile and bounded launch

Use a private copy of the installed DxWnd directory and a separate copy of the
GOG assets (exclude `legacy`). In the copied `dxwnd.ini`, change only `path0`
to the copied `CSTORM.EXE`. Preserve the operator's working windowed profile.
The tested installation is DxWnd 2.06.15 from `C:\Programy\v2_06_15_build`.
The controller launches its private `dxwnd.exe /Q /R:1` with the private DxWnd
directory as cwd. `/R:1` selects target zero; no undocumented DLL ABI is used.
Private files do not isolate DxWnd's shared named kernel objects, hence the
exclusive-session check.

The initial local setup lives in `artifacts/carrier_bootstrap_20260908`.
For that setup, choose a fresh report/log name for every run:

```powershell
$repo = (Get-Location).Path
$probe = Join-Path $repo 'artifacts/carrier_bootstrap_20260908'
& ./carrier/scripts/Invoke-CyberStormBounded.ps1 `
  -PrivateDxWndDir "$probe/dxwnd" -PrivateConfigPath "$probe/dxwnd/dxwnd.ini" `
  -PrivateAssetsDir "$probe/assets" `
  -ObserverDll "$repo/carrier/build/cs_observer.dll" `
  -AttachHelper "$repo/carrier/build/cs_attach.exe" `
  -ReportPath "$probe/fresh-run.json" -LogDir "$probe/fresh-run-logs" `
  -DurationSeconds 25
```

`-PreflightOnly` checks file/profile inputs without starting DxWnd or the game.
It does not test the live exclusive-session lease or display enumeration.

The attach helper verifies the PID's exact executable path, x86 architecture
and loaded `dxwnd.dll`, resolves remote LoadLibraryW through its owner module,
and loads the observer. The controller waits for the same PID's post-inventory
`observer=ready` line; an attached marker alone is insufficient. The observer
chains existing main-image IAT targets for LoadLibrary and GetProcAddress.
It does not replace those targets with fresh system lookups. A timeout leaves
any pending remote pathname allocation alive until controller-owned cleanup.

## Next contract

First establish a controlled pre-game observation point: the current late
attach can miss startup calls and cannot by itself prove deterministic startup.
Then define the game's event/frame boundary, input and clock channels, dynamic
library/COM boundaries and an explicit state/output oracle. Gameplay recording
is done by the operator after these capture hooks exist. Only then use ORIGINAL
replay as the gate for the first recovered function binding.

Win32 replay formats are experimental. Obsolete inputs should fail clearly;
do not implement old-format readers or migrations to preserve prior recordings.
The shared contract must follow observed needs across Icy Tower and CyberStorm.
