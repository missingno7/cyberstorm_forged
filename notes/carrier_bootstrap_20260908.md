# First CyberStorm native bootstrap — 2026-09-08

The GOG image ran as an OS-loaded x86 process under a private copy of the
operator's DxWnd 2.06.15 profile. The final 15-second run attached the observer,
completed its import inventory, observed real dynamic calls, and emptied both
owned process jobs at the deadline. This establishes the windowed bootstrap
and instrumentation route, not deterministic replay or a recovered game.

[Machine-readable evidence](carrier_bootstrap_20260908.json) records binary and
log hashes, readiness, hook targets, actual calls, display samples and cleanup.
Raw reports remain under ignored `artifacts/carrier_bootstrap_20260908/`.

## Observations

- Visible `CyberStorm` window: client 792 x 572, style `0x14C80000`, exstyle
  `0x100`; the operator profile requests an 800 x 600 window.
- Both displays retained 3840 x 2160 at 32 bpp, respectively 60 and 240 Hz.
  The final controller checked again after process cleanup. Sampling was about
  once per second, so this is not a trace of every possible transient change.
- Observer inventoried 162 main-image IAT slots. It installed two LoadLibraryA
  and two GetProcAddress hooks, preserving the duplicate descriptors' identical
  DxWnd targets (`0x10095DE0` and `0x10095E60` in this run).
- After readiness, the game called LoadLibraryA for `DSOUND.DLL` and resolved
  `DirectSoundCreate`; both returned non-null pointers. The recorded last-error
  value 87 is preserved diagnostic state, not evidence that those successful
  calls failed.
- Initial module inventory included `cwarsdll.dll`, `_INMM.dll`,
  `libvorbisfile.dll` and `libvorbis.dll`. Library presence does not establish
  which API calls gameplay will reach or that a compatible replacement exists.
- The final game sample reported normal base priority 8, responding=true,
  and 1.016 CPU seconds. No desktop input-latency trace was collected; this
  does not diagnose the earlier Icy Tower desktop stalls.
- Final run: 15.139 seconds, deadline termination, attach exit 0,
  observer_ready=true, game/DxWnd job active=0 and attach job active=0.
  Deadline termination deliberately returns controller exit 1, not a fabricated
  natural game completion. No game/DxWnd processes remained afterward.
- All 206 original asset files and the installed DxWnd config were hash-checked
  unchanged after the runs. Runtime writes were confined to copied inputs.

Run 1 established the windowed launch but could not see the 32-bit DxWnd DLL
through .NET Process.Modules. Run 2 used Toolhelp32 with SNAPMODULE32 and reached
observer readiness. Run 3 verified the final cleanup reporting and captured the
dynamic DirectSound calls. The controller's DEVMODE display union was also
corrected: the first report's orientation field had read monitor position X;
width, height, bpp and frequency fields were unaffected.

## Validation

The x86 MSVC build passed with warnings treated as errors. The contract fixture
checked ordinal representations, forwarding ambiguity and RVA bounds. A separate
owned synthetic process verified actual LoadLibraryA and GetProcAddress hooks,
including a named export and ordinal 7, against pre-hook returns and last-error
values. All results matched and the observer log proved that the hooks ran.
The first synthetic fixture could not read an open writer's log through CRT
`fopen_s`; its reader now uses explicit shared-read/write access. The observer
itself did not need changing for that correction.

Controller readiness fixtures reject empty, wrong-PID and attached-only logs;
the ready marker passes. Shared process membership/lifecycle tests and Icy
Tower's synthetic gate failure suite passed without launching Icy Tower.
The 11 source-breadcrumb extraction tests also passed.

## Architecture and next work

The reusable mechanism demonstrated across both projects is process ownership
in PortForge. The late injected observer and CyberStorm identities remain project
code until further targets establish the right shared loaded-image contract.
The route preserves executable identity for DxWnd; it does not prove the manual
mapper unsuitable merely because CyberStorm sections have zero VirtualSize.

Next establish a controlled observation point before relevant game execution,
then define input/time channels and a game-loop/frame coordinate. Inventory
dynamic exports and DirectSound/other COM boundaries under a human-recorded
workload. Build a nonempty state/output oracle and repeat ORIGINAL runs before
introducing a first recovered-function binding. Source landmarks from the June
binary guide that work but cannot substitute for boundaries, ABI and behavior.

The operator will record gameplay when capture is ready. No automated gameplay,
screenshots or Computer Use are part of this bootstrap. Experimental replay and
snapshot formats may change freely; reject obsolete inputs instead of building
backward-compatible readers or migrations. Every changed contract needs fresh
evidence, not relaxed comparison gates.
