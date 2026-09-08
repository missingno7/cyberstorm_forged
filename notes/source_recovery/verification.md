# Verification of the first static pipeline

2026-09-08, framework pin `fceedbc2d4188ebfa7cf1160e6b14ceb697317ff`.

- Integrated `tests/test_extract_breadcrumbs.py`: 11 tests PASS, including
  argument order, dynamic/null message distinction, missing message push,
  wrong call target, wrong stack cleanup, instruction gap and truncated PE.
- Regenerated all machine-produced reports from the two local, hash-checked
  EXEs in the CyberStorm repository. June: 214 accepted sites; GOG: 222.
- Independent supervisor checks against decoded instructions matched June
  call `0x00402358` (`shell\shell.c:428`, `invalid difficulty value`) and
  `0x0047AF60` (`graph\gfx\g_cds.c:114`, the surface-create diagnostic).
  The independent ABI review includes further samples and the GOG counterpart.
- Both unknown-input controls failed with the named June/GOG hash refusal
  while an invalid objdump path was supplied, confirming rejection before
  decoder invocation. Local logs are in `artifacts/unknown_*_rejection.log`.
- The worker regenerated the finalized extraction twice with byte-identical
  outputs. Integration changed the documented invocation and the wording of
  line evidence to include both imm8 and imm32 pushes, then regenerated here.

The decoder is GNU objdump in Intel x86 mode with 16-byte instruction display
width. Accepted evidence is a physically contiguous, decoded local sequence,
not a proof of global reachability, all incoming control-flow paths, or caller
function extents. The source scan covers NUL-terminated directory-qualified
paths in non-executable sections; rejected candidates are retained separately.
The xref table is the validated dispatcher subset, not every possible code or
data reference to each string. Exact-line cross-build anchors deliberately
miss shifted line numbers and unresolved/dynamic messages.

No game executable was launched. No source function is promoted as recovered
or behaviorally equivalent by these static results.
