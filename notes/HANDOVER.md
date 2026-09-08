# CyberStorm recovery handover — 2026-09-08

## Runtime continuation (supersedes the execution pause below for CyberStorm)

Model policy: GPT-6 Astra is reserved for the primary supervisor's
orchestration, review and integration work. Every implementation or test task
must be delegated explicitly to a `gpt-5.6-terra` or `gpt-5.6-luna` subagent;
subagents must never inherit the supervisor's model. A status listing does not
prove the resolved model.

The operator later authorized building/running a windowed bootstrap through the
existing DxWnd profile, with gameplay recording reserved for the operator.
Read [the bootstrap report](carrier_bootstrap_20260908.md) and
[carrier setup](../carrier/README.md) first. The final bounded run reached
observer readiness, inventoried 162 IAT slots, forwarded real DirectSound loader
calls and emptied both process jobs. Replay, snapshots and replacement bindings
are still unimplemented. No original assets or installed DxWnd config changed.

PortForge main is now published at `223ac21`; both projects use its shared native
process helper. Replay backward compatibility is explicitly unnecessary during
Win32 development. Do not add migration paths to preserve old recordings.
Icy Tower execution remains paused independently; its unfinished changes and
batch-15 proof gaps were preserved. The historical static-only record follows.

The operator requested publishing the ready PortForge work and continuing from
the newly supplied original CyberStorm binary. PortForge main was merged without
conflicts, checked and pushed at `fceedbc2d4188ebfa7cf1160e6b14ceb697317ff`.
This repository's gitlink now records that commit. No CyberStorm binaries or
other game assets are tracked, and this repository has not been pushed.

Read `../README.md` for the two exact input hashes and runtime pause. The June
legacy file is the primary static baseline; the GOG file is a distinct comparison
build with a December PE timestamp. A separately named December artifact from
the supplied proposal is not present, so do not claim exact identity with it.

## Accepted direction

Recover source landmarks from the binary before speculative source decompilation.
`source_recovery/assert_abi_review.md` records an independent instruction-level
check: June diagnostic target `0x00477920` takes a source pointer, a 32-bit line
word, and a message pointer through a caller-cleaned 12-byte stack interface.
The analogous GOG target is `0x0047D5A0`. Original function names and exact C
types are not established. The routines can return normally.

The data pipeline and its generated reports belong to this project first.
The hash-selected diagnostic addresses and string/path conventions are CyberStorm
policy. No generic PortForge pseudo-debug subsystem has been introduced.

## Next evidence boundary

The reports distinguish retained source paths, validated local diagnostic call
patterns, and cross-build diagnostic anchors. These are not a complete census
of native functions or a function-equivalence proof. Missing breadcrumbs do not
establish library ownership. Header/inlining/macro provenance can complicate
even a positive source landmark.

Next, take one small group of these landmarks and establish its containing
function boundaries using control flow and call-entry evidence. Validate the
inferred ABI and globals before assigning a source-unit recovery task. The
`GFXCDSSurface::create` and `GFXCDSSurface::setPalette` labels are useful named
landmarks for a bounded boundary analysis; they do not justify a graphics port
or running either executable. Whole-function matching must retain ambiguous
candidates and account for line shifts between builds.

Icy Tower remains unfinished: batch 15 has no new in-vivo promotions, and its
nontermination/desktop-latency investigation remains open. Game execution stays
paused; no CyberStorm or Icy Tower game was launched during this static work.
