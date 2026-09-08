# June 1996 assertion/error ABI spot check

Input inspected: `cyberstorm_forged/assets/legacy/CSTORM.EXE`, SHA-256
`C5D3CB8772442A131EBD5A6A84C725D31FD685311E98B4EDAA89B822671D3E73`.
This is a bounded instruction-level review of four source-path sites and the
repeated target, not a function census or a source reconstruction.

## Decisive repeated target: `0x00477920`

The direct callers clean twelve bytes with `add esp, 0xC`, so this target uses
a caller-cleaned 32-bit ABI. Its prologue saves registers and reserves `0x400`
bytes. It then reads the original incoming arguments at these offsets:

```text
0x00477938  mov ecx, [esp+0x41C]   ; incoming arg 2
0x0047793F  push ecx
0x00477940  mov esi, [esp+0x41C]   ; after one push: incoming arg 1
0x00477947  push esi
...
0x00477957  mov edi, [esp+0x434]   ; after six pushes: incoming arg 3
0x0047795E  push edi
```

The observed call sequence establishes the argument order as:

```c
void __cdecl F_00477920(const char *source_file,
                        unsigned source_line,
                        const char *message);
```

`F_00477920` is a defensible neutral identifier. The evidence shows a
centralized diagnostic formatter, but does not prove an original
routine name or distinguish every macro family that can reach it.

The inspected routine can return normally through its epilogue at 0x004779A9; a fatal or non-returning contract has not been established.

## Independent callsite sample

| Source site | Exact instruction sequence | Established association |
|---|---|---|
| `0x00402349` | `push 0x48400C`; `push 0x1AC`; `push 0x487FD0`; `call 0x477920`; `add esp,0xC` | `shell\\shell.c`, line 428, message `invalid difficulty value`. |
| `0x0047AF54` | `push 0x485DF4`; `push 0x72`; `push 0x49EC24`; `call 0x477920`; `add esp,0xC` | `graph\\gfx\\g_cds.c`, line 114, message `GFXCDSSurface::create: Failed to create a surface.` |
| `0x0047B03C` | `push 0x485E27`; `push 0xD2`; `push 0x49EC24`; `call 0x477920`; `add esp,0xC` | `graph\\gfx\\g_cds.c`, line 210, message `GFXCDSSurface::setPalette: start out of range.` |
| `0x004121C7` | `push eax`; `push 0x15D`; `push 0x4883D0`; `call 0x477920`; `add esp,0xC` | `shell\\commscrn.c`, line 349. The preceding `test eax,eax; jne` means the message argument is the zero result on this path, demonstrating that a diagnostic string is optional/dynamic. |

The argument order in every fixed-message sample is therefore **message,
line, filename in push order**, which is the reverse of the C declaration
above on 32-bit cdecl. The declaration is an illustrative ABI sketch; return type and line signedness have not been recovered.

## Central-routine pitfall

`debug\\assert.c` is itself referenced at `0x00477892`:

```text
0x0047788B  push 0x49DA58
0x00477890  push 0x68
0x00477892  push 0x49E19C       ; "debug\\assert.c"
...
0x004778BC  call 0x004782B9
```

This is inside the diagnostic machinery and calls `0x004782B9`, a local
formatting/string-builder helper, rather than `0x00477920`. It is decisive
counterevidence to treating every path-string xref as a client assertion
callsite or a translation-unit assignment. The raw first-pass proximity row
for it must remain excluded from client function attribution.

## What the evidence supports

For a decoded direct call to `0x00477920`, with the three actual stack
arguments verified, the extractor may emit a **basic-block landmark**:

```text
callsite VA, source_file, source_line, message pointer/null/dynamic,
target 0x00477920, confidence=high
```

It may identify the containing function only after an independent function
boundary analysis. It may then say that the function *contains a diagnostic
landmark from* that translation unit. It must not treat this alone as proof
that the whole function originated in that file, or assign a semantic name
from the path. The `GFXCDSSurface::create` text supports that diagnostic label
at the callsite; it does not name every containing routine or all nearby code.

## Required extractor validation before promotion

1. Decode candidate code with a real x86 instruction decoder and accept only
   actual direct `call rel32` instructions that resolve to `0x00477920`.
   Do not use raw `E8` byte scanning.
2. Require a single reachable basic block with stack order `push message`,
   `push line`, `push source-file`, followed immediately by that call and a
   caller cleanup of twelve bytes. Record null/dynamic message operands rather
   than fabricating text.
3. Validate each source-file immediate resolves to a terminated retained path
   string and each line operand is the second call argument. Do not reject
   small values: line 1 is present in the first-pass data.
4. Exclude or separately classify references made from the diagnostic
   implementation range itself, including the `debug\\assert.c` self-reference
   above and calls to local formatting helpers such as `0x004782B9`.
5. Determine function boundaries before grouping landmarks. A function-level
   translation-unit association needs multiple in-function landmarks or other
   evidence; one landmark provides only a local source location.
6. Cross-check carrier-style report fields independently: the emitted file,
   line, message operand class, target, caller block, and containing function
   range must all be reproducible from disassembly. Preserve raw evidence and
   mark unresolved control-flow, indirect calls, tail paths, and header/macro
   provenance as uncertain.

The central ABI is now strong enough for a narrowly validated callsite
extractor. Function ownership, source ordering, and semantic naming remain
separate hypotheses requiring the validation above.

## GOG counterpart: supervisor check

The GOG input SHA-256 is
`b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181`.
Its target `0x0047D5A0` saves the same four registers and reserves `0x400`
stack bytes. The corresponding incoming arguments are read at `0x0047D5B8`
(`[esp+0x41C]`, line), `0x0047D5C0` (`[esp+0x41C]`, filename after the
additional push), and `0x0047D5D7` (`[esp+0x434]`, message). Formatting calls
`0x0047E0DB` at `0x0047D5F4` and cleans `0x24` argument bytes.

The GOG sample at `0x0040275F` pushes message `0x0048A00C`, line 522,
and source `0x0048E4DC`, then calls `0x0047D5A0` at `0x0040276E` and
cleans twelve bytes. Its diagnostic is the same `invalid difficulty value`
message as the June sample, but its line is 522 rather than 428. This supports
the corresponding diagnostic ABI and illustrates why exact-line anchor
matching is deliberately incomplete. It does not prove whole-function
behavioral equivalence between builds.
