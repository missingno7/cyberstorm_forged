# MissionForce: CyberStorm reconstruction

Static source-breadcrumb recovery is the current first step. No CyberStorm
carrier or recovered game implementation has been verified here.

## Inputs

The operator supplied both builds locally. Preserve both; game binaries and
assets are not committed to this repository.

| Local input | Bytes | SHA-256 | Role |
|---|---:|---|---|
| `assets/legacy/CSTORM.EXE` | 709120 | `c5d3cb8772442a131ebd5a6a84c725d31fd685311e98b4edaa89b822671d3e73` | Original June 1996 candidate; primary static reconstruction baseline |
| `assets/CSTORM.EXE` | 736256 | `b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181` | GOG distribution; operator reports that it runs on modern Windows; comparison build |

The legacy hash matches the supplied research proposal's June 1.00A candidate.
The proposal's separately named December `CSTORM(1).EXE` has not been supplied
under that name. Do not identify the GOG binary as that exact artifact without
matching evidence. Source paths and assertion diagnostics are evidence of
retained source landmarks, not a complete debug database or recovered C source.

## Framework

`port_forge` is pinned to main commit
`fceedbc2d4188ebfa7cf1160e6b14ceb697317ff`, published on 2026-09-08.
It includes the Icy Tower work on rejecting empty digest evidence, generated
binding capacity, and constant-only library include routing, merged with the
then-current upstream main. The three focused Win32 test scripts and seven
framework structure/documentation/schema checks passed on the merged tree.

Initialize the framework with `git submodule update --init --recursive`.
The pin records a tested version; follow later main changes through explicit
updates rather than silently changing the reconstruction environment.

## Recovery order and proof limits

1. Verify both binary identities and extract source-path/diagnostic strings.
2. Recover assert/error argument flow and conservatively associate callsites
   with filenames and line landmarks; retain unresolved and conflicting cases.
3. Build evidence-backed pseudo-symbol and cross-build maps. Diagnostic names
   need callsite support; address proximity alone does not establish ownership.
4. Choose an original translation unit only after enough function-boundary,
   ABI, global-state and behavioral evidence exists to make recovery reviewable.

Absence of a source breadcrumb does not classify a function as library code.
Source lines are landmarks, not exact function extents. Cross-version matching
must preserve ambiguity; neither source-path equality nor one diagnostic proves
function equivalence. Runtime behavior and modern-host compatibility remain
separate from the June binary's value as a semantic evidence source.

Game runs remain paused after operator-reported desktop input latency during
Icy Tower carrier runs. Static parsing does not execute either CyberStorm image.
