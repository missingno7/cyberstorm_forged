# CyberStorm semantic breadcrumb recovery

Inputs:
- June baseline SHA-256 c5d3cb8772442a131ebd5a6a84c725d31fd685311e98b4edaa89b822671d3e73; PE timestamp 1996-06-13T07:01:11+00:00.
- GOG candidate SHA-256 b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181; PE timestamp 1996-12-17T22:36:03+00:00.

Results:
- June original source paths recovered: 140.
- June paths with accepted decoded source-line-call-cleanup xrefs: 61.
- June accepted line-number callsites: 214.
- June message operands: immediate string 31; immediate unresolved 0; dynamic 99; null 84.
- Native functions assigned to source files: 0; enclosing caller boundaries are unresolved.
- Approximate caller line ranges: 0; no caller function extents are inferred.
- Distinct explicit scope labels found in accepted diagnostic text: 2; assigned to functions: 0.
- Shared dispatcher pseudo-symbols: 1.
- Crossbuild canonical function mappings: 0; no function boundaries are promoted.
- Unique exact source-line-message crossbuild callsite anchors: 19; these are not function identities. Line shifts, such as the validated difficulty check 428 to 522, intentionally do not match this strict anchor rule.

The supported result is a validated dispatcher subset, not all source xrefs: source, line, message operand classification, and decoded common target. It does not establish whole source-file ownership of machine functions. Rejected literal and call-pattern candidates are retained in separate CSV files.

Reproduce with python tools/extract_breadcrumbs.py --june assets/legacy/CSTORM.EXE --gog assets/CSTORM.EXE --out notes/source_recovery. The extractor uses the installed objdump decoder and Python standard library.