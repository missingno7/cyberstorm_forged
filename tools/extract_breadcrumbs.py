#!/usr/bin/env python3
"""Decoded, read-only source-breadcrumb extractor for supplied PE32 inputs."""
import argparse
import csv
import hashlib
import json
import re
import struct
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

OBJDUMP = r"C:\msys64\mingw64\bin\objdump.exe"
JUNE_SHA256 = "c5d3cb8772442a131ebd5a6a84c725d31fd685311e98b4edaa89b822671d3e73"
GOG_SHA256 = "b9d950fe3682885943ae1e7fe1b68a1b1e7b9b0c6d44fa426459eb879965b181"
JUNE_DIAGNOSTIC_TARGET = 0x00477920
GOG_DIAGNOSTIC_TARGET = 0x0047D5A0
SOURCE_PATH = re.compile(
    r"(?i)(?:[a-z0-9_. -]+\\)+[a-z0-9_. -]+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$"
)
SCOPE_LABEL = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)+\b")
DISASM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([a-z][a-z0-9]*)\s*(.*)$"
)
HEX_IMMEDIATE = re.compile(r"0x([0-9a-fA-F]+)$")


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe(path):
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("input lacks MZ header")
    pe_offset = u32(data, 0x3C)
    if pe_offset + 24 > len(data):
        raise ValueError("PE header lies outside input")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("input is not a PE image")
    if u16(data, pe_offset + 4) != 0x14C:
        raise ValueError("input is not x86 PE")
    section_count = u16(data, pe_offset + 6)
    timestamp = u32(data, pe_offset + 8)
    optional_size = u16(data, pe_offset + 20)
    optional = pe_offset + 24
    if optional_size < 32:
        raise ValueError("PE optional header is too short for PE32 image base")
    if optional + optional_size > len(data):
        raise ValueError("PE optional header lies outside input")
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("PE section table lies outside input")
    if u16(data, optional) != 0x10B:
        raise ValueError("input is not PE32")
    image_base = u32(data, optional + 28)
    sections = []
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset:offset + 8].split(b"\0")[0].decode("ascii", "replace")
        sections.append(
            {
                "name": name,
                "virtual_size": u32(data, offset + 8),
                "rva": u32(data, offset + 12),
                "raw_size": u32(data, offset + 16),
                "raw_offset": u32(data, offset + 20),
                "characteristics": u32(data, offset + 36),
            }
        )
        if sections[-1]["raw_offset"] + sections[-1]["raw_size"] > len(data):
            raise ValueError("section raw range lies outside input")
    return data, image_base, timestamp, sections


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_known_input(path, expected_hash, label):
    actual = sha256_file(path)
    if actual != expected_hash:
        raise ValueError(
            "%s input hash is unknown; refusing PE decode and build-specific classification" % label
        )
    return actual


def file_offset_to_section(sections, file_offset):
    for section in sections:
        start = section["raw_offset"]
        if start <= file_offset < start + section["raw_size"]:
            return section
    return None


def read_source_literals(data, image_base, sections):
    literals = []
    rejects = []
    for match in re.finditer(rb"[\x20-\x7E]{4,}", data):
        value = match.group().decode("ascii", "replace")
        if not value.lower().endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")):
            continue
        section = file_offset_to_section(sections, match.start())
        nul_terminated = match.end() < len(data) and data[match.end()] == 0
        executable = bool(section and section["characteristics"] & 0x20000000)
        if not SOURCE_PATH.fullmatch(value):
            rejects.append(
                {
                    "literal": value,
                    "file_offset": "0x%X" % match.start(),
                    "reason": "not a directory-qualified plausible source path",
                }
            )
            continue
        if section is None or executable or not nul_terminated:
            rejects.append(
                {
                    "literal": value,
                    "file_offset": "0x%X" % match.start(),
                    "reason": "executable, unmapped, or not NUL-terminated",
                }
            )
            continue
        va = image_base + section["rva"] + match.start() - section["raw_offset"]
        literals.append({"path": value, "va": va, "section": section["name"]})
    return literals, rejects


def read_nul_ascii_strings(data, image_base, sections):
    values = {}
    for match in re.finditer(rb"[\x20-\x7E]{1,}", data):
        if match.end() >= len(data) or data[match.end()] != 0:
            continue
        section = file_offset_to_section(sections, match.start())
        if section is None or section["characteristics"] & 0x20000000:
            continue
        va = image_base + section["rva"] + match.start() - section["raw_offset"]
        values[va] = match.group().decode("ascii", "replace")
    return values


def decoded_instructions(path):
    command = [OBJDUMP, "-d", "-Mintel", "--insn-width=16", str(path)]
    output = subprocess.check_output(command, text=True, errors="replace")
    instructions = []
    for line in output.splitlines():
        match = DISASM_LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(3)
        operands = match.group(4).strip()
        instructions.append(
            {
                "address": address,
                "length": len(match.group(2).split()),
                "mnemonic": mnemonic,
                "operands": operands,
                "text": line,
            }
        )
    return instructions


def immediate_operand(instruction):
    match = HEX_IMMEDIATE.fullmatch(instruction["operands"].strip())
    return int(match.group(1), 16) if match else None


def add_esp_immediate(instruction):
    match = re.fullmatch(r"esp,0x([0-9a-fA-F]+)", instruction["operands"].replace(" ", "").lower())
    return int(match.group(1), 16) if match else None


def c_string_at_va(data, image_base, sections, va):
    for section in sections:
        start_va = image_base + section["rva"]
        end_va = start_va + section["raw_size"]
        if start_va <= va < end_va:
            offset = section["raw_offset"] + va - start_va
            end = data.find(b"\0", offset, section["raw_offset"] + section["raw_size"])
            if end < 0:
                return ""
            raw = data[offset:end]
            if any(byte < 0x20 and byte not in (9, 10, 13) for byte in raw):
                return ""
            return raw.decode("ascii", "replace")
    return ""


def adjacent(left, right):
    return left["address"] + left["length"] == right["address"]


def message_fields(instruction, data, image_base, sections):
    operand = instruction["operands"].strip()
    value = immediate_operand(instruction)
    if value is None:
        return operand, "dynamic", "", ""
    if value == 0:
        return operand, "null", "", ""
    text = c_string_at_va(data, image_base, sections, value)
    if text:
        return operand, "immediate_string", "0x%08X" % value, text
    return operand, "immediate_unresolved", "0x%08X" % value, ""


def decoded_breadcrumbs(label, instructions, source_by_va, data, image_base, sections, expected_target):
    rows = []
    rejects = []
    for index, instruction in enumerate(instructions):
        if instruction["mnemonic"] != "push":
            continue
        source_va = immediate_operand(instruction)
        if source_va not in source_by_va:
            continue
        source = source_by_va[source_va]
        previous = instructions[index - 1] if index else None
        message = instructions[index - 2] if index > 1 else None
        following = instructions[index + 1] if index + 1 < len(instructions) else None
        cleanup = instructions[index + 2] if index + 2 < len(instructions) else None
        line_value = immediate_operand(previous) if previous and previous["mnemonic"] == "push" else None
        target = immediate_operand(following) if following and following["mnemonic"] == "call" else None
        cleanup_value = add_esp_immediate(cleanup) if cleanup and cleanup["mnemonic"] == "add" else None
        pattern = (
            message is not None
            and message["mnemonic"] == "push"
            and line_value is not None
            and 1 <= line_value <= 20000
            and target == expected_target
            and cleanup_value == 12
            and adjacent(message, previous)
            and adjacent(previous, instruction)
            and adjacent(instruction, following)
            and adjacent(following, cleanup)
        )
        if not pattern:
            rejects.append(
                {
                    "source_file": source["path"],
                    "xref_address": "0x%08X" % instruction["address"],
                    "reason": "does not meet contiguous push message; push immediate line; push source; call known dispatcher; add esp,0xC pattern",
                }
            )
            continue
        diagnostic_operand, message_kind, diagnostic_address, diagnostic = message_fields(
            message, data, image_base, sections
        )
        rows.append(
            {
                "build": label,
                "source_file": source["path"],
                "string_address": "0x%08X" % source_va,
                "xref_address": "0x%08X" % instruction["address"],
                "xref_kind": "decoded push imm32",
                "caller_function": "",
                "line_number": str(line_value),
                "line_evidence": "adjacent decoded immediate push",
                "assert_call_address": "0x%08X" % following["address"],
                "assert_target": "0x%08X" % expected_target,
                "diagnostic_operand": diagnostic_operand,
                "message_kind": message_kind,
                "diagnostic_address": diagnostic_address,
                "diagnostic": diagnostic,
                "confidence": "contiguous decoded five-instruction dispatcher pattern",
            }
        )
    return rows, rejects


def write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def inspect(path, label, expected_target):
    data, base, timestamp, sections = parse_pe(path)
    literals, literal_rejects = read_source_literals(data, base, sections)
    instructions = decoded_instructions(path)
    source_by_va = {literal["va"]: literal for literal in literals}
    rows, call_rejects = decoded_breadcrumbs(
        label, instructions, source_by_va, data, base, sections, expected_target
    )
    for row in literal_rejects:
        row["build"] = label
    for row in call_rejects:
        row["build"] = label
    return {
        "path": str(path),
        "label": label,
        "sha256": hashlib.sha256(data).hexdigest(),
        "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "literals": literals,
        "literal_rejects": literal_rejects,
        "rows": rows,
        "call_rejects": call_rejects,
        "instructions": instructions,
    }


def source_tree_markdown(june):
    groups = defaultdict(list)
    for literal in june["literals"]:
        directory = literal["path"].split("\\", 1)[0]
        groups[directory].append(literal)
    lines = [
        "# Recovered source-path string tree",
        "",
        "Each entry is a NUL-terminated, directory-qualified source-path literal from a non-executable PE section.",
        "",
    ]
    for directory in sorted(groups):
        lines.extend(["## " + directory, ""])
        for literal in sorted(groups[directory], key=lambda row: row["path"].lower()):
            lines.append("- %s at 0x%08X" % (literal["path"], literal["va"]))
        lines.append("")
    return "\n".join(lines)


def main():
    global OBJDUMP
    parser = argparse.ArgumentParser()
    parser.add_argument("--june", required=True, type=Path)
    parser.add_argument("--gog", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--objdump", default=OBJDUMP, help="path to GNU objdump")
    args = parser.parse_args()
    OBJDUMP = args.objdump
    args.out.mkdir(parents=True, exist_ok=True)
    june_hash = verify_known_input(args.june, JUNE_SHA256, "June")
    gog_hash = verify_known_input(args.gog, GOG_SHA256, "GOG")
    june = inspect(args.june, "june_legacy", JUNE_DIAGNOSTIC_TARGET)
    gog = inspect(args.gog, "gog_candidate", GOG_DIAGNOSTIC_TARGET)
    if june["sha256"] != june_hash or gog["sha256"] != gog_hash:
        raise RuntimeError("input changed during extraction")

    fields = [
        "build", "source_file", "string_address", "xref_address", "xref_kind",
        "caller_function", "line_number", "line_evidence", "assert_call_address",
        "assert_target", "diagnostic_operand", "message_kind", "diagnostic_address",
        "diagnostic", "confidence",
    ]
    write_csv(args.out / "source_breadcrumbs.csv", fields, june["rows"] + gog["rows"])
    reject_fields = ["build", "source_file", "xref_address", "reason"]
    write_csv(args.out / "breadcrumb_call_rejects.csv", reject_fields, june["call_rejects"] + gog["call_rejects"])
    write_csv(args.out / "source_literal_rejects.csv", ["build", "literal", "file_offset", "reason"], june["literal_rejects"] + gog["literal_rejects"])

    (args.out / "source_tree.md").write_text(source_tree_markdown(june), encoding="utf-8")
    common = Counter(row["assert_target"] for row in june["rows"])
    main_target, main_count = common.most_common(1)[0] if common else ("", 0)
    assert_lines = [
        "# Decoded diagnostic dispatcher evidence",
        "",
        "The extractor accepts a breadcrumb only when objdump decodes five physically contiguous instructions: push message; push immediate line; push source; direct call to the build-specific dispatcher; add esp,0xC. The message operand is recorded as immediate_string, immediate_unresolved, null, or dynamic.",
        "",
        "June accepted patterns: %d." % len(june["rows"]),
        "Most common decoded direct target: %s at %d sites." % (main_target, main_count),
        "",
        "Representative validated site 0x00402349 is:",
        "- push 0x0048400C, a literal message beginning invalid difficulty value;",
        "- push 0x000001AC, line 428;",
        "- push 0x00487FD0, shell\\shell.c;",
        "- call 0x00477920;",
        "- add esp,0x0C.",
        "",
        "GOG representative site 0x0040275F pushes invalid difficulty value, line 522, and source 0x0048E4DC; it calls 0x0047D5A0 and cleans 12 bytes. Its common target has the same observed dispatcher shape, including source, line, and message stack reads.",
        "",
        "This establishes caller-cleaned 12-byte arguments at these sites: source pointer, 32-bit line word, message pointer. Under normal right-to-left x86 pushes, callee order is (source, line, message). Exact C types, return type, signedness, routine name, and translation unit remain unresolved. The June common target has a reentrancy guard, formatter call, MessageBox-like IAT call, guard clear, and normal epilogue. debug\\assert.c is only a retained source-path literal, not ownership proof.",
    ]
    (args.out / "assert_system.md").write_text("\n".join(assert_lines), encoding="utf-8")

    pseudo = [
        {
            "canonical_id": "DIAG_00477920",
            "address": "0x00477920",
            "source_file": "",
            "line_min": "",
            "line_max": "",
            "explicit_name_if_any": "",
            "confidence": "strong",
            "evidence": "Decoded representative cdecl callsite plus %d accepted source-line-message neighborhoods." % main_count,
        }
    ] if main_target == "0x00477920" else []
    write_csv(args.out / "pseudo_symbols.csv", ["canonical_id", "address", "source_file", "line_min", "line_max", "explicit_name_if_any", "confidence", "evidence"], pseudo)
    write_csv(args.out / "canonical_functions.csv", ["canonical_id", "june_address", "gog_address", "basis", "source_file", "line_evidence", "status"], [])

    def anchor_key(row):
        if not row["diagnostic"]:
            return None
        return row["source_file"].lower(), row["line_number"], row["diagnostic"]

    june_anchors = defaultdict(list)
    gog_anchors = defaultdict(list)
    for row in june["rows"]:
        if anchor_key(row):
            june_anchors[anchor_key(row)].append(row)
    for row in gog["rows"]:
        if anchor_key(row):
            gog_anchors[anchor_key(row)].append(row)
    anchors = []
    for key in sorted(set(june_anchors) & set(gog_anchors)):
        if len(june_anchors[key]) == 1 and len(gog_anchors[key]) == 1:
            left = june_anchors[key][0]
            right = gog_anchors[key][0]
            anchors.append(
                {
                    "source_file": left["source_file"],
                    "line_number": left["line_number"],
                    "diagnostic": left["diagnostic"],
                    "june_callsite": left["assert_call_address"],
                    "gog_callsite": right["assert_call_address"],
                    "june_target": left["assert_target"],
                    "gog_target": right["assert_target"],
                    "status": "unique exact source-line-message diagnostic callsite anchor; not a function identity",
                }
            )
    write_csv(args.out / "matched_callsite_anchors.csv", ["source_file", "line_number", "diagnostic", "june_callsite", "gog_callsite", "june_target", "gog_target", "status"], anchors)

    labels = []
    for row in june["rows"] + gog["rows"]:
        for label in sorted(set(SCOPE_LABEL.findall(row["diagnostic"]))):
            labels.append(
                {
                    "build": row["build"],
                    "scope_label": label,
                    "source_file": row["source_file"],
                    "line_number": row["line_number"],
                    "callsite": row["assert_call_address"],
                    "status": "diagnostic-text label; not assigned as an enclosing function name",
                }
            )
    write_csv(args.out / "explicit_diagnostic_labels.csv", ["build", "scope_label", "source_file", "line_number", "callsite", "status"], labels)

    june_paths = {row["path"].lower() for row in june["literals"]}
    gog_paths = {row["path"].lower() for row in gog["literals"]}
    original = {row["path"].lower(): row for row in june["literals"]}
    later = {row["path"].lower(): row for row in gog["literals"]}
    diff = [
        "# Source-path literal difference",
        "",
        "June legacy PE timestamp: %s." % june["timestamp"],
        "GOG candidate PE timestamp: %s." % gog["timestamp"],
        "The PE timestamp is build metadata, not by itself release/version identity.",
        "",
        "June accepted paths: %d. GOG accepted paths: %d. Shared: %d." % (len(june_paths), len(gog_paths), len(june_paths & gog_paths)),
        "",
        "## Only GOG",
        "",
    ]
    diff.extend("- %s at 0x%08X" % (later[key]["path"], later[key]["va"]) for key in sorted(gog_paths - june_paths))
    diff.extend(["", "No source addition, code motion, or gameplay conclusion follows from literal presence alone."])
    (args.out / "version_source_diff.md").write_text("\n".join(diff), encoding="utf-8")

    report = [
        "# CyberStorm semantic breadcrumb recovery",
        "",
        "Inputs:",
        "- June baseline SHA-256 %s; PE timestamp %s." % (june["sha256"], june["timestamp"]),
        "- GOG candidate SHA-256 %s; PE timestamp %s." % (gog["sha256"], gog["timestamp"]),
        "",
        "Results:",
        "- June original source paths recovered: %d." % len(june_paths),
        "- June paths with accepted decoded source-line-call-cleanup xrefs: %d." % len({row["source_file"].lower() for row in june["rows"]}),
        "- June accepted line-number callsites: %d." % len(june["rows"]),
        "- June message operands: immediate string %d; immediate unresolved %d; dynamic %d; null %d." % (
            sum(row["message_kind"] == "immediate_string" for row in june["rows"]),
            sum(row["message_kind"] == "immediate_unresolved" for row in june["rows"]),
            sum(row["message_kind"] == "dynamic" for row in june["rows"]),
            sum(row["message_kind"] == "null" for row in june["rows"]),
        ),
        "- Native functions assigned to source files: 0; enclosing caller boundaries are unresolved.",
        "- Approximate caller line ranges: 0; no caller function extents are inferred.",
        "- Distinct explicit scope labels found in accepted diagnostic text: %d; assigned to functions: 0." % len({row["scope_label"] for row in labels}),
        "- Shared dispatcher pseudo-symbols: %d." % len(pseudo),
        "- Crossbuild canonical function mappings: 0; no function boundaries are promoted.",
        "- Unique exact source-line-message crossbuild callsite anchors: %d; these are not function identities. Line shifts, such as the validated difficulty check 428 to 522, intentionally do not match this strict anchor rule." % len(anchors),
        "",
        "The supported result is a validated dispatcher subset, not all source xrefs: source, line, message operand classification, and decoded common target. It does not establish whole source-file ownership of machine functions. Rejected literal and call-pattern candidates are retained in separate CSV files.",
        "",
        "Reproduce with python tools/extract_breadcrumbs.py --june assets/legacy/CSTORM.EXE --gog assets/CSTORM.EXE --out notes/source_recovery. The extractor uses the installed objdump decoder and Python standard library.",
    ]
    (args.out / "semantic_recovery_report.md").write_text("\n".join(report), encoding="utf-8")
    (args.out / "inputs.json").write_text(json.dumps({"june": june["sha256"], "gog": gog["sha256"]}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
