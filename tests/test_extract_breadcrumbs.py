import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "extract_breadcrumbs.py"
SPEC = importlib.util.spec_from_file_location("extract_breadcrumbs", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def instruction(address, length, mnemonic, operands):
    return {
        "address": address,
        "length": length,
        "mnemonic": mnemonic,
        "operands": operands,
        "text": "",
    }


def sequence(message="0x2000", target="0x477920", cleanup="esp,0xc", gap=False):
    offsets = [0, 5, 10, 15, 20]
    if gap:
        offsets[3] += 1
        offsets[4] += 1
    base = 0x400000
    return [
        instruction(base + offsets[0], 5, "push", message),
        instruction(base + offsets[1], 5, "push", "0x1ac"),
        instruction(base + offsets[2], 5, "push", "0x1000"),
        instruction(base + offsets[3], 5, "call", target),
        instruction(base + offsets[4], 3, "add", cleanup),
    ]


class DecoderParserTests(unittest.TestCase):
    def decoded_rows(self, instructions):
        return MODULE.decoded_breadcrumbs(
            "june_legacy", instructions, {0x1000: {"path": "shell\\shell.c"}},
            b"", 0x400000, [], 0x477920,
        )

    def test_direct_immediate_only(self):
        self.assertEqual(MODULE.immediate_operand({"operands": "0x487fd0"}), 0x487FD0)
        self.assertIsNone(MODULE.immediate_operand({"operands": "DWORD PTR ds:0x50d410"}))

    def test_cleanup_shape(self):
        self.assertEqual(MODULE.add_esp_immediate({"operands": "esp,0xc"}), 12)
        self.assertNotEqual(MODULE.add_esp_immediate({"operands": "esp,0x8"}), 12)

    def test_source_path_requires_directory(self):
        self.assertIsNone(MODULE.SOURCE_PATH.fullmatch("h0.C"))
        self.assertIsNotNone(MODULE.SOURCE_PATH.fullmatch("shell\\shell.c"))

    def test_invalid_pe_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.parse_pe(Path(__file__))

    def test_truncated_optional_header_and_section_table_reject(self):
        def pe_prefix(size, sections):
            data = bytearray(size)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x40)
            data[0x40:0x44] = b"PE\0\0"
            struct.pack_into("<H", data, 0x44, 0x14C)
            struct.pack_into("<H", data, 0x46, sections)
            struct.pack_into("<H", data, 0x54, 32)
            if size >= 0x78:
                struct.pack_into("<H", data, 0x58, 0x10B)
                struct.pack_into("<I", data, 0x74, 0x400000)
            return data

        with tempfile.TemporaryDirectory() as directory:
            optional = Path(directory) / "optional.bin"
            optional.write_bytes(pe_prefix(0x60, 0))
            table = Path(directory) / "table.bin"
            table.write_bytes(pe_prefix(0x78, 1))
            with self.assertRaises(ValueError):
                MODULE.parse_pe(optional)
            with self.assertRaises(ValueError):
                MODULE.parse_pe(table)

    def test_valid_contiguous_order_accepts_immediate_unresolved(self):
        rows, rejects = self.decoded_rows(sequence())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rejects, [])
        self.assertEqual(rows[0]["message_kind"], "immediate_unresolved")

    def test_dynamic_and_null_messages_are_preserved(self):
        dynamic_rows, _ = self.decoded_rows(sequence("eax"))
        null_rows, _ = self.decoded_rows(sequence("0x0"))
        self.assertEqual(dynamic_rows[0]["message_kind"], "dynamic")
        self.assertEqual(dynamic_rows[0]["diagnostic_operand"], "eax")
        self.assertEqual(null_rows[0]["message_kind"], "null")
        self.assertEqual(null_rows[0]["diagnostic_operand"], "0x0")

    def test_missing_message_push_rejects(self):
        instructions = sequence()
        instructions[0]["mnemonic"] = "mov"
        rows, rejects = self.decoded_rows(instructions)
        self.assertEqual(rows, [])
        self.assertEqual(len(rejects), 1)

    def test_wrong_target_rejects(self):
        rows, rejects = self.decoded_rows(sequence(target="0x477921"))
        self.assertEqual(rows, [])
        self.assertEqual(len(rejects), 1)

    def test_wrong_cleanup_rejects(self):
        rows, rejects = self.decoded_rows(sequence(cleanup="esp,0x8"))
        self.assertEqual(rows, [])
        self.assertEqual(len(rejects), 1)

    def test_address_gap_rejects(self):
        rows, rejects = self.decoded_rows(sequence(gap=True))
        self.assertEqual(rows, [])
        self.assertEqual(len(rejects), 1)


if __name__ == "__main__":
    unittest.main()
