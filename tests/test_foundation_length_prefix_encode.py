#!/usr/bin/env python3
"""Unit tests for the foundation length-prefix encode checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_length_prefix_encode -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_length_prefix_encode as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-length-prefix-encode-94",
    "evidence.json")
BINARY = os.path.join("artifacts", "node", "94", "hl-node")


def load_fixture():
    with open(EVIDENCE) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = checker.elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(EVIDENCE))
    return ev, binary, sections, packet_dir


class TestLengthPrefixEncode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        # Raises on any mismatch; silence is success.
        checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)

    def test_small_class_header_is_length_times_eight(self):
        result, header, total = checker.evaluate_rule(1, 0)
        self.assertEqual((result, header, total), (1, b"\x00", 1))
        result, header, total = checker.evaluate_rule(2, 1)
        self.assertEqual((result, header, total), (2, b"\x08", 2))
        result, header, total = checker.evaluate_rule(32, 31)
        self.assertEqual((result, header, total), (32, b"\xf8", 32))

    def test_small_class_boundary_is_0x1f_not_0x20(self):
        # 0x1f is the last small length; 0x20 switches to the medium class.
        result, header, total = checker.evaluate_rule(32, 0x1F)
        self.assertEqual(header, b"\xf8")
        result, header, total = checker.evaluate_rule(34, 0x20)
        self.assertEqual((result, header, total), (34, b"\x04\x02", 34))

    def test_medium_class_header_is_length_times_sixteen_plus_four(self):
        result, header, total = checker.evaluate_rule(34, 0x20)
        self.assertEqual((result, header, total), (34, b"\x04\x02", 34))
        result, header, total = checker.evaluate_rule(4097, 0xFFF)
        self.assertEqual((result, header, total), (4097, b"\xf4\xff", 4097))

    def test_medium_class_boundary_is_0xfff_not_0x1000(self):
        # 0xfff is the last medium length; 0x1000 switches to the large class.
        result, header, total = checker.evaluate_rule(4097, 0xFFF)
        self.assertEqual(header, b"\xf4\xff")
        result, header, total = checker.evaluate_rule(4099, 0x1000)
        self.assertEqual((result, header, total), (4099, b"\x0c\x00\x01\x00", 4099))

    def test_large_class_header_is_length_times_sixteen_plus_twelve(self):
        result, header, total = checker.evaluate_rule(4099, 0x1000)
        self.assertEqual((result, header, total), (4099, b"\x0c\x00\x01\x00", 4099))

    def test_capacity_short_by_one_fails_with_minus_70(self):
        # Both capacity checks precede their stores, so a short capacity
        # writes nothing and returns -70 exactly.
        self.assertEqual(
            checker.evaluate_rule(0, 0),
            (0xFFFFFFFFFFFFFFBA, None, None))
        self.assertEqual(
            checker.evaluate_rule(31, 31),
            (0xFFFFFFFFFFFFFFBA, None, None))
        self.assertEqual(
            checker.evaluate_rule(33, 32),
            (0xFFFFFFFFFFFFFFBA, None, None))
        self.assertEqual(
            checker.evaluate_rule(4098, 4096),
            (0xFFFFFFFFFFFFFFBA, None, None))

    def test_header_truncates_to_low_32_bits_above_2_to_32(self):
        # The header formulas use ecx, so a length above 32 bits truncates
        # the header while the total and the copy length stay 64-bit.
        result, header, total = checker.evaluate_rule(
            0x100000003, 0x100000000)
        self.assertEqual(
            (result, header, total),
            (0x100000003, b"\x0c\x00\x00\x00", 0x100000003))

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            result, header, total = checker.evaluate_rule(
                int(edge["capacity"], 16), int(edge["length"], 16))
            self.assertEqual(hex(result), edge["result"], edge)
            if header is None:
                self.assertIsNone(edge["header_hex"], edge)
                self.assertIsNone(edge["total"], edge)
                self.assertIsNone(edge["output_hex"], edge)
            else:
                self.assertEqual(header.hex(), edge["header_hex"], edge)
                self.assertEqual(total, edge["total"], edge)
                if edge["copy_content_checked"]:
                    data = bytes.fromhex(edge["data_hex"])
                    self.assertEqual((header + data).hex(),
                                     edge["output_hex"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660100")
        self.assertEqual(call["site"], "0x557162e")
        self.assertFalse(call["target_fde_start"])
        self.assertIsNone(call["target_fde_extent"])
        self.assertIsNone(call["target_fde_section_offset"])
        self.assertEqual(
            call["target_bytes"],
            "ff25a28c11006801000000e9d0ffffff")

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], ["0x5573b9c"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x55739f0"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        with open(os.path.join(self.packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("5571600:", window)
        self.assertIn("557162e:", window)
        self.assertIn("5571693:", window)
        self.assertIn("5571694:", window)
        with open(os.path.join(self.packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("5573b9c:", caller)
        with open(os.path.join(self.packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("5571600..0000000005571694", frames)
        self.assertIn("002d14a4", frames)
        self.assertIn("002d14c4", frames)
        self.assertIn("002d1784", frames)
        self.assertIn("55716a0", frames)

    def _corrupted(self, mutate):
        ev = copy.deepcopy(self.ev)
        mutate(ev)
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corruption_body_sha(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__("sha256", "0" * 64))

    def test_corruption_padding_count(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__("padding_bytes", 11))

    def test_corruption_window_fde_offset(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__(
                "fde_section_offset", "0xdeadbeef"))

    def test_corruption_call_target(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target", "0x5660101"))

    def test_corruption_callee_fde_claim(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target_fde_start", True))

    def test_corruption_plt_stub_bytes(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__(
                "target_bytes", "ff25a28c11006801000000e9d0fffffe"))

    def test_corruption_caller_list(self):
        self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x5000000"]))

    def test_corruption_rule_edge_header(self):
        def mutate(ev):
            ev["rule"]["edges"][3]["header_hex"] = "29"
        self._corrupted(mutate)

    def test_corruption_rule_edge_total(self):
        def mutate(ev):
            ev["rule"]["edges"][4]["total"] = 33
        self._corrupted(mutate)

    def test_corruption_rule_edge_result(self):
        def mutate(ev):
            ev["rule"]["edges"][1]["result"] = "0x0"
        self._corrupted(mutate)

    def test_corruption_target_digest(self):
        self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))


if __name__ == "__main__":
    unittest.main()
