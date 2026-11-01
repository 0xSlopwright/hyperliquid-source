"""Tests for tools/bridge_send_to_evm_path.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_send_to_evm_path", ROOT / "tools" / "bridge_send_to_evm_path.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-send-to-evm-path-94"


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.cases = {case.label: case for case in tool.all_cases()}

    setUpClass = classmethod(prepare)

    def run_label(self, label):
        return tool.compare(self.harness, None, self.cases[label])

    def poke(self, patches):
        self.harness.machine.patches = patches
        self.harness.machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()

    def killed(self, patches, label):
        self.poke(patches)
        try:
            return bool(self.run_label(label))
        except tool.FAULTS:
            return True


class Input(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256"):
            tool.load_image(expected="0" * 64)

    def test_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_outside_every_fde(self):
        image = tool.load_image()
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(tool.SEND_EVM + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)

    def test_nobits_section_gives_no_file_bytes(self):
        image = tool.load_image()
        bss = image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            image.offset(bss["address"] + 16)

    def test_truncated_relocation_section_is_refused(self):
        image = tool.load_image()
        image.named[".rela.dyn"] = dict(image.named[".rela.dyn"], size=image.named[".rela.dyn"]["size"] - 1)
        with self.assertRaisesRegex(tool.EvidenceError, "truncated"):
            list(image.relocations())


class Rules(unittest.TestCase):
    def test_hex_recipient_pads_left(self):
        self.assertEqual(tool.recipient_rule("0x1", 0), (tool.STATUS_OK, bytes(31) + b"\x01"))
        self.assertEqual(tool.recipient_rule("0x", 0), (tool.STATUS_OK, bytes(32)))

    def test_hex_recipient_needs_the_prefix(self):
        self.assertEqual(tool.recipient_rule("00", 0)[0], 0xB6)
        self.assertEqual(tool.recipient_rule("0x" + "1" * 65, 0)[0], 0xB6)

    def test_base58_needs_exactly_32_bytes(self):
        self.assertEqual(tool.recipient_rule("1" * 32, 1), (tool.STATUS_OK, bytes(32)))
        self.assertEqual(tool.recipient_rule("1" * 31, 1)[0], 0xB6)
        self.assertEqual(tool.recipient_rule("0", 1)[0], 0xB6)

    def test_system_address(self):
        fix = tool.Fix()
        self.assertEqual(tool.system_address(fix, tool.NATIVE_ID), b"\x22" * 20)
        self.assertEqual(tool.system_address(fix, 1), b"\x20" + bytes(18) + b"\x01")
        self.assertEqual(tool.system_address(tool.Fix(native=0), tool.NATIVE_ID)[0], 0x20)

    def test_system_range_ends_before_token_10000(self):
        self.assertTrue(tool.system_range(b"\x20" + bytes(17) + b"\x27\x0f"))
        self.assertFalse(tool.system_range(b"\x20" + bytes(17) + b"\x27\x10"))


class Real(Base):
    def test_every_case_matches(self):
        for label in self.cases:
            with self.subTest(label=label):
                self.assertFalse(self.run_label(label))

    def test_case_kinds(self):
        self.assertEqual({case.kind for case in self.cases.values()}, set(tool.COMPARES))

    def test_rule_that_allows_native_data_fails(self):
        real = tool.system_rule
        tool.system_rule = lambda fix, item: (tool.STATUS_OK, [])
        try:
            self.assertTrue(self.run_label("system_native_data"))
        finally:
            tool.system_rule = real

    def test_rule_with_a_wrong_route_fails(self):
        real = tool.route_rule
        tool.route_rule = lambda fix, item: (0x15B, None, [])
        try:
            self.assertTrue(self.run_label("route_spot"))
        finally:
            tool.route_rule = real

    def test_rule_without_the_mutation_check_fails(self):
        real = tool.move_rule

        def plain(fix, item):
            status, events = real(fix, item)
            return (fix.core if status == 0x17E else status), [row for row in events if row != ("status drop", fix.core)]
        tool.move_rule = plain
        try:
            self.assertTrue(self.run_label("move_core_touches"))
        finally:
            tool.move_rule = real

    def test_native_row_is_wei_and_sender(self):
        self.assertFalse(self.run_label("system_native"))
        memory = self.harness.machine.memory
        self.assertEqual(int.from_bytes(memory.bytes_at(tool.QUEUE_AT, 32), "little"), 5000 * 10 ** 10)
        self.assertEqual(memory.bytes_at(tool.QUEUE_AT + 32, 20), tool.USER)
        self.assertEqual(memory.read(tool.STATE_AT + 0x3110, 8), 1)

    def test_erc20_row_holds_contract_and_data(self):
        self.assertFalse(self.run_label("system_erc20_data"))
        memory = self.harness.machine.memory
        row = tool.QUEUE_AT + 0x400
        self.assertEqual(int.from_bytes(memory.bytes_at(row, 32), "little"), 500000)
        self.assertEqual(memory.read(row + 0x20, 8), 3)
        self.assertEqual(memory.read(row + 0x28, 8), tool.VTABLE_AT)
        self.assertEqual(memory.bytes_at(row + 0x94, 20), tool.CONTRACT)

    def test_depth_word_returns(self):
        self.assertFalse(self.run_label("route_unified_move"))
        self.assertEqual(self.harness.machine.memory.read(tool.STATE_AT + 0x58, 8), tool.DEPTH)


class Mutants(Base):
    def test_gas_limit(self):
        self.assertTrue(self.killed({0x2729564: 0x41}, "wire_gas_over"))

    def test_gas_status(self):
        self.assertTrue(self.killed({0x2729572: 0x4A}, "wire_gas_over"))

    def test_data_limit(self):
        self.assertTrue(self.killed({0x27296B8: 0x01}, "wire_data_over"))

    def test_native_queue(self):
        self.assertTrue(self.killed({0x27160B4: 0xB8}, "system_native_queue_full"))

    def test_erc20_queue(self):
        self.assertTrue(self.killed({0x2715E75: 0x0A}, "system_erc20_queue_full"))

    def test_fee_cap(self):
        self.assertTrue(self.killed({0x27166A3: 0x01}, "system_fee_over"))

    def test_single_limit(self):
        self.assertTrue(self.killed({0x27155CC: 0x01}, "system_usdc_over"))

    def test_multi_sig_status(self):
        self.assertTrue(self.killed({0x271550C: 0x4F}, "system_multi_user"))

    def test_native_data_status(self):
        self.assertTrue(self.killed({0x271561F: 0x49}, "system_native_data"))

    def test_usd_cap(self):
        self.assertTrue(self.killed({0x272C3B4: 0xC2}, "move_token_capped"))

    def test_base58_length(self):
        self.assertTrue(self.killed({0x3988C1F: 0x21}, "recipient_15"))

    def test_agent_status(self):
        self.assertTrue(self.killed({0x2728D4F: 0x84}, "agent_stranger"))

    def test_limit_branch(self):
        self.assertTrue(self.killed({0x272A8BE: 0x87}, "route_cap_under"))

    def test_invalid_send_status(self):
        self.assertTrue(self.killed({0x272A22A: 0x5C}, "route_self"))


class Static(Base):
    def test_key_rows_hold(self):
        self.assertEqual(len(tool.key_row_lines(self.image)), len(tool.KEY_ROWS) + 1)

    def test_moved_key_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.KEY_ROWS[0][0])] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "row moved"):
            tool.key_row_lines(tool.Image(bytes(blob)))

    def test_status_names(self):
        rows = {row[0]: row[3] for row in (tool.status_row(self.image, tag) for tag in tool.STATUS_TAGS)}
        self.assertEqual(rows[0x149], "gas_limit too large")
        self.assertEqual(rows[0x148], "Send to EVM with data not configured")
        self.assertEqual(rows[0x14E], "Multi-sig user cannot transfer token to EVM")
        self.assertEqual(rows[tool.STATUS_OK], "")

    def test_decode_table_gives_the_rule_alphabet(self):
        self.assertEqual(tool.base58_alphabet(self.image), tool.BASE58_TEXT)

    def test_broken_decode_table_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.ALPHABET_AT) + ord("2")] = 0
        with self.assertRaises(tool.EvidenceError):
            tool.base58_alphabet(tool.Image(bytes(blob)))

    def test_gate_rows_name_only_known_statuses(self):
        known = {"%#x" % tag for tag in tool.STATUS_TAGS}
        for row in tool.GATES:
            for word in row[3].split(", "):
                if word != "carried":
                    self.assertIn(word, known)


class Files(unittest.TestCase):
    def test_manifest_matches(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_tamper_is_seen(self):
        digest = hashlib.sha256(b"x").hexdigest()
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertNotIn(digest, " ".join(rows))

    def test_tables_without_mutants_regenerate(self):
        files = tool.render(tool.analyse(tool.load_image(), full=False))
        for name in ("cases.tsv", "functions.tsv", "call-sites.tsv", "status-text.tsv", "node-layouts.tsv", "key-rows.tsv", "gates.tsv", "record-fields.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)


if __name__ == "__main__":
    unittest.main()
