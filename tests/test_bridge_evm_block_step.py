"""Tests for tools/bridge_evm_block_step.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_evm_block_step", ROOT / "tools" / "bridge_evm_block_step.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-evm-block-step-94"


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
            image.exact_fde(tool.STEP + 1)
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
    def test_keccak_known_digests(self):
        self.assertEqual(tool.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(tool.keccak256(b"Transfer(address,address,uint256)").hex()[:16], "ddf252ad1be2c89b")

    def test_scale_floor_and_cap(self):
        self.assertEqual(tool.scale_rule(10 ** 10 - 1, 10), 0)
        self.assertEqual(tool.scale_rule(25 * 10 ** 9, 10), 2)
        self.assertIsNone(tool.scale_rule(tool.MAX_NUMBER * 10 ** 10, 10))
        self.assertIsNone(tool.scale_rule(1, 20))
        self.assertIsNone(tool.scale_rule(tool.TOP, -1))

    def test_token_system_address(self):
        self.assertEqual(tool.token_address((1, 5), 5), b"\x22" * 20)
        self.assertEqual(tool.token_address((0, 5), 5), b"\x20" + bytes(18) + b"\x05")
        self.assertEqual(tool.token_address((1, 5), 0x0102), b"\x20" + bytes(17) + b"\x01\x02")

    def test_hold_saturates(self):
        kept, held, logs = tool.hold_rule(((0, 5, b"a"), (3, 1, b"b")), {b"a": tool.WORD - 1})
        self.assertEqual((kept, held, logs), ([(3, 1, b"b")], {b"a": tool.WORD}, 1))

    def test_retry_drops_the_data_block(self):
        row = tool.plain_row(0)
        row = row[:0x28] + bytes.fromhex("0100000000000000") + row[0x30:]
        rest, back, drops = tool.retry_rule({"flag": 0}, [row])
        self.assertEqual((rest, drops), ([], [("data drop",)]))
        self.assertEqual(back[0x28:0x30], bytes(8))


class Real(Base):
    def test_every_case_matches(self):
        for label in self.cases:
            with self.subTest(label=label):
                self.assertFalse(self.run_label(label))

    def test_case_kinds(self):
        self.assertEqual({case.kind for case in self.cases.values()}, set(tool.COMPARES))

    def test_rule_that_lets_dust_through_fails(self):
        real = tool.scale_rule
        tool.scale_rule = lambda value, exponent: value
        try:
            self.assertTrue(self.run_label("classify_received"))
        finally:
            tool.scale_rule = real

    def test_rule_with_no_keep_fails(self):
        real = tool.KEEP_FLOOR
        tool.KEEP_FLOOR = tool.TOP
        try:
            self.assertTrue(self.run_label("drain_keep_failed"))
        finally:
            tool.KEEP_FLOOR = real

    def test_rule_without_the_cap_in_the_check_fails(self):
        real = tool.reconcile_rule

        def plain(item):
            return real(dict(item, minted=0))
        tool.reconcile_rule = plain
        try:
            self.assertTrue(self.run_label("reconcile_minted"))
        finally:
            tool.reconcile_rule = real

    def test_rule_with_no_halt_fails(self):
        real = tool.step_rule

        def plain(item, memory):
            return real(dict(item, reconcile=(2, 0)), memory)
        tool.step_rule = plain
        try:
            self.assertTrue(self.run_label("step_underflow_flags"))
        finally:
            tool.step_rule = real

    def test_halted_block_pays_no_usdc_row(self):
        self.assertFalse(self.run_label("step_underflow_flags"))
        memory = self.harness.machine.memory
        self.assertEqual(memory.read(tool.STATE_AT + 0x31A2, 1), 1)
        self.assertEqual(memory.read(tool.OUT_AT + 0x10, 8), 1)
        self.assertEqual(memory.read(tool.STATE_AT + 0x3178, 8), 1)

    def test_data_call_head_is_seven_words(self):
        self.assertFalse(self.run_label("drain_erc20_data_empty"))
        row = [event for event in self.harness.events if event[0] == "exec"][0]
        self.assertEqual(row[7][:8], tool.SELECTOR_DATA)
        self.assertEqual(len(row[7]) // 2, 4 + 7 * 32)
        self.assertEqual(row[6], 2)

    def test_native_call_has_no_data(self):
        self.assertFalse(self.run_label("drain_native_one"))
        row = [event for event in self.harness.events if event[0] == "exec"][0]
        self.assertEqual(row[1:8], (0, tool.GAS_NATIVE, 10 ** 18, "22" * 20, tool.USER.hex(), 0, ""))

    def test_link_writes_the_cap(self):
        self.assertFalse(self.run_label("link_set"))
        self.assertEqual(self.harness.machine.memory.read(tool.STATE_AT + 0x3A48, 8), tool.LINK_MAX)

    def test_unset_clears_the_cap(self):
        self.assertFalse(self.run_label("link_unset"))
        self.assertEqual(self.harness.machine.memory.read(tool.STATE_AT + 0x3A48, 8), 0)

    def test_copy_uses_its_own_entry(self):
        self.assertNotEqual(tool.STEP, tool.STEP_COPIES[0])
        self.assertTrue(self.cases["copy_step_two_rows"].items["copy"])


class Mutants(Base):
    def test_native_gas(self):
        self.assertTrue(self.killed({0x3730F49: 0x31}, "drain_native_one"))

    def test_kind_of_a_linked_transfer(self):
        self.assertTrue(self.killed({0x327112F: 0x05}, "drain_linked_balance_above"))

    def test_keep_floor(self):
        self.assertTrue(self.killed({0x3271392: 0x01}, "drain_keep_failed"))

    def test_transfer_selector(self):
        self.assertTrue(self.killed({0x3730FA0: 0xA8}, "drain_erc20_plain"))

    def test_data_selector(self):
        self.assertTrue(self.killed({0x3731127: 0x6C}, "drain_erc20_data"))

    def test_action_tag(self):
        self.assertTrue(self.killed({0x27611F2: 0xAE}, "step_one_token_row"))

    def test_row_end_tag(self):
        self.assertTrue(self.killed({0x2761603: 0xCD}, "step_signed_stop"))

    def test_halt_byte_value(self):
        self.assertTrue(self.killed({0x2760D53: 0x02}, "step_underflow_flags"))

    def test_native_decimals(self):
        self.assertTrue(self.killed({0x3427536: 0x0B}, "classify_received"))

    def test_token_decimals_byte(self):
        self.assertTrue(self.killed({0x2760182: 0xFF}, "reconcile_plain"))

    def test_constant_100(self):
        self.assertTrue(self.killed({0x2760691: 0x65}, "reconcile_queue_counts"))

    def test_link_cap(self):
        self.assertTrue(self.killed({0x274BBB3: 0x7E}, "link_set"))

    def test_status_of_link(self):
        self.assertTrue(self.killed({0x274B992: 0xDE}, "link_used_token_zero"))


class Static(Base):
    def test_key_rows_hold(self):
        self.assertEqual(len(tool.key_row_lines(self.image)), len(tool.KEY_ROWS) + 1)

    def test_moved_key_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.KEY_ROWS[0][0])] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "row moved"):
            tool.key_row_lines(tool.Image(bytes(blob)))

    def test_topics_are_keccak_of_the_texts(self):
        self.assertEqual(len(tool.signature_lines(self.image)), 7)

    def test_changed_topic_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.TOPIC_LOW[0])] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "Received topic"):
            tool.signature_lines(tool.Image(bytes(blob)))

    def test_jump_rows_reach_the_arms(self):
        rows = {tuple(line.split("\t")[:2]): line.split("\t")[2] for line in tool.table_lines(self.image)[1:]}
        self.assertEqual(rows[("VoteGlobal raw tag", "0x61")], "%#x" % tool.RETRY_ARM)
        self.assertEqual(rows[("raw 0x5e selector", "3")], "%#x" % tool.RELEASE_ARM)
        self.assertEqual(rows[("raw 0x5e selector", "4")], "%#x" % tool.SELECTOR_GAUGE)

    def test_status_text(self):
        rows = {row[0]: row[3] for row in (tool.status_row(self.image, tag) for tag in tool.STATUS_TAGS)}
        self.assertEqual(rows[tool.STATUS_TAGS[-1]], "")

    def test_fragments_lie_inside_their_hosts(self):
        for start, end in tool.FRAGMENTS.items():
            host = self.image.fde(start)
            self.assertLessEqual(end, host[1])


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
        for name in ("cases.tsv", "functions.tsv", "call-sites.tsv", "status-text.tsv", "node-layouts.tsv", "key-rows.tsv", "gates.tsv", "record-fields.tsv", "field-sites.tsv", "rodata-texts.tsv", "signatures.tsv", "jump-rows.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)


if __name__ == "__main__":
    unittest.main()
