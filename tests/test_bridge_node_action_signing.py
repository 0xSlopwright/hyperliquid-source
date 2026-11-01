"""Tests for tools/bridge_node_action_signing.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_node_action_signing", ROOT / "tools" / "bridge_node_action_signing.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-node-action-signing-94"


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.spec, cls.chain_at, cls.time_at = tool.build_spec(cls.harness.table)
        cls.cases = {case.label: case for case in tool.all_cases(cls.chain_at, cls.time_at)}

    setUpClass = classmethod(prepare)

    def run_label(self, label):
        return tool.compare(self.harness, self.spec, self.cases[label])

    def poke(self, patches):
        self.harness.machine.patches = patches
        self.harness.machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()

    def flip(self, va, at, kind="branch"):
        self.poke(tool.mutate_patch(self.image, va, at, kind))


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
            image.exact_fde(tool.BUILD + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)


class Rules(unittest.TestCase):
    def test_row_of(self):
        self.assertEqual(tool.row_of(0x74), 0)
        self.assertEqual(tool.row_of(0x73), 20)
        self.assertEqual(tool.row_of(0xCB), 87)

    def test_unix_ms_epoch(self):
        self.assertEqual(tool.unix_ms((tool.date_word(1970, 1), 0, 0)), 0)
        self.assertEqual(tool.unix_ms((tool.date_word(1970, 2), 1, 2000000)), 86401002)

    def test_expiry_floor(self):
        self.assertEqual(tool.expiry_after((tool.date_word(1960, 1), 0, 0)), 30000)
        self.assertEqual(tool.expiry_after((tool.date_word(1970, 1), 1, 0)), 31000)

    def test_leap_second_nanos_are_kept(self):
        self.assertEqual(tool.unix_ms((tool.date_word(1970, 1), 59, 1999000000)), 60999)

    def test_user_rows_are_twenty(self):
        self.assertEqual(len(tool.USER_SIGNED_ROWS), 20)


class Static(Base):
    def test_status_texts_read(self):
        rows = {row[0]: row[3] for row in map(lambda tag: tool.status_row(self.image, tag), tool.STATUS_TAGS)}
        self.assertEqual(rows[0x8C], "Action does not support expires_after")
        self.assertEqual(rows[0x5D], "Nonce mismatch.")

    def test_expiry_table_matches_the_user_rows(self):
        table = self.harness.table
        self.assertEqual(tuple(row for row in range(tool.ROWS) if not table.has_expiry(row)), tool.USER_SIGNED_ROWS)

    def test_plain_table_is_the_user_rows_and_multi_sig(self):
        self.assertEqual(sorted(self.harness.table.plain_host), sorted(tool.USER_SIGNED_ROWS + (52,)))

    def test_multi_table_is_the_user_rows(self):
        self.assertEqual(tuple(sorted(self.harness.table.multi_host)), tool.USER_SIGNED_ROWS)

    def test_gate_offsets_match_the_notes(self):
        self.assertEqual(self.chain_at, tool.table_offsets())

    def test_builder_sites_are_the_listed_eight(self):
        self.assertEqual(tool.slot_sites(self.image, tool.SLOT_BUILD), sorted(site for site, _ in tool.REQUEST_SITES))

    def test_no_site_sets_the_multi_or_vault_byte(self):
        for row in tool.site_rows(self.image):
            self.assertEqual((row["multi_byte"], row["vault_byte"]), (0, 0), hex(row["site"]))

    def test_site_tags(self):
        tags = [row["tag"] for row in tool.site_rows(self.image)]
        self.assertEqual(tags, [None, 0x75, 0x85, 0xCB, 0xB0, 0xB2, 0xB1, 0x95])

    def test_stack_store_refuses_a_missing_store(self):
        self.assertIsNone(tool.stack_store(bytes(64), 0x21C0, 8))

    def test_sample_facts(self):
        self.assertEqual(tool.sample_facts(self.image)["take_limit"], 2)
        self.assertEqual(tool.sample_facts(self.image)["wallet_stride"], 0x98)

    def test_single_callers(self):
        self.assertEqual(tool.direct_sites(self.image, tool.SIGNER_MAP), [0x3341C37])
        self.assertEqual(tool.slot_sites(self.image, tool.SLOT_WALLETS), [0x3341B65])

    def test_every_survivor_class_names_a_real_row(self):
        for va in tool.SURVIVOR_CLASS:
            self.image.fde(va)

    def test_folder_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


class Bytes(Base):
    def check(self, prefix):
        hit = 0
        for label, case in self.cases.items():
            if label.startswith(prefix):
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)
                hit += 1
        self.assertGreater(hit, 0)

    def test_plain_cases(self):
        self.check("plain/")

    def test_multi_cases(self):
        self.check("multi/")

    def test_verify_cases(self):
        self.check("verify/")

    def test_send_cases(self):
        self.check("send/")

    def test_build_table_cases(self):
        self.check("build/0x")

    def test_multi_wrap_cases(self):
        self.check("build/multi/")

    def test_date_cases(self):
        self.check("build/date/")

    def test_random_cases(self):
        self.check("build/random/")

    def test_gate_failure_falls_to_the_agent_form(self):
        self.assertIsNone(self.run_label("plain/47/nonce/3"))
        self.assertIn(("drop", 0x5D), self.harness.events)
        self.assertTrue(any(row[0] == "payload" for row in self.harness.events))


class Wire(Base):
    def test_bundle_cases(self):
        for label, case in self.cases.items():
            if label.startswith("bundle/"):
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_decode_cases(self):
        for label, case in self.cases.items():
            if label.startswith("decode/"):
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_real_writer_into_real_reader(self):
        case = self.cases["bundle/two/0x%x" % 1761900000123]
        self.assertIsNone(tool.compare(self.harness, self.spec, case))
        memory = self.harness.machine.memory
        arc = memory.read(memory.read(tool.STATE_AT + 0x4D8, 8) + 0x168 + 8, 8)
        wire = memory.bytes_at(memory.read(arc + 0x18, 8), memory.read(arc + 0x20, 8))
        back = tool.Case("decode/back", "decode", wire=wire, wallet=case.fields["wallet"])
        self.assertIsNone(tool.compare(self.harness, self.spec, back))
        self.assertEqual(memory.read(tool.OUT_AT, 2), 0x186)
        self.assertEqual(memory.read(tool.OUT_AT + 0x18, 8), 2)
        self.assertEqual(memory.read(tool.OUT_AT + 0x20, 8), 1761900000123)

    def test_empty_bundle_is_written_but_the_reader_refuses_it(self):
        wire = tool.wire_bundle([], 1, bytes(20))[0]
        self.assertEqual(len(wire), 78)
        self.assertEqual(tool.decode_bundle({"events": []}, wire)[0], 0x86)

    def test_msgpack_forms(self):
        self.assertEqual(tool.msgpack_sizes([1, 200, 300]), bytes.fromhex("9301ccc8cd012c"))
        self.assertEqual(tool.msgpack_sizes([0] * 16)[:3], bytes.fromhex("dc0010"))

    def test_reader_status_for_bad_vault_tag(self):
        self.assertEqual(tool.decode_record(bytes(0x49) + b"\x02" + bytes(8)), (0x89, 2))


class Negative(Base):
    def assert_breaks(self, label):
        try:
            result = tool.compare(self.harness, self.spec, self.cases[label])
        except (tool.Halt, tool.Panicked, KeyError, tool.EvidenceError):
            return
        self.assertIsNotNone(result, label)

    def test_expiry_add(self):
        self.poke({0x3341FA8: 0x31})
        self.assert_breaks("build/0x80/given")

    def test_floor_flip(self):
        self.flip(0x3341FA2, 1, "cmov")
        self.assert_breaks("build/date/before")

    def test_nonce_tag_gate_flip(self):
        self.flip(0x3341B42, 1)
        self.assert_breaks("build/0x80/given")

    def test_multi_gate_flip(self):
        self.flip(0x3341B57, 1)
        self.assert_breaks("build/multi/agent/2")

    def test_chain_id_compare(self):
        self.poke({0x3341CBC: 0x02})
        self.assert_breaks("build/multi/chain/3")

    def test_multi_user_store(self):
        self.poke({0x3341BC9: 0x08})
        self.assert_breaks("build/multi/agent/1")

    def test_plain_gate_chain_flip(self):
        self.flip(0x38EDE12, 0)
        self.assert_breaks("plain/76/ok/3")

    def test_plain_gate_expiry_flip(self):
        self.flip(0x38EDE37, 0)
        self.assert_breaks("plain/76/expiry/3")

    def test_fallback_tag_flip(self):
        self.flip(0x3362E11, 0)
        self.assert_breaks("plain/47/ok/3")

    def test_multi_fallback_flip(self):
        self.flip(0x335EFBF, 1)
        self.assert_breaks("multi/77/ok/3")

    def test_verify_status_immediate(self):
        self.poke({0x333F771: 0x87})
        self.assert_breaks("verify/0x74/ok/3")

    def test_sender_tag(self):
        self.poke({0x4A10FC5: 0xB3})
        self.assert_breaks("send/cdeposit/3/0x1")

    def test_bundle_nonce_byte_order(self):
        self.poke({0x3340B54: 0x90})
        self.assert_breaks("bundle/one/0x%x" % 1761900000123)

    def test_bundle_sum_gate_flip(self):
        self.flip(0x342E7DC, 1)
        self.assert_breaks("decode/sum off")

    def test_reader_length_floor(self):
        self.poke({0x342E4C7: 0x10})
        self.assert_breaks("decode/short")

    def test_record_vault_tag_gate(self):
        self.flip(0x333F909, 1)
        self.assert_breaks("decode/vault tag")

    def test_queue_tag(self):
        self.poke({0x44ADC79: 0x08})
        self.assert_breaks("bundle/one/0x%x" % 1761900000123)

    def test_sign_error_gate_flip(self):
        self.flip(0x359EEBC, 1)
        self.assert_breaks("plain/0x74/agent")

    def test_changed_nonce_breaks_the_match(self):
        case = self.cases["build/0x80/given"]
        fields = dict(case.fields, nonce=case.fields["nonce"] + 1)
        self.harness.reset()
        spec_state = {"events": [], "now_ms": 0, "utc": fields["utc"], "envelope": (0, 0), "wallets": []}
        request = {"action": fields["action"], "chain": fields["chain"], "has_nonce": 1, "nonce": fields["nonce"], "vault": fields["vault"], "wallet": fields["wallet"], "multi": 0}
        want = self.spec.build(spec_state, request)
        self.assertIsNone(self.run_label("build/0x80/given"))
        self.assertNotEqual(self.harness.machine.memory.read(tool.OUT_AT + 0x148, 8), want["nonce"])


class Output(unittest.TestCase):
    def test_render_is_ascii_without_mark(self):
        for path in FOLDER.iterdir():
            if path.suffix in (".tsv", ".json"):
                data = path.read_bytes()
                self.assertTrue(all(byte < 128 for byte in data), path.name)
                self.assertNotIn(b"\x40", data, path.name)


if __name__ == "__main__":
    unittest.main()
