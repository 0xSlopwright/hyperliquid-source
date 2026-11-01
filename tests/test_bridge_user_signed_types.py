"""Tests for tools/bridge_user_signed_types.py: static reads, the specification on real bytes, and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_user_signed_types", ROOT / "tools" / "bridge_user_signed_types.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-user-signed-types-94"
WITHDRAW_TEXT = b"HyperliquidTransaction:Withdraw(string hyperliquidChain,string destination,string amount,uint64 time)"


def row_named(name, multi=0):
    return next(row for row in tool.TYPES if row[0] == name and row[1] == multi)


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.cases = {case.label: case for case in tool.all_cases()}

    setUpClass = classmethod(prepare)

    def run_label(self, label):
        return tool.run_case(self.harness, self.cases[label])

    def poke(self, va, value):
        machine = self.harness.machine
        machine.patches = {va: value}
        machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()


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


class Spec(unittest.TestCase):
    def test_keccak_known_answers(self):
        self.assertEqual(tool.keccak(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(tool.keccak(b"transfer(address,uint256)")[:4].hex(), "a9059cbb")

    def test_withdraw_type_text(self):
        self.assertEqual(tool.type_text(row_named("Withdraw")), WITHDRAW_TEXT)

    def test_multi_row_adds_two_addresses_first(self):
        text = tool.type_text(row_named("Withdraw", 1))
        self.assertIn(b"(string hyperliquidChain,address payloadMultiSigUser,address outerSigner,string destination", text)

    def test_plain_and_multi_counts(self):
        self.assertEqual(sum(1 for row in tool.TYPES if not row[1]), 21)
        self.assertEqual(sum(1 for row in tool.TYPES if row[1]), 20)

    def test_every_multi_row_has_a_plain_row(self):
        for row in tool.TYPES:
            self.assertIn(row[0], tool.PLAIN)

    def test_digest_depends_on_each_input(self):
        row = row_named("Withdraw")
        values = tool.values_for(row, 0)
        base = tool.digest_of(row, 3, 0xA4B1, values)
        self.assertNotEqual(base, tool.digest_of(row, 2, 0xA4B1, values))
        self.assertNotEqual(base, tool.digest_of(row, 3, 0x66EEE, values))
        self.assertNotEqual(base, tool.digest_of(row, 3, 0xA4B1, dict(values, amount=b"1")))

    def test_absent_agent_name_hashes_as_empty(self):
        self.assertEqual(tool.field_word("opt", None), tool.keccak(b""))


class Static(Base):
    def test_hops_cover_every_row(self):
        rows = tool.hop_rows(self.harness)
        self.assertEqual(len(rows), 41)
        self.assertTrue(all(len(hops) == 5 for _, hops in rows))

    def test_missing_hop_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.body_slot_call(self.harness, 0x38E30C0, 0x38E3F90)
        with self.assertRaises(tool.EvidenceError):
            tool.body_direct_call(self.harness, 0x37F0780, 0x38F1720)

    def test_dispatch_tables(self):
        table = tool.dispatch_rows(self.harness)
        self.assertEqual(len(table["plain"]), 88)
        self.assertEqual(len(table["multi"]), 88)
        self.assertEqual(table["plain"][47]["action"], "Withdraw")
        self.assertEqual(table["multi"][47]["action"], "Withdraw/multi")
        self.assertEqual(table["plain"][47]["tag"], 0xA3)
        self.assertEqual(table["multi"][52]["action"], "")

    def test_row_outside_the_host_is_refused(self):
        begin, _ = self.image.exact_fde(tool.DISPATCH)
        with self.assertRaises(tool.EvidenceError):
            tool.arm_row(self.harness, tool.DISPATCH_TABLE, 1, begin, begin + 1)

    def test_static_names(self):
        names = tool.static_reads(self.harness)
        self.assertEqual(names["chain_names"], list(tool.CHAIN_NAMES))
        self.assertEqual(names["domain_name"], "HyperliquidSignTransaction")
        self.assertEqual(names["prefix_1901"], "1901")
        self.assertEqual(names["enum_names"]["vote"], list(tool.ENUM_NAMES["vote"]))
        self.assertEqual(names["enum_names"]["cat"], list(tool.ENUM_NAMES["cat"]))
        self.assertEqual(names["enum_names"]["abs"], list(tool.ENUM_NAMES["abs"]))
        self.assertEqual(names["address_encodings"], list(tool.ENUM_NAMES["enc"]))
        self.assertEqual(names["status_text_0x15"], "Vault may not perform this action.")


class Real(Base):
    def test_type_tier_runs_real_keccak(self):
        """The permutation itself in real bytes, once, against the specification."""
        machine = self.harness.machine
        kept = machine.slots.pop(tool.KECCAK_F)
        stubs = machine.real.stubs
        machine.real.stubs = stubs - {tool.KECCAK_F}
        try:
            self.assertIsNone(self.run_label("type/Withdraw"))
        finally:
            machine.slots[tool.KECCAK_F] = kept
            machine.real.stubs = stubs

    def test_withdraw_chain(self):
        for label in ("type/Withdraw", "struct/Withdraw/0", "digest/Withdraw/0", "wrap/Withdraw/0", "sign/Withdraw/0", "verify/Withdraw/0", "verify/Withdraw/1", "verify/Withdraw/2", "verify/Withdraw/3"):
            self.assertIsNone(self.run_label(label), label)

    def test_withdraw_multi_chain(self):
        for label in ("type/Withdraw/multi", "struct/Withdraw/multi/0", "verify/Withdraw/multi/2"):
            self.assertIsNone(self.run_label(label), label)

    def test_gates_in_order(self):
        for name in ("chain", "vault", "nonce", "expires", "recover", "all", "vault-first", "nonce-first", "type-error"):
            self.assertIsNone(self.run_label("gate/Withdraw/%s" % name), name)

    def test_send_multi_sig_has_two_gates_only(self):
        for name in ("chain", "nonce", "recover", "no-vault-gate", "no-expires-gate"):
            self.assertIsNone(self.run_label("gate/SendMultiSig/%s" % name), name)

    def test_field_shapes(self):
        for label in ("verify/ApproveAgent/1", "verify/GovVote/2", "verify/GovPropose/2", "verify/UserSetAbstraction/2", "verify/SendToEvmWithData/2", "verify/SendToEvmWithData/multi/2", "verify/SendAsset/multi/3", "verify/CUserModify/0"):
            self.assertIsNone(self.run_label(label), label)

    def test_tier4_text(self):
        for index in range(5):
            self.assertIsNone(self.run_label("tier4/Withdraw/%d" % index))

    def test_dispatch_cases(self):
        for label in ("dispatch/163/Withdraw", "dispatch/163/Withdraw/nonce", "dispatch/163/Withdraw/recover", "dispatch/118/rest", "dispatch/low-tag/rest", "dispatch/198/inner-nonce-equal", "dispatch/198/inner-nonce-differs", "dispatch/202/StakingLinkDisableTradingUser", "dispatch/168/SendMultiSig"):
            self.assertIsNone(self.run_label(label), label)


class Negative(Base):
    def test_gate_condition_flip_is_seen(self):
        self.poke(0x3A1BFFA, 0x74)  # jne becomes je at the chain compare
        self.assertTrue(self.run_label("verify/Withdraw/0"))

    def test_status_immediate_flip_is_seen(self):
        self.poke(0x3A1C00C, 0x5C)
        with_nonce = self.run_label("gate/Withdraw/nonce")
        self.assertTrue(with_nonce)

    def test_field_offset_flip_is_seen(self):
        self.poke(0x38E3258, 0x00)  # destination pointer read at +0 instead of +8
        trouble = None
        try:
            trouble = self.run_label("struct/Withdraw/0")
        except (tool.Halt, tool.Panicked) as error:
            trouble = str(error)
        self.assertTrue(trouble)

    def test_type_text_byte_flip_is_seen(self):
        self.poke(tool.CAMEL + 0x79, 0x5E)  # the 0x5f underscore compare
        trouble = None
        try:
            trouble = self.run_label("type/Withdraw/multi")
        except (tool.Halt, tool.Panicked) as error:
            trouble = str(error)
        self.assertTrue(trouble)

    def test_wrong_expected_digest_is_seen(self):
        case = self.cases["verify/Withdraw/0"]
        kept = tool.digest_of
        tool.digest_of = lambda *args: bytes(32)
        try:
            self.assertEqual(tool.run_case(self.harness, case), "digest at the recover call")
        finally:
            tool.digest_of = kept


class Packet(Base):
    def test_cases_and_tables_match_the_packet(self):
        files = tool.render(tool.analyse(self.image, full=False))
        for name in ("cases.tsv", "vectors.tsv", "types.tsv", "fields.tsv", "hops.tsv", "dispatch.tsv"):
            self.assertEqual(files[name], (FOLDER / name).read_text(encoding="ascii"), name)

    def test_mutation_rows_have_reasons(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        self.assertTrue(rows)
        self.assertFalse([row for row in rows if row[3] != "killed" and not row[5]])

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
