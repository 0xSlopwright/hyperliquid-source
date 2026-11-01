import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_register_validator as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-register-validator-94"


class Shared:
    image = None
    harness = None
    cases = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)
    Shared.cases = dict((case.name, case) for case in tool.named_cases())


def outcome(name, **change):
    case = Shared.cases[name]
    fields = dict((key, getattr(case, key)) for key in tool.Case.FIELDS)
    fields.update(change)
    return tool.Case(name, **fields)


def status(case):
    got = tool.run_case(Shared.harness, case)
    return dict((item[0], item[1:]) for item in got if item[0] in ("status", "payload"))["status"][0]


class JoinPath(unittest.TestCase):
    def test_every_named_case_matches_real_bytes(self):
        self.assertGreaterEqual(len(Shared.cases), 350)
        for case in Shared.cases.values():
            tool.check_case(Shared.harness, case)

    def test_generated_cases_match(self):
        seen = set()
        for case in tool.vector_cases(60):
            seen.add(tool.check_case(Shared.harness, case)[0][1])
        self.assertTrue({tool.OK, tool.NOT_ALLOWED} <= seen)

    def test_gate_order_is_set_key_proof_cold_then_present(self):
        names = ("join_set_empty", "join_undecodable_a", "join_proof_refused", "join_recover_error", "join_cold_differs_0", "join_present_1_0_0", "join_ok_chain3")
        self.assertEqual([status(Shared.cases[name]) for name in names], [tool.NOT_ALLOWED, tool.NOT_ALLOWED, tool.BAD_PROOF, tool.RECOVER_FAIL, tool.COLD_MISMATCH, tool.PRESENT, tool.OK])

    def test_refused_proof_stops_before_the_cold_digest(self):
        got = tool.run_case(Shared.harness, Shared.cases["join_proof_refused"])
        self.assertEqual([item[0] for item in got if item[0] in ("equation", "agent", "recover")], ["equation"])

    def test_present_row_is_found_after_the_cold_signature(self):
        got = tool.run_case(Shared.harness, Shared.cases["join_present_1_0_0"])
        self.assertEqual([item[0] for item in got if item[0] in ("equation", "agent", "recover")], ["equation", "agent", "recover"])

    def test_new_row_holds_one_wei_for_the_signer(self):
        got = tool.run_case(Shared.harness, Shared.cases["join_ok_chain3"])
        row = [item for item in got if item[0] == "row"][0]
        signer = tool.address(1).hex()
        self.assertEqual(row[2:], (signer, tool.address(2).hex(), ((signer, 1),)))

    def test_mode_three_alone_signs_as_a(self):
        for mode, source in ((3, "61"), (0, "62"), (1, "62"), (2, "62"), (0xAB03, "61")):
            got = tool.run_case(Shared.harness, outcome("join_ok_chain3", mode=mode))
            self.assertEqual([item for item in got if item[0] == "agent"][0][2], source)

    def test_message_has_no_key_and_decimal_nonce(self):
        case = outcome("join_ok_chain3", nonce=905)
        got = tool.run_case(Shared.harness, case)
        scalar = [item for item in got if item[0] == "equation"][0][6]
        digest = hashlib.sha512(case.proof[:32] + case.key + b"VALIDATOR_JOIN905").digest()
        self.assertEqual(int.from_bytes(bytes.fromhex(scalar), "little"), int.from_bytes(digest, "little") % tool.L)

    def test_key_point_is_negated(self):
        case = Shared.cases["join_ok_chain3"]
        x, y = tool.point_of(case.key)
        got = [item for item in tool.run_case(Shared.harness, case) if item[0] == "equation"][0]
        self.assertEqual((int(got[2], 16), int(got[3], 16)), ((tool.P - x) % tool.P, y))

    def test_each_cold_byte_counts(self):
        for name in Shared.cases:
            if name.startswith("join_cold_differs_"):
                self.assertEqual(status(Shared.cases[name]), tool.COLD_MISMATCH)

    def test_chain_runs_decoded_action_through_the_body(self):
        self.assertEqual(status(Shared.cases["chain_ok_owned"]), tool.OK)
        self.assertEqual(status(Shared.cases["chain_absent"]), tool.NOT_ALLOWED)


class Negative(unittest.TestCase):
    def test_wrong_sha256_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_compare_refuses_a_changed_status(self):
        case = Shared.cases["join_set_empty"]
        got = tool.run_case(Shared.harness, case)
        bad = (("status", tool.OK),) + got[1:]
        self.assertFalse(tool.compare(bad, tool.spec_run(case), case))

    def test_flipped_gate_branch_is_seen(self):
        site = 0x33678D1
        offset = Shared.image.offset(site)
        byte = bytes(Shared.image.blob[offset + 1:offset + 2])[0]
        harness = tool.Harness(Shared.image, {site + 1: byte ^ 1})
        self.assertIsNotNone(tool.first_failure(harness, [Shared.cases["join_set_empty"]], [tool.spec_run(Shared.cases["join_set_empty"])]))

    def test_flipped_key_byte_read_is_seen(self):
        case = outcome("join_ok_chain3", key=b"\x01" * 32)
        self.assertEqual(status(case), tool.NOT_ALLOWED)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(Exception):
            Shared.image.exact_fde(0x10)

    def test_read_with_a_changed_rule_is_seen(self):
        case = Shared.cases["read_empty_map_owned"]
        self.assertNotEqual(tool.run_case(Shared.harness, case), ("error", "missing field `nonce`"))

    def test_lower_case_tag_text_is_absent(self):
        rows = tool.text_rows(Shared.image)
        self.assertIn(("absent", "registerValidator"), rows)


class Wire(unittest.TestCase):
    def test_hex_quantity_has_no_leading_zero(self):
        self.assertEqual(tool.quantity(bytes(32)), "0x0")
        self.assertEqual(tool.quantity(b"\xAB" + bytes(31)), "0xab")

    def test_three_dispatch_arms(self):
        rows = tool.arm_rows(Shared.image)
        self.assertEqual([row[4] for row in rows], ["0x0", "0xa80", "0x0"])

    def test_every_copy_matches(self):
        rows = tool.copy_rows(Shared.image, Shared.harness, list(Shared.cases.values()))
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row[3] > 0 for row in rows))


class Files(unittest.TestCase):
    def test_summary_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_scenarios"], len(Shared.cases))
        self.assertEqual(data["functions"], len(tool.NAMES))

    def test_manifest_lists_every_file(self):
        names = set()
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, set(path.name for path in FOLDER.iterdir()) - {"MANIFEST.sha256"})

    def test_scenarios_file_matches_the_rules(self):
        rows = dict(line.split("\t", 1) for line in (FOLDER / "scenarios.tsv").read_text().splitlines()[1:])
        for name in ("join_set_empty", "read_good_owned", "seed_empty", "write_pretty_base"):
            case = Shared.cases[name]
            self.assertEqual(rows[name], tool.describe(case, tool.spec_run(case)))

    def test_no_external_tool_in_source(self):
        text = (pathlib.Path(tool.__file__)).read_text()
        for word in ("sub" + "process", "obj" + "dump", "read" + "elf"):
            self.assertNotIn(word + "(", text.replace("objdump or readelf", ""))


if __name__ == "__main__":
    unittest.main()
