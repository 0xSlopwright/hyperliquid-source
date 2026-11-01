"""Independent FSE native/fixture controls, without compiling or running Rust.

Native corruption checks use real changed 771-byte views and GNU decoding.
Corpus checks bind pre-Rust mathematical expectations; they are not execution
of the library. Its linked-client qualification is recorded separately.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import fse_weight_table as table

PACKET = ROOT / "research/work-items/RE-001-fse-weight-table-94"
OBSERVED = PACKET / "observed"
ORACLE = PACKET / "independent-oracle"
CONTROLS = PACKET / "independent-controls"
VECTORS = ROOT / "src/node94-fse-weight-table"
BODY_SHA256 = "8d7636d905df5188c3a5d0d495cf337bf1eca14949a373cc7e5393f5ae94484e"


def load_json(path):
    return json.loads(path.read_text())


def changed(raw, offset, replacement):
    copy = bytearray(raw)
    copy[offset:offset + len(replacement)] = replacement
    return bytes(copy)


class FseAdmissionBoundaryTests(unittest.TestCase):
    def test_existing_output_precedes_admission_and_wrong_input_exports_nothing(self):
        with tempfile.TemporaryDirectory(prefix="fse-no-export-") as temporary:
            root = Path(temporary)
            output = root / "retained"
            output.mkdir()
            marker = output / "marker"
            marker.write_bytes(b"retain prior evidence")
            with self.assertRaisesRegex(table.EvidenceError, "new|preserved"):
                table.collect(root / "missing-node", output)
            self.assertEqual(marker.read_bytes(), b"retain prior evidence")
            self.assertEqual([p.name for p in output.iterdir()], ["marker"])
            bad = root / "bad-node"
            bad.write_bytes(b"not the captured input")
            with self.assertRaisesRegex(table.EvidenceError, "authenticated"):
                table.collect(bad, root / "failed")
            self.assertFalse((root / "failed").exists())

    def test_tiny_decoder_extent_and_real_unqualified_provider_refuse(self):
        for raw in (b"", bytes(1025)):
            with self.subTest(bytes=len(raw)):
                with self.assertRaisesRegex(table.EvidenceError, "tiny"):
                    table.decode_span(raw)
        with tempfile.TemporaryDirectory(prefix="fse-provider-") as temporary:
            provider = Path(temporary) / "not-the-qualified-reader"
            provider.write_bytes(b"ordinary non-executable fixture")
            provider.chmod(0o600)
            with mock.patch.object(table, "PROVIDER", provider):
                with self.assertRaisesRegex(table.EvidenceError, "provider unavailable"):
                    table.decode_span(b"\x90")


class FseNativeRawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = bytes.fromhex((OBSERVED / "constructor.hex").read_text())
        cls.listing = (OBSERVED / "table.objdump.txt").read_text()

    def test_complete_native_code_and_bounded_contract_parameters(self):
        self.assertEqual(len(self.raw), 771)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), BODY_SHA256)
        proof = table.prove_table(self.raw, self.listing)
        self.assertEqual(proof["native_rows"], 213)
        self.assertEqual(proof["proof"]["calls"], 0)
        self.assertEqual(proof["proof"]["normal_RAX"], 0)
        self.assertIs(proof["listing_prose_semantic_authority"], False)
        self.assertIs(proof["whole_decoder_or_Rust_or_byte_identity_claim"], False)
        parameters = proof["parameters"]
        for name, value in (("scratch_extra", 8), ("table_header_bytes", 4),
                            ("stride_bias", 3), ("low_symbol_field", 2),
                            ("low_next_initial", 1), ("final_symbol_field", 6),
                            ("final_bits_field", 7), ("final_base_field", 4)):
            self.assertEqual(parameters[name], value)
        # The caller caps are a separately bound qualification premise, not
        # constants decoded from this 771-byte constructor alone.
        self.assertEqual([(d["log"], d["T"], d["stride"],
                           d["caller876_max_symbol"],
                           d["constructor_residual_only_max_symbol"],
                           d["table_bytes"]) for d in proof["domains"]],
                         [(5, 32, 23, 91, 95, 132), (6, 64, 43, 11, 15, 260)])
        for raw in (self.raw[:-1], self.raw + b"\x90"):
            with self.assertRaisesRegex(table.EvidenceError, "complete 771"):
                table.prove_table(raw)

    def test_actual_changed_native_rows_fail_below_the_whole_image_gate(self):
        design = load_json(CONTROLS / "NATIVE-CONTROL-DESIGN.json")
        self.assertEqual(design["body_sha256"], BODY_SHA256)
        mutations = design["actual_same_length_changed_row_controls"]
        self.assertEqual(len(mutations), 39)
        for mutation in mutations:
            with self.subTest(address=hex(mutation["address"]), meaning=mutation["meaning"]):
                before = bytes.fromhex(mutation["before_hex"])
                after = bytes.fromhex(mutation["after_hex"])
                offset = mutation["address"] - 0x556fb60
                self.assertEqual(self.raw[offset:offset + len(before)], before)
                self.assertEqual(len(before), len(after))
                raw = changed(self.raw, offset, after)
                rows, actual_listing, provider = table.decode_span(raw)
                self.assertEqual(len(rows), 213)
                self.assertEqual(provider["input_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(provider["exit"], 0)
                with self.assertRaisesRegex(table.EvidenceError, "Opcode|Actual|stride"):
                    table.prove_table(raw, actual_listing)

    def test_listing_address_bytes_and_coverage_are_bound_but_prose_is_not(self):
        lines = self.listing.splitlines()
        selected = next(i for i, line in enumerate(lines)
                        if re.match(r"^\s*556fb60:", line))
        original = lines[selected]
        for name, replacement in (("address", original.replace("556fb60:", "556fb61:", 1)),
                                  ("bytes", original.replace("41 57", "41 56", 1))):
            with self.subTest(corrupt=name):
                self.assertNotEqual(replacement, original)
                edited = list(lines)
                edited[selected] = replacement
                with self.assertRaisesRegex(table.EvidenceError, "coverage|boundary|bytes"):
                    table.verify_listing("\n".join(edited), self.raw)
        for name, edited in (("missing", lines[:selected] + lines[selected + 1:]),
                              ("duplicate", lines + [original])):
            with self.subTest(corrupt=name):
                with self.assertRaisesRegex(table.EvidenceError, "count/coverage"):
                    table.verify_listing("\n".join(edited), self.raw)
        # Keep actual address/bytes and change only disassembler prose. Raw
        # opcode/dataflow checks still prove the same bounded certificate.
        prose = list(lines)
        self.assertIn("\t", original)
        prose[selected] = original.rsplit("\t", 1)[0] + "\tret invented-prose"
        self.assertEqual(table.prove_table(self.raw, "\n".join(prose)),
                         table.prove_table(self.raw, self.listing))


class FseMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = table.load_target()
        cls.observation = table.analyze(cls.data)
        cls.metadata = cls.observation["metadata"]

    @classmethod
    def tearDownClass(cls):
        # Do not retain a full capture in the module/class after these tests.
        del cls.data, cls.observation, cls.metadata

    def metadata_refuses(self, offset, replacement, reason):
        with self.assertRaisesRegex(table.EvidenceError, reason):
            table.derive_metadata(changed(self.data, offset, replacement))

    def test_actual_snapshot_binds_full_records_code_and_fresh_observation(self):
        metadata = self.metadata
        self.assertEqual((metadata["start"], metadata["end"], metadata["bytes"]),
                         (0x556fb60, 0x556fe63, 771))
        raw = self.data[metadata["file_offset"]:metadata["file_offset"] + 771]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), BODY_SHA256)
        for name, count in (("FDE", 72), ("CIE", 24)):
            record = metadata["frame_records"][name]
            self.assertEqual(record["bytes"], count)
            actual = self.data[record["file_offset"]:record["file_offset"] + count]
            self.assertEqual(actual.hex(), record["raw"])
            self.assertEqual(struct.unpack_from("<I", actual)[0], count - 4)
        frame = metadata["FDE"]
        self.assertEqual((frame["start"], frame["end"]), (0x556fb60, 0x556fe63))
        self.assertIsNone(frame["lsda"])
        load = metadata["PT_LOAD"]
        section = metadata["section"]
        self.assertEqual(load["file_offset"] + 0x556fb60 - load["va"], metadata["file_offset"])
        self.assertEqual(section["offset"] + 0x556fb60 - section["address"], metadata["file_offset"])
        self.assertTrue(load["flags"] & 1 and section["flags"] & 4)
        self.assertEqual(self.observation["target"]["sha256"], table.TARGET_SHA256)
        retained = load_json(OBSERVED / "records.json")
        for key in ("target", "metadata", "proof", "native_rows"):
            self.assertEqual(retained[key], self.observation[key])
        self.assertEqual(len(self.observation["native_rows"]), 213)

    def test_full_input_identity_is_distinct_from_selected_metadata_validation(self):
        altered = changed(self.data, len(self.data) - 1,
                          bytes([self.data[-1] ^ 1]))
        with self.assertRaisesRegex(table.EvidenceError, "authenticated"):
            table.analyze(altered)

    def test_actual_complete_fde_and_cie_corruptions_refuse_below_identity(self):
        fde = self.metadata["frame_records"]["FDE"]
        cie = self.metadata["frame_records"]["CIE"]
        cases = [(fde["file_offset"] + 12, struct.pack("<I", 770)),
                 (fde["file_offset"], struct.pack("<I", 4)),
                 (fde["file_offset"] + 4, b"\0" * 4),
                 (cie["file_offset"] + 16, b"\x1c")]
        last = fde["file_offset"] + fde["bytes"] - 1
        cases.append((last, bytes([self.data[last] ^ 1])))
        for offset, replacement in cases:
            with self.subTest(file_offset=offset):
                self.metadata_refuses(offset, replacement, "FDE|frame|CIE|metadata|encoding|record")

    def test_actual_section_and_executable_load_coordinates_must_agree(self):
        section = self.metadata["section"]
        shoff = struct.unpack_from("<Q", self.data, 40)[0]
        stride, count = struct.unpack_from("<HH", self.data, 58)
        candidates = []
        for index in range(count):
            header = shoff + index * stride
            _, _, flags, address, offset, size = struct.unpack_from("<IIQQQQ", self.data, header)
            if (address, offset, size) == (section["address"], section["offset"], section["size"]):
                candidates.append((header, flags))
        self.assertEqual(len(candidates), 1)
        header, flags = candidates[0]
        self.metadata_refuses(header + 8, struct.pack("<Q", flags & ~4), "executable section")
        load = self.metadata["PT_LOAD"]
        phoff = struct.unpack_from("<Q", self.data, 32)[0]
        phstride = struct.unpack_from("<H", self.data, 54)[0]
        header = phoff + load["index"] * phstride
        for relative, replacement in ((4, struct.pack("<I", load["flags"] & ~1)),
                                       (8, struct.pack("<Q", load["file_offset"] + 1)),
                                       (32, struct.pack("<Q", 0x556fe63 - load["va"] - 1))):
            with self.subTest(program_header_field=relative):
                self.metadata_refuses(header + relative, replacement, "PT_LOAD|mapping")


class FseProtocolFixtureTests(unittest.TestCase):
    def test_primary39_serialized_vectors_bind_pre_rust_tables_and_whole_output(self):
        source = [r for r in load_json(ORACLE / "STIMULI.json") if r["domain"] == "caller876"]
        expected = {r["id"]: r for r in load_json(ORACLE / "EXPECTED.json")}
        standalone = {r["id"] for r in load_json(ORACLE / "STIMULI.json") if r["domain"] != "caller876"}
        inputs = (VECTORS / "target-inputs.txt").read_text().splitlines()
        outputs = (VECTORS / "target-expected.txt").read_text().splitlines()
        unit = (VECTORS / "target-vectors.tsv").read_text().splitlines()
        self.assertEqual((len(source), len(inputs), len(outputs), len(unit)), (39, 39, 39, 39))
        self.assertEqual(len(standalone), 3)
        for original, stimulus, result, unit_row in zip(source, inputs, outputs, unit):
            identifier, log_text, max_text, coefficients, initial_hex = stimulus.split(" ")
            self.assertEqual(identifier, original["id"])
            self.assertNotIn(identifier, standalone)
            self.assertEqual(int(log_text), original["log"])
            self.assertEqual(int(max_text), len(original["coefficients"]) - 1)
            actual = list(map(int, coefficients.split(",")))
            self.assertEqual(actual, original["coefficients"] + [0] * (256 - len(original["coefficients"])))
            self.assertEqual(len(initial_hex), 520)
            out_id, status, length_text, complete_hex = result.split(" ")
            self.assertEqual((out_id, status), (identifier, "ok"))
            count = int(length_text)
            prefix = bytes.fromhex(expected[identifier]["table_hex"])
            self.assertEqual(count, len(prefix))
            self.assertEqual(count, 4 + 4 * (1 << original["log"]))
            complete = bytes.fromhex(complete_hex)
            self.assertEqual(len(complete), 260)
            self.assertEqual(complete, prefix + bytes.fromhex(initial_hex)[count:])
            self.assertEqual(unit_row, stimulus + "\t" + result)

    def test_supplemental_domain_policy_and_zero_bit_expectations_stay_distinct(self):
        stimuli = load_json(CONTROLS / "OWN-API-STIMULI.json")
        expected = load_json(CONTROLS / "OWN-API-EXPECTED.json")
        self.assertEqual((len(stimuli), len(expected)), (30, 30))
        qualified = [row for row in expected if row["qualified_caller_domain"]]
        rejected = [row for row in expected if not row["qualified_caller_domain"]]
        self.assertEqual((len(qualified), len(rejected)), (14, 16))
        lookup = {row["id"]: row for row in stimuli}
        for row in rejected:
            self.assertEqual(row["status"], "unsupported")
            self.assertEqual(row["length"], 0)
            self.assertEqual(row["complete260_hex"], lookup[row["id"]]["initial260_hex"])
        for row in qualified:
            self.assertEqual(row["details"]["native_success_RAX"], 0)
            self.assertEqual(row["length"], 132 if lookup[row["id"]]["log"] == 5 else 260)
        singles = {row["id"]: row for row in qualified if row["id"] in ("single5", "single6")}
        for name, total in (("single5", 32), ("single6", 64)):
            self.assertEqual(singles[name]["details"]["bit_zero_rows"], total)
            raw = bytes.fromhex(singles[name]["complete260_hex"])
            for state in range(total):
                self.assertEqual(struct.unpack_from("<HBB", raw, 4 + state * 4), (state, 0, 0))
        # These are frozen expectations, not a pretend run of the Rust library.
        # Separate real linked-client receipts qualify actual table behavior.


if __name__ == "__main__":
    unittest.main()
