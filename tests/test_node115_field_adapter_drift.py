"""Independent RE-014 controls; static bytes only, no captured execution.

The numeric expectations and mutation design were frozen from independently
parsed official ar/ELF data and the admitted node115 intake before this producer
was written.  The explicit provider is optional for ordinary discovery; a local
qualification run must supply HL_RE014_LIBCORE and report zero skips.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_field_adapter_drift as drift


FIELD_OFFSETS = [93, 100, 154, 207, 284, 294, 309, 324, 370]
FIELD_TYPES = [2, 2, 2, 2, 2, 9, 2, 9, 2]
FIELD_SECTIONS = [1104, 1115, 1116, 1117, 1113, 883, 1116, 883, 1106]
LITERALS = [(93, b", "), (100, b" { "), (154, b": "),
            (207, b" {\n"), (309, b": "), (370, b",\n")]
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ARCHIVE_SHA256 = "ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256"


def changed(raw, offset, replacement):
    """One private in-memory copy; never modify the admitted image on disk."""
    copy = bytearray(raw)
    copy[offset:offset + len(replacement)] = replacement
    return bytes(copy)


class AdmissionAndPublicationControls(unittest.TestCase):
    def test_wrong_full_input_identities_are_not_evidence(self):
        for method in (drift.authenticate_target, drift.authenticate_archive):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(drift.EvidenceError, "authenticated"):
                    method(b"not the admitted artifact")

    def test_existing_output_precedes_input_reads_and_failures_export_nothing(self):
        with tempfile.TemporaryDirectory(prefix="re014-output-") as tmp:
            root = Path(tmp)
            output = root / "prior"
            output.mkdir()
            marker = output / "marker"
            marker.write_bytes(b"preserve existing evidence\n")
            with self.assertRaises(FileExistsError):
                drift.generate(root / "missing-target", root / "missing-core", output)
            self.assertEqual(marker.read_bytes(), b"preserve existing evidence\n")
            self.assertEqual(list(output.iterdir()), [marker])
            bad_target, bad_core = root / "bad-target", root / "bad-core"
            bad_target.write_bytes(b"invalid target")
            bad_core.write_bytes(b"invalid core")
            failed = root / "failed"
            with self.assertRaises(drift.EvidenceError):
                drift.generate(bad_target, bad_core, failed)
            self.assertFalse(failed.exists())


class ActualNode115Bindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        provider = os.environ.get("HL_RE014_LIBCORE")
        if not provider:
            raise unittest.SkipTest("Set HL_RE014_LIBCORE to the explicitly supplied pinned official archive; no download or qualification is implied.")
        cls.provider = Path(provider)
        # These immutable objects alone supply the full-image test observations.
        cls.target = Path(drift.TARGET).read_bytes()
        cls.archive = cls.provider.read_bytes()
        cls.report = drift.analyze(cls.target, cls.archive)

    @classmethod
    def tearDownClass(cls):
        del cls.report, cls.target, cls.archive

    def target_refuses(self, offset, replacement, reason):
        mutant = changed(self.target, offset, replacement)
        with self.assertRaisesRegex(drift.EvidenceError, reason):
            drift.derive(mutant, self.archive)

    def archive_refuses(self, offset, replacement, reason):
        mutant = changed(self.archive, offset, replacement)
        with self.assertRaisesRegex(drift.EvidenceError, reason):
            drift.derive(self.target, mutant)

    def test_actual_parent_fields_data_and_exact_selected_extents(self):
        report = self.report
        self.assertIs(report["identity_admitted"], True)
        self.assertEqual(hashlib.sha256(self.target).hexdigest(), TARGET_SHA256)
        self.assertEqual(hashlib.sha256(self.archive).hexdigest(), ARCHIVE_SHA256)
        parent = report["parent390"]
        self.assertEqual((parent["source_bytes"], parent["target_bytes"],
                          parent["actual_RELA_bytes"], parent["nonRELA_bytes"]),
                         (390, 390, 36, 354))
        self.assertIs(parent["all_nonRELA_equal"], True)
        rows = parent["relocations"]
        self.assertEqual([r["offset"] for r in rows], FIELD_OFFSETS)
        self.assertEqual([r["type"] for r in rows], FIELD_TYPES)
        self.assertEqual([r["symbol"]["section_index"] for r in rows], FIELD_SECTIONS)
        self.assertTrue(all(r["field_width"] == 4 and r["addend"] == -4 for r in rows))
        # Independently fixed member/data offsets, not a supplied arbitrary mask.
        member_offset = report["source_archive"]["member_data_offset"]
        self.assertEqual(member_offset, 46334)
        source = self.archive[member_offset + 1303856:member_offset + 1303856 + 390]
        target = bytes.fromhex(parent["raw_target_hex"])
        mask = {i for offset in FIELD_OFFSETS for i in range(offset, offset + 4)}
        self.assertEqual(len(mask), 36)
        self.assertEqual(sum(a != b for a, b in zip(source, target)), 35)
        self.assertEqual(sum(source[i] == target[i] for i in range(390) if i not in mask), 354)
        self.assertEqual([(r["parent_field_offset"], bytes.fromhex(r["raw_hex"]))
                          for r in report["parent_literal_references"]], LITERALS)
        self.assertEqual(sum(r["bytes"] for r in report["parent_literal_references"]), 14)
        table = report["parent48B_vtable"]
        self.assertEqual(len(bytes.fromhex(table["raw_hex"])), 48)
        self.assertEqual(struct.unpack("<6Q", bytes.fromhex(table["raw_hex"])),
                         (0, 24, 8, 0, 0, 0))
        pointers = table["pointer_bindings"]
        self.assertEqual([p["source_RELA"]["offset"] for p in pointers], [24, 32, 40])
        self.assertEqual([p["source_RELA"]["symbol"]["info"] & 15 for p in pointers], [2, 2, 3])
        self.assertTrue(all(p["source_RELA"]["type"] == 1 and p["source_RELA"]["addend"] == 0 for p in pointers))
        self.assertTrue(all(p["target_RELATIVE"]["type"] == 8 and p["target_RELATIVE"]["symbol_index"] == 0 for p in pointers))
        self.assertTrue(all(not p["further_behavior_qualified"] and not p["runtime_pointer_observed"] for p in pointers))
        self.assertEqual(report["parent_GOT_to_adapter"]["parent_field_offsets"], [294, 324])
        self.assertEqual(report["parent_GOT_to_adapter"]["RELATIVE"]["addend"], 0x1686bd0)
        self.assertEqual(pointers[0]["target_RELATIVE"]["addend"], 0x1686bd0)
        for name, start, end in (("parent390", 0x167d950, 0x167dad6),
                                 ("adapter630", 0x1686bd0, 0x1686e46)):
            frame = report[name]["frame"]
            self.assertEqual((frame["start"], frame["end"], frame["bytes"]), (start, end, end - start))
            self.assertIs(frame["global_index_census_claimed"], False)
            self.assertLess(frame["index_entries_consulted"], 40)
            body = self.target[frame["body_file_offset"]:frame["body_file_offset"] + frame["bytes"]]
            self.assertEqual(hashlib.sha256(body).hexdigest(), frame["body_sha256"])
        self.assertEqual(hashlib.sha256(target).hexdigest(), "31186c955933babc770b727c75061c5e270efac7fd0a308eb4520e1ae5033569")

    def test_unmasked_parent_byte_and_each_real_target_displacement_refuse(self):
        parent = self.report["parent390"]
        offset = parent["frame"]["body_file_offset"]
        self.target_refuses(offset, bytes([self.target[offset] ^ 1]), "nonRELA")
        for row in parent["relocations"]:
            with self.subTest(field=row["offset"]):
                self.target_refuses(row["target_field_file_offset"], b"\0" * 4,
                                    "target|read lacks|comparison")

    def test_real_source_rela_shapes_and_defined_wrong_symbols_refuse(self):
        rows = self.report["parent390"]["relocations"]
        for row in rows:
            offset = row["archive_record_file_offset"]
            field, info, addend = struct.unpack_from("<QQq", self.archive, offset)
            with self.subTest(kind_field=field):
                self.archive_refuses(offset, struct.pack("<QQq", field, (info & ~0xffffffff) | 1, addend), "kind/addend")
        row = rows[0]
        offset = row["archive_record_file_offset"]
        field, info, addend = struct.unpack_from("<QQq", self.archive, offset)
        self.archive_refuses(offset, struct.pack("<QQq", field, info, 0), "kind/addend")
        # Duplicate an actual field: refusal is the used field-domain guard.
        second = rows[1]["archive_record_file_offset"]
        self.archive_refuses(second, struct.pack("<Q", FIELD_OFFSETS[0]), "field domain")
        member_offset = self.report["source_archive"]["member_data_offset"]
        definitions = self.report["source_archive"]["function_definitions"]
        parent_symbol = definitions[0]
        self.assertEqual((parent_symbol["section_index"], parent_symbol["size"]), (381, 390))
        self.archive_refuses(member_offset + parent_symbol["file_offset"] + 8,
                             struct.pack("<Q", 1), "function symbol/section")
        # A real, defined executable FUNC is in bounds, but is the wrong method.
        wrong = parent_symbol["symbol_index"]
        for row in (r for r in rows if r["offset"] in (294, 324)):
            offset = row["archive_record_file_offset"]
            field, info, addend = struct.unpack_from("<QQq", self.archive, offset)
            with self.subTest(wrong_symbol_field=field):
                self.archive_refuses(offset, struct.pack("<QQq", field, (wrong << 32) | (info & 0xffffffff), addend), "source GOT symbol")

    def test_actual_literal_bytes_and_vtable_fixed_header_are_not_masked(self):
        for row in self.report["parent_literal_references"]:
            offset = row["target_file_offset"]
            with self.subTest(literal_reference=row["parent_field_offset"]):
                self.target_refuses(offset, bytes([self.target[offset] ^ 1]), "literal/vtable raw data")
        # Byte8 is in the fixed header, separate from the three pointer fields.
        offset = self.report["parent48B_vtable"]["target_file_offset"] + 8
        self.target_refuses(offset, bytes([self.target[offset] ^ 1]), "literal/vtable raw data")

    def test_real_typed_pointer_records_and_selected_adapter_links_refuse(self):
        bindings = self.report["parent48B_vtable"]["pointer_bindings"]
        records = [b["target_RELATIVE"] for b in bindings]
        records.append(self.report["parent_GOT_to_adapter"]["RELATIVE"])
        for row in records:
            offset = row["record_file_offset"]
            slot, info, addend = struct.unpack_from("<QQq", self.target, offset)
            for replacement, label in (((info & ~0xffffffff) | 1, "kind"),
                                       (info | (1 << 32), "symbol")):
                with self.subTest(slot=slot, corrupt=label):
                    self.target_refuses(offset, struct.pack("<QQq", slot, replacement, addend), "symbol-free RELATIVE")
        for row in (records[0], records[-1]):
            with self.subTest(selected_addend=row["offset"]):
                self.target_refuses(row["record_file_offset"] + 16,
                                    struct.pack("<q", 0x167d950), "selected.*adapter")
        # Move both real GOT displacements and their actual RELA slot together.
        # A mapped addend cannot justify an unmapped eight-byte pointer storage.
        missing_slot = 0x70000000
        mutant = bytearray(self.target)
        for row in self.report["parent390"]["relocations"]:
            if row["offset"] in (294, 324):
                struct.pack_into("<i", mutant, row["target_field_file_offset"],
                                 missing_slot - (row["target_field_VA"] + 4))
        struct.pack_into("<Q", mutant, records[-1]["record_file_offset"], missing_slot)
        with self.assertRaisesRegex(drift.EvidenceError, "read lacks|file-backed|slot"):
            drift.derive(bytes(mutant), self.archive)
        del mutant
        # A second genuine row redirected to the selected slot creates ambiguity.
        self.target_refuses(records[1]["record_file_offset"], struct.pack("<Q", records[0]["offset"]), "one symbol-free RELATIVE")
        for binding in bindings:
            offset = binding["archive_record_file_offset"]
            field, info, addend = struct.unpack_from("<QQq", self.archive, offset)
            with self.subTest(source_pointer=field):
                self.archive_refuses(offset, struct.pack("<QQq", field, (info & ~0xffffffff) | 2, addend), "source vtable pointer")
        selected = bindings[0]
        offset = selected["archive_record_file_offset"]
        field, info, addend = struct.unpack_from("<QQq", self.archive, offset)
        self.archive_refuses(offset, struct.pack("<QQq", field, info, 1), "source vtable pointer")
        wrong = self.report["source_archive"]["function_definitions"][0]["symbol_index"]
        self.archive_refuses(offset, struct.pack("<QQq", field, (wrong << 32) | (info & 0xffffffff), addend), "source selected vtable method")

    def test_real_fde_extent_cie_binding_and_duplicate_selected_index_refuse(self):
        for name, wrong_size in (("parent390", 389), ("adapter630", 622)):
            frame = self.report[name]["frame"]
            # A correct pc_range outside a declared short record is not a FDE.
            for declared in (4, 8, 12):
                with self.subTest(frame=name, corrupt="declared length", length=declared):
                    self.target_refuses(frame["FDE_file_offset"], struct.pack("<I", declared),
                                        "FDE.*length|augmentation|record")
            # The final declared byte starts an unterminated augmentation ULEB.
            # Authentic begin/range bytes cannot justify reading the next CFA byte.
            prefix = bytearray(self.target[frame["FDE_file_offset"]:frame["FDE_file_offset"] + 17])
            struct.pack_into("<I", prefix, 0, 13)
            prefix[16] = 0x80
            with self.subTest(frame=name, corrupt="augmentation beyond declared record"):
                self.target_refuses(frame["FDE_file_offset"], bytes(prefix), "augmentation|FDE.*length|record")
            with self.subTest(frame=name, corrupt="extent"):
                self.target_refuses(frame["FDE_range_file_offset"], struct.pack("<I", wrong_size), "FDE extent")
            with self.subTest(frame=name, corrupt="CIE binding"):
                self.target_refuses(frame["FDE_CIE_pointer_file_offset"], b"\0" * 4, "CIE")
            entry = frame["index_entry_file_offset"]
            with self.subTest(frame=name, corrupt="nonunique adjacent start"):
                self.target_refuses(entry + 8, self.target[entry:entry + 4], "neighborhood is not strict")
        frame = self.report["adapter630"]["frame"]
        self.target_refuses(frame["CIE_encoding_file_offset"], b"\x1c", "CIE encoding/record")

    def test_opaque_changes_stay_unqualified_and_never_transfer_622_mask(self):
        def assert_no_transfer(report):
            self.assertIs(report["identity_admitted"], False)
            adapter = report["adapter630"]
            self.assertEqual((adapter["source_bytes"], adapter["target_bytes"],
                              adapter["extent_drift_bytes"], adapter["compared_bytes"]),
                             (622, 630, 8, 0))
            self.assertIs(adapter["mask_transferred"], False)
            self.assertIs(adapter["behavior_transferred"], False)

        baseline = self.report["adapter630"]
        offset = baseline["frame"]["body_file_offset"]
        mutant = changed(self.target, offset, bytes([self.target[offset] ^ 1]))
        observed = drift.derive(mutant, self.archive)
        assert_no_transfer(observed)
        self.assertNotEqual(observed["adapter630"]["raw_target_sha256"], baseline["raw_target_sha256"])
        with self.assertRaisesRegex(drift.EvidenceError, "authenticated node115"):
            drift.analyze(mutant, self.archive)
        del mutant, observed
        # No source/target body association has been proved for these two methods.
        for binding in self.report["parent48B_vtable"]["pointer_bindings"][1:]:
            row = binding["target_RELATIVE"]
            with self.subTest(opaque_source_field=binding["source_RELA"]["offset"]):
                mutant = changed(self.target, row["record_file_offset"] + 16, struct.pack("<q", 0x167d950))
                observed = drift.derive(mutant, self.archive)
                assert_no_transfer(observed)
                pointer = next(p for p in observed["parent48B_vtable"]["pointer_bindings"] if p["slot_VA"] == binding["slot_VA"])
                self.assertEqual(pointer["target_RELATIVE"]["addend"], 0x167d950)
                self.assertIs(pointer["further_behavior_qualified"], False)
                self.assertIs(pointer["selected_630_adapter"], False)

    def test_generate_reproduces_the_same_bounded_record(self):
        with tempfile.TemporaryDirectory(prefix="re014-positive-") as tmp:
            output = Path(tmp) / "observed"
            record = drift.generate(drift.TARGET, self.provider, output)
            self.assertEqual(record, self.report)
            files = list(output.iterdir())
            self.assertEqual([p.name for p in files], ["records.json"])
            self.assertEqual(files[0].read_bytes(), (json.dumps(self.report, sort_keys=True, indent=2) + "\n").encode())


if __name__ == "__main__":
    unittest.main()
