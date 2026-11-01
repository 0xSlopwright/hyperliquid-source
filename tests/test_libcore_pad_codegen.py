"""Portable static format controls around licensed, real 622-byte excerpts.

ELF headers below are newly built test fixtures, not original generated objects.
Separate retained full-object/target controls qualify the actual code-generation
observation.  No fixture/object/captured code is loaded or executed here.
"""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import libcore_pad_codegen as probe

FIXTURES = ROOT / "research/work-items/RE-002-libcore-pad-codegen/fixtures"
GENERATED = FIXTURES / "generated-adapter622.bin"
CAPTURED = FIXTURES / "captured-adapter622.bin"
OFFICIAL = FIXTURES / "official-native-adapter622.bin"
FUNCTION_NAME = "_ZN_fixture_PadAdapter_write_strE"


def fixture_elf(body, *, kind=1, data=b"    ", relas=None, aliases=()):
    """Rebase real code/PC32 observations into an explicitly synthetic container."""
    if relas is None:
        relas = [(558, (2 << 32) | 2, -4)] if kind == 1 else []
    strings = bytearray(b"\0")
    def name(text):
        position = len(strings)
        strings.extend(text.encode() + b"\0")
        return position
    function_name = name(FUNCTION_NAME)
    object_name = name("fixture_four_spaces")
    alias_names = [name("_ZN_fixture_PadAdapter_write_str_alias_" + str(i))
                   for i in range(len(aliases))]
    text_address, data_address = (0, 0) if kind == 1 else (0x1000, 0x3000)
    linked = bytearray(body)
    if kind != 1:
        struct.pack_into("<i", linked, 558, data_address - (text_address + 562))
    symtab = bytearray(24)
    symtab.extend(struct.pack("<IBBHQQ", function_name, 18, 0, 1, text_address, len(body)))
    symtab.extend(struct.pack("<IBBHQQ", object_name, 1, 0, 2, 0, len(data)))
    for alias_name, (value, size) in zip(alias_names, aliases):
        symtab.extend(struct.pack("<IBBHQQ", alias_name, 18, 0, 1,
                                  text_address + value, size))
    section_names = ["", ".text.fixture", ".rodata.fixture", ".rela.text.fixture",
                     ".symtab", ".strtab", ".shstrtab"]
    shstr = bytearray(b"\0")
    name_offsets = [0]
    for text in section_names[1:]:
        name_offsets.append(len(shstr))
        shstr.extend(text.encode() + b"\0")
    payloads = [b"", bytes(linked), data,
                b"".join(struct.pack("<QQq", *r) for r in relas),
                bytes(symtab), bytes(strings), bytes(shstr)]
    raw = bytearray(64 + (112 if kind != 1 else 0))
    offsets = [0]
    for i, payload in enumerate(payloads[1:], 1):
        alignment = 16 if i == 1 else 8
        raw.extend(b"\0" * (-len(raw) % alignment))
        offsets.append(len(raw))
        raw.extend(payload)
    raw.extend(b"\0" * (-len(raw) % 8))
    shoff = len(raw)
    specs = [(0, 0, 0, 0, 0, 0), (1, 6, text_address, 0, 0, 0),
             (1, 2, data_address, 0, 0, 0), (4, 0, 0, 4, 1, 24),
             (2, 0, 0, 5, 1, 24), (3, 0, 0, 0, 0, 0),
             (3, 0, 0, 0, 0, 0)]
    for i, (typ, flags, address, link, info, entsize) in enumerate(specs):
        raw.extend(struct.pack("<IIQQQQIIQQ", name_offsets[i], typ, flags, address,
                               offsets[i], len(payloads[i]), link, info, 1, entsize))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", raw, 0, ident, kind, 62, 1, 0,
                     64 if kind != 1 else 0, shoff, 0, 64, 56,
                     2 if kind != 1 else 0, 64, len(specs), 6)
    if kind != 1:
        for p, index, flags, address in ((64, 1, 5, text_address),
                                         (120, 2, 4, data_address)):
            struct.pack_into("<IIQQQQQQ", raw, p, 1, flags, offsets[index], address,
                             address, len(payloads[index]), len(payloads[index]), 1)
    return bytes(raw), {"text": offsets[1], "data": offsets[2], "rela": offsets[3],
                        "symtab": offsets[4], "section_headers": shoff}


def changed(data, offset, replacement):
    copy = bytearray(data)
    copy[offset:offset + len(replacement)] = replacement
    return bytes(copy)


class PadCodegenStaticControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = GENERATED.read_bytes()
        cls.target = CAPTURED.read_bytes()
        cls.official = OFFICIAL.read_bytes()
        cls.elf, cls.offsets = fixture_elf(cls.generated)

    def compare(self, data):
        rows = probe.candidate_functions(data)
        self.assertEqual(len(rows), 1)
        return probe.compare_candidate(data, rows[0], self.target)

    def test_exact_real_excerpts_keep_their_three_separate_identities(self):
        for raw, expected in ((self.generated, "ab7fc88e156c3ef084ae3db3f3de8bbbccfbcf711365c253d3bb4251e8196086"),
                              (self.target, "d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4"),
                              (self.official, "b4a9667d6b39bdcd1d0f745265ad609696fc2ec134eccc7fb83887a284687f55")):
            self.assertEqual(len(raw), 622)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        self.assertEqual([i for i, (a, b) in enumerate(zip(self.generated, self.target)) if a != b],
                         [558, 559, 560, 561])
        self.assertEqual([i for i, (a, b) in enumerate(zip(self.generated, self.official)) if a != b],
                         [464, 467])

    def test_declared_rebased_fixture_binds_one_real_typed_field_and_618_bytes(self):
        result = self.compare(self.elf)
        self.assertEqual(result["comparison"], "actual_ET_REL_fields_only")
        self.assertEqual((result["field_bytes"], result["non_RELA_bytes"],
                          result["equal_non_RELA_bytes"]), (4, 618, 618))
        self.assertEqual(result["non_RELA_difference_offsets"], [])
        self.assertEqual(result["raw_difference_offsets"], [558, 559, 560, 561])
        field, = result["actual_relocations"]
        self.assertEqual((field["offset"], field["kind"], field["width"], field["addend"]),
                         (558, 2, 4, -4))
        self.assertEqual(field["referent_hex"], "20202020")

    def test_original_native_two_true_gaps_remain_unmasked(self):
        raw, _ = fixture_elf(self.official)
        result = self.compare(raw)
        self.assertEqual(result["LEA_hex"], "4d8d2437")
        self.assertEqual(result["non_RELA_difference_offsets"], [464, 467])
        self.assertEqual(result["equal_non_RELA_bytes"], 616)
        self.assertEqual(result["raw_difference_offsets"], [464, 467, 558, 559, 560, 561])

    def test_serialized_rela_offset_type_addend_and_duplicate_records_refuse(self):
        position = self.offsets["rela"]
        for field, info, addend in ((557, (2 << 32) | 2, -4),
                                    (559, (2 << 32) | 2, -4),
                                    (558, (2 << 32) | 9, -4),
                                    (558, (2 << 32) | 2, 0)):
            with self.subTest(field=field, info=info, addend=addend):
                with self.assertRaisesRegex(ValueError, "offset/type/addend"):
                    self.compare(changed(self.elf, position, struct.pack("<QQq", field, info, addend)))
        for relas in ([], [(558, (2 << 32) | 2, -4)] * 2):
            with self.subTest(records=len(relas)):
                raw, _ = fixture_elf(self.generated, relas=relas)
                with self.assertRaisesRegex(ValueError, "exactly one actual code RELA"):
                    self.compare(raw)

    def test_real_referent_relation_rejects_wrong_symbol_bounds_or_space_data(self):
        rela = self.offsets["rela"]
        # Symbol1 is a valid defined FUNC, but not the actual four-byte data OBJECT.
        with self.assertRaisesRegex(ValueError, "data OBJECT"):
            self.compare(changed(self.elf, rela + 8, struct.pack("<Q", (1 << 32) | 2)))
        with self.assertRaisesRegex(ValueError, "symbol index out of bounds"):
            self.compare(changed(self.elf, rela + 8, struct.pack("<Q", (999 << 32) | 2)))
        object_record = self.offsets["symtab"] + 48
        for relative, replacement in ((4, b"\x02"), (8, struct.pack("<Q", 1)),
                                       (16, struct.pack("<Q", 5))):
            with self.subTest(object_field=relative):
                with self.assertRaisesRegex(ValueError, "data OBJECT"):
                    self.compare(changed(self.elf, object_record + relative, replacement))
        with self.assertRaisesRegex(ValueError, "four-space referent"):
            self.compare(changed(self.elf, self.offsets["data"], b"!"))

    def test_matching_function_requires_actual_type_and_complete_section_bounds(self):
        record = self.offsets["symtab"] + 24
        for relative, replacement, reason in ((4, b"\x11", "not STT_FUNC"),
                                               (8, struct.pack("<Q", 1), "section bounds"),
                                               (16, struct.pack("<Q", 0), "nonempty"),
                                               (6, struct.pack("<H", 2), "executable")):
            with self.subTest(function_field=relative):
                with self.assertRaisesRegex(ValueError, reason):
                    probe.candidate_functions(changed(self.elf, record + relative, replacement))
        self.assertEqual(probe.candidate_functions(changed(self.elf, record + 6, b"\0\0")), [])

    def test_non_rela_bytes_and_instruction_family_cannot_gain_more_mask(self):
        offset = self.offsets["text"]
        result = self.compare(changed(self.elf, offset, bytes([self.generated[0] ^ 1])))
        self.assertEqual(result["non_RELA_difference_offsets"], [0])
        self.assertEqual(result["equal_non_RELA_bytes"], 617)
        with self.assertRaisesRegex(ValueError, "instruction family"):
            self.compare(changed(self.elf, offset + 555, b"\x49"))
        candidate, = probe.candidate_functions(self.elf)
        with self.assertRaisesRegex(ValueError, "complete captured body"):
            probe.compare_candidate(self.elf, candidate, self.target[:-1])

    def test_caller_candidate_metadata_cannot_substitute_a_favorable_body(self):
        candidate, = probe.candidate_functions(self.elf)
        for key, value in (("body_hex", self.target.hex()), ("file_offset", 0),
                           ("body_sha256", hashlib.sha256(self.target).hexdigest()),
                           ("invented_mask", [464, 467])):
            with self.subTest(key=key):
                forged = dict(candidate, **{key: value})
                with self.assertRaisesRegex(ValueError, "bound to this ELF"):
                    probe.compare_candidate(self.elf, forged, self.target)

    def test_identical_extent_aliases_coalesce_but_distinct_candidates_all_remain(self):
        raw, _ = fixture_elf(self.generated, aliases=((0, 622),))
        rows = probe.candidate_functions(raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["names"]), 2)
        raw, _ = fixture_elf(self.generated, aliases=((0, 621),))
        rows = probe.candidate_functions(raw)
        self.assertEqual(sorted(c["size"] for c in rows), [621, 622])
        results = [probe.compare_candidate(raw, c, self.target) for c in rows]
        partial = next(r for r in results if r["size"] == 621)
        self.assertIs(partial["complete_comparable"], False)
        self.assertEqual(partial["comparison"], "raw_only")
        self.assertNotIn("non_RELA_bytes", partial)

    def test_linked_format_comparison_stays_raw_without_an_inherited_mask(self):
        raw, locations = fixture_elf(self.official, kind=3)
        result = self.compare(raw)
        self.assertEqual(result["comparison"], "raw_only")
        self.assertEqual(result["actual_relocations"], [])
        self.assertNotIn("non_RELA_bytes", result)
        self.assertNotIn("equal_non_RELA_bytes", result)
        self.assertTrue({464, 467}.issubset(result["raw_difference_offsets"]))
        with self.assertRaisesRegex(ValueError, "Linked four-space referent"):
            self.compare(changed(raw, locations["data"], b"!"))

    def test_linked_section_validity_cannot_replace_the_actual_segment_mapping(self):
        raw, _ = fixture_elf(self.official, kind=3)
        # The section table and its genuine excerpt stay unchanged in each case.
        for offset, replacement in ((120, struct.pack("<I", 0)),
                                     (128, struct.pack("<Q", 1)),
                                     (124, struct.pack("<I", 5))):
            with self.subTest(program_header_field=offset):
                with self.assertRaisesRegex(ValueError, "PT_LOAD|mapping|executable|segment"):
                    self.compare(changed(raw, offset, replacement))

    def test_two_fixed_recipes_have_no_caller_flag_passthrough(self):
        result = probe.recipes(Path("/fixture/rustc"), Path("/fixture/source.rs"), Path("/fixture/output"))
        self.assertEqual([r["name"] for r in result], ["default", "thin"])
        first, second = [r["argv"] for r in result]
        self.assertNotIn("-Clto=thin", first)
        self.assertEqual(second.count("-Clto=thin"), 1)
        self.assertEqual(first[:-1], [x for x in second[:-1] if x != "-Clto=thin"])
        self.assertEqual(first[-1], "/fixture/output/default")
        self.assertEqual(second[-1], "/fixture/output/thin")

    def test_existing_output_and_wrong_providers_refuse_before_compilation(self):
        for method in (probe.captured, probe.core_member):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(ValueError, "size/SHA"):
                    method(b"not an admitted input")
        with tempfile.TemporaryDirectory(prefix="pad-no-build-") as tmp:
            root = Path(tmp)
            output = root / "prior"
            output.mkdir()
            marker = output / "marker"
            marker.write_bytes(b"keep this prior output")
            with self.assertRaisesRegex(ValueError, "Output already exists"):
                probe.build(root / "absent-prefix", root / "absent-node", output)
            self.assertEqual(marker.read_bytes(), b"keep this prior output")
            self.assertEqual([p.name for p in output.iterdir()], ["marker"])
            with self.assertRaises((OSError, ValueError)):
                probe.build(root / "absent-prefix", root / "absent-node", root / "failed")
            self.assertFalse((root / "failed").exists())


if __name__ == "__main__":
    unittest.main()
