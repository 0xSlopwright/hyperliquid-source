"""Tests for tools/vty_tracker.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-vty-tracker-94"
spec_ = importlib.util.spec_from_file_location("vty_tracker", ROOT / "tools" / "vty_tracker.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["vty_tracker"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Row, Track, Case = tool.Row, tool.Track, tool.Case
at = tool.at
TOP = tool.MASK[8]
POP_BRANCH = 0x392BBEE
SAMPLED_BYTE = 0x392BF9E


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=40)
    FILES = tool.render(RESULT)


def run(case):
    got = HARNESS.run(case)
    want = tool.spec_for(HARNESS, case)
    assert tool.same(case, got, want), case.name
    return got


def record(track, when, price, **fields):
    got = run(tool.one("t", track, when, price, **fields))
    return got["trackers"][7] if not got["panic"] else got


def words(row):
    return struct.unpack("<3dQ", row[:32])


def rate(rows, mode):
    got = run(Case("t", kind="select", rows=tuple(rows), mode=mode))
    return None if not got["some"] else tool.to_float(got["value"])


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


def with_bytes(address, data):
    edited = copy.copy(IMAGE)
    blob = bytearray(IMAGE.blob)
    offset = IMAGE.offset(address)
    blob[offset:offset + len(data)] = data
    edited.blob = bytes(blob)
    return edited


class Tables(unittest.TestCase):
    def test_constants(self):
        rows = {row[3]: row for row in RESULT["constants"]}
        self.assertEqual(rows["elapsed must be above"][2], "20.0")
        self.assertEqual(rows["elapsed must be at most"][2], "100.0")
        self.assertEqual(rows["denominator epsilon"][2], "1e-20")
        self.assertEqual(rows["decay floor"][2], "10.0")
        self.assertEqual(rows["smallest elapsed sum"][2], "1e-15")
        self.assertEqual(rows["negative snap edge"][2], "-1e-15")
        self.assertEqual(rows["delay for an asset with no tracker"][2], "0.001")
        self.assertEqual(rows["default min, default max"][2], "(0.0001, 0.0003)")
        self.assertEqual(rows["metric low, metric high"][2], "(0.01, 0.05)")

    def test_function_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.WRITER), (0x392B930, 0x392C1F6))
        self.assertEqual(IMAGE.exact_fde(tool.SELECT), (0x3930C30, 0x3930FEE))
        self.assertEqual(IMAGE.exact_fde(tool.DEFAULT), (0x3930FF0, 0x393120A))
        self.assertEqual(IMAGE.exact_fde(tool.FOLD), (0x3BE4E20, 0x3BE5011))
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.WRITER + 1)

    def test_writer_slot(self):
        self.assertEqual(IMAGE.relative()[tool.SLOT_WRITER], tool.WRITER)

    def test_field_keys(self):
        keys = [row[2] for row in RESULT["keys"] if row[0] == "0x39314d0"]
        self.assertEqual(keys, ["desc", "samples", "emas", "val", "n_updates", "n_bucket_updates", "alert_bucket_guard"])
        self.assertEqual({row[0]: row[1] for row in RESULT["fields"]}["val.max"], "0x68")

    def test_field_pin_refuses_other_bytes(self):
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(with_bytes(0x3931BD2 + 5, b"\x70"))

    def test_default_day(self):
        HARNESS.fresh(Case("t"))
        self.assertEqual(HARNESS.make_date(tool.DEFAULT_DAY), HARNESS.make_date(365))
        self.assertEqual(HARNESS.make_date(365) >> 13, 1971)


class FirstSample(unittest.TestCase):
    def test_new_tracker(self):
        got = run(Case("t", steps=((7, (86400 * 100, 0), 2.0),)))["trackers"][7]
        self.assertEqual(got["label"], b"AssetWire(7)")
        self.assertEqual(got["cap"], 4)
        self.assertEqual((got["millis"], got["seen"]), (600000, 52560))
        self.assertEqual([words(row)[2] for row in got["rows"]], [30.0, 100.0, 300.0, 1000.0])
        self.assertEqual((got["low"], got["high"]), (tool.to_bits(0.0001), tool.to_bits(0.0003)))
        self.assertEqual((got["row_cap"], got["row_block"]), (4, 0xC0))

    def test_tree_insert_splits(self):
        self.assertEqual(run(tool.miss_cases()[9 + 2])["length"], 12)


class Spacing(unittest.TestCase):
    def test_one_second_gate(self):
        base = Track(samples=tool.older(-5))
        self.assertEqual(len(record(base, at(-4), 9.0)["samples"]), 2)
        self.assertEqual(len(record(base, at(-5, 999999999), 9.0)["samples"]), 1)

    def test_last_date_panics(self):
        got = record(Track(samples=[((tool.MAX_DAY * 86400 + 86399, 0), 3.0)]), (tool.MAX_DAY * 86400 + 86399, 0), 4.0)
        self.assertTrue(got["panic"])


class Queue(unittest.TestCase):
    def test_no_pop_at_twenty(self):
        got = record(Track(samples=tool.older(0), rows=tool.ready_rows()), at(20), 101.0)
        self.assertEqual((len(got["samples"]), got["sampled"]), (2, 0))

    def test_pop_with_update(self):
        got = record(Track(samples=tool.older(0), rows=tool.ready_rows()), at(21), 101.0)
        self.assertEqual((len(got["samples"]), got["sampled"]), (1, 1))

    def test_hundred_is_inside(self):
        got = record(Track(samples=tool.older(0), rows=tool.ready_rows()), at(100), 101.0)
        self.assertEqual(got["sampled"], 1)

    def test_pop_without_update(self):
        got = record(Track(samples=tool.older(0), rows=tool.ready_rows()), at(100, 1000), 101.0)
        self.assertEqual((len(got["samples"]), got["sampled"]), (1, 0))

    def test_full_young_queue_doubles(self):
        got = record(Track(samples=tool.older(*range(8))), at(9), 1.0)
        self.assertEqual((got["cap"], len(got["samples"])), (16, 9))


class Value(unittest.TestCase):
    def row_after(self, price, old=100.0, decay=30.0):
        got = record(Track(samples=[(at(-40), old)], rows=[Row(0.0, 0.0, decay, 0, None)]), at(0), price)
        return words(got["rows"][0])

    def test_plain_value(self):
        move = 101.0 / (100.0 + 1e-20) - 1.0
        value = move * move / 40.0
        self.assertEqual(self.row_after(101.0)[0], value)

    def test_cap(self):
        self.assertEqual(self.row_after(5000.0)[0], 1.0)

    def test_infinity_stays(self):
        self.assertEqual(self.row_after(math.inf)[0], math.inf)

    def test_nan_stays(self):
        self.assertTrue(math.isnan(self.row_after(math.nan)[0]))

    def test_seconds_truncate_to_microseconds(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.0, 0.0, 30.0, 0, at(-2, 999999999))]), at(0), 101.0)
        self.assertEqual(words(got["rows"][0])[1], 1.0)

    def test_retain(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 4.0 * 20, 3, at(-2))]), at(0), 100.0)
        num, denom, _, count = words(got["rows"][0])
        self.assertEqual(denom, 2.0 + (1 - 1 / 80.0) * 0.25)
        self.assertEqual(count, 4)

    def test_reset_floors_decay(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 5.0, 3, at(-6))]), at(0), 100.0)
        self.assertEqual(words(got["rows"][0]), (0.0, 0.0, 10.0, 0))
        self.assertEqual(got["rows"][0][32:36], bytes(4))

    def test_decay_edge_is_inside(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 6.0, 3, at(-6))]), at(0), 100.0)
        self.assertEqual(words(got["rows"][0])[3], 4)

    def test_future_row_gives_zero_gap(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 30.0, 3, at(30))]), at(0), 100.0)
        self.assertEqual(words(got["rows"][0])[1], (1 - 1 / 30.0) * 0.25)

    def test_count_saturates(self):
        got = record(Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 30.0, TOP, at(-1))]), at(0), 100.0)
        self.assertEqual(words(got["rows"][0])[3], TOP)


class Select(unittest.TestCase):
    def test_root(self):
        self.assertEqual(rate([Row(4e-6, 1.0, 30.0, 40)], 1), math.sqrt(4e-6))

    def test_cap_at_one(self):
        self.assertEqual(rate([Row(4.0, 1.0, 30.0, 40)], 1), 1.0)

    def test_infinity_passes(self):
        self.assertEqual(rate([Row(math.inf, 1.0, 30.0, 40)], 1), math.inf)

    def test_count_gate(self):
        self.assertIsNone(rate([Row(1.0, 1.0, 30.0, 29)], 1))
        self.assertIsNotNone(rate([Row(1.0, 1.0, 30.0, 30)], 1))

    def test_denominator_gate(self):
        self.assertIsNone(rate([Row(1e-16, math.nextafter(1e-15, 0.0), 30.0, 40)], 1))
        self.assertIsNotNone(rate([Row(1e-16, 1e-15, 30.0, 40)], 1))

    def test_snap_edge(self):
        self.assertIsNone(rate([Row(-1e-15, 1.0, 30.0, 40)], 1))
        self.assertEqual(rate([Row(math.nextafter(-1e-15, 0.0), 1.0, 30.0, 40)], 1), 0.0)

    def test_order(self):
        rows = [Row(1e-6, 1.0, 30.0, 40), Row(9e-6, 1.0, 30.0, 40), Row(4e-6, 1.0, 30.0, 40)]
        self.assertEqual(rate(rows, 0), math.sqrt(1e-6))
        self.assertEqual(rate(rows, 1), math.sqrt(9e-6))

    def test_nan_order(self):
        rows = [Row(math.nan, 1.0, 30.0, 40), Row(math.inf, 1.0, 30.0, 40)]
        self.assertTrue(math.isnan(rate(rows, 1)))
        self.assertEqual(rate(rows, 0), math.inf)

    def test_invalid_row_never_changes_row_bytes(self):
        rows = (Row(1.0, 1.0, 30.0, 40), Row(-1.0, 1.0, 30.0, 40))
        got = HARNESS.run(Case("t", kind="select", rows=rows, mode=1))
        self.assertEqual(words(got["rows"][1])[0], -1.0)


class Counters(unittest.TestCase):
    def after(self, sampled, rows=None, logged=0, seen=2 * 10 ** 10):
        return record(Track(samples=[(at(-40), 100.0)], rows=tool.ready_rows() if rows is None else rows, sampled=sampled, logged=logged, seen=seen), at(0), 100.5)

    def test_gate(self):
        self.assertEqual(self.after(19)["low"], tool.to_bits(tool.DEFAULT_MIN))
        self.assertNotEqual(self.after(20)["low"], tool.to_bits(tool.DEFAULT_MIN))

    def test_no_row_keeps_values(self):
        got = self.after(30, rows=[Row(1.0, 1.0, 30.0, 1)])
        self.assertEqual((got["low"], got["high"]), (tool.to_bits(tool.DEFAULT_MIN), tool.to_bits(tool.DEFAULT_MAX)))

    def test_saturate(self):
        got = self.after(TOP, logged=TOP)
        self.assertEqual((got["sampled"], got["logged"]), (TOP, TOP))

    def test_bucket_clears_second_counter(self):
        self.assertEqual(self.after(5, logged=9, seen=0)["logged"], 0)
        self.assertEqual(self.after(5, logged=9)["logged"], 10)


class Bucket(unittest.TestCase):
    def test_equal_keeps(self):
        bucket = tool.millis_of(at(0)) // tool.BUCKET_MILLIS
        got = record(Track(seen=bucket, logged=4, rows=[]), at(0), 1.0)
        self.assertEqual((got["seen"], got["logged"]), (bucket, 4))

    def test_before_epoch_is_zero(self):
        got = record(Track(seen=3, logged=4, rows=[]), (-500000, 0), 1.0)
        self.assertEqual((got["seen"], got["logged"]), (3, 4))

    def test_wide_divide(self):
        got = record(Track(seen=0, millis=3, rows=[]), (4294968, 0), 1.0)
        self.assertEqual(got["seen"], 4294968000 // 3)


class Fold(unittest.TestCase):
    def fold(self, keys, curve, start=0.0, **fields):
        fields.setdefault("tracks", ((3, Track(high=0.002)), (9, Track(high=0.004))))
        return run(Case("t", kind="fold", keys=keys, curve=curve, start=start, **fields))

    def test_largest_wins(self):
        self.assertEqual(tool.to_float(self.fold((3, 9), (0.9, 1.7))["result"]), 1.7)
        self.assertEqual(tool.to_float(self.fold((3, 9), (1.7, 0.9))["result"]), 1.7)

    def test_max_field_is_read(self):
        got = self.fold((9,), (0.9,))
        self.assertEqual(got["events"][0], "curve 2 9 %#x" % tool.to_bits(0.004))

    def test_absent_key(self):
        self.assertEqual(tool.to_float(self.fold((4,), ())["result"]), 0.001)

    def test_no_tree(self):
        self.assertEqual(tool.to_float(self.fold((3,), (), root=False)["result"]), 0.001)

    def test_nan_panics(self):
        self.assertTrue(self.fold((3,), (math.nan,))["panic"])


class Logger(unittest.TestCase):
    def test_flag_one_only(self):
        self.assertEqual([row[2] for row in RESULT["logger"]], [0x77, 0, 0x77])


class Controls(unittest.TestCase):
    def test_counter_gate_edit(self):
        case = tool.one("t", Track(samples=[(at(-40), 100.0)], rows=tool.ready_rows(), sampled=20), at(0), 100.5)
        self.assertTrue(killed(flip(SAMPLED_BYTE + 3), case))

    def test_pop_edit(self):
        case = tool.one("t", Track(samples=tool.older(0), rows=tool.ready_rows()), at(100, 1000), 101.0)
        self.assertTrue(killed(flip(POP_BRANCH + 9), case))

    def test_row_gate_edit(self):
        case = Case("t", kind="select", rows=(Row(1.0, 1.0, 30.0, 29),), mode=1)
        self.assertTrue(killed({0x3930CB3: 0x76}, case))

    def constant_case(self):
        return tool.one("t", Track(samples=tool.older(0), rows=tool.ready_rows()), at(21), 101.0)

    def test_low_edge_constant(self):
        harness = tool.Harness(with_bytes(0x20B038, struct.pack("<d", 22.0)))
        self.assertIsNotNone(tool.first_failure(harness, [self.constant_case()]))

    def test_epsilon_constant(self):
        harness = tool.Harness(with_bytes(0x20AA60, struct.pack("<d", 1.0)))
        self.assertIsNotNone(tool.first_failure(harness, [self.constant_case()]))

    def test_floor_constant(self):
        harness = tool.Harness(with_bytes(0x20A8A8, struct.pack("<d", 11.0)))
        case = tool.one("t", Track(samples=[(at(-40), 100.0)], rows=[Row(0.5, 0.25, 5.0, 3, at(-6))]), at(0), 100.0)
        self.assertIsNotNone(tool.first_failure(harness, [case]))

    def test_unedited_passes(self):
        self.assertIsNone(tool.first_failure(HARNESS, tool.gate_cases()[:6]))

    def test_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the target")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_nobits_never_resolves(self):
        self.assertNotIn(".bss", [section["name"] for section in IMAGE.mapped])

    def test_unknown_case_field(self):
        with self.assertRaises(tool.EvidenceError):
            Case("t", nonsense=1)


class Evidence(unittest.TestCase):
    def test_files_match(self):
        for name, text in FILES.items():
            if name in ("evidence.json", "mutations.tsv", "outcomes.tsv"):
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_outcomes_match(self):
        self.assertEqual((FOLDER / "outcomes.tsv").read_text(encoding="ascii"), FILES["outcomes.tsv"])

    def test_mutations_all_classified(self):
        rows = [line.split("\t") for line in (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]]
        self.assertGreater(len(rows), 300)
        self.assertEqual([row for row in rows if row[3] == "unclassified"], [])

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_summary(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["mutations"]["killed"] + data["mutations"]["survived"], data["mutations"]["total"])


class ReviewBoundaries(unittest.TestCase):
    def test_native_elapsed_multiply_overflow_drives_jo(self):
        read = lambda at, size: IMAGE.blob[IMAGE.offset(at):IMAGE.offset(at) + size]
        imul = tool.decode(read, 0x1447181)
        clear = tool.decode(read, imul.next)
        jump = tool.decode(read, clear.next)
        self.assertEqual((imul.op, imul.width, imul.target), ("imul3", 8, 1000000))
        self.assertEqual((jump.va, jump.op, jump.cc, jump.target), (0x144718C, "jcc", 0, 0x14471CE))
        for value in ((2**63 - 1) // 1000000, (2**63 - 1) // 1000000 + 1,
                      -(2**63 // 1000000), -(2**63 // 1000000) - 1):
            machine = tool.Machine(IMAGE)
            machine.regs[tool.RSI] = value & TOP
            overflow = not -2**63 <= value * 1000000 < 2**63
            machine.cf = machine.of = not overflow
            machine.step(imul)
            machine.step(clear)  # XORPD does not overwrite integer flags.
            self.assertEqual((machine.cf, machine.of), (overflow, overflow))
            self.assertEqual(machine.step(jump), jump.target if overflow else jump.next)

    def test_native_divsd_exact_special_value_bits(self):
        # Intel SDM vol1 Tables4-7/11-1: masked exceptions, DAZ/FTZ off.
        # Read the actual scalar xmm0/xmm6 division from the selector.
        read = lambda at, size: IMAGE.blob[IMAGE.offset(at):IMAGE.offset(at) + size]
        ins = tool.decode(read, 0x3930CF2)
        self.assertEqual((ins.op, ins.a, ins.b), ("divsd", ("x", 0), ("x", 6)))
        posinf, neginf = 0x7FF0000000000000, 0xFFF0000000000000
        posone, negone = 0x3FF0000000000000, 0xBFF0000000000000
        negzero, indefinite = 0x8000000000000000, 0xFFF8000000000000
        cases = [(a, b, indefinite) for a in (posinf, neginf) for b in (posinf, neginf)]
        cases += [(a, b, indefinite) for a in (0, negzero) for b in (0, negzero)]
        cases += [(posone, 0, posinf), (posone, negzero, neginf),
                  (negone, 0, neginf), (negone, negzero, posinf),
                  (0, negone, negzero), (negzero, negone, 0),
                  (posone, neginf, negzero), (negone, neginf, 0),
                  (0x7FF8000000000123, posone, 0x7FF8000000000123),
                  (posone, 0xFFF8000000000456, 0xFFF8000000000456),
                  (0xFFF0000000000123, posone, 0xFFF8000000000123),
                  (posone, 0x7FF0000000000456, 0x7FF8000000000456),
                  (0xFFF8000000000123, 0x7FF8000000000456, 0xFFF8000000000123),
                  (0x7FF0000000000123, 0xFFF8000000000456, 0x7FF8000000000123)]
        for a, b, expected in cases:
            with self.subTest(a=hex(a), b=hex(b)):
                machine = tool.Machine(IMAGE)
                machine.xmm[0] = (0x123456789ABCDEF0 << 64) | a
                machine.xmm[6] = b
                machine.step(ins)
                self.assertEqual(machine.xmm[0], (0x123456789ABCDEF0 << 64) | expected)
                self.assertEqual(tool.to_bits(tool.fdiv_spec(tool.to_float(a), tool.to_float(b))), expected)

    def test_indefinite_sign_changes_total_order_selection(self):
        rows = (Row(math.inf, math.inf, 30.0, 40), Row(0.25, 1.0, 30.0, 40))
        for mode, expected in ((0, 0xFFF8000000000000), (1, 0x3FE0000000000000)):
            result = run(Case("review_divsd_total_order", kind="select", rows=rows, mode=mode))
            self.assertTrue(result["some"])
            self.assertEqual(result["value"], expected)

    def test_microsecond_multiply_and_add_overflow_in_record_path(self):
        # Dates are built by the captured chrono constructor in the abstract model.
        # All dates lie in the accepted chrono range; no target process runs.
        now = (250000 * 365 * 86400, 0)
        cases = [("multiply_overflow", (-250000 * 365 * 86400, 0), 0.0),
                 ("largest_micros", (now[0] - 9223372036854 - 1, 224192001), float(2**63 - 1) / 1e6),
                 ("add_overflow", (now[0] - 9223372036854 - 1, 224192000), 0.0)]
        for name, then, elapsed in cases:
            case = Case(name, tracks=((7, Track(samples=[((now[0]-30, 0), 100.0)],
                        rows=[Row(1.0, 1.0, 30.0, 100, then)])),), steps=((7, now, 101.0),))
            result = run(case)
            self.assertFalse(result["panic"])
            self.assertEqual(tool.seconds_since(now, then), elapsed)
            num, denom, decay, count = words(result["trackers"][7]["rows"][0])
            if elapsed:
                self.assertEqual((num, denom, decay, count), (0.0, 0.0, 30.0, 0))
            else:
                self.assertEqual((num, denom, decay, count), (1 - 1/30.0, 1 - 1/30.0, 30.0, 101))

    def test_signed_imul_operand_widths_and_flag_clearing(self):
        # Independently encoded instructions; only the Python model is run.
        for prefix, width in ((b"\x66", 2), (b"", 4), (b"\x48", 8)):
            for tail, op in ((bytes.fromhex("6bf60a"), "imul3"),
                             (bytes.fromhex("0faff7"), "imul2")):
                raw = prefix + tail + b"\x90" * 16
                ins = tool.decode(lambda va, count: raw[va:va + count], 0)
                self.assertEqual((ins.op, ins.width), (op, width))
                bound = 1 << (8 * width - 1)
                for a, b in ((0, 10), ((bound - 1) // 10, 10),
                             ((bound - 1) // 10 + 1, 10), (-bound, -1)):
                    if op == "imul3" and b != 10:
                        continue
                    with self.subTest(width=width, op=op, a=a, b=b):
                        machine = tool.Machine(IMAGE)
                        machine.regs[tool.RSI] = a & tool.MASK[width]
                        machine.regs[tool.RDI] = b & tool.MASK[width]
                        overflow = not -bound <= a * b < bound
                        machine.cf = machine.of = not overflow
                        machine.step(ins)
                        self.assertEqual(machine.regs[tool.RSI] & tool.MASK[width], a * b & tool.MASK[width])
                        self.assertEqual((machine.cf, machine.of), (overflow, overflow))


if __name__ == "__main__":
    unittest.main()
