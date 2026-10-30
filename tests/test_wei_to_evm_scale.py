"""Controls for tools/wei_to_evm_scale.py (RE-004, node #94)."""

import filecmp
import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'wei_to_evm_scale.py'
PACKET = ROOT / 'research' / 'work-items' / 'RE-004-wei-to-evm-scale-94'

spec = importlib.util.spec_from_file_location('wei_to_evm_scale', TOOL)
wes = importlib.util.module_from_spec(spec)
sys.modules['wei_to_evm_scale'] = wes
spec.loader.exec_module(wes)

BINARY = ROOT / wes.BINARY
CACHE = {}
ANCHORS = {0x2715320: (0x27155c4, 0x2715a29, 0x271628d, 0x27162e4, 0x2716954),
           0x4d0a6d0: (0x4d0a97a, 0x4d0ae3a, 0x4d0b690, 0x4d0b6e7, 0x4d0bd36),
           0x4d0bfa0: (0x4d0c24a, 0x4d0c70a, 0x4d0cf60, 0x4d0cfb7, 0x4d0d606)}
SCALES = [(-2, 100), (-2, 101), (-1, 10), (-19, 10 ** 19), (-20, 0), (0, 5), (2, 7), (10, 3), (18, 10 ** 8),
          (19, 2 ** 64 - 1), (58, 11579208923731619542), (58, 11579208923731619543), (77, 1), (77, 2),
          (78, 0), (127, 1), (-128, 0)]
GATES = [(0, wes.LIMIT, None, 0, 1), (0, wes.LIMIT + 1, None, 0, 1), (1, wes.LIMIT + 100, None, 0, 1),
         (2, 100, 2, 0x10, 1), (2, 100, 2, 0, 0), (1, 100, 2, 0, 0), (1, 100, 2, 0, 2), (3, 100, None, 0, 1)]


def small(rows):
    listing = '\n'.join(f'  {0x1000 + 4 * i:x}:\t{row}' for i, row in enumerate(rows))
    return wes.parse_listing(listing + f'\n  {0x1000 + 4 * len(rows):x}:\tint3')


class Fixture(unittest.TestCase):
    def set_up_class(cls):
        if not CACHE:
            data = BINARY.read_bytes()
            img = wes.Image(data)
            fdes = wes.Fdes(img)
            insns, ranges = wes.load_code(BINARY, fdes, wes.COPIES + wes.HELPERS)
            CACHE.update(data=data, img=img, fdes=fdes, insns=insns, ranges=ranges, slots=img.slots(),
                         copies=[wes.find_copy(insns, ranges[s]) for s in wes.COPIES],
                         analysis=wes.analyse(BINARY, data))
        for name in ('data', 'img', 'fdes', 'insns', 'ranges', 'slots', 'copies'):
            setattr(cls, name, CACHE[name])
        cls.result, cls.table, cls.bounds, cls.gate_rows, _ = CACHE['analysis']

    setUpClass = classmethod(set_up_class)

    def machine(self, insns=None):
        return wes.Machine(insns or self.insns, self.img, self.slots, wes.DROPS)

    def differs(self, insns, copy=None):
        copy = copy or self.copies[0]
        machine = self.machine(insns)
        try:
            for exponent, wei in SCALES:
                records = [(1, 0, 8), (1, exponent, 6)]
                if wes.run_gate(machine, copy, 1, wei, 2, 0, records) != wes.gate_model(1, wei, 2, 0, records):
                    return True
            for token, wei, native, data, flag in GATES:
                records = wes.gate_records(token, flag)
                if (wes.run_gate(machine, copy, token, wei, native, data, records)
                        != wes.gate_model(token, wei, native, data, records)):
                    return True
        except wes.Unmodelled:
            return True
        return False

    def mutate(self, va, mnemonic=None, ops=None):
        out = []
        hit = 0
        for ins in self.insns:
            if ins[0] == va:
                ins = (ins[0], mnemonic or ins[1], ops if ops is not None else ins[2], ins[3])
                hit += 1
            out.append(ins)
        self.assertEqual(hit, 1)
        return out

    def ins(self, va):
        return next(ins for ins in self.insns if ins[0] == va)


class Results(Fixture):
    def test_counts(self):
        v = self.result['vectors']
        self.assertEqual(v['copies'], 3)
        self.assertEqual(v['mismatches'], 0)
        self.assertEqual(v['per_copy'], {'scale': 2086, 'scale_ok': 995, 'scale_tag': 1091, 'gates': 288})

    def test_anchors(self):
        for copy in self.copies:
            want = ANCHORS[copy['start']]
            self.assertEqual((copy['entry'], copy['success'], copy['fail'], copy['tail'], copy['panic']), want)

    def test_extents(self):
        self.assertEqual(self.ranges[0x2715320]['end'], 0x2716bb7)
        self.assertEqual(self.ranges[0x4d0a6d0]['end'], 0x4d0bf96)
        self.assertEqual(self.ranges[0x4d0bfa0]['end'], 0x4d0d866)

    def test_each_copy_alone(self):
        for copy in self.copies:
            self.assertFalse(self.differs(self.insns, copy))

    def test_gate_function_scan(self):
        scan = self.result['gate_function_scan']
        self.assertEqual(tuple(scan['both']), wes.COPIES)
        self.assertGreater(scan['load_functions'], 3)
        self.assertGreater(scan['limit_functions'], 2)

    def test_texts(self):
        self.assertEqual(self.result['texts']['0xba'], 'Invalid number of decimals: {}')
        self.assertEqual(self.result['texts']['0x148'], 'Send to EVM with data not configured')
        self.assertEqual(self.result['constants']['f64_table_exact_entries'], 23)

    def test_exponent_table(self):
        self.assertEqual(len(self.table), 256)
        rows = {row[0]: row[1:] for row in self.table}
        self.assertEqual(rows[-20], ['tag:0xba'] * 3)
        self.assertEqual(rows[-19], ['ok:0', 'tag:0xba', 'tag:0xba'])
        self.assertEqual(rows[-2], ['ok:0', 'tag:0xba', 'ok:1000000'])
        self.assertEqual(rows[0], ['ok:0', 'ok:1', 'ok:100000000'])
        self.assertEqual(rows[77], ['ok:0', f'ok:{10 ** 77}', 'tag:0xba'])
        self.assertEqual(rows[78], ['tag:0xba'] * 3)
        self.assertEqual(rows[127], ['tag:0xba'] * 3)
        self.assertEqual(rows[-128], ['tag:0xba'] * 3)

    def test_bounds(self):
        rows = {row[0]: row for row in self.bounds}
        self.assertEqual(rows[57][2], 'none')
        self.assertEqual(rows[58][1:], (11579208923731619542, 11579208923731619543))
        self.assertEqual(rows[77][1:], (1, 2))
        self.assertEqual(rows[78][1:], ('none', 'all'))

    def test_guarded_range_never_overflows(self):
        self.assertEqual(self.result['guarded_range']['largest_product_bits'], 124)

    def test_native_exponent_and_token_flag(self):
        machine = self.machine()
        copy = self.copies[0]
        self.assertEqual(wes.run_gate(machine, copy, 2, 3, 2, 0, wes.gate_records(2, 0)), ('ok', 0, 3 * 10 ** 10))
        self.assertEqual(wes.run_gate(machine, copy, 1, 100, 2, 0, wes.gate_records(1, 1)), ('ok', 1, 1))

    def test_error_value_is_the_scaled_amount(self):
        machine = self.machine()
        copy = self.copies[1]
        for wei, decimals, want in ((101, 2, 1.01), (2 ** 53 + 1, 0, 2.0 ** 53), (2 ** 64 - 1, 8, 184467440737.09552)):
            records = [(1, 0, 8), (1, -1 if wei % 10 else -2, decimals)]
            got = wes.run_gate(machine, copy, 1, wei, None, 0, records)
            self.assertEqual(got[:2], ('tag', 0xba))
            self.assertEqual(struct.unpack('<d', got[2].to_bytes(8, 'little'))[0], want)

    def test_lead_witnesses(self):
        rows = {(w['exponent'], w['amount']): w for w in self.result['lead']['witnesses']}
        self.assertEqual((rows[18, 10 ** 8]['binary'], rows[18, 10 ** 8]['lead']), (10 ** 26, None))
        self.assertEqual((rows[-2, 1000]['binary'], rows[-2, 1000]['lead']), (10, 10))
        self.assertEqual((rows[-2, 1001]['binary'], rows[-2, 1001]['lead']), (None, None))

    def test_outputs_match_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, table, bounds, gate_rows, copies = CACHE['analysis']
            wes.write_outputs(Path(tmp), self.result, table, bounds, gate_rows, copies, self.data)
            names = ['evidence.json', 'exponent-table.tsv', 'boundaries.tsv', 'gates.tsv', 'block-bytes.txt']
            match, bad, err = filecmp.cmpfiles(tmp, PACKET, names, shallow=False)
            self.assertEqual((sorted(match), bad, err), (sorted(names), [], []))

    def test_manifest(self):
        rows = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertEqual(len(rows), 6)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


class NegativeControls(Fixture):
    def test_tampered_digest(self):
        with self.assertRaises(wes.EvidenceError):
            wes.check_digest(self.data[:-1] + bytes([self.data[-1] ^ 1]))

    def test_out_of_range_va(self):
        with self.assertRaises(wes.EvidenceError):
            self.img.read(0x7fffffff0000, 8)
        with self.assertRaises(wes.EvidenceError):
            self.fdes.range_of(0x10)

    def test_missing_anchor(self):
        other = dict(self.ranges[0x27a1150])
        with self.assertRaises((StopIteration, wes.EvidenceError)):
            wes.find_copy(self.insns, other)

    def test_wrong_stack_slot_shape(self):
        with self.assertRaises(wes.EvidenceError):
            wes.rsp_slot(('m', 8, wes.RBX, None, 1, 0x10))

    def test_limit_constant(self):
        ins = self.ins(0x27155ca)
        self.assertTrue(self.differs(self.mutate(0x27155ca, ops=(ins[2][0], ('i', wes.LIMIT + 1)))))

    def test_limit_compare(self):
        self.assertTrue(self.differs(self.mutate(0x27155d9, 'setae')))

    def test_native_exponent(self):
        self.assertTrue(self.differs(self.mutate(0x2715754, ops=(('r', wes.RDX, 1), ('i', 9)))))

    def test_sign_branch(self):
        self.assertTrue(self.differs(self.mutate(0x2715696, 'js')))

    def test_remainder_ignored(self):
        self.assertTrue(self.differs(self.mutate(0x2716287, 'jmp')))

    def test_quotient_and_u32_path(self):
        self.assertTrue(self.differs(self.mutate(0x2716281, 'nop', ())))

    def test_ladder_constant(self):
        ins = self.ins(0x27156ba)
        self.assertTrue(self.differs(self.mutate(0x27156ba, ops=ins[2][:2] + (('i', 101),))))

    def test_product_overflow_ignored(self):
        self.assertTrue(self.differs(self.mutate(0x27159f2, 'nop', ())))

    def test_power_overflow_ignored(self):
        self.assertTrue(self.differs(self.mutate(0x271594e, 'jmp')))

    def test_record_flag(self):
        ins = self.ins(0x2715641)
        self.assertTrue(self.differs(self.mutate(0x2715641, ops=(ins[2][0], ('i', 2)))))

    def test_multiply_helper_step(self):
        self.assertEqual(self.ins(0x4de57b5)[1], 'adc')
        good, bad = self.machine(), self.machine(self.mutate(0x4de57b5, 'nop', ()))
        copy = self.copies[1]
        wrong = 0
        for exponent in range(30, 58):
            for wei in wes.seeded(6):
                records = [(1, 0, 8), (1, exponent, 6)]
                want = wes.gate_model(1, wei, None, 0, records)
                self.assertEqual(wes.run_gate(good, copy, 1, wei, None, 0, records), want)
                wrong += wes.run_gate(bad, copy, 1, wei, None, 0, records) != want
        self.assertGreater(wrong, 0)

    def test_frame_filler_has_no_effect(self):
        machine = self.machine()
        copy = self.copies[2]
        records = [(1, 0, 8), (1, 18, 6)]
        self.assertEqual(wes.run_gate(machine, copy, 1, 77, 2, 0, records, b'one'),
                         wes.run_gate(machine, copy, 1, 77, 2, 0, records, b'two'))

    def test_filler_dependence_would_show(self):
        """A control that reads an unmodelled frame slot changes with the filler."""
        insns = self.mutate(0x27159f8, 'mov', (('r', wes.R13, 8), ('m', 8, wes.RSP, None, 1, 0x500)))
        machine = self.machine(insns)
        copy = self.copies[0]
        records = [(1, 0, 8), (1, 2, 6)]
        self.assertNotEqual(wes.run_gate(machine, copy, 1, 1, 2, 0, records, b'one'),
                            wes.run_gate(machine, copy, 1, 1, 2, 0, records, b'two'))

    def test_unset_record_stops(self):
        machine = self.machine()
        copy = self.copies[0]
        original = wes.OFF_EXP
        wes.OFF_EXP = 0x20                       # the record byte the code reads is now never written
        try:
            with self.assertRaises(wes.Unmodelled):
                wes.run_gate(machine, copy, 1, 1, None, 0, [(1, 0, 8), (1, 0, 6)])
        finally:
            wes.OFF_EXP = original

    def test_unknown_call_stops(self):
        machine = wes.Machine(self.insns, self.img, self.slots, ())
        with self.assertRaises(wes.Unmodelled):
            wes.run_gate(machine, self.copies[0], 1, 1, None, 0, [(1, 0, 8), (1, 0, 6)])

    def test_models(self):
        self.assertIsNone(wes.scale_model(-20, 0, 0))
        self.assertEqual(wes.scale_model(-19, 0, 0), 0)
        self.assertIsNone(wes.scale_model(-2, 101, 0))
        self.assertIsNone(wes.scale_model(78, 0, 0))
        self.assertEqual(wes.scale_model(77, 1, 0), 10 ** 77)
        self.assertEqual(wes.gate_model(3, 1, None, 0, wes.gate_records(3, 1)), ('panic',))


class Evaluator(unittest.TestCase):
    def setUp(self):
        self.img = wes.Image(BINARY.read_bytes())

    def execute(self, rows):
        machine = wes.Machine(small(rows + ['ret']), self.img, {})
        machine.setreg(wes.RSP, wes.FRAME)
        machine.store(wes.FRAME, 8, wes.RET_MAGIC)
        machine.run(0x1000)
        return machine

    def test_unset_register_stops(self):
        with self.assertRaises(wes.Unmodelled):
            self.execute(['add    rax,rcx'])

    def test_unset_memory_stops(self):
        with self.assertRaises(wes.Unmodelled):
            self.execute(['mov    rax,QWORD PTR [rsp-0x10]'])

    def test_unknown_mnemonic_stops(self):
        with self.assertRaises(wes.Unmodelled):
            self.execute(['vpaddq ymm0,ymm1,ymm2'])

    def test_misaligned_movdqa_stops(self):
        with self.assertRaises(wes.Unmodelled):
            self.execute(['pxor   xmm0,xmm0', 'movdqa XMMWORD PTR [rsp+0x4],xmm0'])

    def test_partial_register_survives_push_pop(self):
        m = self.execute(['mov    r13b,0x7', 'push   r13', 'pop    r13', 'mov    al,r13b'])
        self.assertEqual(m.regs[wes.RAX] & 0xff, 7)
        with self.assertRaises(wes.Unmodelled):
            self.execute(['mov    r13b,0x7', 'push   r13', 'pop    r13', 'mov    eax,r13d', 'add    eax,0x1'])

    def test_u64_to_double_idiom(self):
        for wei in (0, 1, 2 ** 53 + 1, 2 ** 63, 2 ** 64 - 1):
            m = wes.Machine(small([
                'movsd  xmm0,QWORD PTR [rsp+0x10]',
                'unpcklps xmm0,XMMWORD PTR [rip+0x0]        # 203e80',
                'subpd  xmm0,XMMWORD PTR [rip+0x0]        # 202ea0',
                'movapd xmm1,xmm0', 'unpckhpd xmm1,xmm0', 'addsd  xmm1,xmm0', 'ret']), self.img, {})
            m.setreg(wes.RSP, wes.FRAME)
            m.store(wes.FRAME, 8, wes.RET_MAGIC)
            m.store(wes.FRAME + 0x10, 8, wei)
            m.run(0x1000)
            self.assertEqual(m.xmm[1] & wes.MASK, wes.d2u(float(wei)))


if __name__ == '__main__':
    unittest.main()
