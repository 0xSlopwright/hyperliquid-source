import copy
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import owner, validate_progress
from elf_index import sections, unwind_index


def fixture():
    data = bytearray(832)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
    data[64:64+len(names)] = names
    entries = [(0,0,0,0,0,0), (1,3,0,0,64,len(names)), (11,1,6,0x100,256,32),
               (17,1,2,0x200,320,20), (31,1,2,0x300,384,16)]
    # Use the actual string offsets so fixtures remain readable.
    entries[2] = (names.index(b'.text'),1,6,0x100,256,32)
    entries[3] = (names.index(b'.eh_frame_hdr'),1,2,0x200,320,20)
    entries[4] = (names.index(b'.eh_frame\0'),1,2,0x300,384,16)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512+i*64, *e, 0,0,1,0)
    data[320:324] = bytes([1,0x1b,3,0x3b])
    struct.pack_into('<Iii', data, 328, 1, -0x100, 0x100)
    return data


class UnwindTests(unittest.TestCase):
    def test_data_relative_negative_start(self):
        secs, rows = unwind_index(fixture())
        self.assertEqual(rows, [{'index':0, 'start':0x100, 'fde':0x300, 'section':'.text', 'next_index_upper_bound':0x120}])

    def test_rejects_truncated_table(self):
        data = fixture()
        struct.pack_into('<I', data, 328, 100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_unknown_encoding(self):
        data = fixture(); data[323] = 0
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_non_executable_start(self):
        data = fixture(); struct.pack_into('<i', data, 332, 0x100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_truncated_sections(self):
        with self.assertRaises(ValueError): sections(fixture()[:600])


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.parts = json.loads((self.root / 'research/components.json').read_text())['components']
        self.progress = json.loads((self.root / 'research/progress.json').read_text())

    def test_specific_handler_before_exchange_fallback(self):
        self.assertEqual(owner('l1/exchange/handlers/14_order.rs', self.parts), 'action-dispatch')
        self.assertEqual(owner('l1/exchange/impl_trading.rs', self.parts), 'exchange')
        self.assertEqual(owner('l1/clearinghouse/oracle/reference_oracle.rs', self.parts), 'risk')

    def test_unknown_tree_rejected(self):
        with self.assertRaises(ValueError): owner('unrecognized/private.rs', self.parts)

    def test_complete_gate_without_evidence_rejected(self):
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['gates']['built'] = True
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_fabricated_denominator_rejected(self):
        d = copy.deepcopy(self.progress)
        row = d['components']['orderbook']
        row['raw_equal_bodies'] = 2; row['total_function_windows'] = 1
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_component_rejected(self):
        d = copy.deepcopy(self.progress); del d['components']['visor']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)
