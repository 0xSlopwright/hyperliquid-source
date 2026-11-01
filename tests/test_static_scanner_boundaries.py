"""Synthetic byte-census boundaries, including candidates inside displacements."""
import ast
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint_slow as slow


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bi = load('scanner_bincode_independent', 'research/work-items/RE-005-bincode-slow-widths/independent_verify.py')
li = load('scanner_lthash_independent', 'research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py')


def independent_counts(tb, tva, rel):
    if hasattr(bi, 'reader_call_counts'):
        return bi.reader_call_counts(tb, tva, rel)
    # Retain the exact original loop as the before-correction regression oracle.
    tree = ast.parse(Path(bi.__file__).read_text())
    check = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'check')
    start = next(i for i, n in enumerate(check.body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'counts' for t in n.targets))
    ns = dict(vars(bi), tb=tb, tva=tva, rel=rel)
    exec(compile(ast.Module(body=check.body[start:start + 2], type_ignores=[]), bi.__file__, 'exec'), ns)
    return ns['counts']


class CompleteOffsets(unittest.TestCase):
    def test_tool_final_fitting_indirect_call(self):
        target = 0x2000
        raw = b'\xff\x15\x00\x00\x00\x00'
        secs = {'.text': {'offset': 0, 'size': len(raw), 'addr': 0x1000}}
        with patch.object(slow, 'READER_CALL_COUNTS', {target: 1}):
            got = slow._call_got_sites(raw, secs, {0x1006: target})
        self.assertEqual(got, {'0x2000': [{'site': '0x1000', 'got_slot': '0x1006'}]})

    def test_independent_final_fitting_indirect_call(self):
        raw = b'\xff\x15\x00\x00\x00\x00'
        with patch.object(bi, 'CALL_COUNTS', {0x2000: 1}):
            self.assertEqual(independent_counts(raw, 0x1000, {0x1006: 0x2000}), {0x2000: 1})

    def test_independent_final_fitting_direct_call(self):
        raw = b'\xe8\x00\x00\x00\x00'
        secs = {'.text': (0x1000, 0, 5), '.rela.dyn': (0, 5, 0)}
        self.assertEqual(li.scan_refs(raw, secs, (0x1005,)), {0x1005: [(0x1000, 'call')]})

    def test_independent_final_fitting_direct_jump(self):
        raw = b'\xe9\xfb\xff\xff\xff'
        secs = {'.text': (0x1000, 0, 5), '.rela.dyn': (0, 5, 0)}
        self.assertEqual(li.scan_refs(raw, secs, (0x1000,)), {0x1000: [(0x1000, 'jmp')]})

    def test_overlapping_indirect_candidates_and_truncated_tail(self):
        for n in range(12):
            raw = (b'\xff\x15\xff\x15\x00\x00\x00\x00\xff\x15')[:n]
            positions = [i for i in range(max(0, n - 5)) if raw[i:i + 2] == b'\xff\x15']
            rel = {0x1000 + i + 6 + struct.unpack_from('<i', raw, i + 2)[0]: 0x2000 for i in positions}
            secs = {'.text': {'offset': 0, 'size': len(raw), 'addr': 0x1000}}
            with self.subTest(n=n), patch.object(slow, 'READER_CALL_COUNTS', {0x2000: len(positions)}), patch.object(bi, 'CALL_COUNTS', {0x2000: len(positions)}):
                sites = slow._call_got_sites(raw, secs, rel)['0x2000']
                self.assertEqual([int(r['site'], 16) - 0x1000 for r in sites], positions)
                self.assertEqual(independent_counts(raw, 0x1000, rel), {0x2000: len(positions)})

    def test_direct_candidates_inside_displacements_and_final_lea(self):
        for raw in (b'\xe8\xe9\xe8\xe9\x00\x00\x00\x00', b'\x8d\x05\xff\xff\xff\xff', b'\xe8', b'\xe9\x00\x00\x00', b''):
            expected = {}
            for i, op in enumerate(raw):
                if op in (0xe8, 0xe9) and i + 5 <= len(raw):
                    target = 0x1000 + i + 5 + struct.unpack_from('<i', raw, i + 1)[0]
                    expected.setdefault(target, []).append((0x1000 + i, 'call' if op == 0xe8 else 'jmp'))
                if op == 0x8d and i + 6 <= len(raw) and raw[i + 1] & 0xc7 == 5:
                    target = 0x1000 + i + 6 + struct.unpack_from('<i', raw, i + 2)[0]
                    expected.setdefault(target, []).append((0x1000 + i - 1, 'lea'))
            secs = {'.text': (0x1000, 0, len(raw)), '.rela.dyn': (0, len(raw), 0)}
            self.assertEqual(li.scan_refs(raw, secs, tuple(expected)), {k: sorted(v) for k, v in expected.items()})
