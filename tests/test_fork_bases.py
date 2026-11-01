import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('fork_bases', ROOT / 'tools/fork_bases.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PACKET = ROOT / 'research/work-items/RE-002-fork-bases/fork-bases.json'


class ForkBasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.committed = json.loads(PACKET.read_text())
        cls.result = mod.build(previous=cls.committed)

    def test_offline_regeneration_matches_packet(self):
        self.assertEqual(mod.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'fork-bases.json').write_bytes(PACKET.read_bytes())
            subprocess.run([sys.executable, str(ROOT / 'tools/fork_bases.py'), '--out', d, '--check'], check=True)

    def test_fork_points(self):
        f94 = self.result['fork_locations']['94']
        f115 = self.result['fork_locations']['115']
        self.assertEqual(sorted(f94['forks']), ['bincode-fork', 'hyper-alloy-core-fork', 'hyper-fork', 'hyper-tls-fork'])
        self.assertEqual(f94['forks']['hyper-tls-fork']['src/client.rs'], [[136, 19], [151, 30]])
        self.assertEqual(f115['forks']['hyper-tls-fork']['src/client.rs'], [[127, 19], [142, 30]])
        self.assertEqual(f94['forks']['bincode-fork']['src/lib.rs'], [[170, 22]])
        self.assertEqual(f115['forks']['bincode-fork']['src/lib.rs'], [[171, 22]])
        self.assertIn('revm-precompile', f115['forks'])
        self.assertNotIn('revm-precompile', f94['forks'])

    def test_overflow_helpers_and_sites(self):
        messages = {f'attempt to {op} with overflow' for op in
                    ('add', 'subtract', 'multiply', 'negate', 'shift left', 'shift right')}
        for release, ov in self.result['overflow'].items():
            self.assertEqual(set(ov['helpers'].values()), messages, release)
            self.assertEqual(sum(ov['call_sites_by_origin'].values()), ov['call_sites'])
            self.assertGreater(ov['call_sites_by_origin']['std'], 0, release)
        self.assertEqual(self.result['overflow']['94']['helpers']['0x157b480'], 'attempt to add with overflow')
        self.assertEqual(self.result['overflow']['94']['helpers']['0x157b520'], 'attempt to subtract with overflow')
        self.assertGreater(self.result['overflow']['94']['call_sites_by_origin']['crates.io'], 40000)

    def test_upstream_bases_beat_controls(self):
        for row in self.committed['upstream']:
            base = [r for r in row['revisions'] if r['role'] == 'base']
            ctrl = [r for r in row['revisions'] if r['role'] == 'control']
            fixed = [sum(e.get('token_start_at_best_shift', e.get('token_start', 0)) for e in r['files'].values()) for r in base]
            self.assertEqual(len(set(fixed)), 1, row['fork'])
            self.assertTrue(all(r['token_start'] < base[0]['points'] for r in ctrl), (row['fork'], row['capture']))

    def test_corrupted_upstream_point_set_is_rejected(self):
        bad = copy.deepcopy(self.committed)
        files = bad['upstream'][0]['revisions'][0]['files']
        files[next(iter(files))]['points'] += 1
        with self.assertRaises(mod.EvidenceError):
            mod.build(previous=bad)

    def test_corrupted_helper_message_is_rejected(self):
        data, _ = mod.checked('visor')
        elf = mod.Elf(data)
        va = next(int(k, 16) for k, v in mod.overflow(elf)['helpers'].items() if v.startswith('attempt to add'))
        broken = bytearray(data)
        off = elf.off(va)
        broken[off + 10:off + 14] = b'\0\0\0\0'  # retarget the message LEA
        with self.assertRaises(mod.EvidenceError):
            mod.overflow(mod.Elf(bytes(broken)))

    def test_malformed_elf_is_rejected(self):
        with self.assertRaises(mod.EvidenceError):
            mod.Elf(b'\x7fELF\x01\x01' + b'\0' * 58)
        data, _ = mod.checked('visor')
        broken = bytearray(data)
        broken[58:60] = (63).to_bytes(2, 'little')
        with self.assertRaises(mod.EvidenceError):
            mod.Elf(bytes(broken))


if __name__ == '__main__':
    unittest.main()
