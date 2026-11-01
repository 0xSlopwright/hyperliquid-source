import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('hyper_fork_url_pin', ROOT / 'tools/hyper_fork_url_pin.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PACKET = ROOT / 'research/work-items/RE-002-hyper-fork-url-pin/hyper-fork-url-pin.json'


class UrlPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = mod.build()
        cls.data, _ = mod.checked('94')
        cls.secs = mod.sections(cls.data)
        cls.relocs = mod.relative_relocs(cls.data, cls.secs)

    def test_regeneration_matches_packet(self):
        self.assertEqual(mod.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'hyper-fork-url-pin.json').write_bytes(PACKET.read_bytes())
            subprocess.run([sys.executable, str(ROOT / 'tools/hyper_fork_url_pin.py'), '--out', d, '--check'], check=True)

    def test_both_captures_carry_the_fork(self):
        for release in ('94', '115'):
            t = self.result['targets'][release]
            self.assertEqual(set(t['string_file_offsets']), {'two_matching_urls', 'only_trying'})
            for point, records in t['fork_only_points'].items():
                self.assertTrue(any(r['lea_sites'] for r in records), (release, point))
        self.assertEqual(len(self.result['targets']['94']['anchors']), len(mod.ANCHORS))

    def test_map_is_never_filled(self):
        p94 = self.result['targets']['94']['map_population']
        p115 = self.result['targets']['115']['map_population']
        self.assertEqual(len(p94['config_builds']), 4)
        self.assertEqual(len(p115['config_builds']), 3)
        for p in (p94, p115):
            self.assertTrue(all(b['tag_value'] == 0 for b in p['config_builds']))
        self.assertEqual(len(p94['config_clone_callers']), 4)
        self.assertEqual([c['writes_config_offset'] for c in p115['make_mut_callers']], ['0x70', '0x70'])

    def test_nonzero_tag_store_is_rejected(self):
        broken = bytearray(self.data)
        va = int(self.result['targets']['94']['map_population']['config_builds'][0]['tag_store'], 16)
        off = next(s['offset'] + va - s['addr'] for s in self.secs.values()
                   if s['addr'] and s['addr'] <= va < s['addr'] + s['size'])
        broken[off + 4] = 1  # movq $0x1,0x30(%rax)
        with self.assertRaises(mod.EvidenceError):
            mod.population(bytes(broken), self.secs, '94')

    def test_wrong_bytes_are_rejected(self):
        va, hexbytes, kind, want, meaning = mod.ANCHORS[2]
        bad = (va, '410fb78d70020000', kind, want, meaning)  # node len at +0x270 instead of +0x272
        with self.assertRaises(mod.EvidenceError):
            mod.check_anchor(self.data, self.secs, self.relocs, '94', bad)

    def test_wrong_location_is_rejected(self):
        anchor = next(a for a in mod.ANCHORS if a[2] == 'lea_location' and a[3] == (494, 21))
        bad = anchor[:3] + ((495, 21),) + anchor[4:]
        with self.assertRaises(mod.EvidenceError):
            mod.check_anchor(self.data, self.secs, self.relocs, '94', bad)

    def test_wrong_got_target_is_rejected(self):
        anchor = next(a for a in mod.ANCHORS if a[2] == 'call_got' and a[3] == 0x4edba50)
        bad = anchor[:3] + (0x4edba60,) + anchor[4:]
        with self.assertRaises(mod.EvidenceError):
            mod.check_anchor(self.data, self.secs, self.relocs, '94', bad)

    def test_wrong_template_is_rejected(self):
        saved = copy.deepcopy(mod.STRINGS)
        try:
            mod.STRINGS['only_trying'] = b'\x17hyper-fork only trying \xc0\x04 at \xc0\x01\n'
            anchor = next(a for a in mod.ANCHORS if a[3] == 'only_trying')
            with self.assertRaises(mod.EvidenceError):
                mod.check_anchor(self.data, self.secs, self.relocs, '94', anchor)
        finally:
            mod.STRINGS.clear()
            mod.STRINGS.update(saved)


if __name__ == '__main__':
    unittest.main()
