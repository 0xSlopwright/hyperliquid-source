"""Controls for tools/local_abci_gates_static.py (node #94 local abci_state startup gates)."""
import contextlib
import io
import json
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import local_abci_gates_static as la  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / la.TARGET
PACKET = ROOT / 'research/work-items/local-abci-gates-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == la.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = la.Image(CACHE['data'])
        CACHE['result'] = la.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits):
    c = load()
    data = bytearray(c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


class Models(unittest.TestCase):
    def test_height_gate(self):
        self.assertTrue(la.too_far_behind(0, 20000))
        self.assertFalse(la.too_far_behind(1, 20000))
        self.assertTrue(la.too_far_behind(100, 20100))
        self.assertFalse(la.too_far_behind(2 ** 64 - 10, 2 ** 64 - 2))
        self.assertTrue(la.too_far_behind(2 ** 64 - 10, 2 ** 64 - 1))

    def test_day_division_truncates(self):
        rng = random.Random(94)
        values = [0, 1, 86399, 86400, -1, -86399, -86400, -86401, 2 ** 40, -(2 ** 40)]
        values += [rng.randrange(-(2 ** 47), 2 ** 47) for _ in range(2000)]
        for x in values:
            q = abs(x) // 86400
            want = (q if x >= 0 else -q) & 0xffffffff
            self.assertEqual(la.days_86400(x), want, x)

    def test_freshness_compare(self):
        self.assertTrue(la.freshness_panics((1, 2, 3), (1, 2, 4)))
        self.assertFalse(la.freshness_panics((1, 2, 3), (1, 2, 3)))
        self.assertFalse(la.freshness_panics((2, 0, 0), (1, 86399, 999)))

    def test_select_heights(self):
        self.assertIsNone(la.select_heights([]))
        self.assertIsNone(la.select_heights([(5, 9)]))
        self.assertEqual(la.select_heights([(5, 9)], other_len=1), (5, 9))
        self.assertEqual(la.select_heights([(1, 100), (2, 3), (1, 200)]), (2, 3))
        self.assertEqual(la.select_heights([(4, 10), (4, 30), (4, 20)]), (4, 30))
        rng = random.Random(94)
        for _ in range(500):
            vals = [(rng.randrange(4), rng.randrange(4)) for _ in range(rng.randrange(2, 7))]
            self.assertEqual(la.select_heights(vals), max(vals))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_height_gate(self):
        g = self.result['height_gate']
        self.assertEqual((g['tolerance'], g['saturating'], g['ok_branch']), (20000, True, '0x226adb1'))
        self.assertEqual({k: (v['len'], v['text']) for k, v in g['messages'].items()},
                         {'too_far_behind': (30, 'local height is too far behind'),
                          'stale_hardfork': (35, 'local height is from stale hardfork')})

    def test_tolerance_log(self):
        t = self.result['tolerance_log']
        self.assertEqual((t['default'], t['hardfork'], t['join']), (540.0, 840.0, '0x2269164'))
        self.assertEqual(t['branches_into_join'], ['0x226901b', '0x226902e'])
        self.assertEqual((t['log_placeholders'], t['tolerance_arg_index']), (5, 2))

    def test_freshness(self):
        f = self.result['freshness']
        self.assertEqual((f['added_seconds'], f['message_seconds'], f['template_placeholders']), (600, 600.0, 2))
        self.assertEqual((f['location_file'], f['location_line'], f['location_column']),
                         ('/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs', 346, 9))
        self.assertEqual(f['slots']['panic'], ['0x576e098', '0x157b810'])

    def test_status_log_fields(self):
        st = self.result['status_log']
        self.assertEqual(st['fields'], {'[rsp+0xd8]': 'local_height', '[rsp+0xc8]': 'initial_height',
                                        '[rsp+0xd0]': 'latest_height'})
        self.assertEqual(st['template'], '0x1ef6dd')

    def test_height_selection(self):
        h = self.result['height_selection']
        self.assertEqual(h['error'], {'text': 'unable to find at least 2 valid rpc heights', 'len': 43,
                                      'pieces': {'0x0': '0x3d7964', '0x10': '0x3d7974', '0x1b': '0x3d797f'}})
        self.assertEqual((h['iterator_next'], h['retry_template'], h['retry_template_lea']),
                         ('0x27df4f0', '0x1f2256', '0x226a7eb'))
        self.assertEqual(h['branches'], {'len_gt_1_to_loop': '0x226a56c', 'len_0_to_error': '0x226a6d2',
                                         'single_other_not_1_to_error': '0x226a6d2', 'loop_back': '0x226a680',
                                         'ok_to_result': '0x226a719', 'ok_to_slots': '0x226a912',
                                         'error_retry_back': '0x2269bcc'})

    def test_callers(self):
        c = self.result['callers']
        self.assertEqual((c['direct_calls'], c['caller_fde'], c['caller_states_when_al_set']),
                         (['0x22aef61', '0x22affe7'], '0x22ae8a0', [10, 11]))
        self.assertEqual(c['state0_arm'], '0x2271d38')
        self.assertEqual(sorted(c['future_strings'].values()), ['check_reachability_firewall_ips', 'failed to load firewall ips'])

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(la.main([]), 0)
        self.assertIn('local_height.saturating_add(20000) <= latest_height', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(la.EvidenceError, pattern):
            la.analyse(data)

    def test_gate_constant(self):
        self.refuses(patched((0x226ab20, struct.pack('<i', 200))), 'gate at 0x226ab0a: bytes changed')

    def test_gate_messages(self):
        self.refuses(patched((0x3d79b2, b'L')), 'too_far_behind message at 0x3d79b2')
        self.refuses(patched((0x3d798f, b'L')), 'stale_hardfork message at 0x3d798f')

    def test_tolerance_constants(self):
        self.refuses(patched((0x20a3d8, struct.pack('<d', 600.0))), 'tolerance constants are 600.0, 840.0')
        self.refuses(patched((0x20a230, struct.pack('<d', 600.0))), 'tolerance constants are 540.0, 600.0')

    def test_extra_branch_into_join(self):
        start = la.STARTUP_FDE + 0x100
        rel = 0x2269164 - (start + 6)
        self.refuses(patched((start, b'\x0f\x84' + struct.pack('<i', rel))), 'branches into join 0x2269164')

    def test_extra_slot_reference(self):
        self.refuses(patched((la.STARTUP_FDE + 0x100, b'\x48\x8b\x84\x24\xe0\x00\x00\x00')), r'\[rsp\+0xe0\] references')

    def test_log_template(self):
        self.refuses(patched((0x1f5428 + 20, b'X')), 'log template 0x1f5428 changed')

    def test_freshness_seconds(self):
        self.refuses(patched((0x2271d52 + 0x55, struct.pack('<I', 0x4e20))), 'freshness at 0x2271d52: bytes changed')

    def test_location_file(self):
        self.refuses(patched((0x1f40cf + 1, b'X')), 'Location file is')

    def test_panic_slot_relocation(self):
        c = load()
        img = c['img']
        rela = next(s for s in img.secs if s['name'] == '.rela.dyn')
        data = bytearray(c['data'])
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', data, pos)
            if where == 0x576e098 and info & 0xffffffff == 8:
                struct.pack_into('<q', data, pos + 16, 0x157b840)
        self.refuses(bytes(data), 'panic slot does not reach the panic shim')

    def test_extra_caller(self):
        site = la.STARTUP_FDE + 0x100
        self.refuses(patched((site, b'\xe8' + struct.pack('<i', la.FRESH_FDE - (site + 5)))),
                     r"direct calls to 0x2271d00: \['0x2268af0', '0x22aef61', '0x22affe7'\]")

    def test_state0_arm_moved(self):
        self.refuses(patched((la.POLL_TABLE, struct.pack('<i', 0x2272398 - la.POLL_TABLE))), 'state-0 arm is 0x2272398')

    def test_status_label_changed(self):
        self.refuses(patched((0x1ef6dd + 14 + 29, b'X')), r'placeholder 2 label .* is not a \[name: \] field')

    def test_status_argument_swapped(self):
        self.refuses(patched((0x226aa1e + 4, b'\xc8')), 'status_log at 0x226a974: bytes changed')

    def test_extra_height_slot_reference(self):
        self.refuses(patched((la.STARTUP_FDE + 0x100, b'\x48\x8b\x84\x24\xd0\x00\x00\x00')), r'\[rsp\+0xd0\] references')

    def test_template_text(self):
        self.refuses(patched((0x1ed195, b'U')), 'freshness template 0x1ed194 changed')

    def test_selection_compare_flipped(self):
        self.refuses(patched((0x226a69e, b'\x92')), 'select_guard_loop at 0x226a53f: bytes changed')

    def test_selection_error_text(self):
        self.refuses(patched((0x3d7980, b'X')), 'error string rebuilt as')

    def test_retry_template(self):
        self.refuses(patched((0x1f2256 + 5, b'X')), 'retry template at 0x1f2256 changed')

    def test_got_heights_template(self):
        self.refuses(patched((0x1e7641 + 20, b'X')), 'got-heights template changed')


if __name__ == '__main__':
    unittest.main()
