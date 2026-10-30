"""Controls for tools/gossip_rpc_timeouts_static.py (node #94 gossip RPC timeouts and retry record)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gossip_rpc_timeouts_static as gt  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / gt.TARGET
PACKET = ROOT / 'research/work-items/gossip-rpc-timeouts-94/records.json'
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == gt.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = gt.Image(CACHE['data'])
        CACHE['result'] = gt.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(va, new):
    c = load()
    data = bytearray(c['data'])
    off = c['img'].offset(va, len(new))
    data[off:off + len(new)] = new
    return bytes(data)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = load()['result']

    def test_timeouts(self):
        rows = [(t['fde'], t['descriptor'], t['seconds']) for t in self.result['timeouts']]
        self.assertEqual(rows, [('0x1fd4570', 'gossip_rpc_request', 10.0), ('0x1fd4570', 'verify_rpc', 5.0),
                                ('0x226bb20', 'gossip_rpc_request', 10.0), ('0x435cb20', 'gossip_rpc_request', 10.0)])
        self.assertEqual(self.result['seconds_to_micros'], 1e6)
        self.assertTrue(all(t['micros_multiplies'] for t in self.result['timeouts']))

    def test_retry_records(self):
        for r in self.result['retries']:
            self.assertEqual((r['tries'], r['sleep_seconds'], r['template'], r['format_slot']),
                             (10, 2.0, '0x1f2107', '0x576e040'))
            self.assertEqual(r['f64_immediates'], [2.0, 60.0])
        self.assertEqual([(r['sixty_sites'], r['writer_target']) for r in self.result['retries']],
                         [(['0x20399c0'], '0x204b340'), (['0x43888a0'], '0x43a17c0')])

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(gt.main([]), 0)
        self.assertIn('tries=10 sleep=2.0 s', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruptions(unittest.TestCase):
    def refuses(self, data, pattern):
        with self.assertRaisesRegex(gt.EvidenceError, pattern):
            gt.analyse(data)

    def test_timeout_seconds_changed(self):
        for t in gt.TIMEOUTS:
            self.refuses(patched(t['imm_at'] + 2, struct.pack('<d', 60.0)), 'bytes changed')

    def test_shared_constant_changed(self):
        self.refuses(patched(0x20a8a8, struct.pack('<d', 60.0)), 'immediate 10.0 != movsd constant 60.0')

    def test_descriptor_text_changed(self):
        self.refuses(patched(0x3c4610, b'X'), 'descriptor at 0x3c4610')
        self.refuses(patched(0x3c4639, b'X'), 'descriptor at 0x3c4639')

    def test_micros_constant_redirected(self):
        data = bytearray(load()['data'])
        for va in (0x1fd475e, 0x1fd500c):
            off = load()['img'].offset(va + 4, 4)
            data[off:off + 4] = b'\x00\x00\x00\x00'
        self.refuses(bytes(data), 'no multiply by the 1e6 constant in FDE 0x1fd4570')

    def test_retry_count_and_sleep_changed(self):
        for r in gt.RETRIES:
            rec = r['va'] + len(bytes.fromhex(r['hex']))
            tries = rec + bytes.fromhex(gt.RECORD).index(bytes.fromhex('48c78360010000'))
            self.refuses(patched(tries + 7, b'\x0b'), 'retry record stores')
            secs = rec + bytes.fromhex(gt.RECORD).index(bytes.fromhex('48b8'))
            self.refuses(patched(secs + 2, struct.pack('<d', 60.0)), 'retry record stores')

    def test_template_text_changed(self):
        self.refuses(patched(0x1f2108, b'R'), 'does not carry')

    def test_extra_sixty_in_request_future(self):
        extra = b'\x48\xb8' + struct.pack('<d', 60.0)
        self.refuses(patched(0x2039400, extra), r"60.0 sites are \['0x2039400', '0x20399c0'\]")

    def test_writer_call_moved(self):
        self.refuses(patched(gt.RETRIES[1]['writer_call'], b'\x90'), 'writer call opcode')

    def test_window_outside_fde(self):
        saved = gt.RETRIES[0]['fde']
        try:
            gt.RETRIES[0]['fde'] = 0x4387f40
            self.refuses(load()['data'], 'outside FDE 0x4387f40')
        finally:
            gt.RETRIES[0]['fde'] = saved


if __name__ == '__main__':
    unittest.main()
