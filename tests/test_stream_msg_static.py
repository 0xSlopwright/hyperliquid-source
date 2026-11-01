"""Controls for tools/stream_msg_static.py (node #94 node/stream_msg.rs MessagePack encoder and bincode decoders)."""
import contextlib
import io
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import stream_msg_static as sm  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / sm.TARGET
PACKET = ROOT / 'research/work-items/stream-msg-codecs-94/records.json'
PAD = 0x157b559  # seven int3 bytes between two const panic functions, outside every window
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == sm.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = sm.Image(CACHE['data'])
        CACHE['result'] = sm.analyse(CACHE['data'])
        CACHE['sha256'] = identity['sha256']
    return CACHE


def patched(*edits, data=None):
    c = load()
    data = bytearray(data or c['data'])
    for va, new in edits:
        off = c['img'].offset(va, len(new))
        data[off:off + len(new)] = new
    return bytes(data)


def rela_edit(slot, new):
    """Rewrite the addend of the RELATIVE .rela.dyn entry for `slot`."""
    c = load()
    rela = next(s for s in c['img'].secs if s['name'] == '.rela.dyn')
    data = bytearray(c['data'])
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, _ = struct.unpack_from('<QQq', data, pos)
        if where == slot and info & 0xffffffff == 8:
            struct.pack_into('<q', data, pos + 16, new)
            return bytes(data)
    raise AssertionError(f'no RELATIVE entry at {slot:#x}')


def rel32(va, length, target):
    return struct.pack('<i', target - (va + length))


@contextlib.contextmanager
def rewrite(va, new, length=None, target=None):
    """Patch window bytes and re-pin the window and operand tables, so only the semantic checks can object."""
    data = patched((va, new))
    name = sm.window_of(va)
    fde, start, hexs = sm.WINDOWS[name]
    raw = bytearray(bytes.fromhex(hexs))
    raw[va - start:va - start + len(new)] = new
    ops = {va: (length, target)} if length else {}
    with mock.patch.dict(sm.WINDOWS, {name: (fde, start, raw.hex())}), mock.patch.dict(sm.OPERANDS, ops):
        yield data


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Models(unittest.TestCase):
    def test_headers(self):
        self.assertEqual(sm.header('map', 2), b'\x82')
        self.assertEqual(sm.header('map', 16), b'\xde\x00\x10')
        self.assertEqual(sm.header('array', 6), b'\x96')
        self.assertEqual(sm.header('array', 0x10000), b'\xdd\x00\x01\x00\x00')
        self.assertEqual(sm.header('str', 21), b'\xb5')
        self.assertEqual(sm.header('str', 32), b'\xd9\x20')

    def test_named_skeleton(self):
        s = sm.skeleton(named=True)
        self.assertTrue(s.startswith(b'\x82\xaaabci_block\x86\xa4time<time>\xb5signed_action_bundles'))
        self.assertTrue(s.endswith(b'\xa8proposer<proposer>\xa5resps<resps>'))

    def test_array_skeleton_has_no_names(self):
        self.assertEqual(sm.skeleton(named=False),
                         b'\x92\x96<time><signed_action_bundles><round><parent_round><hardfork><proposer><resps>')

    def test_greeting(self):
        self.assertEqual(sm.greeting(0), ('Full', None))
        self.assertEqual([sm.greeting(t)[1] for t in range(1, 6)], [3, 4, 5, 6, 7])
        self.assertEqual(sm.greeting(6), ('error', 5, 6, 'AbciStreamGreeting'))

    def test_greeting_hash_tag1_one_arm(self):
        self.assertEqual(sm.greeting_hash(1), ('arm', 1, 80))
        self.assertEqual(sm.greeting_hash(1, inner_ok=False), ('error', 'inner 32-byte error', 3))
        self.assertEqual(sm.greeting_hash(3), ('error', 5, 3, 'GreetingHash'))
        self.assertEqual(sm.lead_greeting_hash(1, 32), ('arm', 'Compact', 32))

    def test_read_hash32(self):
        self.assertEqual(sm.read_hash32(40), ('ok', 32))
        self.assertEqual(sm.read_hash32(10), ('error', 0, 22))
        self.assertEqual(sm.read_hash32(10, limit=40, counted=20), ('error', 2))


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    def setUp(self):
        self.result = load()['result']

    def test_census(self):
        c = self.result['census']
        self.assertEqual(c['location_refs'], ['0x466e4e0'])
        self.assertEqual(c['encode_slot_calls'], ['0x474cc03'])
        self.assertEqual(c['direct_callers']['0x466e3f0'], [])

    def test_serialize_order(self):
        self.assertEqual(self.result['abci_block_serialize']['order'],
                         ['abci_block', 'time', 'signed_action_bundles', 'round', 'parent_round', 'hardfork',
                          'proposer', 'resps'])

    def test_greeting_arms(self):
        g = self.result['abci_stream_greeting']
        self.assertEqual(g['discriminants'], {'1': 3, '2': 4, '3': 5, '4': 6, '5': 7})
        self.assertEqual(self.result['strings']['allowed'], {'AbciStreamGreeting': '0..=5', 'GreetingHash': '0..=2'})

    def test_packet_matches_regeneration(self):
        expected = json.loads(PACKET.read_text())
        got = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(json.dumps(got, sort_keys=True)), expected)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sm.main([]), 0)
        self.assertIn('unwrap at stream_msg.rs:43:48', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruption(unittest.TestCase):
    def rejects(self, data, pattern):
        with self.assertRaisesRegex(sm.EvidenceError, pattern):
            sm.analyse(data)

    def test_window_bytes(self):
        self.rejects(patched((0x466e3f9, b'\x90')), 'encode_arc at 0x466e3f0: bytes changed')

    def test_vec_pointer(self):
        with rewrite(0x466e404 + 5, b'\x02') as data:
            self.rejects(data, '0x466e404 is not')

    def test_struct_map_byte(self):
        with rewrite(0x466e41e + 7, b'\x00') as data:
            self.rejects(data, '0x466e41e is not')

    def test_ok_value(self):
        with rewrite(0x466e43f + 2, b'\x05') as data:
            self.rejects(data, '0x466e43f is not')

    def test_arc_size(self):
        with rewrite(0x466e45c + 1, b'\x30') as data:
            self.rejects(data, '0x466e45c is not')

    def test_outer_entries(self):
        with rewrite(0x459d51e + 1, b'\x03') as data:
            self.rejects(data, '0x459d51e is not')

    def test_inner_entries(self):
        with rewrite(0x459d599 + 1, b'\x05') as data:
            self.rejects(data, '0x459d599 is not')

    def test_name_length(self):
        with rewrite(0x459d63f + 1, b'\x14') as data:
            self.rejects(data, '0x459d63f is not ba15000000')

    def test_field_order(self):
        with rewrite(0x459d67b, b'\x48\x8d\x35' + rel32(0x459d67b, 7, 0x6f73e6), 7, 0x6f73e6) as data:
            self.rejects(data, 'does not pin 0x6f73e1')

    def test_resps_tag(self):
        with rewrite(0x459d77e + 3, b'\x03') as data:
            self.rejects(data, '0x459d77e is not')

    def test_map_marker(self):
        with rewrite(sm.MAP_HEADER + 0x18, b'\xde') as data:
            self.rejects(data, f'{sm.MAP_HEADER + 0xe:#x} is not')

    def test_fixstr_marker(self):
        with rewrite(0x4aed5cd + 3, b'\xb0') as data:
            self.rejects(data, f'{sm.MARKER_BYTE:#x} is not')

    def test_jump_table(self):
        self.rejects(patched((sm.JUMP_TABLE + 8, struct.pack('<i', 0x4674966 - sm.JUMP_TABLE))),
                     'jump table entry 2 goes to 0x4674966')

    def test_greeting_bound(self):
        with rewrite(0x4674852 + 3, b'\x06') as data:
            self.rejects(data, '0x4674852 is not')

    def test_greeting_hash_ok_test(self):
        with rewrite(0x466e823 + 4, b'\x01') as data:
            self.rejects(data, '0x466e823 is not')

    def test_greeting_hash_err_branch(self):
        with rewrite(0x466e84f, b'\xeb' + struct.pack('<b', 0x466e7ff - (0x466e84f + 2)), 2, 0x466e7ff) as data:
            self.rejects(data, 'does not pin 0x466e7f8')

    def test_type_name(self):
        self.rejects(patched((0x6f877f, b'X')), 'type name at 0x6f877f changed')

    def test_allowed_range(self):
        self.rejects(patched((0x203580 + 12, b'\x06')), r'allowed variants at 0x203580 are \(0, 0, 6\)')

    def test_location_line(self):
        self.rejects(patched((sm.UNWRAP_LOCATION[0] + 16, struct.pack('<I', 44))), 'stream_msg.rs Locations are')

    def test_stray_location_reference(self):
        self.rejects(patched((PAD, b'\x4c\x8d\x05' + rel32(PAD, 7, sm.UNWRAP_LOCATION[0]))),
                     r"references are \['0x157b559', '0x466e4e0'\]")

    def test_encode_slot(self):
        self.rejects(rela_edit(sm.ENCODE_SLOT, sm.ENCODE_ARC + 1), 'slot 0x5776ac8 no longer holds')

    def test_field_name_text(self):
        self.rejects(patched((0x20af88, b'P')), 'field name proposer at 0x20af88 changed')

    def test_operand_outside_windows(self):
        with mock.patch.dict(sm.OPERANDS, {PAD: (7, 0)}):
            self.rejects(load()['data'], 'outside every window')


if __name__ == '__main__':
    unittest.main()
