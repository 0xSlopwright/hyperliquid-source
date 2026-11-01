"""Controls for tools/tokio_metrics_poll_static.py (node #94 traffic-recorder seed: tokio-metrics instrument_poll)."""
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
import tokio_metrics_poll_static as tm  # noqa: E402
from artifacts import check  # noqa: E402

BINARY = ROOT / tm.TARGET
PACKET = ROOT / 'research/work-items/traffic-recorder-instrumented-poll-94/records.json'
PAD = 0x157b559  # seven int3 bytes between two const panic functions, outside every window
CACHE = {}


def load():
    if not CACHE:
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == tm.TARGET)
        check(BINARY, identity)
        CACHE['data'] = BINARY.read_bytes()
        CACHE['img'] = tm.Image(CACHE['data'])
        CACHE['result'] = tm.analyse(CACHE['data'])
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
    name = tm.window_of(va)
    fde, start, hexs = tm.WINDOWS[name]
    raw = bytearray(bytes.fromhex(hexs))
    raw[va - start:va - start + len(new)] = new
    ops = {va: (length, target)} if length else {}
    with mock.patch.dict(tm.WINDOWS, {name: (fde, start, raw.hex())}), mock.patch.dict(tm.OPERANDS, ops):
        yield data


def poll(**kw):
    base = dict(instrumented_at=(10, 100), woke_at=0, idled_at=0, did_poll_once=True,
                poll_start=(11, 0), inner_start=(11, 10), inner_end=(11, 30),
                slow_poll_threshold=(0, 50_000), long_delay_threshold=(0, 50_000))
    base.update(kw)
    return tm.instrument_poll(**base)


class Models(unittest.TestCase):
    def test_review_counterexample(self):
        # closed PR 585 review: woke_at 1000, sample (0, 100), helper result (0, 250), threshold (0, 500)
        m, _ = poll(instrumented_at=(0, 100), woke_at=1000, idled_at=1000, poll_start=(0, 1350),
                    long_delay_threshold=(0, 500))
        self.assertEqual(m['total_short_delay_duration_ns'], 250)
        self.assertEqual(m['total_short_delay_count'], 1)
        self.assertEqual(m['total_scheduled_duration_ns'], 250)
        self.assertNotIn('total_idled_count', m)
        self.assertEqual(tm.byte_reading(1000), 1000)

    def test_long_delay_at_threshold(self):
        m, _ = poll(instrumented_at=(0, 0), woke_at=1, poll_start=(0, 501), long_delay_threshold=(0, 500))
        self.assertEqual((m['total_long_delay_count'], m['total_long_delay_duration_ns']), (1, 500))
        m, _ = poll(instrumented_at=(0, 0), woke_at=1, poll_start=(0, 500), long_delay_threshold=(0, 500))
        self.assertEqual(m['total_short_delay_duration_ns'], 499)

    def test_idle_is_strict(self):
        m, _ = poll(woke_at=700, idled_at=700, poll_start=(10, 900))
        self.assertNotIn('total_idled_count', m)
        m, _ = poll(woke_at=701, idled_at=700, poll_start=(10, 900))
        self.assertEqual((m['total_idled_count'], m['total_idle_duration_ns']), (1, 1))

    def test_unwoken_poll_is_not_scheduled(self):
        m, _ = poll(woke_at=0)
        self.assertFalse({'total_scheduled_count', 'total_long_delay_count', 'total_short_delay_count'} & set(m))

    def test_first_poll_and_idled_at(self):
        m, idled = poll(did_poll_once=False, instrumented_at=(10, 100), poll_start=(12, 50))
        self.assertEqual((m['first_poll_count'], m['total_first_poll_delay_ns']), (1, 1_999_999_950))
        self.assertEqual(idled, 999_999_930)

    def test_scheduled_saturates(self):
        m, _ = poll(instrumented_at=(10, 0), woke_at=5 * tm.NS, poll_start=(11, 0))
        self.assertEqual(m['total_scheduled_duration_ns'], 0)
        self.assertEqual(m['total_short_delay_count'], 1)

    def test_slow_poll_at_threshold(self):
        m, _ = poll(inner_start=(11, 0), inner_end=(11, 50_000))
        self.assertEqual((m['total_slow_poll_count'], m['total_slow_poll_duration']), (1, 50_000))
        m, _ = poll(inner_start=(11, 0), inner_end=(11, 49_999))
        self.assertEqual(m['total_fast_poll_count'], 1)

    def test_from_ns_magic(self):
        for n in [0, 1, tm.NS - 1, tm.NS, tm.NS + 1, 2 ** 32, 2 ** 63, tm.U64] + \
                 [k * tm.NS + d for k in (1, 7, 2 ** 33, 18446744072) for d in (-1, 0, 1)]:
            self.assertEqual(tm.from_ns(n), divmod(n, tm.NS), n)

    def test_instant_add_overflow(self):
        with self.assertRaisesRegex(OverflowError, 'overflow when adding duration to instant'):
            tm.add(((1 << 63) - 1, tm.NS - 1), (0, 1))

    def test_on_wake_first_wins(self):
        self.assertEqual(tm.on_wake((5, 0), (6, 0), 0), tm.NS)
        self.assertEqual(tm.on_wake((5, 0), (7, 0), 123), 123)
        self.assertEqual(tm.on_wake((5, 0), (4, 0), 0), 0)


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Results(unittest.TestCase):
    def setUp(self):
        self.result = load()['result']

    def test_census(self):
        c = self.result['census']
        self.assertEqual(c['task_rs_2483_fdes'], 66)
        self.assertEqual(c['idle_location_fdes'], ['0x3d12780', '0x3d12f20', '0x3d133b0', '0x3d13840',
                                                   '0x3d13cd0', '0x3d14390'])
        self.assertEqual(c['direct_callers']['0x3d21670'], ['0x3d13b5c'])
        self.assertEqual(c['direct_callers']['0x3d21990'], ['0x3d1323c'])
        self.assertEqual(c['traffic_recorder_location_refs'], {'0x5718be8': ['0x3d13fdd'], '0x57193f8': ['0x3d216ca']})

    def test_copies(self):
        self.assertEqual(self.result['poll_traffic']['returns'], 'Poll::Pending only')
        self.assertEqual(self.result['poll_lu']['future'], '0x3d21520 (base/src/lu.rs:199:21)')
        self.assertEqual(self.result['state']['0x10'], 'woke_at')
        self.assertEqual(self.result['raw_metrics']['0x80'], 'total_short_delay_duration_ns')

    def test_waker_vtable(self):
        self.assertEqual(self.result['strings']['waker_vtable']['wake_by_ref'], '0x3d0a2e0')

    def test_packet_matches_regeneration(self):
        rec = dict(self.result, target_sha256=load()['sha256'])
        self.assertEqual(json.loads(PACKET.read_text()), json.loads(json.dumps(rec, sort_keys=True)))

    def test_excerpts_one_return_per_poll(self):
        text = (PACKET.parent / 'excerpts.objdump.txt').read_text()
        for name in ('poll_traffic', 'poll_lu'):
            _, lo, hexs = tm.WINDOWS[name]
            hi = lo + len(bytes.fromhex(hexs))
            rets = [l for l in text.splitlines() if l.startswith(' ') and ':' in l and
                    lo <= int(l.split(':')[0], 16) < hi and l.split('\t')[-1].strip() == 'ret']
            self.assertEqual(len(rets), 1, name)

    def test_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(tm.main([]), 0)
        self.assertIn('66 FDEs reference task.rs:2483:23', out.getvalue())


@unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
class Corruption(unittest.TestCase):
    def rejects(self, data, pattern):
        with self.assertRaisesRegex(tm.EvidenceError, pattern):
            tm.analyse(data)

    def test_window_bytes(self):
        self.rejects(patched((0x3d13d30, b'\x90')), 'poll_traffic at 0x3d13cd0: bytes changed')

    def test_short_long_buckets_swapped(self):
        with rewrite(0x3d13ea6, bytes.fromhex('ba88000000')) as d:
            self.rejects(d, '0x3d13ea6 is not ba80000000')

    def test_idle_branch(self):
        with rewrite(0x3d13d9f, b'\x72', 2, 0x3d13dc5) as d:
            self.rejects(d, '0x3d13d9f is not 73')

    def test_did_poll_once_offset(self):
        with rewrite(0x3d13d0a, bytes.fromhex('80bb6901000000')) as d:
            self.rejects(d, '0x3d13d0a is not 80bb6801000000')

    def test_woke_at_offset(self):
        with rewrite(0x3d13d94, bytes.fromhex('48874818')) as d:
            self.rejects(d, '0x3d13d94 is not 48874810')

    def test_long_threshold_field(self):
        with rewrite(0x3d13e88, bytes.fromhex('483b9090000000')) as d:
            self.rejects(d, '0x3d13e88 is not 483b90a0000000')

    def test_slow_threshold_field(self):
        with rewrite(0x3d14208, bytes.fromhex('483b81a0000000')) as d:
            self.rejects(d, '0x3d14208 is not 483b8190000000')

    def test_long_threshold_nanos_branch(self):
        with rewrite(0x3d13ea4, b'\x73', 2, 0x3d13eb4) as d:
            self.rejects(d, '0x3d13ea4 is not 76')

    def test_scheduled_saturation(self):
        with rewrite(0x3d13e72, b'\x90' * 4) as d:
            self.rejects(d, '0x3d13e72 is not 480f45ce')

    def test_instrumented_at_offset(self):
        with rewrite(0x3d13cf9, bytes.fromhex('498b4530')) as d:
            self.rejects(d, '0x3d13cf9 is not 498b4538')

    def test_waker_vtable_lea(self):
        with rewrite(0x3d13f88, b'\x48\x8d\x0d' + rel32(0x3d13f88, 7, 0x5718a48), 7, 0x5718a48) as d:
            self.rejects(d, 'vtable 0x5718a40 users are')
            with self.assertRaisesRegex(tm.EvidenceError, '0x3d13f88 does not pin 0x5718a40'):
                tm.check_poll_traffic(tm.Image(d))

    def test_inner_future_call(self):
        with rewrite(0x3d146ac, b'\xe8' + rel32(0x3d146ac, 5, tm.TRAFFIC_FUTURE), 5, tm.TRAFFIC_FUTURE) as d:
            self.rejects(d, 'direct callers are')
            with self.assertRaisesRegex(tm.EvidenceError, '0x3d146ac does not pin 0x3d21520'):
                tm.check_poll_lu(tm.Image(d))

    def test_returns_pending(self):
        with rewrite(0x3d14259, bytes.fromhex('b000')) as d:
            self.rejects(d, '0x3d14259 is not b001')

    def test_sleep_seconds(self):
        with rewrite(0x3d1412b, bytes.fromhex('48b80000000000004e40')) as d:
            self.rejects(d, '0x3d1412b is not 48b8000000000000')

    def test_on_wake_overflow_test(self):
        with rewrite(0x3d0a346, bytes.fromhex('4885c9')) as d:
            self.rejects(d, '0x3d0a346 is not 4885d2')

    def test_sub_timespec_ok_tag(self):
        with rewrite(0x4ee37a5, bytes.fromhex('48c70301000000')) as d:
            self.rejects(d, '0x4ee37a5 is not 48c70300000000')

    def test_location_line(self):
        self.rejects(patched((tm.IDLE_SUB_LOCATION + 16, struct.pack('<I', 2484))), 'Locations are')

    def test_location_file(self):
        self.rejects(rela_edit(0x5718be8, tm.TM_PATH_VA), 'different length or path')

    def test_lu_location(self):
        self.rejects(patched((tm.LU_RESUME_LOCATION[0] + 16, struct.pack('<I', 198))), 'lu.rs Location')

    def test_vtable_slot(self):
        self.rejects(rela_edit(tm.WAKER_VTABLE + 0x10, tm.WAKE), 'waker vtable')

    def test_instant_add_message(self):
        self.rejects(patched((tm.INSTANT_ADD[0], b'X')), 'instant-add overflow message changed')

    def test_stray_location_reference(self):
        self.rejects(patched((PAD, b'\x48\x8d\x3d' + rel32(PAD, 7, tm.IDLE_SUB_LOCATION))), 'has 7 references')

    def test_stray_direct_call(self):
        self.rejects(patched((PAD, b'\xe8' + rel32(PAD, 5, tm.POLL_TRAFFIC))), 'direct callers are')

    def test_operand_outside_windows(self):
        with mock.patch.dict(tm.OPERANDS, {PAD: (7, 0)}):
            self.rejects(load()['data'], 'outside every window')

    def test_wrong_identity(self):
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == tm.TARGET)
        bad = dict(identity, sha256='0' * 64)
        with self.assertRaises(Exception):
            check(BINARY, bad)


if __name__ == '__main__':
    unittest.main()
