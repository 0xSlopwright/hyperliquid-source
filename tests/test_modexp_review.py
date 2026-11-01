"""Native-grounded oracle and harness controls; no captured execution."""
import importlib.util
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import modexp


class ModexpReviewTests(unittest.TestCase):
    def test_berlin_clamps_zero_iteration_before_division(self):
        # 0x4e934a7 CMP/ADC returns 1; 0x4e93163 MUL then divisor 3.
        for exponent in (b'', b'\x00', b'\x01'):
            with self.subTest(exponent=exponent):
                self.assertEqual(modexp.gas_eip2565(bytes(256), exponent, bytes(256)), 341)

    def test_byzantium_retains_long_zero_exponent_length(self):
        # 0x4e9348f computes 8*(elen-32); 0x4e93581 keeps this for zero head.
        self.assertEqual(modexp.gas_eip198(bytes(64), bytes(33), bytes(64)), 1638)

    def test_wrapper_pads_nonempty_zero_modulus(self):
        # Core gives empty Vec; wrapper 0x4e92674..b6 pads to modulus length.
        self.assertEqual(modexp.ref_modexp(b'\x03', b'\x05', bytes(2)), bytes(2))
        self.assertEqual(modexp.ref_modexp(b'\x03', b'\x05', b''), b'')


class ModexpHarnessReviewTests(unittest.TestCase):
    def test_known_fixtures_and_reject_malformed_lengths(self):
        for vector in modexp.VECTORS.values():
            body = modexp.enc_input(*vector)
            self.assertEqual(modexp.validate_fixture(modexp.BERLIN, body, 10000000), tuple(map(len, vector)))
        for entry, body, gas in ((0, bytes(96), 1), (modexp.BERLIN, b'', 1),
                                 (modexp.BERLIN, bytes(97), 1),
                                 (modexp.BERLIN, bytes(96), 10000001),
                                 (modexp.BERLIN, modexp.enc_input(bytes(257), b'', b''), 1)):
            with self.subTest(entry=entry, size=len(body), gas=gas), self.assertRaises(ValueError):
                modexp.validate_fixture(entry, body, gas)

    def test_incomplete_receipts_are_rejected(self):
        import copy
        import json
        packet = Path(modexp.ROOT) / 'research/work-items/RE-028-modexp-94/modexp.json'
        original = json.loads(packet.read_text())
        for kind in ('return', 'kind', 'mutation'):
            result = copy.deepcopy(original)
            if kind == 'return': result['vectors']['eip198_ex1']['berlin']['returned'] = False
            elif kind == 'kind': result['vectors']['eip198_ex1']['berlin']['kind'] = 'err'
            else: result['mutations']['div3_to_4']['returned'] = False
            with self.subTest(kind=kind): self.assertTrue(modexp.expectation_errors(result))

    def test_terminal_and_extended_register_scanner_controls(self):
        import struct
        for prefix in (b'\xff\x15', b'\xff\x25', b'\x48\x8b\x05', b'\x4c\x8b\x25'):
            code = prefix + struct.pack('<i', 0x2000 - 0x1000 - len(prefix) - 4)
            self.assertEqual(len(modexp.slot_refs([(0x1000, code)], 0x2000)), 1)
            self.assertEqual(modexp.slot_refs([(0x1000, code[:-1])], 0x2000), [])
        for op in (b'\xe8', b'\xe9'):
            code = op + struct.pack('<i', 0x2000 - 0x1005)
            self.assertEqual(modexp.direct_candidates([(0x1000, code)], 0x2000), [0x1000])
            self.assertEqual(modexp.direct_candidates([(0x1000, code[:-1])], 0x2000), [])

    def test_default_cli_never_requests_emulation(self):
        from unittest.mock import patch
        import contextlib
        import io
        with patch.object(Path, 'read_bytes', return_value=b'fixture'), \
             patch.object(modexp, 'analyse', return_value={}) as analyse, \
             patch.object(modexp, 'render', return_value='{}\n'), \
             patch.object(modexp, 'expectation_errors', return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(modexp.main([]), 0)
        analyse.assert_called_once_with(b'fixture', check_sha=True, run_emu=False)

    def test_host_callback_memory_bounds_and_zero_size(self):
        from unittest.mock import Mock
        engine = Mock()
        engine.mem_read.return_value = b'ab'
        memory = modexp.FixtureMemory(engine, ((0x1000, 0x1100),), ((0x2000, 0x2100),))
        memory.copy(0x20fe, 0x1000, 2)
        engine.mem_write.assert_called_once_with(0x20fe, b'ab')
        for operation in (lambda: memory.copy(0x20ff, 0x1000, 2),
                          lambda: memory.copy(0x2000, 0x10ff, 2),
                          lambda: memory.copy(0x2000, 0x1000, 0x10001),
                          lambda: memory.fill(0x2000, 0, 0x10001)):
            with self.assertRaises(ValueError): operation()
        memory.copy(0, 0, 0)  # no dereference
        memory.fill(0, 0, 0)

    def test_allocator_rejects_large_requests_and_exhaustion(self):
        from unittest.mock import Mock
        engine = Mock()
        memory = modexp.FixtureMemory(engine, (), ((modexp.HEAP, modexp.HEAP + modexp.FixtureMemory.HEAP_SIZE),))
        self.assertEqual(memory.allocate(0), modexp.HEAP)
        self.assertEqual(memory.allocate(16), modexp.HEAP + 16)
        for size in (-1, 0x10001, 1 << 64):
            with self.assertRaises(ValueError): memory.allocate(size)
        memory.next_heap = modexp.HEAP + modexp.FixtureMemory.HEAP_SIZE
        with self.assertRaisesRegex(ValueError, 'heap exhausted'): memory.allocate(1)
        memory.next_heap = modexp.HEAP
        memory.allocations = 4096
        with self.assertRaisesRegex(ValueError, 'heap exhausted'): memory.allocate(1)

    def test_image_authentication_allows_only_declared_mutations(self):
        data = modexp.TARGET.read_bytes()
        modexp.authenticate_fixture_image(data)
        segs = modexp.segments(data)
        for va, old, new in modexp.FIXTURE_MUTATIONS:
            altered = bytearray(data)
            offset = modexp.va_to_off(segs, va)
            altered[offset:offset + len(new) // 2] = bytes.fromhex(new)
            modexp.authenticate_fixture_image(bytes(altered))
            altered[0] ^= 1
            with self.assertRaises(ValueError): modexp.authenticate_fixture_image(bytes(altered))

    def test_no_native_allocator_or_unreviewed_external_in_allowlist(self):
        for va in (modexp.MALLOC, modexp.REALLOC, modexp.FREE, 0x54c5620, modexp.PANIC, modexp.UNWIND_RESUME_PLT):
            self.assertFalse(any(a <= va < b for a, b in modexp.FIXTURE_CODE_RANGES))


if __name__ == '__main__':
    unittest.main()
