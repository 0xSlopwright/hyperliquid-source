import contextlib
import hashlib
import io


import json


from pathlib import Path


import shutil


import struct


import subprocess


import sys


import tempfile


import unittest


from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))


import bridge_inventory as bi


ROOT = Path(__file__).resolve().parents[1]


ARTIFACT = ROOT / 'artifacts/node/94/hl-node'


MAINNET_SITE = bytes.fromhex('4180ff03b8b1a40000b9ee6e0600480f44c8')


INTERLEAVED_SITE = bytes.fromhex('4080fd03c60061b9b1a40000baee6e0600480f44d1')


def mapping_for(payload, va=0x1000, size=0x400):
    buffer = bytearray(size)
    buffer[:len(payload)] = payload
    return bytes(buffer), bi.Mapping([(0, va, size, 5)])


class ChainSiteTests(unittest.TestCase):
    def test_decodes_seeded_shape(self):
        data, mapping = mapping_for(MAINNET_SITE)
        site = bi.decode_chain_site(data, mapping, 0x1000)
        self.assertEqual(site['selected_when_equal'], 42161)
        self.assertEqual(site['selected_otherwise'], 421614)
        self.assertEqual(site['destination_register'], 'rcx')
        self.assertEqual(site['compare_register'], 'r15b')
        self.assertEqual(site['bytes'], MAINNET_SITE.hex())

    def test_skips_interleaved_tag_store(self):
        data, mapping = mapping_for(INTERLEAVED_SITE)
        site = bi.decode_chain_site(data, mapping, 0x1000)
        self.assertEqual(site['destination_register'], 'rdx')
        self.assertEqual(site['conditional'], 'cmove')

    def test_rejects_swapped_immediates(self):
        swapped = bytearray(MAINNET_SITE)
        swapped[5:9], swapped[10:14] = MAINNET_SITE[10:14], MAINNET_SITE[5:9]
        data, mapping = mapping_for(bytes(swapped))
        with self.assertRaisesRegex(ValueError, 'expected mainnet'):
            bi.decode_chain_site(data, mapping, 0x1000)

    def test_rejects_non_register_cmove(self):
        broken = bytearray(MAINNET_SITE)
        broken[-1] = 0x08  # mod=00
        data, mapping = mapping_for(bytes(broken))
        with self.assertRaisesRegex(ValueError, 'non-register'):
            bi.decode_chain_site(data, mapping, 0x1000)

    def test_rejects_missing_compare(self):
        data, mapping = mapping_for(b'\x90' * 32)
        with self.assertRaisesRegex(ValueError, 'missing REX cmpb'):
            bi.decode_chain_site(data, mapping, 0x1000)


class XrefTests(unittest.TestCase):
    def test_resolves_movups_disp32(self):
        # movups 0x1000(%rip) at 0x2000 targeting 0x2013, then filler.
        insn = bytes.fromhex('0f1005') + struct.pack('<i', 0x2013 - 0x2027)
        data, mapping = mapping_for(b'\x90' * 0x20 + insn, va=0x2000, size=0x100)
        refs = bi.rip_relative_xrefs(data, mapping, 0x2013)
        self.assertEqual([r['instruction_va'] for r in refs], [0x2020])
        self.assertEqual(refs[0]['insn_bytes'], insn.hex())

    def test_ignores_absolute_and_wrong_target(self):
        data, mapping = mapping_for(b'\x0f\x10\x04\x25\x13\x20\x00\x00' * 4, va=0x2000)
        self.assertEqual(bi.rip_relative_xrefs(data, mapping, 0x2013), [])


class WindowScanTests(unittest.TestCase):
    def test_call_ending_at_window_end_is_found(self):
        call = b'\xe8' + struct.pack('<i', 0x100)  # call at 0x1003 -> 0x1108
        data, mapping = mapping_for(b'\x90' * 3 + call)
        self.assertEqual(bi.direct_calls(data, mapping, 0x1000, 8), [0x1108])
        self.assertEqual(bi.direct_calls(data, mapping, 0x1000, 7), [])

    def test_literal_load_ending_at_window_end_is_found(self):
        load = bytes.fromhex('0f1005') + struct.pack('<i', 0x20)  # movups at 0x1002
        data, mapping = mapping_for(b'\x90' * 2 + load)
        self.assertEqual(bi.literal_loads(data, mapping, 0x1000, 9),
                         [{'load_va': 0x1002, 'literal_va': 0x1029}])
        self.assertEqual(bi.literal_loads(data, mapping, 0x1000, 8), [])


class TableTests(unittest.TestCase):
    def test_rejects_arm_outside_function(self):
        table = struct.pack('<8i', *([0x7FFF] * 8))
        data, mapping = mapping_for(table, va=0x1000, size=0x100)
        with mock.patch.object(bi, 'STRUCT_HASH_TABLE', 0x1000), \
                mock.patch.object(bi, 'STRUCT_HASH_START', 0x1000):
            with self.assertRaisesRegex(ValueError, 'outside struct_hash'):
                bi.decode_struct_hash_table(data, mapping)

    def test_decodes_relative_entries(self):
        table = struct.pack('<8i', *([0x20] * 8))
        data, mapping = mapping_for(table, va=0x1000, size=0x100)
        with mock.patch.object(bi, 'STRUCT_HASH_TABLE', 0x1000), \
                mock.patch.object(bi, 'STRUCT_HASH_START', 0x1000):
            arms = bi.decode_struct_hash_table(data, mapping)
        self.assertEqual([a['target_va'] for a in arms], [0x1020] * 8)
        self.assertEqual([a['discriminant'] for a in arms], list(range(8)))


class FunctionBoundsTests(unittest.TestCase):
    """Synthetic ELF whose first function is followed by alignment padding."""

    TEXT, HDR, FRAME = 0x1000, 0x2000, 0x3000

    def build(self, functions):
        # functions: list of (start, pc_range), one FDE record each.
        cie = struct.pack('<I', 0) + b'\x01zR\x00\x01\x78\x10\x01\x1b'
        frame = bytearray(struct.pack('<I', len(cie)) + cie)
        fde_vas = []
        for start, pc_range in functions:
            fde_va = self.FRAME + len(frame)
            body = struct.pack('<I', fde_va + 4 - self.FRAME)
            body += struct.pack('<i', start - (fde_va + 8))  # initial_location
            body += struct.pack('<I', pc_range)            # address_range
            body += b'\x00'                              # empty augmentation
            frame += struct.pack('<I', len(body)) + body
            fde_vas.append(fde_va)
        frame += b'\x00' * 4
        header = bytes([1, 0x1B, 0x03, 0x3B])
        header += struct.pack('<i', self.FRAME - (self.HDR + 4))
        header += struct.pack('<I', len(functions))
        for (start, _range), fde_va in zip(functions, fde_vas):
            header += struct.pack('<i', start - self.HDR)
            header += struct.pack('<i', fde_va - self.HDR)
        names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
        shoff = 0x800
        data = bytearray(shoff + 5 * 64)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', data, 40, shoff)
        struct.pack_into('<HHH', data, 58, 64, 5, 1)
        data[64:64 + len(names)] = names
        data[0x400:0x400 + len(header)] = header
        data[0x600:0x600 + len(frame)] = frame
        rows = [(0, 0, 0, 0, 0, 0),
                (names.index(b'.shstrtab'), 3, 0, 0, 64, len(names)),
                (names.index(b'.text'), 1, 6, self.TEXT, 0x200, 0x100),
                (names.index(b'.eh_frame_hdr'), 1, 2, self.HDR, 0x400, len(header)),
                (names.index(b'.eh_frame\0'), 1, 2, self.FRAME, 0x600, len(frame))]
        for index, row in enumerate(rows):
            struct.pack_into('<IIQQQQIIQQ', data, shoff + index * 64, *row, 0, 0, 1, 0)
        return bytes(data)

    def test_end_is_fde_extent_not_next_start(self):
        data = self.build([(0x1000, 0x10), (0x1020, 0x20)])
        # 0x1010..0x1020 is padding; the next start must not become the end.
        self.assertEqual(bi.function_bounds(data, 0x1008), (0x1000, 0x1010))

    def test_last_function_end_comes_from_fde(self):
        data = self.build([(0x1000, 0x10), (0x1020, 0x20)])
        self.assertEqual(bi.function_bounds(data, 0x1030), (0x1020, 0x1040))

    def test_precedes_first_start_still_rejected(self):
        data = self.build([(0x1000, 0x10)])
        with self.assertRaisesRegex(ValueError, 'precedes the first unwind start'):
            bi.function_bounds(data, 0x800)

    def test_padding_and_exclusive_end_are_not_function_bytes(self):
        data = self.build([(0x1000, 0x10), (0x1020, 0x20)])
        for va in (0x1010, 0x1018, 0x1040):
            with self.subTest(va=va), self.assertRaisesRegex(ValueError, 'outside.*FDE extent'):
                bi.function_bounds(data, va)

    def test_truncated_fde_record_is_rejected(self):
        data = bytearray(self.build([(0x1000, 0x10)]))
        struct.pack_into('<I', data, 0x600 + 17, 0x10000)
        with self.assertRaisesRegex(ValueError, 'record outside section'):
            bi.function_bounds(bytes(data), 0x1008)

    def test_invalid_cie_is_rejected_before_interpreting_range(self):
        data = bytearray(self.build([(0x1000, 0x10)]))
        data[0x608] = 9
        with self.assertRaisesRegex(ValueError, 'Unsupported CIE version'):
            bi.function_bounds(bytes(data), 0x1008)

    def test_extent_leaving_executable_section_is_rejected(self):
        data = self.build([(0x1000, 0x200)])
        with self.assertRaisesRegex(ValueError, 'leaves executable'):
            bi.function_bounds(data, 0x1008)


class ArtifactTests(unittest.TestCase):
    def run_cli(self, artifact, output):
        return subprocess.run(
            [sys.executable, str(ROOT / 'tools/bridge_inventory.py'),
             '--artifact', str(artifact), '--out', str(output)],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )

    def assert_report_and_excerpts(self, result, output, artifact_name):
        self.assertEqual(result.returncode, 0, result.stderr)
        canonical = ROOT / 'research/work-items/bridge/evidence'
        expected = json.loads((canonical / 'bridge-inventory.json').read_text())
        expected['artifact'] = artifact_name
        self.assertEqual(json.loads(result.stdout), expected)
        self.assertEqual((output / 'bridge-inventory.json').read_text(), result.stdout)
        excerpts = list(canonical.glob('*.bin'))
        self.assertEqual(len(excerpts), 4)
        self.assertEqual({p.name for p in output.glob('*.bin')}, {p.name for p in excerpts})
        for excerpt in excerpts:
            self.assertEqual((output / excerpt.name).read_bytes(), excerpt.read_bytes())

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_explicit_relative_artifact_writes_canonical_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report'
            relative = ARTIFACT.relative_to(ROOT)
            result = self.run_cli(relative, output)
            self.assert_report_and_excerpts(result, output, relative.as_posix())

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_external_artifact_is_portable_and_still_digest_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / 'verified-node94'
            shutil.copyfile(ARTIFACT, external)
            output = Path(directory) / 'report'
            result = self.run_cli(external, output)
            self.assert_report_and_excerpts(result, output, external.name)
            self.assertNotIn(str(external.parent), result.stdout)
            with external.open('r+b') as handle:
                handle.write(b'bad!')
            refused_output = Path(directory) / 'refused'
            refused = self.run_cli(external, refused_output)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('SHA-256', refused.stderr)
            self.assertFalse(refused_output.exists())

    def test_rejects_corrupted_digest(self):
        # NamedTemporaryFile keeps an exclusive delete-on-close handle on Windows,
        # so the artifact loader cannot reopen it by name there.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'hl-node'
            path.write_bytes(b'\x7fELF')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                bi.load_artifact(path, 94)

    def test_missing_literal_is_detected(self):
        self.assertEqual(bi.find_all(b'no literal here', b'requestWithdrawal'), [])

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_end_to_end_report_is_pinned(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bi.main(['--release', '94'])
        report = json.loads(out.getvalue())
        self.assertEqual(report['artifact_sha256'], bi.TARGET_SHA256[94])
        self.assertEqual(report['artifact'], 'artifacts/node/94/hl-node')
        self.assertEqual(report['literal']['va'], bi.SEED_LITERAL_OFFSET)
        self.assertEqual(len(report['chain_id_sites']), 3)
        seeded = bi.Mapping(bi.load_segments(ARTIFACT.read_bytes())).offset_to_va(bi.SEED_CHAIN_OFFSET)
        self.assertTrue(any(s['site_va'] <= seeded < s['site_va'] + s['length']
                            for s in report['chain_id_sites']))
        layout = report['struct_hash']['withdrawal_arm_layout']['field_source_offsets']
        self.assertEqual(layout['account']['offset'], 1)
        self.assertEqual(layout['destination']['offset'], 0x15)
        self.assertEqual(report['struct_hash']['withdrawal_encoder']['tags'], [6, 0, 0, 4, 4])
        arms = {a['discriminant']: a for a in report['struct_hash']['arms']}
        # Reserved (6) ends at its jmp at 0x358e7af; 0x3c97be0 belongs to arm 7's continuation.
        self.assertEqual((arms[6]['span'], arms[6]['direct_calls'], arms[6]['continuations']),
                         (0x23A, [0x3C9F240], []))
        self.assertEqual(arms[7]['direct_calls'], [0x3C97BE0])
        self.assertEqual(arms[7]['continuations'],
                         [{'branch_va': 0x358E2B6, 'start_va': 0x358E7B4, 'end_va': 0x358E85B}])
        self.assertTrue(all(arms[i]['continuations'] == [] for i in arms if i != 7))

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_arm_extent_pins_fail_closed(self):
        data = ARTIFACT.read_bytes()
        mapping = bi.Mapping(bi.load_segments(data))
        arms = bi.decode_struct_hash_table(data, mapping)
        for patch, message in (
                (('LAST_ARM_JMP', 0x358E7AE), 'last arm does not end with jmp'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B6, 0x358E7B5, 0x358E85B)]}), 'does not reach'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B7, 0x358E7B4, 0x358E85B)]}), 'expected jcc'),
                (('ARM_CONTINUATIONS', {6: [(0x358E2B6, 0x358E7B4, 0x358E85B)]}), 'expected jcc'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B6, 0x358E7B4, 0x358E85C)]}), 'does not end with a call')):
            with self.subTest(patch=patch), mock.patch.object(bi, *patch):
                with self.assertRaisesRegex(ValueError, message):
                    bi.arm_windows(data, mapping, arms)

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_packet_regenerates_and_manifest_matches(self):
        packet = ROOT / 'research/work-items/bridge'
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bi.main(['--release', '94', '--out', tmp]), 0)
            for path in Path(tmp).iterdir():
                self.assertEqual(path.read_bytes(), (packet / 'evidence' / path.name).read_bytes(), path.name)
        # Packet files only; the manifest also pins ../../../tools and tests
        # for `shasum -c`, which edits to those files must refresh.
        for line in (packet / 'evidence/MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            if not name.startswith('../'):
                self.assertEqual(hashlib.sha256((packet / name).read_bytes()).hexdigest(), digest, name)


class ChainSiteWindowTests(unittest.TestCase):
    def test_rejects_moves_running_past_window(self):
        payload = bytes.fromhex('4180ff03') + b'\xc6\x00\x61' * 12
        data, mapping = mapping_for(payload)
        with self.assertRaises(ValueError):
            bi.decode_chain_site(data, mapping, 0x1000)

    def test_main_reports_missing_artifact(self):
        self.assertEqual(bi.main(['--artifact', '/tmp/definitely-missing-hl.bin']), 1)


if __name__ == '__main__':
    unittest.main()
