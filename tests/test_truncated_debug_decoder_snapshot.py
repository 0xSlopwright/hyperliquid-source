"""truncated_debug generate() must decode a private snapshot of the admitted bytes.

Sibling of the merged snapshot packets (api_suffix_static,
critical_message_static, funding_bucket_static, hourly_rotation_static,
unique_value_static), open #1094 (build_mode_route), open #1095
(latency_sample), open #1103 (liner_init), open #1105 (file_tracker_init),
open #1109 (rate_maintenance), open #1110 (short_string) and own #1100
(cguard_consistency) / #1111 (receiver_poll): this tool admitted the
target once (artifacts.check + source_bindings on the bytes read into
memory) but then ran readelf/objdump against the target *path*, so the
emitted frames/family-objdump/relocations output was bound to whatever
the path served at decode time while records.json stamped the admitted
digest. This is the last path-decoding *_static packet on base.

The pinned node94 capture is an LFS pointer on this VM, so admission
(check/source_bindings/census) is stubbed here; what this test verifies
is exactly the defect's surface — which file the decoders open. The
wrapper swaps the binary file's bytes (same size) at the first decoder
call, modelling a replacement between admission and decode, and records
the path each decoder was given plus the bytes at that path at call time.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import truncated_debug_static as tool

ADMITTED = b'A' * 64
SWAPPED = b'B' * 64
ROW = {'start_va': '0x1400000', 'end_va': '0x1400100',
       'source_xref': '0x1400010', 'bytes': 256, 'guard_profile': 'bf-jle'}


class DecoderSnapshotTests(unittest.TestCase):
    def run_generate(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        binary = root / 'hl-node'
        binary.write_bytes(ADMITTED)
        out = root / 'out'
        calls = []
        swapped = []

        def fake_check_output(cmd, text=True):
            if not swapped:
                binary.write_bytes(SWAPPED)
                swapped.append(True)
            path = cmd[-1]
            calls.append((path, Path(path).read_bytes()))
            if '-wf' in cmd:
                return 'FDE pc=0000000001400000..0000000001400100\n'
            if '-d' in cmd:
                return '  1400010: 4c 8d 05 00 00 00 00 lea rax, [rip+0x0]\n'
            if '-rW' in cmd:
                lines = [f'{slot:x}  RELATIVE\n' for slot in tool.SLOTS]
                lines.append('576e040  RELATIVE\n')
                return ''.join(lines)
            raise AssertionError(f'unexpected decoder call: {cmd}')

        orig = (tool.check, tool.source_bindings, tool.census,
                tool.subprocess.check_output)
        tool.check = lambda binary_, identity: None
        tool.source_bindings = lambda data: []
        # census already reads from the admitted `data`; it is not the
        # defect surface, so it is stubbed alongside admission.
        tool.census = lambda data, fdes: [dict(ROW)]
        tool.subprocess.check_output = fake_check_output
        try:
            result = tool.generate(binary, out)
        finally:
            (tool.check, tool.source_bindings, tool.census,
             tool.subprocess.check_output) = orig
        return binary, out, calls, result

    def test_decoders_do_not_open_the_target_path(self):
        binary, out, calls, _ = self.run_generate()
        self.assertEqual(len(calls), 3)  # readelf frames + 1 objdump + readelf rela
        for path, _ in calls:
            self.assertNotEqual(path, str(binary))

    def test_decoders_read_the_admitted_bytes(self):
        binary, out, calls, result = self.run_generate()
        for path, seen in calls:
            self.assertEqual(seen, ADMITTED)
        self.assertEqual(result['target_bytes'], len(ADMITTED))
        records = json.loads((out / 'records.json').read_text())
        self.assertEqual(records['target_bytes'], len(ADMITTED))
        self.assertTrue((out / 'frames.txt').exists())
        self.assertTrue((out / 'relocations.txt').exists())
        self.assertTrue((out / 'family.objdump.txt').exists())


if __name__ == '__main__':
    unittest.main()
